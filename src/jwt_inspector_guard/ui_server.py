"""Lightweight ThreadingHTTPServer serving the JWT Inspector Guard Web UI and REST API.

Serves the static ``public/`` directory at ``/`` and exposes a small JSON REST
API under ``/api/`` so the browser UI can call backend logic without any
additional dependencies.

Endpoints
---------
GET  /                         → public/index.html
GET  /health                   → {"status": "ok"}
POST /api/decode               → Decode JWT header + payload
POST /api/verify               → HMAC signature verification
POST /api/validate             → Claims validation
POST /api/audit                → Full security lint report
POST /api/inspect              → All-in-one decode + validate + audit
GET  /api/catalog              → List sample tokens and algorithm profiles
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Resolve the public directory (sibling of src/)
# ---------------------------------------------------------------------------
_HERE = pathlib.Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent.parent  # src/jwt_inspector_guard → src → project root
_PUBLIC_DIR = _PROJECT_ROOT / "public"


def _read_public_file(rel_path: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Return (content_bytes, mime_type) for a file in the public directory, or (None, None)."""
    safe_rel = rel_path.lstrip("/")
    if not safe_rel or safe_rel == "":
        safe_rel = "index.html"
    target = (_PUBLIC_DIR / safe_rel).resolve()
    # Security: must remain inside _PUBLIC_DIR
    try:
        target.relative_to(_PUBLIC_DIR)
    except ValueError:
        return None, None

    if target.is_dir():
        target = target / "index.html"

    if not target.is_file():
        return None, None

    mime_map = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".woff2": "font/woff2",
        ".woff": "font/woff",
    }
    ext = target.suffix.lower()
    mime = mime_map.get(ext, "application/octet-stream")
    return target.read_bytes(), mime


# ---------------------------------------------------------------------------
# Lazy import of core modules so ui_server can be imported without failures
# ---------------------------------------------------------------------------

def _get_core():
    """Return a namespace with core functions, importing lazily."""
    from jwt_inspector_guard import token_parser, crypto_engine, claims_validator, security_linter, catalog
    return token_parser, crypto_engine, claims_validator, security_linter, catalog


# ---------------------------------------------------------------------------
# REST API handlers
# ---------------------------------------------------------------------------

def _api_decode(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, _, _, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        return {"error": "token field is required"}
    parsed = token_parser.parse_token(token)
    return parsed.to_dict()


def _api_verify(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, crypto_engine, _, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    secret = str(body.get("secret", ""))
    alg = str(body.get("algorithm", "HS256")).upper()
    if not token:
        return {"error": "token field is required"}
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        return {"error": "Invalid JWT format", "detail": parsed.error_message}
    verified = crypto_engine.verify_hmac(
        parsed.header_b64, parsed.payload_b64, parsed.signature_b64 or "", secret, alg
    )
    return {"verified": verified, "algorithm": alg}


def _api_validate(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, _, claims_validator, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        return {"error": "token field is required"}
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        return {"error": "Invalid JWT format"}
    opts: Dict[str, Any] = {}
    if body.get("issuer"):
        opts["expected_iss"] = body["issuer"]
    if body.get("audience"):
        opts["expected_aud"] = body["audience"]
    if body.get("leeway") is not None:
        opts["leeway"] = float(body["leeway"])
    results = claims_validator.validate_all_claims(parsed.payload, **opts)
    return {"results": [r.to_dict() if hasattr(r, "to_dict") else r for r in results]}


def _api_audit(body: Dict[str, Any]) -> Dict[str, Any]:
    _, _, _, security_linter, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        return {"error": "token field is required"}
    report = security_linter.lint_token(token)
    return report.to_dict() if hasattr(report, "to_dict") else report


def _api_inspect(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, crypto_engine, claims_validator, security_linter, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        return {"error": "token field is required"}
    parsed = token_parser.parse_token(token)
    claim_results = []
    if parsed.is_valid_format:
        claim_results_raw = claims_validator.validate_all_claims(parsed.payload)
        claim_results = [r.to_dict() if hasattr(r, "to_dict") else r for r in claim_results_raw]
    audit_report = security_linter.lint_token(token)
    return {
        "parsed": parsed.to_dict(),
        "claims": claim_results,
        "audit": audit_report.to_dict() if hasattr(audit_report, "to_dict") else audit_report,
    }


def _api_catalog(_body: Dict[str, Any]) -> Dict[str, Any]:
    _, _, _, _, catalog_mod = _get_core()
    tokens = catalog_mod.list_sample_tokens()
    return {
        "tokens": [t.to_dict() for t in tokens],
        "categories": catalog_mod.list_categories(),
    }


def _api_crack(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, crypto_engine, _, _, catalog_mod = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        return {"error": "token field is required"}
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        return {"error": "Invalid token format"}
    alg = parsed.algorithm or "HS256"
    wordlist = body.get("wordlist")
    if not wordlist:
        from jwt_inspector_guard.security_linter import COMMON_WEAK_SECRETS
        wordlist = list(COMMON_WEAK_SECRETS)
    cracked = crypto_engine.crack_hmac_secret(
        parsed.header_b64, parsed.payload_b64, parsed.signature_b64 or "", alg, wordlist
    )
    return {
        "found": cracked is not None,
        "secret": cracked,
        "tested_count": len(wordlist),
        "algorithm": alg,
    }


def _api_mint(body: Dict[str, Any]) -> Dict[str, Any]:
    _, crypto_engine, _, _, _ = _get_core()
    header = body.get("header", {"alg": "HS256", "typ": "JWT"})
    payload = body.get("payload", {"sub": "user_123", "name": "Alice"})
    secret = str(body.get("secret", "secret"))
    alg = str(body.get("algorithm", header.get("alg", "HS256"))).upper()
    token = crypto_engine.generate_hmac_jwt(header, payload, secret, alg)
    from jwt_inspector_guard.token_parser import parse_token
    parsed = parse_token(token)
    return {
        "token": token,
        "header_b64": parsed.header_b64,
        "payload_b64": parsed.payload_b64,
        "signature_b64": parsed.signature_b64,
        "algorithm": alg,
    }


def _api_entropy(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, crypto_engine, _, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        return {"error": "token field is required"}
    parsed = token_parser.parse_token(token)
    total_entropy = crypto_engine.calculate_token_entropy(token)
    payload_entropy = crypto_engine.calculate_token_entropy(parsed.payload_b64)
    sig_entropy = crypto_engine.calculate_token_entropy(parsed.signature_b64 or "")
    return {
        "total_entropy": total_entropy,
        "payload_entropy": payload_entropy,
        "signature_entropy": sig_entropy,
        "length": len(token),
    }


def _api_tamper(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, crypto_engine, _, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    attack_type = str(body.get("type", "none")).lower()
    if not token:
        return {"error": "token field is required"}
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        return {"error": "Invalid token format"}
    
    header = dict(parsed.header)
    payload = dict(parsed.payload)
    
    if attack_type in ("none", "cve-2015-9235"):
        header["alg"] = "none"
        from jwt_inspector_guard.base64_url import base64url_encode_json
        h_b64 = base64url_encode_json(header)
        p_b64 = base64url_encode_json(payload)
        tampered = f"{h_b64}.{p_b64}."
    elif attack_type == "admin_escalate":
        payload["role"] = "admin"
        payload["is_admin"] = True
        payload["admin"] = True
        tampered = crypto_engine.generate_hmac_jwt(header, payload, "secret", header.get("alg", "HS256"))
    elif attack_type == "strip_signature":
        tampered = f"{parsed.header_b64}.{parsed.payload_b64}."
    else:
        tampered = token

    return {"tampered_token": tampered, "attack_type": attack_type}


def _api_jwks(body: Dict[str, Any]) -> Dict[str, Any]:
    from jwt_inspector_guard.jwks_manager import JWKSRotationSimulator
    sim = JWKSRotationSimulator()
    if body.get("rotate", False):
        sim.rotate_active_key()
    external_jwks = body.get("jwks")
    report = sim.audit_jwks_health(external_jwks=external_jwks)
    res = report.to_dict()
    token = body.get("token")
    if token:
        res["resolved_token_key"] = sim.resolve_key_for_token(token)
    return res


def _api_timing(body: Dict[str, Any]) -> Dict[str, Any]:
    from jwt_inspector_guard.timing_defense import (
        benchmark_signature_comparison,
        safe_constant_time_compare,
        vulnerable_early_exit_compare,
    )
    test_vuln = bool(body.get("test_vulnerable", False))
    trials = int(body.get("trials", 50))
    cmp_fn = vulnerable_early_exit_compare if test_vuln else safe_constant_time_compare
    report = benchmark_signature_comparison(compare_func=cmp_fn, trials=trials)
    return report.to_dict()


_API_ROUTES = {
    "/api/decode": _api_decode,
    "/api/verify": _api_verify,
    "/api/validate": _api_validate,
    "/api/audit": _api_audit,
    "/api/inspect": _api_inspect,
    "/api/catalog": _api_catalog,
    "/api/crack": _api_crack,
    "/api/mint": _api_mint,
    "/api/entropy": _api_entropy,
    "/api/tamper": _api_tamper,
    "/api/jwks": _api_jwks,
    "/api/timing": _api_timing,
}


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------

class JWTInspectorHandler(BaseHTTPRequestHandler):
    """HTTP request handler for JWT Inspector Guard UI + REST API."""

    server_version = "JWTInspectorGuard/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # type: ignore[override]
        # Suppress default verbose Apache-style logging; redirect to stderr only on debug
        pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, mime: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self._send_json({"status": "ok", "service": "jwt-inspector-guard"})
            return

        # Static file serving
        content, mime = _read_public_file(path)
        if content is not None and mime is not None:
            self._send_bytes(content, mime)
        else:
            # Fall back to index.html for SPA behaviour
            content, mime = _read_public_file("index.html")
            if content is not None and mime is not None:
                self._send_bytes(content, mime)
            else:
                self._send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        handler = _API_ROUTES.get(path)
        if handler is None:
            self._send_json({"error": f"Unknown API endpoint: {path}"}, 404)
            return

        body = self._read_json_body()
        try:
            result = handler(body)
            self._send_json(result)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)


# ---------------------------------------------------------------------------
# Threading HTTP Server
# ---------------------------------------------------------------------------

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server to handle concurrent requests."""

    daemon_threads = True
    allow_reuse_address = True


def run_server(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Start the JWT Inspector Guard web UI server.

    Args:
        host: Bind address (default: 127.0.0.1).
        port: Port to listen on (default: 8765).
        open_browser: Whether to open the default browser automatically.
    """
    server = ThreadingHTTPServer((host, port), JWTInspectorHandler)
    url = f"http://{host}:{port}"
    print(f"  JWT Inspector Guard UI → {url}")
    print("  Press Ctrl+C to stop.\n")

    if open_browser:
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
