"""Hardened ThreadingHTTPServer serving the JWT Inspector Guard v2.6.0 Web UI and REST API.

Serves the static ``public/`` directory at ``/`` and exposes the JSON REST API
under ``/api/`` on loopback (``127.0.0.1:8124`` by default) with:
- Strict loopback Host header validation (DNS-rebinding 403 defense)
- Strict exact-port Origin allowlisting on GET/HEAD/POST/OPTIONS (403 on untrusted origins)
- Mandatory HTTP security headers + strict loopback CSP + Cache-Control: no-store on /api/*
- Stripped Python version from Server header
- 1 MiB POST body cap (413), strict JSON & numeric validation (400), bounded timing trials (1..5000)
- Real 404 Not Found for unknown paths, traversal containment via Path.is_relative_to()
- Full HEAD support and proper MIME types (.txt, .xml, .json, .png, .svg, etc.)
"""

from __future__ import annotations

import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------------
# Constants & Public Directory Resolution
# ---------------------------------------------------------------------------
APP_VERSION = "2.6.0"
MAX_JSON_BODY_BYTES = 1_048_576  # 1 MiB hard cap
MAX_TIMING_TRIALS = 5000

_HERE = pathlib.Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent.parent  # src/jwt_inspector_guard -> src -> project root
_PUBLIC_DIR = (_PROJECT_ROOT / "public").resolve()

_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' http://127.0.0.1:* http://localhost:*; "
    "frame-ancestors 'self' http://127.0.0.1:* http://localhost:*"
)

_MIME_MAP: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
}


class _BadRequestError(ValueError):
    """Raised when client supplies malformed JSON or invalid parameters (HTTP 400)."""


class _PayloadTooLargeError(ValueError):
    """Raised when Content-Length exceeds MAX_JSON_BODY_BYTES (HTTP 413)."""


def _safe_rel(raw: str) -> str:
    """Validate request path -> safe relative path inside public/, or '' if root or traversal."""
    text = unquote(str(raw or ""))
    if "\x00" in text:
        return ""
    norm = text.replace("\\", "/")
    rel = norm.lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts:
        return ""
    if any(p == ".." for p in parts) or ":" in parts[0]:
        return ""
    return "/".join(parts)


def _allowed_ports(server_port: Optional[int]) -> Set[int]:
    ports: Set[int] = {3000}
    if server_port is not None:
        ports.add(int(server_port))
    else:
        ports.add(8124)
    return ports


def _is_allowed_host(host_header: Optional[str], server_port: Optional[int] = None) -> bool:
    """Validate Host header strictly against exact loopback host + bound port."""
    if not host_header:
        return True
    raw = host_header.strip().lower()
    if not raw:
        return False
    allowed_hosts = {"127.0.0.1", "localhost", "[::1]", "::1"}
    bound_port = int(server_port) if server_port else 8124
    # Handle IPv6 bracketed [::1]:port
    if raw.startswith("["):
        if "]:" in raw:
            h, p = raw.rsplit(":", 1)
            return h == "[::1]" and p.isdigit() and int(p) == bound_port
        return raw == "[::1]" and bound_port == 80
    if ":" in raw:
        h, p = raw.rsplit(":", 1)
        return h in allowed_hosts and p.isdigit() and int(p) == bound_port
    return raw in allowed_hosts and bound_port == 80


def _is_local_origin(origin: Optional[str], server_port: Optional[int] = None) -> bool:
    """True for missing Origin (same-origin/CLI) or exact allowed loopback Origin (host + exact port)."""
    if not origin:
        return True
    try:
        u = urlparse(origin.strip())
    except Exception:
        return False
    if u.scheme != "http":
        return False
    if u.path not in ("", "/") or u.query or u.fragment or u.username or u.password:
        return False
    host = (u.hostname or "").lower()
    if host not in ("localhost", "127.0.0.1", "::1"):
        return False
    try:
        port = u.port
    except ValueError:
        return False
    if port is None:
        return False
    return port in _allowed_ports(server_port)


def _cors_origin(handler: BaseHTTPRequestHandler) -> Optional[str]:
    """Echo Origin ONLY when explicitly present and validated against exact loopback ports."""
    origin = handler.headers.get("Origin")
    server_port = getattr(handler.server, "server_port", None)
    if origin and _is_local_origin(origin, server_port):
        return origin.strip()
    return None


def _read_public_file(rel_path: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Return (content_bytes, mime_type) for a file inside public/, or (None, None)."""
    raw_clean = str(rel_path or "")
    if raw_clean in ("", "/", "/index.html"):
        safe_rel = "index.html"
    else:
        safe_rel = _safe_rel(raw_clean)
        if not safe_rel:
            return None, None
    target = (_PUBLIC_DIR / safe_rel).resolve()
    if not target.is_relative_to(_PUBLIC_DIR):
        return None, None
    if target.is_dir():
        return None, None
    if not target.is_file():
        return None, None
    ext = target.suffix.lower()
    mime = _MIME_MAP.get(ext, "application/octet-stream")
    return target.read_bytes(), mime


# ---------------------------------------------------------------------------
# Lazy import of core modules
# ---------------------------------------------------------------------------

def _get_core():
    from jwt_inspector_guard import (
        catalog,
        claims_validator,
        crypto_engine,
        security_linter,
        token_parser,
    )
    return token_parser, crypto_engine, claims_validator, security_linter, catalog


def _parse_int(val: Any, name: str, default: int, min_v: int, max_v: int) -> int:
    if val is None:
        return default
    if isinstance(val, bool):
        raise _BadRequestError(f"Parameter '{name}' must be an integer")
    try:
        parsed = int(val)
    except (ValueError, TypeError) as exc:
        raise _BadRequestError(f"Parameter '{name}' must be a valid integer") from exc
    if parsed < min_v or parsed > max_v:
        raise _BadRequestError(f"Parameter '{name}' must be between {min_v} and {max_v}")
    return parsed


def _parse_float(val: Any, name: str, default: float, min_v: float, max_v: float) -> float:
    if val is None:
        return default
    if isinstance(val, bool):
        raise _BadRequestError(f"Parameter '{name}' must be a number")
    try:
        parsed = float(val)
    except (ValueError, TypeError) as exc:
        raise _BadRequestError(f"Parameter '{name}' must be a valid number") from exc
    if parsed < min_v or parsed > max_v:
        raise _BadRequestError(f"Parameter '{name}' must be between {min_v} and {max_v}")
    return parsed


# ---------------------------------------------------------------------------
# REST API handlers
# ---------------------------------------------------------------------------

def _api_decode(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, _, _, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        raise _BadRequestError("token field is required")
    parsed = token_parser.parse_token(token)
    return parsed.to_dict()


def _api_verify(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, crypto_engine, _, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    secret = str(body.get("secret", ""))
    jwk = body.get("jwk")
    allow_none = bool(body.get("allow_none", False))
    if not token:
        raise _BadRequestError("token field is required")
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        return {"verified": False, "error": "Invalid JWT format", "detail": parsed.error_message}
    alg = str(body.get("algorithm") or parsed.algorithm or "HS256").upper()
    if isinstance(jwk, dict) and alg in ("ES256", "RS256", "RS384", "RS512"):
        verified = crypto_engine.verify_asymmetric_jwk(
            parsed.header_b64, parsed.payload_b64, parsed.signature_b64 or "", jwk, alg
        )
        return {"verified": verified, "algorithm": alg, "mode": "asymmetric_jwk"}
    verified = crypto_engine.verify_hmac(
        parsed.header_b64,
        parsed.payload_b64,
        parsed.signature_b64 or "",
        secret,
        alg,
        allow_none=allow_none,
    )
    return {"verified": verified, "algorithm": alg, "mode": "hmac"}


def _api_validate(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, _, claims_validator, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        raise _BadRequestError("token field is required")
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        raise _BadRequestError("Invalid JWT format")
    leeway = _parse_float(body.get("leeway"), "leeway", 0.0, 0.0, 86400.0)
    res = claims_validator.validate_claims(
        parsed.payload,
        expected_issuer=body.get("issuer"),
        expected_audience=body.get("audience"),
        expected_subject=body.get("subject"),
        leeway_sec=int(leeway),
    )
    data = res.to_dict() if hasattr(res, "to_dict") else res
    return {"validation": data, "results": [data]}


def _api_audit(body: Dict[str, Any]) -> Dict[str, Any]:
    _, _, _, security_linter, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        raise _BadRequestError("token field is required")
    report = security_linter.lint_token(token)
    return report.to_dict() if hasattr(report, "to_dict") else report


def _api_inspect(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, _, claims_validator, security_linter, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        raise _BadRequestError("token field is required")
    parsed = token_parser.parse_token(token)
    claim_results = []
    validation_dict: Optional[Dict[str, Any]] = None
    if parsed.is_valid_format:
        leeway = _parse_float(body.get("leeway"), "leeway", 0.0, 0.0, 86400.0)
        v_res = claims_validator.validate_claims(
            parsed.payload,
            expected_issuer=body.get("issuer"),
            expected_audience=body.get("audience"),
            leeway_sec=int(leeway),
        )
        validation_dict = v_res.to_dict() if hasattr(v_res, "to_dict") else v_res
        claim_results = [validation_dict]
    audit_report = security_linter.lint_token(token)
    return {
        "parsed": parsed.to_dict(),
        "validation": validation_dict,
        "claims": claim_results,
        "audit": audit_report.to_dict() if hasattr(audit_report, "to_dict") else audit_report,
    }


def _api_catalog(_body: Dict[str, Any]) -> Dict[str, Any]:
    _, _, _, _, catalog_mod = _get_core()
    tokens = catalog_mod.list_sample_tokens()
    return {
        "count": len(tokens),
        "tokens": [t.to_dict() for t in tokens],
        "categories": catalog_mod.list_categories(),
    }


def _api_crack(body: Dict[str, Any]) -> Dict[str, Any]:
    token_parser, crypto_engine, _, _, _ = _get_core()
    token = str(body.get("token", "")).strip()
    if not token:
        raise _BadRequestError("token field is required")
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        raise _BadRequestError("Invalid token format")
    alg = (parsed.algorithm or "HS256").upper()
    wordlist = body.get("wordlist")
    if wordlist is None:
        from jwt_inspector_guard.security_linter import COMMON_WEAK_SECRETS
        wordlist = list(COMMON_WEAK_SECRETS)
    elif not isinstance(wordlist, list):
        raise _BadRequestError("wordlist must be a JSON array of strings")
    else:
        wordlist = [str(w) for w in wordlist[:10000]]
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
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise _BadRequestError("header and payload must be JSON objects")
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
        raise _BadRequestError("token field is required")
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
        raise _BadRequestError("token field is required")
    parsed = token_parser.parse_token(token)
    if not parsed.is_valid_format:
        raise _BadRequestError("Invalid token format")

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
        alg = str(header.get("alg", "HS256")).upper()
        if alg not in ("HS256", "HS384", "HS512"):
            alg = "HS256"
            header["alg"] = "HS256"
        tampered = crypto_engine.generate_hmac_jwt(header, payload, "secret", alg)
    elif attack_type == "strip_signature":
        tampered = f"{parsed.header_b64}.{parsed.payload_b64}."
    elif attack_type == "kid_traversal":
        header["kid"] = "../../../dev/null"
        tampered = crypto_engine.generate_hmac_jwt(header, payload, "", "HS256")
    elif attack_type == "jku_ssrf":
        header["jku"] = "https://attacker.example.invalid/jwks.json"
        tampered = crypto_engine.generate_hmac_jwt(header, payload, "secret", "HS256")
    else:
        tampered = token

    return {"tampered_token": tampered, "attack_type": attack_type}


def _api_jwks(body: Dict[str, Any]) -> Dict[str, Any]:
    from jwt_inspector_guard.jwks_manager import JWKSRotationSimulator
    sim = JWKSRotationSimulator()
    if body.get("rotate", False):
        sim.rotate_active_key()
    external_jwks = body.get("jwks")
    if external_jwks is not None and not isinstance(external_jwks, dict):
        raise _BadRequestError("jwks must be a JSON object")
    report = sim.audit_jwks_health(external_jwks=external_jwks)
    res = report.to_dict()
    token = body.get("token")
    if token:
        res["resolved_token_key"] = sim.resolve_key_for_token(str(token))
    return res


def _api_timing(body: Dict[str, Any]) -> Dict[str, Any]:
    from jwt_inspector_guard.timing_defense import (
        benchmark_signature_comparison,
        safe_constant_time_compare,
        vulnerable_early_exit_compare,
    )
    test_vuln = bool(body.get("test_vulnerable", False))
    trials = _parse_int(body.get("trials"), "trials", 50, 1, MAX_TIMING_TRIALS)
    cmp_fn = vulnerable_early_exit_compare if test_vuln else safe_constant_time_compare
    report = benchmark_signature_comparison(compare_func=cmp_fn, trials=trials)
    return report.to_dict()


def _api_dpop_create(body: Dict[str, Any]) -> Dict[str, Any]:
    from jwt_inspector_guard.dpop_guard import create_dpop_proof
    http_method = str(body.get("method", body.get("http_method", "GET"))).upper().strip()
    http_url = str(body.get("url", body.get("http_url", "https://api.example.com/data")))
    access_token = body.get("access_token") or body.get("token")
    nonce = body.get("nonce")
    alg = str(body.get("alg", "ES256"))
    _, meta = create_dpop_proof(
        http_method=http_method,
        http_url=http_url,
        access_token=access_token,
        nonce=nonce,
        alg=alg,
    )
    return meta


def _api_dpop_verify(body: Dict[str, Any]) -> Dict[str, Any]:
    from jwt_inspector_guard.dpop_guard import verify_dpop_proof
    proof_token = str(body.get("proof_token", body.get("proof", ""))).strip()
    if not proof_token:
        raise _BadRequestError("proof_token field is required")
    http_method = str(body.get("method", body.get("http_method", "GET"))).upper().strip()
    http_url = str(body.get("url", body.get("http_url", "https://api.example.com/data")))
    access_token = body.get("access_token") or body.get("token")
    expected_nonce = body.get("expected_nonce") or body.get("nonce")
    bound_jkt = body.get("bound_jkt") or body.get("jkt")
    max_age_seconds = _parse_int(body.get("max_age_seconds"), "max_age_seconds", 300, 1, 86400)
    result = verify_dpop_proof(
        proof_token=proof_token,
        http_method=http_method,
        http_url=http_url,
        access_token=access_token,
        expected_nonce=expected_nonce,
        bound_jkt=bound_jkt,
        max_age_seconds=max_age_seconds,
    )
    return result.to_dict()


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
    "/api/dpop/create": _api_dpop_create,
    "/api/dpop/verify": _api_dpop_verify,
}


# ---------------------------------------------------------------------------
# Hardened HTTP Request Handler
# ---------------------------------------------------------------------------

class JWTInspectorHandler(BaseHTTPRequestHandler):
    """Hardened loopback HTTP handler for JWT Inspector Guard UI + REST API."""

    server_version = "JWTInspectorGuard/2.6"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # type: ignore[override]
        pass

    def _send_security_headers(self, no_store: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", _CSP_HEADER)
        if no_store:
            self.send_header("Cache-Control", "no-store")
        cors = _cors_origin(self)
        if cors:
            self.send_header("Access-Control-Allow-Origin", cors)
            self.send_header("Vary", "Origin")

    def _check_loopback_guards(self) -> bool:
        """Enforce strict loopback Host & exact-port Origin checks on every request."""
        server_port = getattr(self.server, "server_port", None)
        if not _is_allowed_host(self.headers.get("Host"), server_port):
            self._send_json({"error": "Forbidden: invalid Host header"}, status=403)
            return False
        origin = self.headers.get("Origin")
        if origin and not _is_local_origin(origin, server_port):
            self._send_json({"error": "Forbidden: untrusted Origin"}, status=403)
            return False
        return True

    def _send_json(self, data: Any, status: int = 200, head_only: bool = False) -> None:
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers(no_store=True)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _send_bytes(
        self, data: bytes, mime: str, status: int = 200, head_only: bool = False
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self._send_security_headers(no_store=False)
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def _read_json_body(self) -> Dict[str, Any]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None or raw_len.strip() == "":
            return {}
        try:
            length = int(raw_len.strip())
        except ValueError as exc:
            raise _BadRequestError("Invalid Content-Length header") from exc
        if length < 0:
            raise _BadRequestError("Content-Length cannot be negative")
        if length > MAX_JSON_BODY_BYTES:
            raise _PayloadTooLargeError(
                f"Request body exceeds maximum allowed size of {MAX_JSON_BODY_BYTES} bytes (1 MiB)"
            )
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise _BadRequestError(f"Malformed JSON request body: {exc}") from exc
        if not isinstance(parsed, dict):
            raise _BadRequestError("JSON request body must be an object")
        return parsed

    def _handle_get_or_head(self, head_only: bool) -> None:
        if not self._check_loopback_guards():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/health", "/api/health"):
            self._send_json(
                {
                    "status": "healthy",
                    "service": "jwt-inspector-guard",
                    "version": APP_VERSION,
                    "sovereign": True,
                },
                status=200,
                head_only=head_only,
            )
            return

        if path == "/api/catalog":
            self._send_json(_api_catalog({}), status=200, head_only=head_only)
            return

        if path == "/api/diagnostics":
            from jwt_inspector_guard.mcp_server import get_diagnostics
            self._send_json(get_diagnostics(), status=200, head_only=head_only)
            return

        if path.startswith("/api/"):
            self._send_json({"error": f"Not found: {path}"}, status=404, head_only=head_only)
            return

        content, mime = _read_public_file(path)
        if content is not None and mime is not None:
            self._send_bytes(content, mime, status=200, head_only=head_only)
            return

        self._send_json({"error": f"Not found: {path}"}, status=404, head_only=head_only)

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self._check_loopback_guards():
            return
        self.send_response(204)
        self._send_security_headers(no_store=True)
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_get_or_head(head_only=True)

    def do_GET(self) -> None:  # noqa: N802
        self._handle_get_or_head(head_only=False)

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_loopback_guards():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        handler = _API_ROUTES.get(path)
        if handler is None:
            self._send_json({"error": f"Unknown API endpoint: {path}"}, status=404)
            return

        try:
            body = self._read_json_body()
            result = handler(body)
            self._send_json(result, status=200)
        except _PayloadTooLargeError as exc:
            self._send_json({"error": str(exc)}, status=413)
        except _BadRequestError as exc:
            self._send_json({"error": str(exc)}, status=400)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)


# ---------------------------------------------------------------------------
# Threading HTTP Server
# ---------------------------------------------------------------------------

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server to handle concurrent loopback requests."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32


def run_server(host: str = "127.0.0.1", port: int = 8124, open_browser: bool = True) -> None:
    """Start the JWT Inspector Guard v2.6.0 web UI & REST API server."""
    server = ThreadingHTTPServer((host, port), JWTInspectorHandler)
    url = f"http://{host}:{port}"
    print(f"  JWT Inspector Guard v{APP_VERSION} UI -> {url}")
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
