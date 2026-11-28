"""Comprehensive security, crypto, and REST API tests for jwt_inspector_guard ui_server."""

from __future__ import annotations

import http.client
import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

from jwt_inspector_guard.cli import main as cli_main
from jwt_inspector_guard.crypto_engine import (
    generate_hmac_jwt,
    generate_p256_keypair,
    sign_es256,
    verify_asymmetric_jwk,
    verify_hmac,
)
from jwt_inspector_guard.base64_url import base64url_encode_json
from jwt_inspector_guard.mcp_server import verify_hmac as mcp_verify_hmac
from jwt_inspector_guard.ui_server import (
    JWTInspectorHandler,
    MAX_JSON_BODY_BYTES,
    ThreadingHTTPServer,
    _API_ROUTES,
)


def _start_test_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), JWTInspectorHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, host, port


def test_api_routes_available():
    for route in (
        "/api/decode",
        "/api/verify",
        "/api/validate",
        "/api/audit",
        "/api/inspect",
        "/api/catalog",
        "/api/crack",
        "/api/mint",
        "/api/entropy",
        "/api/tamper",
        "/api/jwks",
        "/api/timing",
        "/api/dpop/create",
        "/api/dpop/verify",
    ):
        assert route in _API_ROUTES


def test_alg_none_rejected_by_default():
    unsigned = generate_hmac_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin"}, "", "none")
    h_b64, p_b64, s_b64 = unsigned.split(".")
    assert s_b64 == ""
    assert verify_hmac(h_b64, p_b64, s_b64, "", "none") is False
    assert verify_hmac(h_b64, p_b64, s_b64, "", "none", allow_none=True) is True
    assert mcp_verify_hmac(unsigned, "", "none") is False
    assert mcp_verify_hmac(unsigned, "", "none", allow_none=True) is True
    assert cli_main(["verify", unsigned, "--no-color", "-q"]) == 1
    assert cli_main(["verify", unsigned, "--allow-none", "--no-color", "-q"]) == 0


def test_es256_p256_sign_and_verify():
    priv_d, pub_jwk = generate_p256_keypair()
    h_b64 = base64url_encode_json({"alg": "ES256", "typ": "JWT"})
    p_b64 = base64url_encode_json({"sub": "alice", "exp": 2050480000})
    sig = sign_es256(h_b64, p_b64, priv_d)
    assert verify_asymmetric_jwk(h_b64, p_b64, sig, pub_jwk, "ES256") is True
    assert verify_asymmetric_jwk(h_b64, p_b64, "FORGED_SIG", pub_jwk, "ES256") is False


def test_ui_server_lifecycle_security_and_endpoints():
    server, host, port = _start_test_server()
    base_url = f"http://{host}:{port}"
    try:
        # 1. GET / + security headers + no Python version disclosure
        with urllib.request.urlopen(f"{base_url}/") as resp:
            assert resp.status == 200
            assert "text/html" in resp.headers.get("Content-Type", "")
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
            assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
            assert "default-src 'self'" in (resp.headers.get("Content-Security-Policy") or "")
            assert "Python" not in (resp.headers.get("Server") or "")
            assert "JWTInspectorGuard/2.6" in (resp.headers.get("Server") or "")
            body = resp.read().decode("utf-8")
            assert "JWT Inspector Guard" in body

        # 2. HEAD / and HEAD /health return 200 with 0 body bytes
        for path in ("/", "/health", "/api/health", "/robots.txt", "/sitemap.xml"):
            conn = http.client.HTTPConnection(host, port)
            conn.request("HEAD", path)
            res = conn.getresponse()
            raw = res.read()
            assert res.status == 200, path
            assert len(raw) == 0, path
            assert res.headers.get("X-Content-Type-Options") == "nosniff"
            conn.close()

        # 3. MIME types for robots.txt and sitemap.xml
        with urllib.request.urlopen(f"{base_url}/robots.txt") as resp:
            assert resp.headers.get("Content-Type") == "text/plain; charset=utf-8"
        with urllib.request.urlopen(f"{base_url}/sitemap.xml") as resp:
            assert resp.headers.get("Content-Type") == "application/xml; charset=utf-8"

        # 4. Real 404 on unknown routes, unknown /api/*, and path traversal
        for bad_path in ("/nonexistent-404-probe", "/api/does-not-exist", "/../../etc/passwd", "/%2e%2e/server.py"):
            conn = http.client.HTTPConnection(host, port)
            conn.request("GET", bad_path)
            res = conn.getresponse()
            res.read()
            assert res.status == 404, bad_path
            conn.close()

        # 5. DNS-rebinding Host header blocked with 403
        conn = http.client.HTTPConnection(host, port)
        conn.request("GET", "/health", headers={"Host": "evil.example.invalid"})
        res = conn.getresponse()
        res.read()
        assert res.status == 403
        conn.close()

        # 6. Untrusted Origin (foreign, port-suffix, cross-port loopback) blocked with 403 on GET, POST & OPTIONS
        for bad_origin in (
            "https://evil.example.invalid",
            f"http://127.0.0.1:{port}0",
            "http://localhost:9999",
        ):
            for method, path in (("GET", "/health"), ("POST", "/api/decode"), ("OPTIONS", "/api/decode")):
                conn = http.client.HTTPConnection(host, port)
                conn.request(method, path, body=b"{}" if method == "POST" else None, headers={"Origin": bad_origin})
                res = conn.getresponse()
                res.read()
                assert res.status == 403, (method, path, bad_origin)
                conn.close()

        # 7. Allowed exact-port Origin succeeds on OPTIONS and POST
        conn = http.client.HTTPConnection(host, port)
        conn.request("OPTIONS", "/api/decode", headers={"Origin": f"http://127.0.0.1:{port}"})
        res = conn.getresponse()
        res.read()
        assert res.status == 204
        assert res.headers.get("Access-Control-Allow-Origin") == f"http://127.0.0.1:{port}"
        conn.close()

        # 8. GET /api/catalog returns 25-token JSON catalog
        with urllib.request.urlopen(f"{base_url}/api/catalog") as resp:
            assert resp.status == 200
            assert "application/json" in resp.headers.get("Content-Type", "")
            assert resp.headers.get("Cache-Control") == "no-store"
            cat = json.loads(resp.read().decode("utf-8"))
            assert len(cat["tokens"]) >= 25

        # 9. POST /api/mint -> /api/validate -> /api/inspect -> /api/crack -> /api/entropy -> /api/tamper
        mint_payload = json.dumps({
            "header": {"alg": "HS256"},
            "payload": {"sub": "123", "role": "admin", "exp": 2050480000},
            "secret": "secret",
        }).encode("utf-8")
        req = urllib.request.Request(f"{base_url}/api/mint", data=mint_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            token = json.loads(resp.read().decode("utf-8"))["token"]

        for ep in ("/api/validate", "/api/inspect"):
            req = urllib.request.Request(
                f"{base_url}{ep}",
                data=json.dumps({"token": token}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert "validation" in data

        # 10. Malformed JSON -> 400 Bad Request
        conn = http.client.HTTPConnection(host, port)
        conn.request("POST", "/api/decode", body=b"{bad json", headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        res.read()
        assert res.status == 400
        conn.close()

        # 11. Bad numeric params -> 400 Bad Request
        for ep, payload in (
            ("/api/timing", {"trials": "notanint"}),
            ("/api/timing", {"trials": 999999}),
            ("/api/validate", {"token": token, "leeway": "bad"}),
        ):
            conn = http.client.HTTPConnection(host, port)
            conn.request("POST", ep, body=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
            res = conn.getresponse()
            res.read()
            assert res.status == 400, (ep, payload)
            conn.close()

        # 12. Oversized > 1 MiB body -> 413 Payload Too Large
        conn = http.client.HTTPConnection(host, port)
        big_body = b"x" * (MAX_JSON_BODY_BYTES + 128)
        conn.request("POST", "/api/decode", body=big_body, headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        res.read()
        assert res.status == 413
        conn.close()

        # 13. Crack, entropy, tamper, DPoP create + verify + forged rejection
        req = urllib.request.Request(
            f"{base_url}/api/crack",
            data=json.dumps({"token": token, "wordlist": ["wrong", "secret", "admin"]}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            assert res["found"] is True and res["secret"] == "secret"

        req = urllib.request.Request(
            f"{base_url}/api/dpop/create",
            data=json.dumps({"http_method": "POST", "http_url": "https://api.example.com/checkout", "access_token": token}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            c_res = json.loads(resp.read().decode("utf-8"))
            proof = c_res["proof_jwt"]
            jkt = c_res["thumbprint"]

        req = urllib.request.Request(
            f"{base_url}/api/dpop/verify",
            data=json.dumps({
                "proof_token": proof,
                "http_method": "POST",
                "http_url": "https://api.example.com/checkout",
                "access_token": token,
                "bound_jkt": jkt,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            v_res = json.loads(resp.read().decode("utf-8"))
            assert v_res["is_valid"] is True and v_res["signature_valid"] is True

        # Forged DPoP signature via HTTP API must fail closed
        h_b64, p_b64, _ = proof.split(".")
        req = urllib.request.Request(
            f"{base_url}/api/dpop/verify",
            data=json.dumps({
                "proof_token": f"{h_b64}.{p_b64}.COMPLETELY_FORGED_GARBAGE_SIG",
                "http_method": "POST",
                "http_url": "https://api.example.com/checkout",
                "access_token": token,
                "bound_jkt": jkt,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            v_bad = json.loads(resp.read().decode("utf-8"))
            assert v_bad["is_valid"] is False and v_bad["signature_valid"] is False

    finally:
        server.shutdown()
        server.server_close()
