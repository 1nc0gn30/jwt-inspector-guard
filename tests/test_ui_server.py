"""Tests for jwt_inspector_guard UI server and extended REST API endpoints."""

from __future__ import annotations

import json
import urllib.request
import threading
from http.server import HTTPServer

from jwt_inspector_guard.ui_server import JWTInspectorHandler, _API_ROUTES


def test_api_routes_available():
    assert "/api/decode" in _API_ROUTES
    assert "/api/verify" in _API_ROUTES
    assert "/api/validate" in _API_ROUTES
    assert "/api/audit" in _API_ROUTES
    assert "/api/inspect" in _API_ROUTES
    assert "/api/catalog" in _API_ROUTES
    assert "/api/crack" in _API_ROUTES
    assert "/api/mint" in _API_ROUTES
    assert "/api/entropy" in _API_ROUTES
    assert "/api/tamper" in _API_ROUTES


def test_ui_server_lifecycle_and_endpoints():
    server = HTTPServer(("127.0.0.1", 0), JWTInspectorHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    base_url = f"http://{host}:{port}"
    try:
        # 1. GET / (serves HTML)
        req = urllib.request.Request(f"{base_url}/")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            assert "text/html" in resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8")
            assert "Google JWT Inspector Guard" in body

        # 2. POST /api/mint
        mint_payload = json.dumps({
            "header": {"alg": "HS256"},
            "payload": {"sub": "123", "role": "admin"},
            "secret": "secret"
        }).encode("utf-8")
        req = urllib.request.Request(f"{base_url}/api/mint", data=mint_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert "token" in res
            token = res["token"]

        # 3. POST /api/crack
        crack_payload = json.dumps({"token": token, "wordlist": ["wrong", "secret", "admin"]}).encode("utf-8")
        req = urllib.request.Request(f"{base_url}/api/crack", data=crack_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["found"] is True
            assert res["secret"] == "secret"

        # 4. POST /api/entropy
        ent_payload = json.dumps({"token": token}).encode("utf-8")
        req = urllib.request.Request(f"{base_url}/api/entropy", data=ent_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert "total_entropy" in res
            assert res["total_entropy"] > 0.0

        # 5. POST /api/tamper
        tamper_payload = json.dumps({"token": token, "type": "none"}).encode("utf-8")
        req = urllib.request.Request(f"{base_url}/api/tamper", data=tamper_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert "tampered_token" in res
            assert res["tampered_token"].endswith(".")

    finally:
        server.shutdown()
        server.server_close()
