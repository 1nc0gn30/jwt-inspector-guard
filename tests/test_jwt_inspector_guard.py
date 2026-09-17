"""Tests for jwt_inspector_guard modules."""

from __future__ import annotations

import json
import pytest

from jwt_inspector_guard.mcp_server import (
    base64url_encode,
    base64url_decode,
    sign_hmac,
    verify_hmac,
    validate_claims,
    audit_jwt_security,
    handle_jsonrpc_request,
    PROTOCOL_VERSION,
    SERVER_NAME,
)
from jwt_inspector_guard.catalog import list_sample_tokens, get_sample_token
from jwt_inspector_guard.cli import main


def test_base64url_roundtrip():
    raw = b"Hello, World! 12345"
    encoded = base64url_encode(raw)
    decoded = base64url_decode(encoded)
    assert decoded == raw


def test_hmac_sign_and_verify():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user_123", "role": "admin"}
    secret = "my-secret-key-12345"
    token = sign_hmac(header, payload, secret, "HS256")
    assert token.count(".") == 2
    assert verify_hmac(token, secret, "HS256") is True
    assert verify_hmac(token, "wrong-secret", "HS256") is False


def test_claims_validation_exp():
    payload_valid = {"exp": 2050480000}
    res_valid = validate_claims(payload_valid)
    assert res_valid["claims_valid"] is True

    payload_expired = {"exp": 1000000000}
    res_expired = validate_claims(payload_expired)
    assert res_expired["claims_valid"] is False
    assert res_expired["is_expired"] is True


def test_security_linter_alg_none():
    # CVE-2015-9235 exploit vector
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
    report = audit_jwt_security(token)
    assert "CRITICAL" in report["risk_level"]
    findings = [f["title"] for f in report["findings"]]
    assert any("none" in title.lower() for title in findings)


def test_catalog_samples():
    samples = list_sample_tokens()
    assert len(samples) >= 5
    sample = get_sample_token("auth0-standard-jwt")
    assert sample is not None
    assert hasattr(sample, "raw_token") or "token" in sample


def test_mcp_initialize():
    req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    res = handle_jsonrpc_request(req)
    assert res["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert res["result"]["serverInfo"]["name"] == SERVER_NAME


def test_mcp_tools_list():
    req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    res = handle_jsonrpc_request(req)
    tool_names = [t["name"] for t in res["result"]["tools"]]
    assert "jwt_decode" in tool_names
    assert "jwt_verify" in tool_names
    assert "jwt_encode" in tool_names
    assert "jwt_audit_security" in tool_names


def test_cli_samples():
    ret = main(["samples", "--no-color"])
    assert ret == 0


def test_cli_test():
    ret = main(["test", "--no-color"])
    assert ret == 0
