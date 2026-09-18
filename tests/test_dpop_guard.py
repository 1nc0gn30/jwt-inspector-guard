"""Comprehensive Test Suite for RFC 9449 DPoP (Proof-of-Possession) & Token Binding Guard."""

import json
import time
from typing import Any, Dict

import pytest

from jwt_inspector_guard.dpop_guard import (
    DPoPAuditIssue,
    DPoPIssueSeverity,
    DPoPReplayStore,
    DPoPVerificationResult,
    bind_token_with_dpop,
    compute_access_token_hash,
    create_dpop_proof,
    normalize_dpop_htu,
    verify_dpop_proof,
)
from jwt_inspector_guard.cli import main as cli_main
from jwt_inspector_guard.mcp_server import handle_jsonrpc_request
from jwt_inspector_guard.ui_server import _api_dpop_create, _api_dpop_verify


def test_normalize_dpop_htu():
    """Verify RFC 9449 §4.3 HTU URL normalization requirements."""
    # Standard https URL with query and fragment
    url1 = "HTTPS://API.Example.COM:443/payments/v1/charge?token=xyz#receipt"
    assert normalize_dpop_htu(url1) == "https://api.example.com/payments/v1/charge"

    # HTTP URL with port 80
    url2 = "http://auth.example.com:80/oauth/v2/token?grant_type=code"
    assert normalize_dpop_htu(url2) == "http://auth.example.com/oauth/v2/token"

    # Custom port preserved
    url3 = "https://internal.service.corp:8443/api/resource"
    assert normalize_dpop_htu(url3) == "https://internal.service.corp:8443/api/resource"

    # Path normalization (empty path -> /, dot segments resolved)
    url4 = "https://api.example.com"
    assert normalize_dpop_htu(url4) == "https://api.example.com/"

    url5 = "https://api.example.com/users/../admin/users"
    assert normalize_dpop_htu(url5) == "https://api.example.com/admin/users"


def test_compute_access_token_hash():
    """Verify SHA-256 Base64URL access token hash (ath)."""
    token = "K50ByENL8-Q"
    ath = compute_access_token_hash(token)
    assert isinstance(ath, str)
    assert len(ath) == 43  # 256 bits = 32 bytes = 43 base64url characters without padding
    # Deterministic check
    assert ath == compute_access_token_hash(token)


def test_create_dpop_proof_structure():
    """Verify generated DPoP proof conforms to RFC 9449 §4.2."""
    proof_jwt, meta = create_dpop_proof(
        http_method="POST",
        http_url="https://api.example.com/transfers",
        access_token="test_bearer_access_token_123",
        nonce="server_nonce_challenge_abc",
        alg="ES256",
    )

    parts = proof_jwt.split(".")
    assert len(parts) == 3

    # Decode and check header
    from jwt_inspector_guard.base64_url import base64url_decode_json
    header = base64url_decode_json(parts[0])
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert "jwk" in header
    assert header["jwk"]["kty"] == "EC"
    # Ensure no private parameters leaked
    assert "d" not in header["jwk"]

    # Decode and check claims
    claims = base64url_decode_json(parts[1])
    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://api.example.com/transfers"
    assert "jti" in claims
    assert "iat" in claims
    assert claims["ath"] == compute_access_token_hash("test_bearer_access_token_123")
    assert claims["nonce"] == "server_nonce_challenge_abc"

    assert meta["thumbprint"] != ""
    assert meta["proof_jwt"] == proof_jwt


def test_token_confirmation_binding():
    """Test binding an access token payload with proof key thumbprint (cnf.jkt)."""
    access_token_claims = {
        "sub": "user_456",
        "iss": "https://auth.example.com",
        "aud": "https://api.example.com",
        "scope": "payments.write",
    }
    proof_jwt, meta = create_dpop_proof("POST", "https://api.example.com/pay")
    jkt = meta["thumbprint"]

    bound_claims = bind_token_with_dpop(access_token_claims, jkt)
    assert "cnf" in bound_claims
    assert bound_claims["cnf"]["jkt"] == jkt


def test_verify_dpop_proof_clean_pass():
    """Test successful end-to-end verification of valid DPoP proof."""
    access_token = "valid_secure_token_xyz"
    proof_jwt, meta = create_dpop_proof(
        http_method="POST",
        http_url="https://api.example.com/v1/checkout?query=ignored",
        access_token=access_token,
        nonce="srv-nonce-999",
    )

    replay_store = DPoPReplayStore(ttl_seconds=300)
    result = verify_dpop_proof(
        proof_token=proof_jwt,
        http_method="POST",
        http_url="https://api.example.com/v1/checkout",
        access_token=access_token,
        expected_nonce="srv-nonce-999",
        bound_jkt=meta["thumbprint"],
        replay_store=replay_store,
    )

    assert result.is_valid is True
    assert result.compliance_score == 100.0
    assert result.token_binding_matched is True
    assert result.replay_detected is False
    assert len(result.issues) == 0
    assert "Clean Audit" in result.to_markdown()


def test_anti_replay_detection():
    """Test anti-replay defense rejects duplicate jti nonces."""
    proof_jwt, meta = create_dpop_proof("GET", "https://api.example.com/profile")
    store = DPoPReplayStore(ttl_seconds=100)

    # First attempt: valid
    res1 = verify_dpop_proof(proof_jwt, "GET", "https://api.example.com/profile", replay_store=store)
    assert res1.is_valid is True
    assert res1.replay_detected is False

    # Second attempt (replay of same proof): rejected
    res2 = verify_dpop_proof(proof_jwt, "GET", "https://api.example.com/profile", replay_store=store)
    assert res2.is_valid is False
    assert res2.replay_detected is True
    assert any(i.code == "DPOP_REPLAY_ATTACK_DETECTED" for i in res2.issues)


def test_stale_and_future_proof_detection():
    """Test rejection of stale or future-dated DPoP proofs."""
    now = 1700000000.0
    # Stale proof (issued 600s ago, max allowed is 300s)
    stale_proof, _ = create_dpop_proof("GET", "https://api.example.com/data", iat=int(now - 600))
    res_stale = verify_dpop_proof(stale_proof, "GET", "https://api.example.com/data", current_time=now)
    assert res_stale.is_valid is False
    assert any(i.code == "STALE_DPOP_PROOF" for i in res_stale.issues)

    # Future proof
    future_proof, _ = create_dpop_proof("GET", "https://api.example.com/data", iat=int(now + 120))
    res_future = verify_dpop_proof(future_proof, "GET", "https://api.example.com/data", current_time=now)
    assert any(i.code == "FUTURE_IAT_CLAIM" for i in res_future.issues)


def test_mismatched_htm_and_htu():
    """Test verification catches mismatched HTTP method and URL."""
    proof_jwt, _ = create_dpop_proof("POST", "https://api.example.com/orders")

    # Mismatched method (GET vs POST)
    res_bad_method = verify_dpop_proof(proof_jwt, "GET", "https://api.example.com/orders")
    assert res_bad_method.is_valid is False
    assert any(i.code == "MISMATCHED_HTM" for i in res_bad_method.issues)

    # Mismatched URL
    res_bad_url = verify_dpop_proof(proof_jwt, "POST", "https://api.example.com/items")
    assert res_bad_url.is_valid is False
    assert any(i.code == "MISMATCHED_HTU" for i in res_bad_url.issues)


def test_mismatched_ath_and_binding():
    """Test verification catches wrong access token or wrong bound key thumbprint."""
    proof_jwt, meta = create_dpop_proof(
        "POST", "https://api.example.com/pay", access_token="token_A"
    )

    # Wrong access token presented
    res_wrong_ath = verify_dpop_proof(
        proof_jwt, "POST", "https://api.example.com/pay", access_token="token_DIFFERENT"
    )
    assert res_wrong_ath.is_valid is False
    assert any(i.code == "INVALID_ATH_HASH" for i in res_wrong_ath.issues)

    # Bound thumbprint mismatch
    res_wrong_jkt = verify_dpop_proof(
        proof_jwt, "POST", "https://api.example.com/pay", access_token="token_A", bound_jkt="wrong_thumbprint_hash"
    )
    assert res_wrong_jkt.is_valid is False
    assert res_wrong_jkt.token_binding_matched is False
    assert any(i.code == "CNF_JKT_THUMBPRINT_MISMATCH" for i in res_wrong_jkt.issues)


def test_cli_dpop_create_and_verify(capsys):
    """Test CLI subcommands `jwt-guard dpop-create` and `jwt-guard dpop-verify`."""
    # 1. dpop-create
    ret_create = cli_main([
        "dpop-create",
        "--method", "POST",
        "--url", "https://api.example.com/v1/charge",
        "--token", "cli_test_token_456",
        "--json"
    ])
    assert ret_create == 0
    captured_create = capsys.readouterr().out
    create_meta = json.loads(captured_create)
    assert "proof_jwt" in create_meta
    assert "thumbprint" in create_meta
    proof_jwt = create_meta["proof_jwt"]
    thumbprint = create_meta["thumbprint"]

    # 2. dpop-verify (Clean pass)
    ret_verify = cli_main([
        "dpop-verify",
        proof_jwt,
        "--method", "POST",
        "--url", "https://api.example.com/v1/charge",
        "--token", "cli_test_token_456",
        "--jkt", thumbprint,
        "--json"
    ])
    assert ret_verify == 0
    captured_verify = capsys.readouterr().out
    verify_data = json.loads(captured_verify)
    assert verify_data["is_valid"] is True
    assert verify_data["token_binding_matched"] is True

    # 3. dpop-verify with mismatched method (returns exit code 1)
    ret_bad = cli_main([
        "dpop-verify",
        proof_jwt,
        "--method", "GET",
        "--url", "https://api.example.com/v1/charge",
        "--json"
    ])
    assert ret_bad == 1


def test_mcp_dpop_tools():
    """Test MCP server tools jwt_create_dpop_proof and jwt_verify_dpop_proof."""
    # 1. jwt_create_dpop_proof
    req_create = {
        "jsonrpc": "2.0",
        "id": "mcp-dpop-1",
        "method": "tools/call",
        "params": {
            "name": "jwt_create_dpop_proof",
            "arguments": {
                "http_method": "POST",
                "http_url": "https://api.example.com/mcp-test",
                "access_token": "mcp_token_789",
            },
        },
    }
    resp_create = handle_jsonrpc_request(req_create)
    assert resp_create is not None
    assert resp_create["result"]["isError"] is False
    create_meta = json.loads(resp_create["result"]["content"][0]["text"])
    assert "proof_jwt" in create_meta
    proof = create_meta["proof_jwt"]
    jkt = create_meta["thumbprint"]

    # 2. jwt_verify_dpop_proof
    req_verify = {
        "jsonrpc": "2.0",
        "id": "mcp-dpop-2",
        "method": "tools/call",
        "params": {
            "name": "jwt_verify_dpop_proof",
            "arguments": {
                "proof_token": proof,
                "http_method": "POST",
                "http_url": "https://api.example.com/mcp-test",
                "access_token": "mcp_token_789",
                "bound_jkt": jkt,
            },
        },
    }
    resp_verify = handle_jsonrpc_request(req_verify)
    assert resp_verify is not None
    assert resp_verify["result"]["isError"] is False
    verify_data = json.loads(resp_verify["result"]["content"][0]["text"])
    assert verify_data["is_valid"] is True
    assert verify_data["compliance_score"] == 100.0


def test_ui_server_dpop_endpoints():
    """Test REST API handlers _api_dpop_create and _api_dpop_verify."""
    create_payload = {
        "http_method": "PUT",
        "http_url": "https://api.example.com/resource/123",
        "access_token": "rest_token_abc",
    }
    create_res = _api_dpop_create(create_payload)
    assert "proof_jwt" in create_res
    assert "thumbprint" in create_res

    verify_payload = {
        "proof_token": create_res["proof_jwt"],
        "http_method": "PUT",
        "http_url": "https://api.example.com/resource/123",
        "access_token": "rest_token_abc",
        "bound_jkt": create_res["thumbprint"],
    }
    verify_res = _api_dpop_verify(verify_payload)
    assert verify_res["is_valid"] is True
    assert verify_res["token_binding_matched"] is True
