"""Unit tests for JWKS lifecycle & key rotation simulator and timing defense validator."""

import json
import pytest

from jwt_inspector_guard import (
    JWKRecord,
    JWKSRotationReport,
    JWKSRotationSimulator,
    TimingDefenseReport,
    benchmark_signature_comparison,
    compute_jwk_thumbprint,
    generate_synthetic_jwk,
    handle_jsonrpc_request,
    safe_constant_time_compare,
    sign_hmac,
    vulnerable_early_exit_compare,
)
from jwt_inspector_guard.cli import main as cli_main
from jwt_inspector_guard.ui_server import _api_jwks, _api_timing


def test_compute_jwk_thumbprint_rfc7638():
    # RFC 7638 Section 3.1 Example Key:
    # {"kty": "RSA", "n": "0vx7agoebGcQSuuPiG...Q", "e": "AQAB"}
    sample_rsa = {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiG387TXfekmstrt0HBRkel66dW5ca55u5z214Q89mUzHKma5Cgs_4Q4MTwvDESBYh-uZKnnqKW2EYkeYWGyH455dX0EYhrSuUUW5WYub360GFR37qh997SoYCJK29v8pu6ZPssJYtKCsR6MrkmokDTNR-kiGyXV9GwtwGFGF10sc98HWxAS629XYN_ITKEhU73tJQT0hYs-Er8HRUHzEcWjl66w6JB45EkH8U2vTsxhQCe0uaaaT1bdq52Y1Tn_fg4vnAzIWD718VpuqjtqwpPeVihzROEQRelAZvYJjgODdHpbW5PqFP98EF4l3LFhnrqdxqw",
        "e": "AQAB",
    }
    thumbprint = compute_jwk_thumbprint(sample_rsa)
    assert isinstance(thumbprint, str)
    assert len(thumbprint) == 43
    # Deterministic output
    assert compute_jwk_thumbprint(sample_rsa) == thumbprint

    # EC key thumbprint
    sample_ec = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xFNTLSw0N3c6jmtkJZaavg38Ty8OOVXHzzk",
        "y": "x_daQauqmfeedrytPlVDnvqq9MrIlMmMWcxPuO28Rkk",
    }
    ec_tp = compute_jwk_thumbprint(sample_ec)
    assert isinstance(ec_tp, str)
    assert len(ec_tp) == 43


def test_generate_synthetic_jwk_types():
    rsa_key = generate_synthetic_jwk(kid="test-rsa-1", alg="RS256", kty="RSA")
    assert rsa_key.kty == "RSA"
    assert rsa_key.kid == "test-rsa-1"
    assert rsa_key.e == "AQAB"
    assert len(rsa_key.n) > 100
    d = rsa_key.to_dict()
    assert d["kty"] == "RSA"
    assert "n" in d
    assert "e" in d

    ec_key = generate_synthetic_jwk(kid="test-ec-1", alg="ES256", kty="EC")
    assert ec_key.kty == "EC"
    assert ec_key.crv == "P-256"
    assert len(ec_key.x) > 20

    oct_key = generate_synthetic_jwk(kid="test-oct-1", alg="HS256", kty="oct")
    assert oct_key.kty == "oct"
    assert oct_key.to_dict(public_only=True) == {"kty": "oct", "kid": "test-oct-1", "use": "sig", "alg": "HS256"}


def test_jwks_rotation_simulator_lifecycle():
    sim = JWKSRotationSimulator()
    init_active = sim.get_active_key()
    assert init_active is not None
    init_kid = init_active.kid

    # Perform key rotation
    new_key, old_key = sim.rotate_active_key(new_kid="k-2026-v2")
    assert new_key.kid == "k-2026-v2"
    assert new_key.status == "active"
    assert old_key.kid == init_kid
    assert old_key.status == "retiring"
    assert old_key.expires_at is not None

    # Revoke a key
    assert sim.revoke_key(init_kid, reason="Emergency revocation drill") is True
    assert sim.get_key(init_kid).status == "revoked"

    # Export JWKS
    jwks_pub = sim.export_jwks(include_revoked=False)
    assert "keys" in jwks_pub
    assert any(k["kid"] == "k-2026-v2" for k in jwks_pub["keys"])
    assert not any(k["kid"] == init_kid for k in jwks_pub["keys"])

    jwks_all = sim.export_jwks(include_revoked=True)
    assert any(k["kid"] == init_kid for k in jwks_all["keys"])


def test_jwks_token_resolution():
    sim = JWKSRotationSimulator()
    active_kid = sim.get_active_key().kid

    # Mint test token using active kid
    h = {"alg": "RS256", "typ": "JWT", "kid": active_kid}
    p = {"sub": "alice", "iss": "https://auth.example.com"}
    raw_token = sign_hmac(h, p, "secret", "HS256")  # simulated token

    res = sim.resolve_key_for_token(raw_token)
    assert res["status"] == "active"
    assert res["key"]["kid"] == active_kid

    # Test token with missing kid
    h_no_kid = {"alg": "RS256", "typ": "JWT"}
    raw_no_kid = sign_hmac(h_no_kid, p, "secret", "HS256")
    res_no_kid = sim.resolve_key_for_token(raw_no_kid)
    assert res_no_kid["resolved"] is False
    assert res_no_kid["status"] == "missing_kid"

    # Test token with unknown kid
    h_unk = {"alg": "RS256", "typ": "JWT", "kid": "nonexistent-key"}
    raw_unk = sign_hmac(h_unk, p, "secret", "HS256")
    res_unk = sim.resolve_key_for_token(raw_unk)
    assert res_unk["resolved"] is False
    assert res_unk["status"] == "key_not_found"

    # Test token with revoked key
    sim.revoke_key(active_kid, reason="Compromised")
    res_revoked = sim.resolve_key_for_token(raw_token)
    assert res_revoked["resolved"] is False
    assert res_revoked["status"] == "revoked"


def test_jwks_health_audit_checks():
    sim = JWKSRotationSimulator()
    report = sim.audit_jwks_health()
    assert isinstance(report, JWKSRotationReport)
    assert report.is_healthy is True

    # Audit external JWKS with private key leak and duplicate kid
    malformed_jwks = {
        "keys": [
            {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB", "d": "PRIVATE_LEAK"},
            {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc2", "e": "AQAB"},
            {"kty": "RSA", "use": "sig", "n": "abc3", "e": "AQAB"},  # missing kid
        ]
    }
    report_bad = sim.audit_jwks_health(external_jwks=malformed_jwks)
    assert report_bad.is_healthy is False
    assert any("Private key parameters leaked" in f for f in report_bad.audit_findings)
    assert any("Duplicate 'kid'" in f for f in report_bad.audit_findings)
    assert any("missing a 'kid'" in f for f in report_bad.audit_findings)


def test_timing_defense_benchmarks():
    # Safe comparison: constant-time verified
    safe_report = benchmark_signature_comparison(compare_func=safe_constant_time_compare, trials=20)
    assert isinstance(safe_report, TimingDefenseReport)
    assert safe_report.constant_time_verified is True
    assert safe_report.timing_leakage_detected is False
    assert safe_report.vulnerability_score < 20.0

    # Vulnerable comparison: timing leakage detected
    vuln_report = benchmark_signature_comparison(compare_func=vulnerable_early_exit_compare, trials=20)
    assert isinstance(vuln_report, TimingDefenseReport)
    assert vuln_report.constant_time_verified is False
    assert vuln_report.timing_leakage_detected is True
    assert vuln_report.vulnerability_score > 50.0


def test_cli_jwks_and_timing_subcommands(capsys):
    # jwks subcommand
    ret_jwks = cli_main(["jwks", "--rotate", "--json"])
    assert ret_jwks == 0
    out_jwks = capsys.readouterr().out
    data_jwks = json.loads(out_jwks)
    assert data_jwks["total_keys"] >= 2
    assert "retiring_keys" in data_jwks

    # timing subcommand
    ret_timing = cli_main(["timing", "--trials", "10", "--json"])
    assert ret_timing == 0
    out_timing = capsys.readouterr().out
    data_timing = json.loads(out_timing)
    assert data_timing["constant_time_verified"] is True

    # timing subcommand with vulnerable test
    ret_vuln = cli_main(["timing", "--test-vulnerable", "--trials", "10", "--json"])
    assert ret_vuln == 0
    out_vuln = capsys.readouterr().out
    data_vuln = json.loads(out_vuln)
    assert data_vuln["timing_leakage_detected"] is True


def test_mcp_jwks_and_timing_tools():
    # MCP tool call: jwt_audit_jwks
    req_jwks = {
        "jsonrpc": "2.0",
        "id": "test-jwks-mcp",
        "method": "tools/call",
        "params": {
            "name": "jwt_audit_jwks",
            "arguments": {"rotate": True},
        },
    }
    resp_jwks = handle_jsonrpc_request(req_jwks)
    assert "result" in resp_jwks
    content_jwks = json.loads(resp_jwks["result"]["content"][0]["text"])
    assert content_jwks["total_keys"] >= 2

    # MCP tool call: jwt_timing_defense_audit
    req_timing = {
        "jsonrpc": "2.0",
        "id": "test-timing-mcp",
        "method": "tools/call",
        "params": {
            "name": "jwt_timing_defense_audit",
            "arguments": {"test_vulnerable": False, "trials": 10},
        },
    }
    resp_timing = handle_jsonrpc_request(req_timing)
    assert "result" in resp_timing
    content_timing = json.loads(resp_timing["result"]["content"][0]["text"])
    assert content_timing["constant_time_verified"] is True


def test_ui_server_jwks_and_timing_endpoints():
    res_jwks = _api_jwks({"rotate": True})
    assert "total_keys" in res_jwks
    assert "retiring_keys" in res_jwks

    res_timing = _api_timing({"test_vulnerable": False, "trials": 10})
    assert res_timing["constant_time_verified"] is True
