"""Model Context Protocol (MCP) Server for JWT Inspector Guard.

Provides a full JSON-RPC 2.0 stdio interface for LLM assistants (Claude, Cursor, Antigravity, etc.)
to inspect, decode, verify, audit, crack, and synthesize JSON Web Tokens.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import hashlib
import hmac
import json
import os
import platform
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Common Constants & Built-in Dictionaries
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "jwt-inspector-guard"
SERVER_VERSION = "0.1.0"

COMMON_SECRETS: List[str] = [
    "secret", "password", "123456", "12345678", "admin", "jwt", "key", "root",
    "123456789", "qwerty", "test", "demo", "development", "jwt_secret", "mysecret",
    "supersecret", "secret123", "auth", "token", "default", "master", "access",
    "private", "api_key", "changeme", "letmein", "welcome", "login", "session",
    "app_secret", "secret_key", "shhhhh", "node_env", "production", "staging",
    "test_key", "secretkey", "jwtsecret", "your-256-bit-secret", "your-secret-key",
    "my-secret-key", "secret123456", "111111", "000000", "iloveyou", "monkey",
    "dragon", "football", "baseball", "trustno1", "starwars", "passphrase",
    "signature", "signature_key", "super_secret", "topsecret", "top_secret",
    "security", "credentials", "symmetric", "hmac_secret", "key123", "secret01",
    "dev_secret", "local_secret", "testsecret", "secrettoken", "access_token",
    "id_token", "bearer", "sample_secret", "example_secret", "test_secret_key",
    "test1234", "password123", "admin123", "administrator", "guest", "anonymous",
    "service", "system", "internal", "config_secret", "encryption_key", "signing_key",
    "jwt_signing_key", "flask_secret_key", "django_secret_key", "express_secret",
    "rails_secret", "spring_secret", "aspnet_secret", "laravel_secret", "1234",
    "12345", "pass", "auth0", "firebase", "supabase", "nextauth", "jsonwebtoken",
    "jwks", "asdf", "qweasd", "123123", "abc123", "hello", "world", "helloworld",
    "test1", "masterkey", "database", "db_password", "apikey", "privatekey",
    "publickey", "signing", "verifier", "tester", "user", "superuser", "root123",
    "toor", "pass123", "secretword", "hidden", "secure", "vault", "safe",
    "strongkey", "superkey", "secretpass", "temp", "temporary", "temp123"
]

# Sensitive keys regex for PII and credential leakage in JWT payload
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|private[_-]?key|ssn|social[_-]?sec|credit[_-]?card|card[_-]?num|cvv|cvc|pin|auth[_-]?token|access[_-]?token|refresh[_-]?token|salt|hash|seed)"
)
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


# ---------------------------------------------------------------------------
# Core Crypto & Utility Functions (Self-contained & Pure Stdlib)
# ---------------------------------------------------------------------------

def base64url_encode(data: Union[bytes, str]) -> str:
    """Encode bytes or string to Base64URL string without padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def base64url_decode(data: str) -> bytes:
    """Decode Base64URL string (with or without padding) to bytes."""
    data = data.strip()
    rem = len(data) % 4
    if rem == 2:
        data += "=="
    elif rem == 3:
        data += "="
    elif rem == 1:
        raise ValueError("Invalid Base64URL string length")
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def decode_jwt_parts(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str, str, str, str]:
    """Split token and decode header, payload, and signature strings."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("JWT must contain at least header and payload separated by '.'")
    if len(parts) > 3:
        raise ValueError("Malformed JWT: contains more than 3 dot-separated segments")

    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_b64 = parts[2] if len(parts) == 3 else ""

    try:
        header_raw = base64url_decode(header_b64).decode("utf-8")
        header = json.loads(header_raw)
        if not isinstance(header, dict):
            header = {"_raw": header}
    except Exception as e:
        header = {"_error": f"Invalid header: {e}"}

    try:
        payload_raw = base64url_decode(payload_b64).decode("utf-8")
        payload = json.loads(payload_raw)
        if not isinstance(payload, dict):
            payload = {"_raw": payload}
    except Exception as e:
        payload = {"_error": f"Invalid payload: {e}"}

    return header, payload, sig_b64, header_b64, payload_b64, token


def format_timestamp(ts: Any) -> Optional[str]:
    """Convert unix timestamp to human-readable UTC ISO format string."""
    try:
        val = float(ts)
        dt = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


def sign_hmac(header: Dict[str, Any], payload: Dict[str, Any], secret: str, algorithm: str = "HS256") -> str:
    """Sign header and payload with HMAC secret."""
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    header_b64 = base64url_encode(header_json)
    payload_b64 = base64url_encode(payload_json)
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    alg_upper = algorithm.upper()
    if alg_upper == "NONE":
        return f"{header_b64}.{payload_b64}."
    elif alg_upper == "HS256":
        digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    elif alg_upper == "HS384":
        digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha384).digest()
    elif alg_upper == "HS512":
        digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported HMAC signing algorithm: {algorithm}")

    sig_b64 = base64url_encode(digest)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_hmac(token: str, secret: str, algorithm: Optional[str] = None) -> bool:
    """Verify HMAC signature of a compact JWT."""
    try:
        header, _, sig_b64, header_b64, payload_b64, _ = decode_jwt_parts(token)
    except Exception:
        return False

    token_alg = str(header.get("alg", "HS256")).upper()
    effective_alg = (algorithm or token_alg).upper()

    if effective_alg == "NONE":
        return sig_b64 == ""

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    if effective_alg == "HS256":
        expected_digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    elif effective_alg == "HS384":
        expected_digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha384).digest()
    elif effective_alg == "HS512":
        expected_digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha512).digest()
    else:
        return False

    try:
        actual_digest = base64url_decode(sig_b64)
    except Exception:
        return False

    return hmac.compare_digest(actual_digest, expected_digest)


def validate_claims(
    payload: Dict[str, Any],
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    leeway: float = 0.0,
    current_time: Optional[float] = None
) -> Dict[str, Any]:
    """Validate standard RFC 7519 claims against policy and current timestamp."""
    now = current_time if current_time is not None else time.time()
    errors: List[str] = []
    warnings: List[str] = []

    # Expiration (exp)
    is_expired = False
    time_to_expiry = None
    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_val = float(exp)
            time_to_expiry = exp_val - now
            if now > (exp_val + leeway):
                is_expired = True
                errors.append(f"Token expired at {format_timestamp(exp_val)} ({abs(int(time_to_expiry))}s ago)")
        except (ValueError, TypeError):
            errors.append(f"Invalid 'exp' claim format: {exp}")
    else:
        warnings.append("Missing 'exp' (Expiration Time) claim: token never expires")

    # Not Before (nbf)
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf_val = float(nbf)
            if now < (nbf_val - leeway):
                errors.append(f"Token not valid before {format_timestamp(nbf_val)} (in {int(nbf_val - now)}s)")
        except (ValueError, TypeError):
            errors.append(f"Invalid 'nbf' claim format: {nbf}")

    # Issued At (iat)
    iat = payload.get("iat")
    if iat is not None:
        try:
            iat_val = float(iat)
            if iat_val > (now + leeway + 300):
                warnings.append(f"Token issued in the future ({format_timestamp(iat_val)})")
        except (ValueError, TypeError):
            warnings.append(f"Invalid 'iat' claim format: {iat}")

    # Issuer (iss)
    iss = payload.get("iss")
    if issuer is not None:
        if iss != issuer:
            errors.append(f"Issuer mismatch: expected '{issuer}', got '{iss}'")

    # Audience (aud)
    aud = payload.get("aud")
    if audience is not None:
        if isinstance(aud, list):
            if audience not in aud:
                errors.append(f"Audience mismatch: '{audience}' not in {aud}")
        elif aud != audience:
            errors.append(f"Audience mismatch: expected '{audience}', got '{aud}'")

    claims_valid = len(errors) == 0

    return {
        "claims_valid": claims_valid,
        "is_expired": is_expired,
        "time_to_expiry_seconds": time_to_expiry,
        "errors": errors,
        "warnings": warnings,
        "formatted_dates": {
            "exp": format_timestamp(exp) if exp is not None else None,
            "iat": format_timestamp(iat) if iat is not None else None,
            "nbf": format_timestamp(nbf) if nbf is not None else None,
        }
    }


def audit_jwt_security(token: str, known_secret: Optional[str] = None) -> Dict[str, Any]:
    """Perform a deep security audit on a JWT, calculating risk score and finding items."""
    findings: List[Dict[str, Any]] = []
    score = 100

    try:
        header, payload, sig_b64, header_b64, payload_b64, _ = decode_jwt_parts(token)
    except Exception as e:
        return {
            "score": 0,
            "grade": "F",
            "risk_level": "CRITICAL RISK",
            "is_secure": False,
            "algorithm": "UNKNOWN",
            "findings": [{
                "id": "MALFORMED_JWT",
                "severity": "CRITICAL",
                "title": "Malformed JWT Structure",
                "description": f"Failed to parse JWT segments: {e}",
                "cve": None,
                "remediation": "Ensure token complies with RFC 7519 compact serialization (header.payload.signature)."
            }],
            "recommendations": ["Reject malformed tokens immediately."]
        }

    alg = str(header.get("alg", "")).strip()
    alg_upper = alg.upper()

    # 1. Critical: alg: none check (CVE-2015-9235)
    if alg_upper == "NONE" or alg == "":
        score -= 50
        findings.append({
            "id": "CVE_2015_9235_NONE_ALGORITHM",
            "severity": "CRITICAL",
            "title": "Unsigned Token / alg: none Vulnerability",
            "description": f"Token specifies '{alg}' algorithm, allowing attackers to forge arbitrary claims without a cryptographic signature.",
            "cve": "CVE-2015-9235",
            "remediation": "Reject 'none' algorithm in verification policy. Enforce explicit algorithm whitelisting (e.g. HS256, RS256)."
        })

    # 2. Check for algorithm casing bypass
    if alg in ["None", "NONE", "nOnE", "NoNe"] and alg != "none":
        findings.append({
            "id": "CASE_INSENSITIVE_ALG_BYPASS",
            "severity": "CRITICAL",
            "title": "Case-Sensitivity Filter Bypass (alg: None)",
            "description": f"Token uses mixed-case '{alg}' algorithm to evade naive string filters while verifying without a signature.",
            "cve": "CVE-2015-9235",
            "remediation": "Normalize algorithm names to lowercase/uppercase before evaluating verification policies."
        })

    # 3. Header Injection Attacks (jku, x5u, jwk, kid)
    if "jku" in header:
        score -= 25
        findings.append({
            "id": "INSECURE_HEADER_JKU",
            "severity": "HIGH",
            "title": "Untrusted JWK Set URL (jku Header)",
            "description": f"Header contains 'jku' URL ({header.get('jku')}). If the server fetches keys dynamically, an attacker can supply an arbitrary key.",
            "cve": "CVE-2018-0114",
            "remediation": "Do not trust arbitrary 'jku' headers. Whitelist allowed domains or use a static local JWKS."
        })

    if "x5u" in header:
        score -= 25
        findings.append({
            "id": "INSECURE_HEADER_X5U",
            "severity": "HIGH",
            "title": "Untrusted X.509 URL (x5u Header)",
            "description": f"Header contains 'x5u' URL ({header.get('x5u')}). An attacker may point to an attacker-controlled certificate.",
            "cve": None,
            "remediation": "Validate x5u URLs against a strict whitelist or embed trusted root CA certificates."
        })

    if "jwk" in header:
        score -= 25
        findings.append({
            "id": "EMBEDDED_JWK_INJECTION",
            "severity": "HIGH",
            "title": "Embedded JWK Key in Header",
            "description": "Header embeds a full public key ('jwk'). If the verifier uses the embedded key to verify the token, anyone can sign valid tokens.",
            "cve": None,
            "remediation": "Configure verifier to only use server-configured public keys, ignoring any client-provided 'jwk' header."
        })

    kid = header.get("kid")
    if kid is not None:
        kid_str = str(kid)
        if ".." in kid_str or "/" in kid_str or "\\" in kid_str:
            score -= 30
            findings.append({
                "id": "KID_PATH_TRAVERSAL",
                "severity": "CRITICAL",
                "title": "Directory Traversal in 'kid' Header",
                "description": f"The 'kid' parameter contains path traversal characters ('{kid_str}'). Could allow attackers to point to /dev/null or known files as keys.",
                "cve": "CVE-2018-1000531",
                "remediation": "Sanitize and strictly validate 'kid' against an allowed list of key identifiers, preventing filesystem path resolution."
            })
        elif any(sql_kw in kid_str.upper() for sql_kw in ["SELECT", "UNION", " OR ", "'", "--"]):
            score -= 30
            findings.append({
                "id": "KID_SQL_INJECTION",
                "severity": "CRITICAL",
                "title": "Potential SQL Injection in 'kid' Header",
                "description": f"The 'kid' parameter contains SQL injection syntax ('{kid_str}').",
                "cve": None,
                "remediation": "Use parameterized queries when looking up keys by 'kid' in database tables."
            })

    # 4. Dictionary Attack on Weak HMAC Secrets
    cracked_secret: Optional[str] = None
    if alg_upper in ["HS256", "HS384", "HS512"]:
        if known_secret and verify_hmac(token, known_secret, alg_upper):
            cracked_secret = known_secret
        else:
            for candidate in COMMON_SECRETS:
                if verify_hmac(token, candidate, alg_upper):
                    cracked_secret = candidate
                    break

        if cracked_secret is not None:
            score -= 40
            findings.append({
                "id": "WEAK_HMAC_SECRET_CRACKED",
                "severity": "CRITICAL",
                "title": "Trivially Crackable HMAC Secret Key",
                "description": f"Token signature was instantly cracked using common dictionary attack! Secret: '{cracked_secret}'",
                "cve": None,
                "remediation": "Use a cryptographically secure random secret with at least 256 bits of entropy (e.g. 'openssl rand -base64 32')."
            })
        elif len(sig_b64) == 0:
            score -= 45
            findings.append({
                "id": "MISSING_SIGNATURE_ON_HMAC",
                "severity": "CRITICAL",
                "title": "HMAC Token Missing Signature Segment",
                "description": f"Token header specifies {alg} but the signature segment is empty.",
                "cve": None,
                "remediation": "Ensure all HMAC tokens are properly signed with a secure symmetric key."
            })

    # 5. Sensitive Data / PII in Payload
    sensitive_claims: List[str] = []
    for k, v in payload.items():
        if SENSITIVE_KEY_PATTERN.search(str(k)):
            sensitive_claims.append(f"Key '{k}'")
        val_str = str(v)
        if CREDIT_CARD_PATTERN.search(val_str):
            sensitive_claims.append(f"Credit Card number in '{k}'")
        if SSN_PATTERN.search(val_str):
            sensitive_claims.append(f"SSN in '{k}'")

    if sensitive_claims:
        score -= 20
        findings.append({
            "id": "PII_OR_CREDENTIAL_LEAKAGE",
            "severity": "HIGH",
            "title": "Sensitive Information / PII in Payload",
            "description": f"Token payload contains sensitive data: {', '.join(sensitive_claims)}. JWT payloads are Base64-encoded, not encrypted.",
            "cve": None,
            "remediation": "Remove sensitive credentials, PII, and financial data from JWT claims. Use JWE (encrypted tokens) or store session state server-side."
        })

    # 6. Expiration & Lifetime Checks
    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        score -= 15
        findings.append({
            "id": "MISSING_EXP_CLAIM",
            "severity": "MEDIUM",
            "title": "Missing Expiration Time ('exp')",
            "description": "Token lacks an 'exp' claim, making it valid indefinitely if intercepted (replay attack risk).",
            "cve": None,
            "remediation": "Include an 'exp' claim with a short lifespan (e.g. 15-60 minutes) for access tokens."
        })
    else:
        try:
            exp_val = float(exp)
            if iat is not None:
                iat_val = float(iat)
                lifetime = exp_val - iat_val
                if lifetime > (86400 * 30):  # > 30 days
                    score -= 15
                    findings.append({
                        "id": "EXCESSIVE_TOKEN_LIFETIME",
                        "severity": "HIGH",
                        "title": f"Excessive Token Lifespan ({int(lifetime // 86400)} days)",
                        "description": f"Token lifetime is set to {int(lifetime // 86400)} days. Long-lived access tokens increase vulnerability to theft.",
                        "cve": None,
                        "remediation": "Limit access token validity to under 1 hour; use refresh tokens or token revocation lists for long sessions."
                    })
                elif lifetime > (86400 * 7):  # > 7 days
                    score -= 10
                    findings.append({
                        "id": "LONG_TOKEN_LIFETIME",
                        "severity": "MEDIUM",
                        "title": f"Long Token Lifespan ({int(lifetime // 86400)} days)",
                        "description": f"Token lifetime is {int(lifetime // 86400)} days. Consider reducing for sensitive operations.",
                        "cve": None,
                        "remediation": "Reduce access token lifespan and implement refresh token rotation."
                    })
        except Exception:
            pass

    # 7. Issuer and Audience presence
    if "iss" not in payload:
        score -= 5
        findings.append({
            "id": "MISSING_ISS_CLAIM",
            "severity": "LOW",
            "title": "Missing Issuer ('iss') Claim",
            "description": "Token does not specify an issuer ('iss'). In distributed microservice environments, issuer validation helps prevent cross-service impersonation.",
            "cve": None,
            "remediation": "Add 'iss' claim identifying the authentication authority."
        })

    if "aud" not in payload:
        score -= 5
        findings.append({
            "id": "MISSING_AUD_CLAIM",
            "severity": "LOW",
            "title": "Missing Audience ('aud') Claim",
            "description": "Token does not specify intended audience ('aud'). Can allow tokens minted for one service to be replayed against another.",
            "cve": None,
            "remediation": "Add 'aud' claim specifying the target resource server."
        })

    # Clamp score
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
        risk_level = "SECURE"
    elif score >= 75:
        grade = "B"
        risk_level = "LOW RISK"
    elif score >= 60:
        grade = "C"
        risk_level = "MODERATE RISK"
    elif score >= 40:
        grade = "D"
        risk_level = "HIGH RISK"
    else:
        grade = "F"
        risk_level = "CRITICAL RISK"

    recommendations = [f["remediation"] for f in findings if f.get("remediation")]
    if not recommendations:
        recommendations.append("Token satisfies standard RFC 7519 / RFC 8725 security best practices.")

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "is_secure": score >= 75 and not any(f["severity"] in ["CRITICAL", "HIGH"] for f in findings),
        "algorithm": alg or "none",
        "findings_count": {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO"),
        },
        "findings": findings,
        "recommendations": recommendations,
        "cracked_secret": cracked_secret,
    }


def crack_jwt_secret(token: str, wordlist: Optional[List[str]] = None, max_attempts: int = 5000) -> Dict[str, Any]:
    """Execute dictionary attack on HMAC-signed token."""
    start_time = time.time()
    candidates = wordlist if wordlist is not None else COMMON_SECRETS
    candidates = candidates[:max_attempts]

    try:
        header, _, _, _, _, _ = decode_jwt_parts(token)
        alg = str(header.get("alg", "HS256")).upper()
    except Exception as e:
        return {
            "cracked": False,
            "secret": None,
            "attempts": 0,
            "time_seconds": round(time.time() - start_time, 4),
            "algorithm": "UNKNOWN",
            "error": str(e)
        }

    if alg not in ["HS256", "HS384", "HS512"]:
        return {
            "cracked": False,
            "secret": None,
            "attempts": 0,
            "time_seconds": round(time.time() - start_time, 4),
            "algorithm": alg,
            "error": f"Dictionary attack only applies to HMAC algorithms (HS256/384/512), not {alg}"
        }

    attempts = 0
    cracked_secret: Optional[str] = None
    for candidate in candidates:
        attempts += 1
        if verify_hmac(token, candidate, alg):
            cracked_secret = candidate
            break

    elapsed = round(time.time() - start_time, 4)
    return {
        "cracked": cracked_secret is not None,
        "secret": cracked_secret,
        "attempts": attempts,
        "time_seconds": elapsed,
        "algorithm": alg,
        "message": (
            f"VULNERABILITY FOUND: Secret '{cracked_secret}' cracked in {elapsed}s ({attempts} attempts)"
            if cracked_secret else
            f"Secret was not found in dictionary of {attempts} candidates in {elapsed}s."
        )
    }


# ---------------------------------------------------------------------------
# Sample Tokens Catalog
# ---------------------------------------------------------------------------

SAMPLE_TOKENS_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "standard-hs256",
        "category": "standard",
        "description": "Standard RFC 7519 compliant HS256 token signed with secret 'your-256-bit-secret'.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "user_12345", "name": "Alice Smith", "iss": "https://auth.example.com", "aud": "https://api.example.com", "iat": int(time.time()), "exp": int(time.time()) + 3600},
            "your-256-bit-secret",
            "HS256"
        ),
        "vulnerability_notes": "Well-formed standard token with valid exp, iss, and aud claims."
    },
    {
        "name": "cve-2015-9235-none",
        "category": "vulnerabilities",
        "description": "Critical CVE-2015-9235 exploit vector using 'alg: none' and an empty signature.",
        "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlLCJyb2xlIjoiYWRtaW5pc3RyYXRvciIsImV4cCI6MjAwMDAwMDAwMH0.",
        "vulnerability_notes": "Vulnerable to signature bypass if server does not explicitly prohibit 'none' algorithm."
    },
    {
        "name": "cve-alg-none-titlecase",
        "category": "vulnerabilities",
        "description": "Case-bypass attack vector using 'alg: None' to evade naive case-sensitive filters.",
        "token": "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlLCJyb2xlIjoiYWRtaW4iLCJleHAiOjIwMDAwMDAwMDB9.",
        "vulnerability_notes": "Attempts to bypass string filters that check only lowercase 'none'."
    },
    {
        "name": "weak-secret-jwt",
        "category": "vulnerabilities",
        "description": "Token signed using common weak secret 'secret'. Easily cracked by dictionary attacks.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "dev_user", "role": "developer", "iat": int(time.time()), "exp": int(time.time()) + 7200},
            "secret",
            "HS256"
        ),
        "vulnerability_notes": "Signs with word 'secret'. Highly vulnerable to offline brute force."
    },
    {
        "name": "weak-password-jwt",
        "category": "vulnerabilities",
        "description": "Token signed with weak password 'password123'.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "operator", "access": "read-write", "iat": int(time.time()), "exp": int(time.time()) + 3600},
            "password123",
            "HS256"
        ),
        "vulnerability_notes": "Vulnerable to dictionary attack with common passwords."
    },
    {
        "name": "expired-token",
        "category": "standard",
        "description": "Properly signed HS256 token whose expiration timestamp ('exp') is in the past.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "expired_session", "iat": 1500000000, "exp": 1500003600},
            "your-256-bit-secret",
            "HS256"
        ),
        "vulnerability_notes": "Expired token. Verifiers must reject with 401 Unauthorized."
    },
    {
        "name": "no-expiry-jwt",
        "category": "vulnerabilities",
        "description": "Token omitting the 'exp' claim, causing perpetual validity and replay vulnerability.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "infinite_user", "role": "member", "iat": int(time.time())},
            "your-256-bit-secret",
            "HS256"
        ),
        "vulnerability_notes": "Lacks 'exp' claim. If leaked, cannot be invalidated without server-side revocation."
    },
    {
        "name": "pii-leakage-jwt",
        "category": "vulnerabilities",
        "description": "Token leaking sensitive user credentials and PII (SSN, credit card, password hash) in unencrypted payload.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "JWT"},
            {
                "sub": "victim_user",
                "email": "victim@example.com",
                "ssn": "123-45-6789",
                "credit_card": "4532-1234-5678-9012",
                "password_hash": "$2b$12$e8YQz.kF5K7Q1Zz...example_hash",
                "exp": int(time.time()) + 3600
            },
            "your-256-bit-secret",
            "HS256"
        ),
        "vulnerability_notes": "High risk PII exposure. JWT payload is readable by anyone with access to the token."
    },
    {
        "name": "header-injection-jku",
        "category": "attacks",
        "description": "Header injection vulnerability using attacker-controlled 'jku' URL.",
        "token": sign_hmac(
            {"alg": "RS256", "typ": "JWT", "jku": "https://attacker.evil.com/jwks.json", "kid": "key1"},
            {"sub": "admin_escalated", "role": "superadmin", "exp": int(time.time()) + 3600},
            "dummy_key",
            "HS256"
        ),
        "vulnerability_notes": "SSRF and signature spoofing risk if verifier fetches jku without domain whitelist."
    },
    {
        "name": "header-injection-kid-traversal",
        "category": "attacks",
        "description": "Path traversal exploit in 'kid' header parameter pointing to /dev/null.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"},
            {"sub": "attacker", "role": "root", "exp": int(time.time()) + 3600},
            "",
            "HS256"
        ),
        "vulnerability_notes": "CVE-2018-1000531 pattern. Exploits verifiers reading key files by filesystem path."
    },
    {
        "name": "oauth2-access-token",
        "category": "oauth2",
        "description": "RFC 9068 JSON Web Token Profile for OAuth 2.0 Access Tokens.",
        "token": sign_hmac(
            {"alg": "HS256", "typ": "at+jwt"},
            {
                "iss": "https://authorization-server.example.com/",
                "sub": "5f47a61d-8692-4a00-bf7a-6242485c2c77",
                "aud": "https://resource-server.example.com/api",
                "client_id": "client_app_abc123",
                "iat": int(time.time()),
                "exp": int(time.time()) + 1800,
                "scope": "openid profile email api:read api:write"
            },
            "your-256-bit-secret",
            "HS256"
        ),
        "vulnerability_notes": "Standard OAuth2 access token with scoped permissions and strict audience."
    }
]


def list_sample_tokens(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve sample tokens optionally filtered by category."""
    if not category or category.lower() == "all":
        return SAMPLE_TOKENS_CATALOG
    cat_lower = category.lower()
    return [s for s in SAMPLE_TOKENS_CATALOG if s["category"].lower() == cat_lower]


def get_sample_token(name: str) -> Optional[Dict[str, Any]]:
    """Retrieve a specific sample token by name."""
    name_lower = name.lower()
    for s in SAMPLE_TOKENS_CATALOG:
        if s["name"].lower() == name_lower:
            return s
    return None


def get_diagnostics() -> Dict[str, Any]:
    """Retrieve platform and runtime diagnostic info."""
    return {
        "status": "healthy",
        "server": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "transport": "stdio/jsonrpc-2.0"
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "endianness": sys.byteorder,
        },
        "crypto": {
            "available_hmac_hashes": ["sha256", "sha384", "sha512", "sha1", "md5"],
            "hashlib_algorithms": sorted(list(hashlib.algorithms_guaranteed)),
            "pure_python_stdlib_only": True,
            "external_dependencies": 0
        },
        "audit_engine": {
            "built_in_secrets_count": len(COMMON_SECRETS),
            "sample_tokens_count": len(SAMPLE_TOKENS_CATALOG),
            "cve_coverage": ["CVE-2015-9235", "CVE-2018-0114", "CVE-2018-1000531", "RFC-8725-BCP"]
        },
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


# ---------------------------------------------------------------------------
# MCP Tool, Resource, and Prompt Registrations
# ---------------------------------------------------------------------------

TOOLS_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "jwt_decode",
        "description": "Decode compact JWT/JWS string into structured header, payload, signature, and human-readable timestamps without verifying signature.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The compact JWT string (header.payload.signature)."
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "jwt_verify",
        "description": "Verify HMAC signature and validate standard RFC 7519 claims (exp, nbf, iss, aud, iat) against expected values.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The compact JWT string to verify."
                },
                "secret": {
                    "type": "string",
                    "description": "The HMAC secret key used for signature verification."
                },
                "algorithm": {
                    "type": "string",
                    "description": "Expected algorithm (e.g. HS256, HS384, HS512, none).",
                    "default": "HS256"
                },
                "issuer": {
                    "type": "string",
                    "description": "Expected issuer ('iss') to validate."
                },
                "audience": {
                    "type": "string",
                    "description": "Expected audience ('aud') to validate."
                },
                "leeway": {
                    "type": "number",
                    "description": "Clock skew leeway in seconds for exp/nbf/iat validation.",
                    "default": 0
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "jwt_encode",
        "description": "Synthesize and mint a new signed JWT with custom header, payload, algorithm, and secret key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "object",
                    "description": "JSON claims object for the token payload (e.g. {'sub': '123', 'role': 'admin'})."
                },
                "secret": {
                    "type": "string",
                    "description": "Secret key for HMAC signing (or empty for 'none' algorithm).",
                    "default": ""
                },
                "algorithm": {
                    "type": "string",
                    "description": "Signing algorithm: 'HS256', 'HS384', 'HS512', or 'none'.",
                    "default": "HS256"
                },
                "header": {
                    "type": "object",
                    "description": "Optional custom header fields (defaults to {'alg': algorithm, 'typ': 'JWT'})."
                },
                "exp_seconds": {
                    "type": "number",
                    "description": "Optional token lifespan in seconds from now to auto-populate 'exp' and 'iat' claims."
                }
            },
            "required": ["payload"]
        }
    },
    {
        "name": "jwt_audit_security",
        "description": "Perform comprehensive security audit on a JWT, detecting CVE-2015-9235 (alg: none), weak HMAC secrets, PII leakage, excessive lifetime, missing expiration, and header injection vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The compact JWT string to audit."
                },
                "known_secret": {
                    "type": "string",
                    "description": "Optional known secret to test if the signature is verifiable."
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "jwt_crack_secret",
        "description": "Test HMAC-signed JWT (HS256/384/512) against built-in dictionary of common weak secrets (or custom wordlist) to find vulnerable signing keys.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The compact JWT string."
                },
                "wordlist": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional custom list of candidate secret keys to test."
                },
                "max_attempts": {
                    "type": "number",
                    "description": "Maximum number of dictionary candidates to test.",
                    "default": 5000
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "jwt_list_samples",
        "description": "List catalog of built-in sample JWT tokens covering standard use cases and real-world CVE attack vectors.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter samples by category: 'all', 'standard', 'vulnerabilities', 'attacks', 'oauth2'.",
                    "default": "all"
                }
            }
        }
    },
    {
        "name": "jwt_diagnostics",
        "description": "Run multi-OS environment diagnostics check for jwt-inspector-guard, crypto engine, and protocol capabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "jwt_audit_jwks",
        "description": "Audit a JSON Web Key Set (JWKS RFC 7517), detect private key leaks or duplicate kids, and simulate graceful key rollover rotation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jwks": {
                    "type": "object",
                    "description": "Optional external JWKS object with 'keys' array to audit. If omitted, audits simulator keystore."
                },
                "token_to_resolve": {
                    "type": "string",
                    "description": "Optional compact JWT to resolve against published JWKS keys by kid."
                },
                "rotate": {
                    "type": "boolean",
                    "description": "Whether to simulate rotating the active signing key. Default: false.",
                    "default": False
                }
            }
        }
    },
    {
        "name": "jwt_timing_defense_audit",
        "description": "Empirically audit signature verification against timing side-channel attacks and verify constant-time comparison defense.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "test_vulnerable": {
                    "type": "boolean",
                    "description": "Whether to run against vulnerable early-exit string comparison. Default: false (tests safe constant-time compare).",
                    "default": False
                },
                "trials": {
                    "type": "integer",
                    "description": "Number of timing benchmark trials per prefix length. Default: 50.",
                    "default": 50
                }
            }
        }
    }
]

RESOURCES_REGISTRY: List[Dict[str, Any]] = [
    {
        "uri": "jwt://samples",
        "name": "JWT Sample Catalog & CVE Vectors",
        "description": "JSON catalog of pre-configured sample JWTs including RFC examples, OAuth2 tokens, and vulnerable tokens demonstrating CVE-2015-9235, weak secrets, and claim tampering.",
        "mimeType": "application/json"
    },
    {
        "uri": "jwt://specs/security-guide",
        "name": "JWT Security Best Practices & Vulnerability Guide",
        "description": "Reference guide for JWT security vulnerabilities, RFC 7519 / RFC 8725 BCP compliance, CVE-2015-9235 (alg: none), HMAC key confusion attacks, brute-force resistance, and secure token design.",
        "mimeType": "text/markdown"
    }
]

PROMPTS_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "jwt_security_audit_prompt",
        "description": "Assistant prompt for analyzing token vulnerabilities, architectural attack surface, and security hardening recommendations for JWT-based auth systems.",
        "arguments": [
            {
                "name": "token",
                "description": "The JWT token string to analyze",
                "required": True
            },
            {
                "name": "architecture_context",
                "description": "Optional description of system architecture (e.g. Microservices, SPA, Mobile app, OAuth2 Resource Server)",
                "required": False
            }
        ]
    },
    {
        "name": "jwt_token_minting_prompt",
        "description": "Assistant prompt for designing and generating secure, minimal-scope, principle-of-least-privilege session tokens.",
        "arguments": [
            {
                "name": "subject",
                "description": "Subject identifier (user ID, client ID, or principal)",
                "required": True
            },
            {
                "name": "roles",
                "description": "Comma-separated roles or scopes (e.g. 'user,read:reports')",
                "required": False
            },
            {
                "name": "expiry_minutes",
                "description": "Lifespan of token in minutes (default: 15)",
                "required": False
            }
        ]
    }
]

SECURITY_GUIDE_MARKDOWN = """# JWT Security Best Practices & Vulnerability Guide (RFC 8725 BCP)

## 1. Critical Vulnerabilities
### CVE-2015-9235: The 'alg: none' Exploit
- **Mechanism**: Attacker modifies the token header to `{"alg": "none"}` and strips the signature segment.
- **Impact**: Verifier treats token as valid without verifying any cryptographic signature, enabling arbitrary privilege escalation.
- **Remediation**: Explicitly reject `alg: none` or case variations (`None`, `NONE`) in verification libraries. Only accept explicitly whitelisted algorithms.

### Key Confusion (RSA Public Key as HMAC Secret)
- **Mechanism**: An attacker changes `alg` from `RS256` to `HS256` and signs the token using the server's public RSA key (which is publicly accessible).
- **Impact**: The verifier, expecting HMAC, uses its public key string as the HMAC secret, validating the attacker's forged token.
- **Remediation**: Enforce strict algorithm pinning; reject symmetric algorithms when asymmetric keys are configured.

### Weak HMAC Secrets & Offline Brute Force
- **Mechanism**: If an HMAC secret is short or predictable (e.g. "secret", "password"), attackers can crack the key offline at millions of hashes per second.
- **Remediation**: Use secrets with at least 256 bits of entropy (`openssl rand -base64 32`).

## 2. Header Parameter Injection
- **`jku` / `x5u` Injection**: Attackers point URLs to external hosts hosting malicious keys (SSRF / Key Spoofing).
- **`kid` Path Traversal (CVE-2018-1000531)**: Passing `../../../dev/null` as `kid` causes the verifier to hash against an empty file.
- **Remediation**: Whitelist allowed `kid` values; never use `kid` directly in file system paths or SQL queries.

## 3. Payload Privacy & Claim Validation
- **PII Leakage**: JWT payloads are Base64URL-encoded, NOT encrypted. Never place passwords, SSNs, credit cards, or internal keys in JWTs.
- **Lifetime & Expiration**: Always include `exp` and `iat` claims. Keep access token lifetimes short (15-60 minutes).
- **Audience & Issuer**: Always specify and validate `iss` and `aud` claims to prevent cross-service token replay.
"""


# ---------------------------------------------------------------------------
# Tool Execution Handlers
# ---------------------------------------------------------------------------

def execute_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a tool by name with arguments and return standard MCP response."""
    try:
        if name == "jwt_decode":
            token = arguments.get("token", "")
            header, payload, sig_b64, header_b64, payload_b64, raw_token = decode_jwt_parts(token)
            alg = header.get("alg", "none")
            typ = header.get("typ", "JWT")
            exp = payload.get("exp")
            iat = payload.get("iat")
            nbf = payload.get("nbf")

            result = {
                "valid_format": True,
                "token_type": typ,
                "algorithm": alg,
                "header": header,
                "payload": payload,
                "signature_b64": sig_b64,
                "signature_length_bytes": len(base64url_decode(sig_b64)) if sig_b64 else 0,
                "raw_segments": {
                    "header_b64": header_b64,
                    "payload_b64": payload_b64,
                    "signature_b64": sig_b64,
                },
                "formatted_claims": {
                    "exp": format_timestamp(exp) if exp is not None else None,
                    "iat": format_timestamp(iat) if iat is not None else None,
                    "nbf": format_timestamp(nbf) if nbf is not None else None,
                }
            }
            return {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": False
            }

        elif name == "jwt_verify":
            token = arguments.get("token", "")
            secret = arguments.get("secret", "")
            algorithm = arguments.get("algorithm")
            issuer = arguments.get("issuer")
            audience = arguments.get("audience")
            leeway = float(arguments.get("leeway", 0.0))

            header, payload, sig_b64, _, _, _ = decode_jwt_parts(token)
            alg = (algorithm or header.get("alg", "HS256")).upper()

            signature_valid = None
            if secret:
                signature_valid = verify_hmac(token, secret, alg)

            claims_check = validate_claims(payload, issuer=issuer, audience=audience, leeway=leeway)
            is_valid = (signature_valid is True or (signature_valid is None and not secret)) and claims_check["claims_valid"]

            result = {
                "is_valid": is_valid,
                "signature_valid": signature_valid,
                "claims_valid": claims_check["claims_valid"],
                "algorithm": alg,
                "is_expired": claims_check["is_expired"],
                "time_to_expiry_seconds": claims_check["time_to_expiry_seconds"],
                "errors": claims_check["errors"],
                "warnings": claims_check["warnings"],
                "formatted_dates": claims_check["formatted_dates"],
                "header": header,
                "payload": payload
            }
            return {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": False
            }

        elif name == "jwt_encode":
            payload = arguments.get("payload", {})
            secret = arguments.get("secret", "")
            algorithm = arguments.get("algorithm", "HS256")
            header = arguments.get("header") or {"alg": algorithm, "typ": "JWT"}
            exp_seconds = arguments.get("exp_seconds")

            # Clone payload to avoid mutating input
            payload_dict = dict(payload)
            now = int(time.time())
            if exp_seconds is not None:
                payload_dict["iat"] = now
                payload_dict["exp"] = now + int(exp_seconds)

            token = sign_hmac(header, payload_dict, secret, algorithm)
            result = {
                "token": token,
                "algorithm": algorithm,
                "header": header,
                "payload": payload_dict,
                "expires_at": format_timestamp(payload_dict.get("exp")),
                "issued_at": format_timestamp(payload_dict.get("iat"))
            }
            return {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": False
            }

        elif name == "jwt_audit_security":
            token = arguments.get("token", "")
            known_secret = arguments.get("known_secret")
            report = audit_jwt_security(token, known_secret=known_secret)
            return {
                "content": [{"type": "text", "text": json.dumps(report, indent=2)}],
                "isError": False
            }

        elif name == "jwt_crack_secret":
            token = arguments.get("token", "")
            wordlist = arguments.get("wordlist")
            max_attempts = int(arguments.get("max_attempts", 5000))
            crack_result = crack_jwt_secret(token, wordlist=wordlist, max_attempts=max_attempts)
            return {
                "content": [{"type": "text", "text": json.dumps(crack_result, indent=2)}],
                "isError": False
            }

        elif name == "jwt_list_samples":
            category = arguments.get("category", "all")
            samples = list_sample_tokens(category=category)
            return {
                "content": [{"type": "text", "text": json.dumps(samples, indent=2)}],
                "isError": False
            }

        elif name == "jwt_diagnostics":
            diag = get_diagnostics()
            return {
                "content": [{"type": "text", "text": json.dumps(diag, indent=2)}],
                "isError": False
            }

        elif name == "jwt_audit_jwks":
            from .jwks_manager import JWKSRotationSimulator
            sim = JWKSRotationSimulator()
            if arguments.get("rotate", False):
                sim.rotate_active_key()

            external_jwks = arguments.get("jwks")
            audit_report = sim.audit_jwks_health(external_jwks=external_jwks)
            result = audit_report.to_dict()

            token = arguments.get("token_to_resolve")
            if token:
                result["resolved_token_key"] = sim.resolve_key_for_token(token)

            return {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": False
            }

        elif name == "jwt_timing_defense_audit":
            from .timing_defense import (
                benchmark_signature_comparison,
                safe_constant_time_compare,
                vulnerable_early_exit_compare,
            )
            test_vuln = arguments.get("test_vulnerable", False)
            trials = int(arguments.get("trials", 50))
            cmp_fn = vulnerable_early_exit_compare if test_vuln else safe_constant_time_compare
            report = benchmark_signature_comparison(compare_func=cmp_fn, trials=trials)
            return {
                "content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}],
                "isError": False
            }

        else:
            return {
                "content": [{"type": "text", "text": f"Error: Unknown tool '{name}'"}],
                "isError": True
            }

    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Tool execution failed: {e}"}],
            "isError": True
        }


# ---------------------------------------------------------------------------
# Protocol Request Routing & JSON-RPC 2.0 Engine
# ---------------------------------------------------------------------------

def process_request(request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC 2.0 request dict and return the response dict."""
    if not isinstance(request_data, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: expected JSON object"}
        }

    req_id = request_data.get("id")
    method = request_data.get("method")
    params = request_data.get("params", {})

    # Notification checks (JSON-RPC requests with no 'id')
    is_notification = ("id" not in request_data)

    if not method or not isinstance(method, str):
        if is_notification:
            return None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid Request: missing method"}
        }

    # 1. MCP Initialization Handshake
    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
                "logging": {}
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            }
        }
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    if method == "notifications/initialized":
        # Notification from client, no response required
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    # 2. Tools
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_REGISTRY}}

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not tool_name:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Missing tool name in params"}
            }
        call_res = execute_tool_call(tool_name, arguments)
        return {"jsonrpc": "2.0", "id": req_id, "result": call_res}

    # 3. Resources
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": RESOURCES_REGISTRY}}

    if method == "resources/read":
        uri = params.get("uri")
        if uri == "jwt://samples":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [{
                        "uri": "jwt://samples",
                        "mimeType": "application/json",
                        "text": json.dumps(SAMPLE_TOKENS_CATALOG, indent=2)
                    }]
                }
            }
        elif uri == "jwt://specs/security-guide":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [{
                        "uri": "jwt://specs/security-guide",
                        "mimeType": "text/markdown",
                        "text": SECURITY_GUIDE_MARKDOWN
                    }]
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Resource not found: '{uri}'"}
            }

    if method == "resources/templates/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": []}}

    # 4. Prompts
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": PROMPTS_REGISTRY}}

    if method == "prompts/get":
        prompt_name = params.get("name")
        arguments = params.get("arguments", {})

        if prompt_name == "jwt_security_audit_prompt":
            token = arguments.get("token", "")
            arch_ctx = arguments.get("architecture_context", "Standard web application API")
            audit_res = audit_jwt_security(token) if token else {}
            prompt_text = (
                f"Please analyze the following JWT token and its security posture for a system with architecture: '{arch_ctx}'.\n\n"
                f"Target Token: {token}\n\n"
                f"Automated Audit Findings:\n{json.dumps(audit_res, indent=2)}\n\n"
                "Provide a comprehensive security review covering:\n"
                "1. Vulnerability assessment (Signature security, algorithm choices, claim validation).\n"
                "2. Potential threat vectors (Replay attacks, privilege escalation, PII leakage, key confusion).\n"
                "3. Hardening recommendations with specific RFC 8725 best practices."
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "description": "JWT Security Audit & Vulnerability Analysis",
                    "messages": [{
                        "role": "user",
                        "content": {"type": "text", "text": prompt_text}
                    }]
                }
            }

        elif prompt_name == "jwt_token_minting_prompt":
            sub = arguments.get("subject", "user_123")
            roles = arguments.get("roles", "user")
            expiry = arguments.get("expiry_minutes", "15")
            prompt_text = (
                f"Design a secure, least-privilege JWT token structure for subject '{sub}' with roles/scopes '{roles}' "
                f"and an expiration lifespan of {expiry} minutes.\n\n"
                "Please generate:\n"
                "1. Header definition (specifying algorithm and type).\n"
                "2. Payload definition with standard RFC 7519 claims (sub, iss, aud, exp, iat, jti).\n"
                "3. Secret generation recommendations (entropy, rotation strategy).\n"
                "4. Validation rules the receiving resource server must enforce."
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "description": "Secure JWT Token Minting Blueprint",
                    "messages": [{
                        "role": "user",
                        "content": {"type": "text", "text": prompt_text}
                    }]
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Prompt not found: '{prompt_name}'"}
            }

    # Unknown method
    if is_notification:
        return None

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: '{method}'"}
    }


def handle_jsonrpc_request(request: Union[Dict[str, Any], str, List[Any]]) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
    """Top-level entry point for JSON-RPC 2.0 requests (supports dicts, strings, and batch arrays)."""
    if isinstance(request, str):
        try:
            parsed = json.loads(request)
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"}
            }
    else:
        parsed = request

    if isinstance(parsed, list):
        # Batch request
        if not parsed:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: empty batch"}
            }
        responses = []
        for req in parsed:
            resp = process_request(req)
            if resp is not None:
                responses.append(resp)
        return responses if responses else None
    else:
        return process_request(parsed)


# ---------------------------------------------------------------------------
# Stdio Server Loop (Multi-OS Framing Support)
# ---------------------------------------------------------------------------

def run_stdio_server() -> None:
    """Run MCP server over stdio with line-by-line and Content-Length framing support."""
    sys.stderr.write(f"[{SERVER_NAME}] Starting MCP Server v{SERVER_VERSION} (Protocol {PROTOCOL_VERSION}) over stdio...\n")
    sys.stderr.flush()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                # EOF reached
                break

            line_str = line.strip()
            if not line_str:
                continue

            # Support Content-Length header framing if client sends LSP-style frames
            if line_str.lower().startswith("content-length:"):
                try:
                    length = int(line_str.split(":", 1)[1].strip())
                    # Consume empty header separator lines
                    while True:
                        sep = sys.stdin.readline()
                        if sep in ["\r\n", "\n", ""]:
                            break
                    body = sys.stdin.read(length)
                    response = handle_jsonrpc_request(body)
                except Exception as e:
                    response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Header framing parse error: {e}"}
                    }
            else:
                # Standard line-delimited JSON
                response = handle_jsonrpc_request(line_str)

            if response is not None:
                out_str = json.dumps(response, separators=(",", ":"))
                sys.stdout.write(out_str + "\n")
                sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            sys.stderr.write(f"[{SERVER_NAME}] Server stopped.\n")
            sys.stderr.flush()
            break
        except Exception as e:
            sys.stderr.write(f"[{SERVER_NAME}] Unexpected error in stdio loop: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    run_stdio_server()
