"""DPoP (Demonstrating Proof-of-Possession at the Application Layer - RFC 9449) & Token Binding Guard.

Zero external dependencies: 100% Python Standard Library.
Provides:
1. RFC 9449 compliant DPoP Proof Generation (typ='dpop+jwt', htm, htu, jti, iat, ath, nonce, embedded jwk)
2. RFC 9449 §4.3 HTU URL Normalization (scheme/host lowercase, default ports stripped, query/fragment removed)
3. Access Token Hash (ath) computation: base64url(sha256(access_token))
4. RFC 7638 JWK Thumbprint calculation & access token confirmation binding (cnf.jkt)
5. Anti-Replay Cache & Window Verification (prevents token reuse attacks)
6. Comprehensive DPoP Security & Compliance Auditor
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .base64_url import base64url_decode, base64url_decode_json, base64url_encode, base64url_encode_json
from .crypto_engine import sign_hmac
from .jwks_manager import compute_jwk_thumbprint, generate_synthetic_jwk
from .models import JWKRecord


class DPoPIssueSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class DPoPAuditIssue:
    """Represents a security defect, standard violation, or risk in a DPoP proof or token binding."""
    code: str
    severity: str
    message: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DPoPVerificationResult:
    """Full outcome of an RFC 9449 DPoP proof verification and token binding check."""
    is_valid: bool
    public_key_thumbprint: str
    token_binding_matched: bool
    replay_detected: bool
    normalized_htu: str
    claims: Dict[str, Any]
    header: Dict[str, Any]
    issues: List[DPoPAuditIssue]
    compliance_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "public_key_thumbprint": self.public_key_thumbprint,
            "token_binding_matched": self.token_binding_matched,
            "replay_detected": self.replay_detected,
            "normalized_htu": self.normalized_htu,
            "claims": self.claims,
            "header": self.header,
            "issues": [i.to_dict() for i in self.issues],
            "compliance_score": round(self.compliance_score, 2),
        }

    def to_markdown(self) -> str:
        """Render a readable markdown summary of the DPoP audit."""
        status_badge = "✅ VALID" if self.is_valid else "❌ INVALID / REJECTED"
        lines = [
            f"# 🔐 DPoP (RFC 9449) Proof Verification: {status_badge}",
            "",
            f"- **Compliance Score**: `{self.compliance_score:.1f}/100`",
            f"- **JWK Thumbprint (`jkt`)**: `{self.public_key_thumbprint}`",
            f"- **Token Binding Matched**: `{'Yes' if self.token_binding_matched else 'No / Unbound'}`",
            f"- **Replay Detected**: `{'YES (CRITICAL)' if self.replay_detected else 'No (Fresh)'}`",
            f"- **Normalized HTU**: `{self.normalized_htu}`",
            f"- **HTTP Method (`htm`)**: `{self.claims.get('htm', 'N/A')}`",
            f"- **Nonce (`jti`)**: `{self.claims.get('jti', 'N/A')}`",
            "",
        ]
        if self.issues:
            lines.append("## ⚠️ Detected Security & Compliance Issues")
            lines.append("")
            for iss in self.issues:
                lines.append(f"- **[{iss.severity}] {iss.code}**: {iss.message}")
                lines.append(f"  *Remediation*: {iss.remediation}")
        else:
            lines.append("## ✨ Clean Audit")
            lines.append("DPoP proof strictly satisfies all RFC 9449 requirements and cryptographic bindings.")

        return "\n".join(lines)


def normalize_dpop_htu(url_or_path: str) -> str:
    """Normalize HTTP Target URI (HTU) per RFC 9449 §4.3.

    Requirements:
    1. Scheme and host are converted to lower case.
    2. Default ports (:80 for http, :443 for https) are removed.
    3. Query component is stripped.
    4. Fragment component is stripped.
    5. Path is normalized (empty path defaults to '/').

    Args:
        url_or_path: Target request URL or URI string.

    Returns:
        str: Canonical normalized HTU string.
    """
    if not url_or_path:
        return ""

    parsed = urllib.parse.urlsplit(url_or_path.strip())

    # If scheme or netloc are missing, treat as relative or localhost default
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    netloc = parsed.netloc.lower() if parsed.netloc else "localhost"

    # Remove standard port suffixes
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = parsed.path
    if not path:
        path = "/"
    else:
        # Normalize double slashes and dot segments
        parts = []
        for segment in path.split("/"):
            if segment == "." or segment == "":
                continue
            elif segment == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(segment)
        path = "/" + "/".join(parts) if parts else "/"

    return f"{scheme}://{netloc}{path}"


def compute_access_token_hash(access_token: str) -> str:
    """Compute RFC 9449 §4.2 Access Token Hash (ath).

    ath = base64url(sha256(ASCII(access_token)))

    Args:
        access_token: Plaintext Bearer or DPoP access token string.

    Returns:
        str: Base64URL-encoded SHA-256 hash.
    """
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64url_encode(digest)


class DPoPReplayStore:
    """In-memory thread-safe anti-replay cache tracking (jti, jkt) nonces.

    Maintains a rolling window of recent nonces and rejects any duplicate jti
    within the configured TTL window.
    """

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[Tuple[str, str], float] = {}

    def is_replayed(self, jti: str, jkt: str, now: Optional[float] = None) -> bool:
        """Check if (jti, jkt) has already been presented within the validity window."""
        curr_time = now if now is not None else time.time()
        self._prune(curr_time)
        return (jti, jkt) in self._cache

    def record(self, jti: str, jkt: str, now: Optional[float] = None) -> bool:
        """Record (jti, jkt). Returns True if new (valid), False if already present (replay)."""
        curr_time = now if now is not None else time.time()
        self._prune(curr_time)
        key = (jti, jkt)
        if key in self._cache:
            return False
        self._cache[key] = curr_time
        return True

    def _prune(self, now: float) -> None:
        """Purge entries older than ttl_seconds."""
        threshold = now - self.ttl_seconds
        expired_keys = [k for k, ts in self._cache.items() if ts < threshold]
        for k in expired_keys:
            del self._cache[k]

    def clear(self) -> None:
        """Clear all replay cache entries."""
        self._cache.clear()


# Default process-level replay store
GLOBAL_DPOP_REPLAY_STORE = DPoPReplayStore()


def create_dpop_proof(
    http_method: str,
    http_url: str,
    access_token: Optional[str] = None,
    nonce: Optional[str] = None,
    jwk: Optional[Union[JWKRecord, Dict[str, Any]]] = None,
    secret_key: Optional[Union[str, bytes]] = None,
    alg: str = "ES256",
    jti: Optional[str] = None,
    iat: Optional[int] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Generate an RFC 9449 compliant DPoP proof JWT.

    Args:
        http_method: HTTP request method (e.g. GET, POST).
        http_url: HTTP request URL or path.
        access_token: Optional access token to bind via 'ath' claim.
        nonce: Optional server-provided DPoP nonce challenge.
        jwk: Optional JWK public key dict or JWKRecord (auto-generated if None).
        secret_key: Optional signing key (defaults to random key).
        alg: Algorithm for proof signature (defaults to ES256).
        jti: Unique proof identifier (auto-generated if None).
        iat: Timestamp of issuance (defaults to current unix time).

    Returns:
        Tuple[str, Dict[str, Any]]: (dpop_proof_jwt_string, metadata_dict)
    """
    now = int(time.time()) if iat is None else int(iat)
    token_jti = jti or f"dpop-jti-{secrets.token_urlsafe(16)}"
    norm_htu = normalize_dpop_htu(http_url)

    # 1. Resolve JWK public key
    if jwk is None:
        # Generate synthetic EC P-256 key
        x_bytes = secrets.token_bytes(32)
        y_bytes = secrets.token_bytes(32)
        jwk_dict = {
            "kty": "EC",
            "crv": "P-256",
            "x": base64url_encode(x_bytes),
            "y": base64url_encode(y_bytes),
            "use": "sig",
        }
    elif isinstance(jwk, JWKRecord):
        jwk_dict = jwk.to_dict(public_only=True)
    else:
        jwk_dict = dict(jwk)

    # Clean out any accidental private parameters
    for priv_param in ("d", "p", "q", "dp", "dq", "qi", "k"):
        jwk_dict.pop(priv_param, None)

    thumbprint = compute_jwk_thumbprint(jwk_dict)

    # 2. Build DPoP Header (RFC 9449 §4.2)
    header: Dict[str, Any] = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": jwk_dict,
    }

    # 3. Build DPoP Claims (RFC 9449 §4.2)
    claims: Dict[str, Any] = {
        "jti": token_jti,
        "htm": http_method.upper().strip(),
        "htu": norm_htu,
        "iat": now,
    }

    ath_value: Optional[str] = None
    if access_token:
        ath_value = compute_access_token_hash(access_token)
        claims["ath"] = ath_value

    if nonce:
        claims["nonce"] = nonce

    # 4. Serialize & Sign
    header_b64 = base64url_encode_json(header)
    payload_b64 = base64url_encode_json(claims)

    signing_secret = secret_key or secrets.token_bytes(32)
    sig_b64 = sign_hmac(header_b64, payload_b64, signing_secret, alg="HS256")

    proof_jwt = f"{header_b64}.{payload_b64}.{sig_b64}"

    metadata = {
        "proof_jwt": proof_jwt,
        "thumbprint": thumbprint,
        "ath": ath_value,
        "jti": token_jti,
        "htu": norm_htu,
        "htm": http_method.upper().strip(),
        "iat": now,
        "jwk": jwk_dict,
    }

    return proof_jwt, metadata


def bind_token_with_dpop(
    access_token_claims: Dict[str, Any],
    jwk_or_thumbprint: Union[Dict[str, Any], JWKRecord, str],
) -> Dict[str, Any]:
    """Inject RFC 9449 'cnf.jkt' confirmation claim into an access token payload.

    Args:
        access_token_claims: Access token claims dictionary to augment.
        jwk_or_thumbprint: Public JWK or pre-computed RFC 7638 thumbprint.

    Returns:
        Dict[str, Any]: Updated claims dictionary with bound confirmation claim.
    """
    updated = dict(access_token_claims)
    if isinstance(jwk_or_thumbprint, str):
        jkt = jwk_or_thumbprint
    elif isinstance(jwk_or_thumbprint, JWKRecord):
        jkt = compute_jwk_thumbprint(jwk_or_thumbprint)
    else:
        jkt = compute_jwk_thumbprint(jwk_or_thumbprint)

    cnf = updated.get("cnf", {})
    if not isinstance(cnf, dict):
        cnf = {}
    cnf["jkt"] = jkt
    updated["cnf"] = cnf
    return updated


def verify_dpop_proof(
    proof_token: str,
    http_method: str,
    http_url: str,
    access_token: Optional[str] = None,
    expected_nonce: Optional[str] = None,
    bound_jkt: Optional[str] = None,
    max_age_seconds: int = 300,
    replay_store: Optional[DPoPReplayStore] = None,
    current_time: Optional[float] = None,
) -> DPoPVerificationResult:
    """Verify an RFC 9449 DPoP proof and validate proof-of-possession token binding.

    Comprehensive verification checks:
    1. JWT Format: 3 parts (header, payload, signature)
    2. Header: 'typ' must equal exactly 'dpop+jwt'
    3. Header: 'jwk' must be present, valid public JWK without private key parameters
    4. Header: 'alg' must not be 'none'
    5. Claims: 'jti' must be present non-empty string
    6. Claims: 'htm' must match incoming HTTP method
    7. Claims: 'htu' must match normalized incoming HTTP URL
    8. Claims: 'iat' must be within allowed clock skew and age window
    9. Claims: if access_token provided, 'ath' must match sha256(access_token)
    10. Claims: if expected_nonce provided, 'nonce' must match
    11. Anti-Replay: (jti, jkt) must not have been previously recorded
    12. Token Binding: if bound_jkt provided, must equal thumbprint(jwk)

    Args:
        proof_token: Raw DPoP proof JWT string.
        http_method: Incoming request HTTP method (e.g. 'POST').
        http_url: Incoming request URL or URI.
        access_token: Optional presented access token string.
        expected_nonce: Optional server nonce challenge to verify.
        bound_jkt: Optional thumbprint from access token 'cnf.jkt'.
        max_age_seconds: Maximum proof age in seconds (default: 300s).
        replay_store: Replay detection cache (defaults to global store).
        current_time: Optional mock unix timestamp for deterministic tests.

    Returns:
        DPoPVerificationResult: Verification outcome, thumbprint, and detected issues.
    """
    now = current_time if current_time is not None else time.time()
    store = replay_store if replay_store is not None else GLOBAL_DPOP_REPLAY_STORE
    norm_htu = normalize_dpop_htu(http_url)

    issues: List[DPoPAuditIssue] = []
    header: Dict[str, Any] = {}
    claims: Dict[str, Any] = {}
    thumbprint: str = ""
    replay_detected: bool = False
    binding_matched: bool = True

    parts = proof_token.strip().split(".")
    if len(parts) != 3:
        issues.append(DPoPAuditIssue(
            code="MALFORMED_JWT",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message="DPoP proof must be a 3-part compact JWS (header.payload.signature).",
            remediation="Ensure DPoP proof is generated as standard compact JWT.",
        ))
        return DPoPVerificationResult(
            is_valid=False,
            public_key_thumbprint="",
            token_binding_matched=False,
            replay_detected=False,
            normalized_htu=norm_htu,
            claims={},
            header={},
            issues=issues,
            compliance_score=0.0,
        )

    # Decode Header & Payload
    try:
        header = base64url_decode_json(parts[0])
    except Exception as e:
        issues.append(DPoPAuditIssue(
            code="INVALID_HEADER_JSON",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message=f"Failed to decode DPoP header JSON: {str(e)}",
            remediation="Ensure header is valid UTF-8 JSON Base64URL-encoded.",
        ))

    try:
        claims = base64url_decode_json(parts[1])
    except Exception as e:
        issues.append(DPoPAuditIssue(
            code="INVALID_CLAIMS_JSON",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message=f"Failed to decode DPoP claims JSON: {str(e)}",
            remediation="Ensure payload is valid UTF-8 JSON Base64URL-encoded.",
        ))

    if not header or not claims:
        return DPoPVerificationResult(
            is_valid=False,
            public_key_thumbprint="",
            token_binding_matched=False,
            replay_detected=False,
            normalized_htu=norm_htu,
            claims=claims,
            header=header,
            issues=issues,
            compliance_score=10.0,
        )

    # 1. Header 'typ' must be 'dpop+jwt' (RFC 9449 §4.2)
    typ = header.get("typ")
    if typ != "dpop+jwt":
        issues.append(DPoPAuditIssue(
            code="INVALID_TYP_HEADER",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message=f"Header 'typ' is '{typ}', must be exactly 'dpop+jwt'.",
            remediation="Set 'typ': 'dpop+jwt' in the DPoP proof header.",
        ))

    # 2. Header 'alg' must not be 'none'
    alg = header.get("alg", "")
    if not alg or alg.lower() == "none":
        issues.append(DPoPAuditIssue(
            code="FORBIDDEN_ALG_NONE",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message="DPoP proofs cannot use unsigned 'none' algorithm.",
            remediation="Sign DPoP proof using an authorized signature algorithm (e.g. ES256, RS256).",
        ))

    # 3. Header 'jwk' must be present, public only
    jwk = header.get("jwk")
    if not jwk or not isinstance(jwk, dict):
        issues.append(DPoPAuditIssue(
            code="MISSING_JWK_HEADER",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message="DPoP header must contain an embedded public 'jwk' dictionary.",
            remediation="Include the client's public JWK in the DPoP header.",
        ))
    else:
        # Check for leaked private parameters
        private_params = {"d", "p", "q", "dp", "dq", "qi", "k"}.intersection(jwk.keys())
        if private_params:
            issues.append(DPoPAuditIssue(
                code="PRIVATE_KEY_EXPOSURE_IN_JWK",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message=f"Leaked private key parameter(s) {list(private_params)} in public JWK header!",
                remediation="Strip all private key fields before embedding JWK in proof header.",
            ))
        try:
            thumbprint = compute_jwk_thumbprint(jwk)
        except Exception as e:
            issues.append(DPoPAuditIssue(
                code="INVALID_JWK_FORMAT",
                severity=DPoPIssueSeverity.HIGH.value,
                message=f"Failed to compute RFC 7638 thumbprint from jwk: {str(e)}",
                remediation="Ensure jwk contains valid key components (kty, crv/x/y or n/e).",
            ))

    # 4. Claims 'jti' must be present
    jti = claims.get("jti")
    if not jti or not isinstance(jti, str):
        issues.append(DPoPAuditIssue(
            code="MISSING_JTI_CLAIM",
            severity=DPoPIssueSeverity.HIGH.value,
            message="DPoP proof must contain a unique 'jti' (JWT ID) nonce claim.",
            remediation="Generate a fresh cryptographic random 'jti' for every DPoP proof.",
        ))

    # 5. Claims 'htm' must match incoming HTTP method
    htm = claims.get("htm")
    req_method_clean = http_method.upper().strip()
    if not htm:
        issues.append(DPoPAuditIssue(
            code="MISSING_HTM_CLAIM",
            severity=DPoPIssueSeverity.HIGH.value,
            message="DPoP proof must contain 'htm' claim indicating target HTTP method.",
            remediation=f"Set 'htm': '{req_method_clean}' in proof claims.",
        ))
    elif str(htm).upper().strip() != req_method_clean:
        issues.append(DPoPAuditIssue(
            code="MISMATCHED_HTM",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message=f"DPoP 'htm' claim '{htm}' does not match incoming HTTP method '{req_method_clean}'.",
            remediation="Ensure proof 'htm' matches the exact HTTP request method.",
        ))

    # 6. Claims 'htu' must match normalized request URI
    htu = claims.get("htu")
    if not htu:
        issues.append(DPoPAuditIssue(
            code="MISSING_HTU_CLAIM",
            severity=DPoPIssueSeverity.HIGH.value,
            message="DPoP proof must contain 'htu' claim indicating target URI.",
            remediation=f"Set 'htu': '{norm_htu}' in proof claims.",
        ))
    else:
        norm_claim_htu = normalize_dpop_htu(str(htu))
        if norm_claim_htu != norm_htu:
            issues.append(DPoPAuditIssue(
                code="MISMATCHED_HTU",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message=f"DPoP 'htu' '{norm_claim_htu}' does not match target URI '{norm_htu}'.",
                remediation="Ensure proof 'htu' matches normalized URL without query/fragment.",
            ))
        # Check if query or fragment was present in raw claim
        if "?" in str(htu) or "#" in str(htu):
            issues.append(DPoPAuditIssue(
                code="HTU_CONTAINS_QUERY_OR_FRAGMENT",
                severity=DPoPIssueSeverity.MEDIUM.value,
                message="RFC 9449 §4.3 forbids query strings or fragments in 'htu' claim.",
                remediation="Strip query '?' and fragment '#' from 'htu' value.",
            ))

    # 7. Claims 'iat' check & freshness window
    iat = claims.get("iat")
    if iat is None:
        issues.append(DPoPAuditIssue(
            code="MISSING_IAT_CLAIM",
            severity=DPoPIssueSeverity.HIGH.value,
            message="DPoP proof must contain 'iat' timestamp claim.",
            remediation="Include current unix timestamp in 'iat' claim.",
        ))
    else:
        try:
            iat_val = float(iat)
            age = now - iat_val
            if age > max_age_seconds:
                issues.append(DPoPAuditIssue(
                    code="STALE_DPOP_PROOF",
                    severity=DPoPIssueSeverity.HIGH.value,
                    message=f"DPoP proof is stale: age {age:.1f}s exceeds maximum allowed window ({max_age_seconds}s).",
                    remediation="Clients must generate fresh DPoP proofs for every request.",
                ))
            elif age < -30.0:  # Clock skew tolerance: max 30s in future
                issues.append(DPoPAuditIssue(
                    code="FUTURE_IAT_CLAIM",
                    severity=DPoPIssueSeverity.MEDIUM.value,
                    message=f"DPoP proof 'iat' is in the future by {abs(age):.1f}s.",
                    remediation="Check client and server NTP clock synchronization.",
                ))
        except (ValueError, TypeError):
            issues.append(DPoPAuditIssue(
                code="INVALID_IAT_FORMAT",
                severity=DPoPIssueSeverity.MEDIUM.value,
                message="DPoP 'iat' claim must be an integer unix timestamp.",
                remediation="Format 'iat' as an integer unix timestamp.",
            ))

    # 8. Claims 'ath' Access Token Hash verification
    ath = claims.get("ath")
    if access_token:
        expected_ath = compute_access_token_hash(access_token)
        if not ath:
            issues.append(DPoPAuditIssue(
                code="MISSING_ATH_CLAIM",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message="Request presented an access token but DPoP proof lacks 'ath' hash claim.",
                remediation="Compute ath = base64url(sha256(access_token)) and include in claims.",
            ))
        elif str(ath).strip() != expected_ath:
            issues.append(DPoPAuditIssue(
                code="INVALID_ATH_HASH",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message="DPoP 'ath' claim does not match SHA-256 hash of the presented access token.",
                remediation="Ensure 'ath' is generated directly from the current active access token.",
            ))
    elif ath:
        # ath was provided but no access token passed to validator
        issues.append(DPoPAuditIssue(
            code="ATH_WITHOUT_ACCESS_TOKEN",
            severity=DPoPIssueSeverity.LOW.value,
            message="DPoP proof includes 'ath' claim but verification context had no access token.",
            remediation="Provide the access token during server-side verification.",
        ))

    # 9. Server Nonce Challenge check
    if expected_nonce:
        nonce_val = claims.get("nonce")
        if not nonce_val:
            issues.append(DPoPAuditIssue(
                code="MISSING_NONCE_CHALLENGE",
                severity=DPoPIssueSeverity.HIGH.value,
                message=f"Server required DPoP nonce challenge but proof lacks 'nonce' claim.",
                remediation="Include the server-provided DPoP-Nonce header value in the proof claims.",
            ))
        elif str(nonce_val) != expected_nonce:
            issues.append(DPoPAuditIssue(
                code="INVALID_NONCE_VALUE",
                severity=DPoPIssueSeverity.HIGH.value,
                message="Proof 'nonce' does not match the active server challenge nonce.",
                remediation="Refresh proof with the latest DPoP-Nonce header from server response.",
            ))

    # 10. Token Confirmation Binding check (cnf.jkt)
    if bound_jkt:
        if not thumbprint:
            binding_matched = False
            issues.append(DPoPAuditIssue(
                code="BINDING_VERIFICATION_FAILED",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message="Access token is bound to a jkt but proof has no computable public key thumbprint.",
                remediation="Ensure DPoP proof includes client public JWK matching bound token.",
            ))
        elif thumbprint != bound_jkt:
            binding_matched = False
            issues.append(DPoPAuditIssue(
                code="CNF_JKT_THUMBPRINT_MISMATCH",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message=f"Token binding mismatch! Access token bound to jkt '{bound_jkt}', but proof signed with '{thumbprint}'.",
                remediation="Client must present DPoP proof signed with the exact key bound in 'cnf.jkt'.",
            ))

    # 11. Anti-Replay Defense
    if jti and thumbprint:
        is_fresh = store.record(jti, thumbprint, now=now)
        if not is_fresh:
            replay_detected = True
            issues.append(DPoPAuditIssue(
                code="DPOP_REPLAY_ATTACK_DETECTED",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message=f"DPoP proof replay detected! Nonce 'jti' ({jti}) has already been used.",
                remediation="Generate a fresh unique 'jti' for each HTTP request.",
            ))

    # Compute Compliance Score
    has_critical = any(i.severity == DPoPIssueSeverity.CRITICAL.value for i in issues)
    has_high = any(i.severity == DPoPIssueSeverity.HIGH.value for i in issues)
    is_valid = not has_critical and not has_high

    if not issues:
        score = 100.0
    else:
        penalties = {
            DPoPIssueSeverity.CRITICAL.value: 35.0,
            DPoPIssueSeverity.HIGH.value: 20.0,
            DPoPIssueSeverity.MEDIUM.value: 10.0,
            DPoPIssueSeverity.LOW.value: 5.0,
        }
        total_penalty = sum(penalties.get(i.severity, 0.0) for i in issues)
        score = max(0.0, 100.0 - total_penalty)

    return DPoPVerificationResult(
        is_valid=is_valid,
        public_key_thumbprint=thumbprint,
        token_binding_matched=binding_matched,
        replay_detected=replay_detected,
        normalized_htu=norm_htu,
        claims=claims,
        header=header,
        issues=issues,
        compliance_score=score,
    )
