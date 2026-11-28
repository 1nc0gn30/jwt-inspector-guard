"""DPoP (Demonstrating Proof-of-Possession at the Application Layer - RFC 9449) & Token Binding Guard.

Zero external dependencies: 100% Python Standard Library.
Provides:
1. RFC 9449 compliant DPoP Proof Generation with real NIST P-256 ECDSA (ES256) keypairs & signatures
2. Real cryptographic JWS signature verification against the embedded public JWK (ES256 / RS256 / RS384 / RS512)
3. RFC 9449 §4.3 HTU URL Normalization (scheme/host lowercase, default ports stripped, query/fragment removed)
4. Access Token Hash (ath) computation: base64url(sha256(access_token))
5. RFC 7638 JWK Thumbprint calculation & access token confirmation binding (cnf.jkt)
6. Anti-Replay Cache & Window Verification (prevents token reuse attacks)
"""

from __future__ import annotations

import hashlib
import secrets
import time
import urllib.parse
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from .base64_url import base64url_decode_json, base64url_encode, base64url_encode_json
from .crypto_engine import generate_p256_keypair, sign_es256, verify_asymmetric_jwk
from .jwks_manager import compute_jwk_thumbprint
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
    signature_valid: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "signature_valid": self.signature_valid,
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
        status_badge = "VALID" if self.is_valid else "INVALID / REJECTED"
        lines = [
            f"# DPoP (RFC 9449) Proof Verification: {status_badge}",
            "",
            f"- **Compliance Score**: `{self.compliance_score:.1f}/100`",
            f"- **Cryptographic Signature**: `{'VALID' if self.signature_valid else 'INVALID'}`",
            f"- **JWK Thumbprint (`jkt`)**: `{self.public_key_thumbprint}`",
            f"- **Token Binding Matched**: `{'Yes' if self.token_binding_matched else 'No / Unbound'}`",
            f"- **Replay Detected**: `{'YES (CRITICAL)' if self.replay_detected else 'No (Fresh)'}`",
            f"- **Normalized HTU**: `{self.normalized_htu}`",
            f"- **HTTP Method (`htm`)**: `{self.claims.get('htm', 'N/A')}`",
            f"- **Nonce (`jti`)**: `{self.claims.get('jti', 'N/A')}`",
            "",
        ]
        if self.issues:
            lines.append("## Detected Security & Compliance Issues")
            lines.append("")
            for iss in self.issues:
                lines.append(f"- **[{iss.severity}] {iss.code}**: {iss.message}")
                lines.append(f"  *Remediation*: {iss.remediation}")
        else:
            lines.append("## Clean Audit")
            lines.append("DPoP proof strictly satisfies all RFC 9449 requirements and cryptographic bindings.")

        return "\n".join(lines)


def normalize_dpop_htu(url_or_path: str) -> str:
    """Normalize HTTP Target URI (HTU) per RFC 9449 §4.3."""
    if not url_or_path:
        return ""

    parsed = urllib.parse.urlsplit(url_or_path.strip())

    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    netloc = parsed.netloc.lower() if parsed.netloc else "localhost"

    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = parsed.path
    if not path:
        path = "/"
    else:
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
    """Compute RFC 9449 §4.2 Access Token Hash (ath): base64url(sha256(ASCII(access_token)))."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64url_encode(digest)


class DPoPReplayStore:
    """In-memory anti-replay cache tracking (jti, jkt) nonces within a rolling TTL window."""

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[Tuple[str, str], float] = {}

    def is_replayed(self, jti: str, jkt: str, now: Optional[float] = None) -> bool:
        curr_time = now if now is not None else time.time()
        self._prune(curr_time)
        return (jti, jkt) in self._cache

    def record(self, jti: str, jkt: str, now: Optional[float] = None) -> bool:
        curr_time = now if now is not None else time.time()
        self._prune(curr_time)
        key = (jti, jkt)
        if key in self._cache:
            return False
        self._cache[key] = curr_time
        return True

    def _prune(self, now: float) -> None:
        threshold = now - self.ttl_seconds
        expired_keys = [k for k, ts in self._cache.items() if ts < threshold]
        for k in expired_keys:
            del self._cache[k]

    def clear(self) -> None:
        self._cache.clear()


GLOBAL_DPOP_REPLAY_STORE = DPoPReplayStore()


def create_dpop_proof(
    http_method: str,
    http_url: str,
    access_token: Optional[str] = None,
    nonce: Optional[str] = None,
    jwk: Optional[Union[JWKRecord, Dict[str, Any]]] = None,
    secret_key: Optional[Union[str, bytes, int]] = None,
    alg: str = "ES256",
    jti: Optional[str] = None,
    iat: Optional[int] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Generate an RFC 9449 compliant DPoP proof JWT signed with real NIST P-256 ECDSA (ES256)."""
    now = int(time.time()) if iat is None else int(iat)
    token_jti = jti or f"dpop-jti-{secrets.token_urlsafe(16)}"
    norm_htu = normalize_dpop_htu(http_url)
    effective_alg = str(alg or "ES256").upper()
    if effective_alg != "ES256":
        effective_alg = "ES256"

    # 1. Resolve asymmetric P-256 keypair (RFC 9449 §4.2 forbids symmetric keys)
    priv_d: Optional[int] = None
    if isinstance(secret_key, int):
        priv_d = secret_key

    if jwk is None:
        priv_d, jwk_dict = generate_p256_keypair()
    elif isinstance(jwk, JWKRecord):
        jwk_dict = jwk.to_dict(public_only=True)
    else:
        jwk_dict = dict(jwk)
        if "d" in jwk_dict and priv_d is None:
            from .base64_url import base64url_decode
            priv_d = int.from_bytes(base64url_decode(str(jwk_dict["d"])), "big")

    # Strip any private key fields from embedded public JWK
    for priv_param in ("d", "p", "q", "dp", "dq", "qi", "k"):
        jwk_dict.pop(priv_param, None)

    if priv_d is None:
        # Caller supplied a public-only JWK without private scalar; generate a real matching P-256 pair
        priv_d, jwk_dict = generate_p256_keypair()

    thumbprint = compute_jwk_thumbprint(jwk_dict)

    # 2. Build DPoP Header (RFC 9449 §4.2)
    header: Dict[str, Any] = {
        "typ": "dpop+jwt",
        "alg": effective_alg,
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

    # 4. Serialize & Sign with real NIST P-256 ECDSA (ES256)
    header_b64 = base64url_encode_json(header)
    payload_b64 = base64url_encode_json(claims)
    sig_b64 = sign_es256(header_b64, payload_b64, priv_d)

    proof_jwt = f"{header_b64}.{payload_b64}.{sig_b64}"

    metadata = {
        "proof_jwt": proof_jwt,
        "thumbprint": thumbprint,
        "ath": ath_value,
        "jti": token_jti,
        "htu": norm_htu,
        "htm": http_method.upper().strip(),
        "iat": now,
        "alg": effective_alg,
        "jwk": jwk_dict,
    }

    return proof_jwt, metadata


def bind_token_with_dpop(
    access_token_claims: Dict[str, Any],
    jwk_or_thumbprint: Union[Dict[str, Any], JWKRecord, str],
) -> Dict[str, Any]:
    """Inject RFC 9449 'cnf.jkt' confirmation claim into an access token payload."""
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
    """Verify an RFC 9449 DPoP proof including real cryptographic JWS signature verification."""
    now = current_time if current_time is not None else time.time()
    store = replay_store if replay_store is not None else GLOBAL_DPOP_REPLAY_STORE
    norm_htu = normalize_dpop_htu(http_url)

    issues: List[DPoPAuditIssue] = []
    header: Dict[str, Any] = {}
    claims: Dict[str, Any] = {}
    thumbprint: str = ""
    replay_detected: bool = False
    binding_matched: bool = True
    signature_valid: bool = False

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
            signature_valid=False,
            public_key_thumbprint="",
            token_binding_matched=False,
            replay_detected=False,
            normalized_htu=norm_htu,
            claims={},
            header={},
            issues=issues,
            compliance_score=0.0,
        )

    header_b64, payload_b64, sig_b64 = parts

    # Decode Header & Payload
    try:
        header = base64url_decode_json(header_b64)
    except Exception as e:
        issues.append(DPoPAuditIssue(
            code="INVALID_HEADER_JSON",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message=f"Failed to decode DPoP header JSON: {str(e)}",
            remediation="Ensure header is valid UTF-8 JSON Base64URL-encoded.",
        ))

    try:
        claims = base64url_decode_json(payload_b64)
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
            signature_valid=False,
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

    # 2. Header 'alg' must be an asymmetric signature algorithm (never 'none' or HS*)
    alg = str(header.get("alg", "")).strip()
    if not alg or alg.lower() == "none":
        issues.append(DPoPAuditIssue(
            code="FORBIDDEN_ALG_NONE",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message="DPoP proofs cannot use unsigned 'none' algorithm.",
            remediation="Sign DPoP proof using an asymmetric signature algorithm (e.g. ES256, RS256).",
        ))
    elif alg.upper().startswith("HS"):
        issues.append(DPoPAuditIssue(
            code="FORBIDDEN_SYMMETRIC_ALG",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message=f"RFC 9449 §4.2 forbids symmetric algorithm '{alg}' for DPoP proofs.",
            remediation="Use an asymmetric algorithm such as ES256 or RS256.",
        ))

    # 3. Header 'jwk' must be present, asymmetric, and public-only
    jwk = header.get("jwk")
    if not jwk or not isinstance(jwk, dict):
        issues.append(DPoPAuditIssue(
            code="MISSING_JWK_HEADER",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message="DPoP header must contain an embedded public 'jwk' dictionary.",
            remediation="Include the client's public asymmetric JWK in the DPoP header.",
        ))
    else:
        if str(jwk.get("kty", "")).lower() == "oct":
            issues.append(DPoPAuditIssue(
                code="FORBIDDEN_SYMMETRIC_JWK",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message="RFC 9449 §4.2 forbids symmetric 'oct' JWK keys in DPoP headers.",
                remediation="Embed an asymmetric EC (P-256) or RSA public key.",
            ))
        private_params = {"d", "p", "q", "dp", "dq", "qi", "k"}.intersection(jwk.keys())
        if private_params:
            issues.append(DPoPAuditIssue(
                code="PRIVATE_KEY_EXPOSURE_IN_JWK",
                severity=DPoPIssueSeverity.CRITICAL.value,
                message=f"Leaked private key parameter(s) {sorted(private_params)} in public JWK header!",
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

    # 3b. Real Cryptographic JWS Signature Verification (fails closed!)
    if isinstance(jwk, dict) and alg and alg.lower() != "none" and not alg.upper().startswith("HS"):
        signature_valid = verify_asymmetric_jwk(header_b64, payload_b64, sig_b64, jwk, alg)
    else:
        signature_valid = False

    if not signature_valid:
        issues.append(DPoPAuditIssue(
            code="INVALID_DPOP_SIGNATURE",
            severity=DPoPIssueSeverity.CRITICAL.value,
            message=f"Cryptographic {alg or 'JWS'} signature verification failed against embedded public JWK.",
            remediation="Sign the DPoP proof with the private key matching the embedded header 'jwk' (ES256/RS256).",
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
            elif age < -30.0:
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
                message="Server required DPoP nonce challenge but proof lacks 'nonce' claim.",
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

    # 11. Anti-Replay Defense (record only when proof signature & structure were present)
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
    is_valid = signature_valid and not has_critical and not has_high

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
        signature_valid=signature_valid,
        public_key_thumbprint=thumbprint,
        token_binding_matched=binding_matched,
        replay_detected=replay_detected,
        normalized_htu=norm_htu,
        claims=claims,
        header=header,
        issues=issues,
        compliance_score=score,
    )
