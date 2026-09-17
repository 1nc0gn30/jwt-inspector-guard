"""JWT Inspector Guard: Multi-OS Model Context Protocol (MCP) server & CLI security inspector for JSON Web Tokens.

Provides pure Python standard library utilities to decode, verify, audit, crack, and synthesize JWTs,
along with MCP stdio protocol handlers and a command-line interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from .mcp_server import (
    base64url_decode,
    base64url_encode,
    decode_jwt_parts,
    format_timestamp,
    get_diagnostics,
    get_sample_token,
    handle_jsonrpc_request,
    list_sample_tokens,
    process_request,
    run_stdio_server,
    sign_hmac,
    verify_hmac,
    audit_jwt_security as _audit_jwt_security_fn,
    validate_claims as _validate_claims_fn,
)
from .models import JWTExploitPayload
from .security_linter import generate_exploit_tokens

__version__ = "0.1.0"
__author__ = "jwt-inspector-guard contributors"
__license__ = "MIT"
__description__ = "Multi-OS Model Context Protocol (MCP) server & CLI security inspector for JSON Web Tokens"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class JWTAlgorithm(str, Enum):
    """Supported and recognized JWT algorithms."""
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    NONE = "none"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"


class TokenType(str, Enum):
    """Recognized token format types."""
    JWT = "JWT"
    JWS = "JWS"
    JWE = "JWE"
    OAUTH2_ACCESS = "OAuth2_Access"
    ID_TOKEN = "ID_Token"
    UNKNOWN = "UNKNOWN"


class SecuritySeverity(str, Enum):
    """Severity levels for security audit findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class DecodedJWT:
    """Structured representation of a decoded JSON Web Token."""
    raw_token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    header_b64: str = ""
    payload_b64: str = ""
    signature_b64: str = ""
    algorithm: str = "none"
    token_type: str = "JWT"
    is_valid_format: bool = True
    error: Optional[str] = None
    formatted_claims: Dict[str, Optional[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert DecodedJWT to dictionary."""
        return {
            "raw_token": self.raw_token,
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature,
            "header_b64": self.header_b64,
            "payload_b64": self.payload_b64,
            "signature_b64": self.signature_b64,
            "algorithm": self.algorithm,
            "token_type": self.token_type,
            "is_valid_format": self.is_valid_format,
            "error": self.error,
            "formatted_claims": self.formatted_claims,
        }


@dataclass
class ValidationResult:
    """Result of signature verification and claim validation."""
    is_valid: bool
    signature_valid: Optional[bool]
    claims_valid: bool
    algorithm: str = "HS256"
    is_expired: bool = False
    time_to_expiry_seconds: Optional[float] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    formatted_dates: Dict[str, Optional[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert ValidationResult to dictionary."""
        return {
            "is_valid": self.is_valid,
            "signature_valid": self.signature_valid,
            "claims_valid": self.claims_valid,
            "algorithm": self.algorithm,
            "is_expired": self.is_expired,
            "time_to_expiry_seconds": self.time_to_expiry_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
            "formatted_dates": self.formatted_dates,
        }


@dataclass
class SecurityAuditReport:
    """Comprehensive security score and findings report."""
    score: int
    grade: str
    risk_level: str
    is_secure: bool
    algorithm: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    findings_count: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    cracked_secret: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert SecurityAuditReport to dictionary."""
        return {
            "score": self.score,
            "grade": self.grade,
            "risk_level": self.risk_level,
            "is_secure": self.is_secure,
            "algorithm": self.algorithm,
            "findings": self.findings,
            "findings_count": self.findings_count,
            "recommendations": self.recommendations,
            "cracked_secret": self.cracked_secret,
        }


# ---------------------------------------------------------------------------
# High-Level API Wrappers
# ---------------------------------------------------------------------------

def parse_jwt(token: str) -> DecodedJWT:
    """Parse a compact JWT string into a structured DecodedJWT object."""
    try:
        header, payload, sig_b64, header_b64, payload_b64, raw_token = decode_jwt_parts(token)
        alg = str(header.get("alg", "none"))
        typ = str(header.get("typ", "JWT"))
        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")

        formatted = {
            "exp": format_timestamp(exp) if exp is not None else None,
            "iat": format_timestamp(iat) if iat is not None else None,
            "nbf": format_timestamp(nbf) if nbf is not None else None,
        }

        return DecodedJWT(
            raw_token=raw_token,
            header=header,
            payload=payload,
            signature=sig_b64,
            header_b64=header_b64,
            payload_b64=payload_b64,
            signature_b64=sig_b64,
            algorithm=alg,
            token_type=typ,
            is_valid_format=True,
            formatted_claims=formatted,
        )
    except Exception as e:
        return DecodedJWT(
            raw_token=token,
            header={},
            payload={},
            signature="",
            is_valid_format=False,
            error=str(e),
        )


def validate_claims(
    payload: Dict[str, Any],
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    leeway: float = 0.0,
    current_time: Optional[float] = None
) -> ValidationResult:
    """Validate token claims and return a ValidationResult object."""
    raw = _validate_claims_fn(
        payload,
        issuer=issuer,
        audience=audience,
        leeway=leeway,
        current_time=current_time
    )
    return ValidationResult(
        is_valid=raw["claims_valid"],
        signature_valid=None,
        claims_valid=raw["claims_valid"],
        is_expired=raw["is_expired"],
        time_to_expiry_seconds=raw["time_to_expiry_seconds"],
        errors=raw["errors"],
        warnings=raw["warnings"],
        formatted_dates=raw["formatted_dates"],
    )


def audit_jwt_security(token: str, known_secret: Optional[str] = None) -> SecurityAuditReport:
    """Run full security scorecard audit on a JWT and return a SecurityAuditReport object."""
    raw = _audit_jwt_security_fn(token, known_secret=known_secret)
    return SecurityAuditReport(
        score=raw.get("score", 0),
        grade=raw.get("grade", "F"),
        risk_level=raw.get("risk_level", "CRITICAL RISK"),
        is_secure=raw.get("is_secure", False),
        algorithm=raw.get("algorithm", "none"),
        findings=raw.get("findings", []),
        findings_count=raw.get("findings_count", {}),
        recommendations=raw.get("recommendations", []),
        cracked_secret=raw.get("cracked_secret"),
    )


__all__ = [
    "DecodedJWT",
    "ValidationResult",
    "SecurityAuditReport",
    "JWTExploitPayload",
    "JWTAlgorithm",
    "TokenType",
    "SecuritySeverity",
    "parse_jwt",
    "verify_hmac",
    "sign_hmac",
    "validate_claims",
    "audit_jwt_security",
    "generate_exploit_tokens",
    "base64url_encode",
    "base64url_decode",
    "get_sample_token",
    "list_sample_tokens",
    "handle_jsonrpc_request",
    "process_request",
    "run_stdio_server",
]
