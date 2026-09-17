"""Domain data models and enumeration types for jwt-inspector-guard.

Defines unified representations for JWT/JWS/JWE token structures, algorithms,
validation outcomes, security vulnerabilities, and security audit reports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class JWTAlgorithm(str, Enum):
    """Supported cryptographic algorithms for JWT/JWS signatures."""

    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    NONE = "none"

    @classmethod
    def from_str(cls, val: Optional[str]) -> JWTAlgorithm:
        """Parse algorithm name case-insensitively.

        Args:
            val: Algorithm name string (e.g. 'HS256', 'none', 'rs256').

        Returns:
            JWTAlgorithm: Matching algorithm enum member.

        Raises:
            ValueError: If algorithm is unrecognized or not supported.
        """
        if not val or not isinstance(val, str):
            return cls.NONE

        cleaned = val.strip()
        cleaned_upper = cleaned.upper()

        if cleaned.lower() == "none":
            return cls.NONE

        for member in cls:
            if member.value.upper() == cleaned_upper:
                return member

        raise ValueError(f"Unsupported or unknown JWT algorithm: {val}")

    @property
    def is_hmac(self) -> bool:
        """Check if algorithm is an HMAC symmetric algorithm."""
        return self in (JWTAlgorithm.HS256, JWTAlgorithm.HS384, JWTAlgorithm.HS512)

    @property
    def is_rsa(self) -> bool:
        """Check if algorithm is an RSA asymmetric algorithm."""
        return self in (JWTAlgorithm.RS256, JWTAlgorithm.RS384, JWTAlgorithm.RS512)

    @property
    def is_ecdsa(self) -> bool:
        """Check if algorithm is an ECDSA asymmetric algorithm."""
        return self in (JWTAlgorithm.ES256, JWTAlgorithm.ES384, JWTAlgorithm.ES512)

    @property
    def is_asymmetric(self) -> bool:
        """Check if algorithm is asymmetric (RSA or ECDSA)."""
        return self.is_rsa or self.is_ecdsa

    @property
    def is_none(self) -> bool:
        """Check if algorithm is unauthenticated 'none'."""
        return self == JWTAlgorithm.NONE


class TokenType(str, Enum):
    """Token representation format classification."""

    JWT = "JWT"
    JWS = "JWS"
    JWE = "JWE"
    UNKNOWN = "UNKNOWN"


class SecuritySeverity(str, Enum):
    """Security risk severity classifications."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score_weight(self) -> int:
        """Numerical weight contribution towards aggregate risk score."""
        weights = {
            SecuritySeverity.CRITICAL: 35,
            SecuritySeverity.HIGH: 20,
            SecuritySeverity.MEDIUM: 10,
            SecuritySeverity.LOW: 5,
            SecuritySeverity.INFO: 1,
        }
        return weights.get(self, 0)


@dataclass
class DecodedJWT:
    """Structured representation of a parsed JSON Web Token."""

    raw_token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature_b64: str
    is_valid_format: bool
    token_type: TokenType
    error_message: Optional[str] = None
    header_b64: str = ""
    payload_b64: str = ""

    @property
    def algorithm(self) -> Optional[str]:
        """Header algorithm claim ('alg')."""
        return self.header.get("alg")

    @property
    def key_id(self) -> Optional[str]:
        """Header key ID claim ('kid')."""
        return self.header.get("kid")

    @property
    def type_header(self) -> Optional[str]:
        """Header type claim ('typ')."""
        return self.header.get("typ")

    @property
    def issuer(self) -> Optional[str]:
        """Payload issuer claim ('iss')."""
        val = self.payload.get("iss")
        return str(val) if val is not None else None

    @property
    def subject(self) -> Optional[str]:
        """Payload subject claim ('sub')."""
        val = self.payload.get("sub")
        return str(val) if val is not None else None

    @property
    def audience(self) -> Any:
        """Payload audience claim ('aud')."""
        return self.payload.get("aud")

    @property
    def expiration(self) -> Optional[Union[int, float]]:
        """Payload expiration time claim ('exp')."""
        val = self.payload.get("exp")
        if isinstance(val, (int, float)):
            return val
        return None

    @property
    def not_before(self) -> Optional[Union[int, float]]:
        """Payload not-before time claim ('nbf')."""
        val = self.payload.get("nbf")
        if isinstance(val, (int, float)):
            return val
        return None

    @property
    def issued_at(self) -> Optional[Union[int, float]]:
        """Payload issued-at time claim ('iat')."""
        val = self.payload.get("iat")
        if isinstance(val, (int, float)):
            return val
        return None

    @property
    def jwt_id(self) -> Optional[str]:
        """Payload unique token identifier claim ('jti')."""
        val = self.payload.get("jti")
        return str(val) if val is not None else None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize decoded token attributes to dictionary."""
        return {
            "raw_token": self.raw_token,
            "header": self.header,
            "payload": self.payload,
            "signature_b64": self.signature_b64,
            "is_valid_format": self.is_valid_format,
            "token_type": self.token_type.value,
            "error_message": self.error_message,
            "header_b64": self.header_b64,
            "payload_b64": self.payload_b64,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "audience": self.audience,
            "expiration": self.expiration,
            "not_before": self.not_before,
            "issued_at": self.issued_at,
            "jwt_id": self.jwt_id,
        }


@dataclass
class ValidationResult:
    """Outcome of token verification and standard claim checks."""

    is_valid: bool
    signature_verified: bool
    claims_valid: bool
    expired: bool
    time_to_expiration_sec: Optional[float] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize validation outcome to dictionary."""
        return asdict(self)


@dataclass
class SecurityVulnerability:
    """Security defect or anomaly identified in a JWT/JWS token."""

    severity: SecuritySeverity
    title: str
    cve_id: Optional[str] = None
    description: str = ""
    impact: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize vulnerability finding to dictionary."""
        return {
            "severity": self.severity.value,
            "title": self.title,
            "cve_id": self.cve_id,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
        }


@dataclass
class SecurityAuditReport:
    """Comprehensive security analysis report for a token."""

    overall_risk_score: int
    risk_level: str
    vulnerabilities: List[SecurityVulnerability] = field(default_factory=list)
    claims_checks: Dict[str, bool] = field(default_factory=dict)
    entropy_score: float = 0.0
    weak_secret_detected: bool = False
    detected_secret: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize audit report to dictionary."""
        return {
            "overall_risk_score": self.overall_risk_score,
            "risk_level": self.risk_level,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "claims_checks": self.claims_checks,
            "entropy_score": self.entropy_score,
            "weak_secret_detected": self.weak_secret_detected,
            "detected_secret": self.detected_secret,
        }


@dataclass
class SampleToken:
    """Curated real-world token vector with expected security properties."""

    id: str
    name: str
    category: str
    description: str
    raw_token: str
    expected_algorithm: str
    expected_issuer: Optional[str] = None
    known_secret: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize sample token record to dictionary."""
        return asdict(self)


@dataclass
class JWTExploitPayload:
    """A mutated or synthesized exploit payload for testing token parser vulnerabilities."""

    attack_type: str
    title: str
    description: str
    mutated_token: str
    cve_id: Optional[str] = None
    expected_vulnerability: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "title": self.title,
            "description": self.description,
            "mutated_token": self.mutated_token,
            "cve_id": self.cve_id,
            "expected_vulnerability": self.expected_vulnerability,
        }


@dataclass
class JWKRecord:
    """Represents an individual JSON Web Key (RFC 7517) in a key set."""
    kty: str
    kid: str
    use: str = "sig"
    alg: Optional[str] = None
    status: str = "active"  # "active", "retiring", "revoked", "expired"
    n: Optional[str] = None
    e: Optional[str] = None
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    k: Optional[str] = None
    created_at: float = 0.0
    expires_at: Optional[float] = None
    revocation_reason: Optional[str] = None

    def to_dict(self, public_only: bool = True) -> Dict[str, Any]:
        """Convert JWK to standard RFC 7517 JSON dictionary."""
        d: Dict[str, Any] = {
            "kty": self.kty,
            "kid": self.kid,
            "use": self.use,
        }
        if self.alg:
            d["alg"] = self.alg
        if self.kty == "RSA":
            if self.n:
                d["n"] = self.n
            if self.e:
                d["e"] = self.e
        elif self.kty in ("EC", "OKP"):
            if self.crv:
                d["crv"] = self.crv
            if self.x:
                d["x"] = self.x
            if self.y:
                d["y"] = self.y
        elif self.kty == "oct" and not public_only:
            if self.k:
                d["k"] = self.k
        return d


@dataclass
class JWKSRotationReport:
    """Audit report and simulation state of a JSON Web Key Set (JWKS)."""
    total_keys: int
    active_key_id: Optional[str]
    retiring_keys: List[str]
    revoked_keys: List[str]
    jwks_json: Dict[str, Any]
    audit_findings: List[str]
    is_healthy: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_keys": self.total_keys,
            "active_key_id": self.active_key_id,
            "retiring_keys": list(self.retiring_keys),
            "revoked_keys": list(self.revoked_keys),
            "jwks_json": self.jwks_json,
            "audit_findings": list(self.audit_findings),
            "is_healthy": self.is_healthy,
        }


@dataclass
class TimingDefenseReport:
    """Empirical audit report measuring signature verification timing side-channel safety."""
    constant_time_verified: bool
    timing_leakage_detected: bool
    vulnerability_score: float
    sample_count: int
    average_early_ns: float
    average_full_ns: float
    timing_delta_ratio: float
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "constant_time_verified": self.constant_time_verified,
            "timing_leakage_detected": self.timing_leakage_detected,
            "vulnerability_score": round(self.vulnerability_score, 2),
            "sample_count": self.sample_count,
            "average_early_ns": round(self.average_early_ns, 2),
            "average_full_ns": round(self.average_full_ns, 2),
            "timing_delta_ratio": round(self.timing_delta_ratio, 3),
            "recommendations": list(self.recommendations),
        }

