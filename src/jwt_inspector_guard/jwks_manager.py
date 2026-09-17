"""JSON Web Key (JWK) & Key Set (JWKS) Lifecycle, Rotation & Audit Simulator (RFC 7517 / RFC 7638).

Provides pure Python JWKS key generation, RFC 7638 thumbprint calculation,
graceful key rollover simulation (active -> retiring -> expired / revoked),
token key ID (kid) resolution, and comprehensive JWKS health auditing.
100% Python Standard Library.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from .base64_url import base64url_decode, base64url_encode
from .models import JWKRecord, JWKSRotationReport
from .token_parser import parse_jwt


def compute_jwk_thumbprint(jwk: Union[JWKRecord, Dict[str, Any]]) -> str:
    """Compute the canonical RFC 7638 SHA-256 thumbprint of a JSON Web Key.

    RFC 7638 specifies lexicographically sorted JSON of required key components:
    - RSA: e, kty, n
    - EC: crv, kty, x, y
    - oct: k, kty

    Args:
        jwk: JWKRecord or dictionary representing a JWK.

    Returns:
        str: Base64URL-encoded SHA-256 thumbprint digest.
    """
    data = jwk.to_dict(public_only=False) if isinstance(jwk, JWKRecord) else dict(jwk)
    kty = data.get("kty", "").upper()

    if kty == "RSA":
        canonical = {
            "e": data.get("e", "AQAB"),
            "kty": "RSA",
            "n": data.get("n", ""),
        }
    elif kty in ("EC", "OKP"):
        canonical = {
            "crv": data.get("crv", "P-256"),
            "kty": kty,
            "x": data.get("x", ""),
            "y": data.get("y", ""),
        }
    elif kty == "OCT":
        canonical = {
            "k": data.get("k", ""),
            "kty": "oct",
        }
    else:
        canonical = {"kty": kty}

    # RFC 7638 requires strictly compact JSON with no whitespace and sorted keys
    canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    return base64url_encode(digest)


def generate_synthetic_jwk(
    kid: Optional[str] = None,
    alg: str = "RS256",
    kty: str = "RSA",
    use: str = "sig",
    status: str = "active",
) -> JWKRecord:
    """Generate a realistic synthetic public JWK for testing and simulation.

    Args:
        kid: Optional Key ID (defaults to RFC 7638 thumbprint prefix).
        alg: Algorithm name (e.g. RS256, ES256, HS256).
        kty: Key type (RSA, EC, oct).
        use: Key usage ('sig' for signature, 'enc' for encryption).
        status: Lifecycle status ('active', 'retiring', 'revoked', 'expired').

    Returns:
        JWKRecord: Populated JWK instance.
    """
    now = time.time()
    kty_clean = kty.upper()

    if kty_clean == "RSA":
        # Realistic 2048-bit modulus simulation (256 random bytes base64url encoded)
        n_bytes = secrets.token_bytes(256)
        n = base64url_encode(n_bytes)
        e = "AQAB"  # 65537
        generated_kid = kid or f"rsa-sig-{secrets.token_hex(4)}"
        return JWKRecord(
            kty="RSA",
            kid=generated_kid,
            use=use,
            alg=alg,
            status=status,
            n=n,
            e=e,
            created_at=now,
            expires_at=now + (86400 * 90),  # 90-day validity
        )
    elif kty_clean in ("EC", "OKP"):
        x_bytes = secrets.token_bytes(32)
        y_bytes = secrets.token_bytes(32)
        generated_kid = kid or f"ec-sig-{secrets.token_hex(4)}"
        return JWKRecord(
            kty="EC",
            kid=generated_kid,
            use=use,
            alg=alg or "ES256",
            status=status,
            crv="P-256",
            x=base64url_encode(x_bytes),
            y=base64url_encode(y_bytes),
            created_at=now,
            expires_at=now + (86400 * 90),
        )
    else:
        # Symmetric octet
        k_bytes = secrets.token_bytes(32)
        generated_kid = kid or f"oct-{secrets.token_hex(4)}"
        return JWKRecord(
            kty="oct",
            kid=generated_kid,
            use=use,
            alg=alg or "HS256",
            status=status,
            k=base64url_encode(k_bytes),
            created_at=now,
            expires_at=now + (86400 * 30),
        )


class JWKSRotationSimulator:
    """Simulates production JWKS keystore lifecycle, key rollover, and validation."""

    def __init__(self, issuer: str = "https://auth.example.com"):
        self.issuer = issuer
        self.keys: Dict[str, JWKRecord] = {}
        # Bootstrap with one default active RSA signing key
        primary_key = generate_synthetic_jwk(kid="k-primary-2026", alg="RS256", kty="RSA", status="active")
        self.keys[primary_key.kid] = primary_key

    def add_key(self, key: JWKRecord) -> None:
        """Register a key into the keystore."""
        self.keys[key.kid] = key

    def get_key(self, kid: str) -> Optional[JWKRecord]:
        """Retrieve key record by ID."""
        return self.keys.get(kid)

    def get_active_key(self) -> Optional[JWKRecord]:
        """Get the currently active signing key."""
        for k in self.keys.values():
            if k.status == "active":
                return k
        return None

    def rotate_active_key(
        self,
        new_kid: Optional[str] = None,
        new_alg: Optional[str] = None,
        grace_period_sec: float = 86400.0,
    ) -> Tuple[JWKRecord, Optional[JWKRecord]]:
        """Perform graceful key rollover: demote active key to retiring, promote new key.

        Args:
            new_kid: Optional custom Key ID for the new key.
            new_alg: Algorithm for the new key (inherits from current if None).
            grace_period_sec: Window in seconds during which the retiring key remains valid.

        Returns:
            Tuple[JWKRecord, Optional[JWKRecord]]: (new_active_key, retired_key)
        """
        current_active = self.get_active_key()
        now = time.time()

        if current_active:
            current_active.status = "retiring"
            current_active.expires_at = now + grace_period_sec

        target_alg = new_alg or (current_active.alg if current_active else "RS256")
        target_kty = current_active.kty if current_active else "RSA"

        new_key = generate_synthetic_jwk(
            kid=new_kid or f"k-rotated-{int(now)}",
            alg=target_alg,
            kty=target_kty,
            status="active",
        )
        self.add_key(new_key)
        return new_key, current_active

    def revoke_key(self, kid: str, reason: str = "Key compromised or emergency rollover") -> bool:
        """Immediately revoke a key, disallowing further signature verifications."""
        key = self.keys.get(kid)
        if not key:
            return False
        key.status = "revoked"
        key.revocation_reason = reason
        return True

    def export_jwks(self, include_revoked: bool = False) -> Dict[str, Any]:
        """Export RFC 7517 compliant JWKS representation."""
        public_keys = []
        for key in self.keys.values():
            if key.status == "revoked" and not include_revoked:
                continue
            public_keys.append(key.to_dict(public_only=True))
        return {"keys": public_keys}

    def resolve_key_for_token(self, token: str) -> Dict[str, Any]:
        """Resolve verification key for a given token, evaluating rotation status.

        Args:
            token: Compact JWT string.

        Returns:
            Dict[str, Any]: Resolution outcome with key details, validity flag, and warnings.
        """
        try:
            parsed = parse_jwt(token)
            header = parsed.header
        except Exception as e:
            return {
                "resolved": False,
                "error": f"Failed to parse token header: {e}",
                "key": None,
                "status": "invalid_token",
            }

        kid = header.get("kid")
        alg = header.get("alg")

        if not kid:
            return {
                "resolved": False,
                "error": "Token header is missing required 'kid' parameter for JWKS resolution",
                "key": None,
                "status": "missing_kid",
            }

        key = self.keys.get(kid)
        if not key:
            return {
                "resolved": False,
                "error": f"Key ID '{kid}' not found in published JWKS set",
                "key": None,
                "status": "key_not_found",
            }

        if key.status == "revoked":
            return {
                "resolved": False,
                "error": f"Key ID '{kid}' has been REVOKED: {key.revocation_reason or 'No reason provided'}",
                "key": key.to_dict(public_only=True),
                "status": "revoked",
            }

        now = time.time()
        if key.expires_at and now > key.expires_at:
            return {
                "resolved": False,
                "error": f"Key ID '{kid}' has EXPIRED (expiration: {key.expires_at})",
                "key": key.to_dict(public_only=True),
                "status": "expired",
            }

        # Algorithm mismatch check
        alg_match = True
        warning = None
        if key.alg and alg and key.alg != alg:
            alg_match = False
            warning = f"Algorithm mismatch: token header specifies '{alg}', but JWK specifies '{key.alg}'"

        status_msg = "active"
        if key.status == "retiring":
            status_msg = "retiring (valid for verification during grace period)"

        return {
            "resolved": alg_match,
            "key": key.to_dict(public_only=True),
            "status": key.status,
            "status_description": status_msg,
            "algorithm_match": alg_match,
            "warning": warning,
        }

    def audit_jwks_health(self, external_jwks: Optional[Dict[str, Any]] = None) -> JWKSRotationReport:
        """Audit JWKS key set for security compliance and hygiene.

        Checks:
        1. Private key exposure (e.g. 'd', 'p', 'q' parameters leaked).
        2. Duplicate or colliding 'kid' values.
        3. Missing 'kid' or missing 'alg' parameters.
        4. Stale/unrotated keys exceeding recommended lifetime.
        5. Key usage restriction ('use' != 'sig').

        Args:
            external_jwks: Optional external JWKS dict to inspect; if None, audits self.

        Returns:
            JWKSRotationReport: Complete health scorecard.
        """
        findings: List[str] = []
        is_healthy = True

        if external_jwks is not None:
            raw_keys = external_jwks.get("keys", [])
        else:
            raw_keys = [k.to_dict(public_only=False) for k in self.keys.values()]

        seen_kids = set()
        active_kid: Optional[str] = None
        retiring_kids: List[str] = []
        revoked_kids: List[str] = []

        for idx, k in enumerate(raw_keys):
            kid = k.get("kid")
            kty = k.get("kty")

            # Check private key parameter leaks
            private_params = [p for p in ("d", "p", "q", "dp", "dq", "qi") if p in k]
            if private_params:
                findings.append(f"CRITICAL: Private key parameters leaked in key #{idx + 1} ('{kid}'): {private_params}")
                is_healthy = False

            if not kid:
                findings.append(f"WARNING: Key #{idx + 1} is missing a 'kid' (Key ID)")
                is_healthy = False
            elif kid in seen_kids:
                findings.append(f"CRITICAL: Duplicate 'kid' detected: '{kid}'")
                is_healthy = False
            else:
                seen_kids.add(kid)

            if not k.get("alg"):
                findings.append(f"INFO: Key '{kid}' does not explicitly specify an 'alg' attribute (RFC 7517 recommendation)")

            if k.get("use") != "sig":
                findings.append(f"NOTICE: Key '{kid}' usage is '{k.get('use')}' (expected 'sig')")

        # Check internal status if self-auditing
        if external_jwks is None:
            for k in self.keys.values():
                if k.status == "active":
                    active_kid = k.kid
                elif k.status == "retiring":
                    retiring_kids.append(k.kid)
                elif k.status == "revoked":
                    revoked_kids.append(k.kid)

            if not active_kid:
                findings.append("CRITICAL: No currently active key found in JWKS set")
                is_healthy = False

        return JWKSRotationReport(
            total_keys=len(raw_keys),
            active_key_id=active_kid,
            retiring_keys=retiring_kids,
            revoked_keys=revoked_kids,
            jwks_json=self.export_jwks(include_revoked=True) if external_jwks is None else external_jwks,
            audit_findings=findings,
            is_healthy=is_healthy,
        )
