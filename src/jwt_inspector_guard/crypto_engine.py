"""Cryptographic signature engine for JWT/JWS tokens.

Provides pure Python standard-library:
- HMAC (HS256 / HS384 / HS512) signing and constant-time verification
- NIST P-256 ECDSA (ES256) key generation, signing, and JWK verification
- RSA PKCS#1 v1.5 (RS256 / RS384 / RS512) JWK verification
- Shannon entropy analysis and weak secret dictionary testing

Zero external dependencies required. Rejects `alg: none` by default (RFC 8725 BCP).
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import math
import secrets
from typing import Any, Callable, Dict, Iterable, Optional, Tuple, Union

from .base64_url import base64url_decode, base64url_encode, base64url_encode_json
from .models import JWTAlgorithm


_HMAC_DIGEST_FACTORIES: Dict[JWTAlgorithm, Callable[[], Any]] = {
    JWTAlgorithm.HS256: hashlib.sha256,
    JWTAlgorithm.HS384: hashlib.sha384,
    JWTAlgorithm.HS512: hashlib.sha512,
}

# ---------------------------------------------------------------------------
# Pure-Python NIST P-256 (secp256r1) Elliptic Curve Primitives (Zero Deps)
# ---------------------------------------------------------------------------
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = (_P256_P - 3) % _P256_P
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_G: Tuple[int, int] = (_P256_GX, _P256_GY)

# DigestInfo DER prefixes for RSA PKCS#1 v1.5 (RFC 8017 §9.2)
_RSA_DIGEST_PREFIXES: Dict[str, Tuple[Callable[[], Any], bytes]] = {
    "RS256": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
    "RS384": (hashlib.sha384, bytes.fromhex("3041300d060960864801650304020205000430")),
    "RS512": (hashlib.sha512, bytes.fromhex("3051300d060960864801650304020305000440")),
}


def _p256_is_on_curve(point: Optional[Tuple[int, int]]) -> bool:
    if point is None:
        return False
    x, y = point
    if not (0 <= x < _P256_P and 0 <= y < _P256_P):
        return False
    return (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256_P == 0


def _p256_add(
    p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]
) -> Optional[Tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % _P256_P, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _p256_mul(k: int, point: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    k %= _P256_N
    if k == 0:
        return None
    result: Optional[Tuple[int, int]] = None
    addend: Optional[Tuple[int, int]] = point
    while k:
        if k & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        k >>= 1
    return result


def generate_p256_keypair() -> Tuple[int, Dict[str, Any]]:
    """Generate a real NIST P-256 ECDSA keypair returning (private_d, public_jwk)."""
    d = 1 + secrets.randbelow(_P256_N - 1)
    pub = _p256_mul(d, _P256_G)
    assert pub is not None
    x_int, y_int = pub
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(x_int.to_bytes(32, "big")),
        "y": base64url_encode(y_int.to_bytes(32, "big")),
        "use": "sig",
    }
    return d, public_jwk


def sign_es256(header_b64: str, payload_b64: str, private_d: int) -> str:
    """Sign a JWS signing input with NIST P-256 ECDSA (ES256, RFC 7518 R||S 64-byte format)."""
    if not (1 <= private_d < _P256_N):
        raise ValueError("Invalid P-256 private scalar")
    signing_input = compute_signing_input(header_b64, payload_b64)
    z = int.from_bytes(hashlib.sha256(signing_input).digest(), "big") % _P256_N
    while True:
        k = 1 + secrets.randbelow(_P256_N - 1)
        pt = _p256_mul(k, _P256_G)
        if pt is None:
            continue
        r = pt[0] % _P256_N
        if r == 0:
            continue
        s = (pow(k, -1, _P256_N) * (z + r * private_d)) % _P256_N
        if s == 0:
            continue
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return base64url_encode(raw_sig)


def verify_es256_jwk(
    header_b64: str, payload_b64: str, signature_b64: str, jwk: Dict[str, Any]
) -> bool:
    """Verify an ES256 (ECDSA P-256 + SHA-256) JWS signature against a public EC JWK."""
    try:
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return False
        x_bytes = base64url_decode(str(jwk.get("x", "")))
        y_bytes = base64url_decode(str(jwk.get("y", "")))
        if len(x_bytes) == 0 or len(y_bytes) == 0 or len(x_bytes) > 32 or len(y_bytes) > 32:
            return False
        pub = (int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"))
        if not _p256_is_on_curve(pub):
            return False

        sig_bytes = base64url_decode(signature_b64.strip())
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        if not (1 <= r < _P256_N and 1 <= s < _P256_N):
            return False

        signing_input = compute_signing_input(header_b64, payload_b64)
        z = int.from_bytes(hashlib.sha256(signing_input).digest(), "big") % _P256_N
        w = pow(s, -1, _P256_N)
        u1 = (z * w) % _P256_N
        u2 = (r * w) % _P256_N
        pt = _p256_add(_p256_mul(u1, _P256_G), _p256_mul(u2, pub))
        if pt is None:
            return False
        return (pt[0] % _P256_N) == r
    except Exception:
        return False


def verify_rs_pkcs1_jwk(
    header_b64: str, payload_b64: str, signature_b64: str, jwk: Dict[str, Any], alg: str = "RS256"
) -> bool:
    """Verify an RS256/RS384/RS512 (RSA PKCS#1 v1.5) JWS signature against a public RSA JWK."""
    try:
        alg_upper = alg.upper()
        if alg_upper not in _RSA_DIGEST_PREFIXES:
            return False
        if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
            return False
        n_bytes = base64url_decode(str(jwk.get("n", "")))
        e_bytes = base64url_decode(str(jwk.get("e", "")))
        if len(n_bytes) < 128 or not e_bytes:
            return False
        n = int.from_bytes(n_bytes, "big")
        e = int.from_bytes(e_bytes, "big")
        if e < 3 or (e & 1) == 0:
            return False

        sig_bytes = base64url_decode(signature_b64.strip())
        k = (n.bit_length() + 7) // 8
        if len(sig_bytes) != k:
            return False
        s_int = int.from_bytes(sig_bytes, "big")
        if s_int >= n:
            return False

        em = pow(s_int, e, n).to_bytes(k, "big")
        hash_fn, prefix = _RSA_DIGEST_PREFIXES[alg_upper]
        digest = hash_fn(compute_signing_input(header_b64, payload_b64)).digest()
        t_bytes = prefix + digest
        ps_len = k - len(t_bytes) - 3
        if ps_len < 8:
            return False
        expected_em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t_bytes
        return hmac.compare_digest(em, expected_em)
    except Exception:
        return False


def verify_asymmetric_jwk(
    header_b64: str,
    payload_b64: str,
    signature_b64: str,
    jwk: Dict[str, Any],
    alg: str,
) -> bool:
    """Verify an asymmetric JWS signature (ES256, RS256/RS384/RS512) using a public JWK."""
    if not signature_b64 or not isinstance(jwk, dict):
        return False
    alg_upper = str(alg or "").upper()
    if alg_upper == "ES256":
        return verify_es256_jwk(header_b64, payload_b64, signature_b64, jwk)
    if alg_upper in _RSA_DIGEST_PREFIXES:
        return verify_rs_pkcs1_jwk(header_b64, payload_b64, signature_b64, jwk, alg_upper)
    return False


def compute_signing_input(header_b64: str, payload_b64: str) -> bytes:
    """Construct the canonical JWS signing input bytes: 'header_b64.payload_b64'."""
    return f"{header_b64}.{payload_b64}".encode("ascii")


def sign_hmac(
    header_b64: str,
    payload_b64: str,
    secret: Union[str, bytes],
    alg: Union[JWTAlgorithm, str] = JWTAlgorithm.HS256,
) -> str:
    """Generate an HMAC signature for a JWT header and payload."""
    if isinstance(alg, str):
        algorithm = JWTAlgorithm.from_str(alg)
    else:
        algorithm = alg

    if algorithm == JWTAlgorithm.NONE:
        return ""

    if algorithm not in _HMAC_DIGEST_FACTORIES:
        raise ValueError(
            f"Algorithm '{algorithm.value}' is not supported for HMAC signing. "
            f"Supported HMAC algorithms: {[a.value for a in _HMAC_DIGEST_FACTORIES]}"
        )

    digest_mod = _HMAC_DIGEST_FACTORIES[algorithm]
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    signing_input = compute_signing_input(header_b64, payload_b64)

    mac = hmac.new(secret_bytes, signing_input, digest_mod)
    return base64url_encode(mac.digest())


def verify_hmac(
    header_b64: str,
    payload_b64: str,
    signature_b64: str,
    secret: Union[str, bytes],
    alg: Union[JWTAlgorithm, str] = JWTAlgorithm.HS256,
    allow_none: bool = False,
) -> bool:
    """Verify an HMAC signature using constant-time digest comparison.

    Rejects `alg: none` by default (RFC 8725 BCP) unless `allow_none=True` is
    explicitly passed by the caller for educational CVE-2015-9235 testing.
    """
    try:
        if isinstance(alg, str):
            algorithm = JWTAlgorithm.from_str(alg)
        else:
            algorithm = alg

        if algorithm == JWTAlgorithm.NONE:
            if not allow_none:
                return False
            return signature_b64 == ""

        if algorithm not in _HMAC_DIGEST_FACTORIES:
            return False

        expected_sig = sign_hmac(header_b64, payload_b64, secret, algorithm)
        return hmac.compare_digest(signature_b64.strip(), expected_sig)
    except Exception:
        return False


def generate_hmac_jwt(
    header: Dict[str, Any],
    payload: Dict[str, Any],
    secret: Union[str, bytes],
    alg: Union[JWTAlgorithm, str] = JWTAlgorithm.HS256,
) -> str:
    """Generate a complete compact JWT token string signed with HMAC."""
    if isinstance(alg, str):
        algorithm = JWTAlgorithm.from_str(alg)
    else:
        algorithm = alg

    hdr = dict(header)
    hdr["alg"] = algorithm.value
    if "typ" not in hdr:
        hdr["typ"] = "JWT"

    header_b64 = base64url_encode_json(hdr)
    payload_b64 = base64url_encode_json(payload)
    sig_b64 = sign_hmac(header_b64, payload_b64, secret, algorithm)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def calculate_token_entropy(token: str) -> float:
    """Calculate the Shannon entropy of a token string in bits per character."""
    if not token:
        return 0.0

    length = len(token)
    counts = collections.Counter(token)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def crack_hmac_secret(
    header_b64: str,
    payload_b64: str,
    signature_b64: str,
    alg: Union[JWTAlgorithm, str],
    wordlist: Iterable[str],
) -> Optional[str]:
    """Test candidate secrets against an HMAC-signed token."""
    try:
        if isinstance(alg, str):
            algorithm = JWTAlgorithm.from_str(alg)
        else:
            algorithm = alg
    except ValueError:
        return None

    if not algorithm.is_hmac or not signature_b64:
        return None

    for candidate in wordlist:
        if verify_hmac(header_b64, payload_b64, signature_b64, candidate, algorithm):
            return candidate

    return None
