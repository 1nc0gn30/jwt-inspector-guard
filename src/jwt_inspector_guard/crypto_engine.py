"""Cryptographic signature engine for JWT/JWS tokens.

Provides pure Python HMAC signing, constant-time signature verification,
Shannon entropy analysis, and weak secret dictionary testing.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import math
from typing import Any, Callable, Dict, Iterable, Optional, Union

from .base64_url import base64url_encode, base64url_encode_json
from .models import JWTAlgorithm


_HMAC_DIGEST_FACTORIES: Dict[JWTAlgorithm, Callable[[], Any]] = {
    JWTAlgorithm.HS256: hashlib.sha256,
    JWTAlgorithm.HS384: hashlib.sha384,
    JWTAlgorithm.HS512: hashlib.sha512,
}


def compute_signing_input(header_b64: str, payload_b64: str) -> bytes:
    """Construct the canonical JWS signing input bytes: 'header_b64.payload_b64'.

    Args:
        header_b64: Base64URL encoded header string.
        payload_b64: Base64URL encoded payload string.

    Returns:
        bytes: Canonical UTF-8/ASCII signing input bytes.
    """
    return f"{header_b64}.{payload_b64}".encode("ascii")


def sign_hmac(
    header_b64: str,
    payload_b64: str,
    secret: Union[str, bytes],
    alg: Union[JWTAlgorithm, str] = JWTAlgorithm.HS256,
) -> str:
    """Generate an HMAC signature for a JWT header and payload.

    Args:
        header_b64: Base64URL encoded header.
        payload_b64: Base64URL encoded payload.
        secret: Signing key secret (string or raw bytes).
        alg: HMAC algorithm (HS256, HS384, HS512, or NONE).

    Returns:
        str: Base64URL encoded HMAC signature (or empty string for NONE).

    Raises:
        ValueError: If algorithm is not supported or not an HMAC algorithm.
    """
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
) -> bool:
    """Verify an HMAC signature using constant-time digest comparison.

    Protects against timing side-channel attacks by evaluating signatures
    via hmac.compare_digest.

    Args:
        header_b64: Base64URL encoded header.
        payload_b64: Base64URL encoded payload.
        signature_b64: Base64URL encoded signature to verify.
        secret: Verification key secret (string or raw bytes).
        alg: HMAC algorithm to test.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    try:
        if isinstance(alg, str):
            algorithm = JWTAlgorithm.from_str(alg)
        else:
            algorithm = alg

        if algorithm == JWTAlgorithm.NONE:
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
    """Generate a complete compact JWT token string signed with HMAC.

    Args:
        header: Header dictionary (e.g. {'alg': 'HS256', 'typ': 'JWT'}).
        payload: Payload claims dictionary.
        secret: Secret signing key.
        alg: Algorithm to use.

    Returns:
        str: Compact 3-part JWT string ('header.payload.signature').
    """
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
    """Calculate the Shannon entropy of a token string in bits per character.

    Shannon Entropy: H(X) = - sum(p(x) * log2(p(x)))

    Args:
        token: Target string (raw token, payload, or signature).

    Returns:
        float: Entropy value in bits per character (typically 0.0 to ~6.0 for Base64).
    """
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
    """Test candidate secrets against an HMAC-signed token.

    Args:
        header_b64: Base64URL encoded header.
        payload_b64: Base64URL encoded payload.
        signature_b64: Base64URL encoded signature.
        alg: JWT algorithm (e.g. HS256).
        wordlist: Iterable sequence of candidate secret strings.

    Returns:
        Optional[str]: Cracked secret if discovered, otherwise None.
    """
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
