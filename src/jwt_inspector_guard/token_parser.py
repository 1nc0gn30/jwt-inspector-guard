"""Token parser for JWT, JWS, and JWE structures.

Parses compact representations, validates base64url encoding, decodes JSON headers
and claims payloads, and extracts candidate tokens from raw text streams.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from .base64_url import (
    base64url_decode_json,
    base64url_decode_to_text,
)
from .models import DecodedJWT, TokenType


# Regex to locate candidate JWT tokens in unstructured text (e.g. logs, headers, config files)
_JWT_CANDIDATE_REGEX = re.compile(
    r"\b(?:Bearer\s+)?([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)\b",
    re.IGNORECASE,
)

# Standard registered JWT claims from RFC 7519
_STANDARD_JWT_CLAIMS = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}


def clean_raw_token(raw_token: str) -> str:
    """Sanitize raw token input by stripping whitespace, quotes, and 'Bearer ' prefix.

    Args:
        raw_token: Unsanitized token string.

    Returns:
        str: Cleaned compact token string.
    """
    if not raw_token or not isinstance(raw_token, str):
        return ""

    cleaned = raw_token.strip().strip("'\"`")
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()

    return cleaned


def parse_jwt(raw_token: str) -> DecodedJWT:
    """Parse a compact JWT, JWS, or JWE string into a structured DecodedJWT object."""
    cleaned = clean_raw_token(raw_token)
    if not cleaned:
        return DecodedJWT(
            raw_token="",
            header={},
            payload={},
            signature_b64="",
            is_valid_format=False,
            token_type=TokenType.UNKNOWN,
            error_message="Token string is empty or blank.",
        )

    parts = cleaned.split(".")

    # Handle standard 3-part JWS / JWT (Header.Payload.Signature)
    if len(parts) == 3:
        header_b64, payload_b64, signature_b64 = parts[0], parts[1], parts[2]
        header: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}
        errors: List[str] = []

        # Parse Header
        try:
            hdr_obj = base64url_decode_json(header_b64)
            if isinstance(hdr_obj, dict):
                header = hdr_obj
            else:
                header = {"_raw_header": hdr_obj}
                errors.append(f"Header JSON must be an object/dict, got {type(hdr_obj).__name__}.")
        except Exception as exc:
            errors.append(f"Header decoding error: {exc}")

        # Parse Payload
        try:
            payload_obj = base64url_decode_json(payload_b64)
            if isinstance(payload_obj, dict):
                payload = payload_obj
            else:
                payload = {"_raw_payload": payload_obj}
        except Exception as exc:
            # Fallback: try decoding as plain text
            try:
                raw_text = base64url_decode_to_text(payload_b64)
                payload = {"_raw_text": raw_text}
            except Exception:
                errors.append(f"Payload decoding error: {exc}")

        # Determine token classification
        token_type = TokenType.JWS
        if isinstance(header, dict) and header.get("typ", "").upper() == "JWT":
            token_type = TokenType.JWT
        elif isinstance(payload, dict) and any(k in payload for k in _STANDARD_JWT_CLAIMS):
            token_type = TokenType.JWT
        elif isinstance(header, dict) and "enc" in header:
            token_type = TokenType.JWE

        is_valid = len(errors) == 0 and bool(header)
        error_msg = "; ".join(errors) if errors else None

        return DecodedJWT(
            raw_token=cleaned,
            header=header,
            payload=payload,
            signature_b64=signature_b64,
            is_valid_format=is_valid,
            token_type=token_type,
            error_message=error_msg,
            header_b64=header_b64,
            payload_b64=payload_b64,
        )

    # Handle 5-part JWE (Header.EncryptedKey.IV.Ciphertext.AuthTag)
    elif len(parts) == 5:
        header_b64, enc_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts
        header = {}
        errors = []

        try:
            hdr_obj = base64url_decode_json(header_b64)
            if isinstance(hdr_obj, dict):
                header = hdr_obj
            else:
                header = {"_raw_header": hdr_obj}
        except Exception as exc:
            errors.append(f"JWE header decoding error: {exc}")

        payload = {
            "_jwe_encrypted": True,
            "encrypted_key_b64": enc_key_b64,
            "iv_b64": iv_b64,
            "ciphertext_b64": ciphertext_b64,
            "tag_b64": tag_b64,
        }

        is_valid = len(errors) == 0 and bool(header)
        error_msg = "; ".join(errors) if errors else None

        return DecodedJWT(
            raw_token=cleaned,
            header=header,
            payload=payload,
            signature_b64=tag_b64,
            is_valid_format=is_valid,
            token_type=TokenType.JWE,
            error_message=error_msg,
            header_b64=header_b64,
            payload_b64=ciphertext_b64,
        )

    # Invalid part count
    return DecodedJWT(
        raw_token=cleaned,
        header={},
        payload={},
        signature_b64="",
        is_valid_format=False,
        token_type=TokenType.UNKNOWN,
        error_message=(
            f"Invalid JWT structure: expected 3 segments (JWS/JWT) or 5 segments (JWE), "
            f"found {len(parts)} dot-separated segment(s)."
        ),
    )


def extract_jwt_candidates(text: str) -> List[str]:
    """Scan raw text for strings matching JWT compact format.

    Args:
        text: Arbitrary string containing logs, headers, or source code.

    Returns:
        List[str]: Cleaned list of candidate JWT token strings found in the text.
    """
    if not text or not isinstance(text, str):
        return []

    matches = _JWT_CANDIDATE_REGEX.findall(text)
    unique_candidates: List[str] = []
    seen = set()

    for match in matches:
        cleaned = clean_raw_token(match)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_candidates.append(cleaned)

    return unique_candidates


def is_jwt_format(token: str) -> bool:
    """Fast check whether a string adheres to standard 3-part or 5-part token format.

    Args:
        token: String to test.

    Returns:
        bool: True if structure matches JWT/JWE format, False otherwise.
    """
    cleaned = clean_raw_token(token)
    if not cleaned:
        return False

    parts = cleaned.split(".")
    if len(parts) not in (3, 5):
        return False

    # Check that each part contains only valid Base64URL characters
    base64url_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    for idx, part in enumerate(parts):
        # 3rd part of unsigned alg:none token can be empty
        if idx == 2 and len(parts) == 3 and part == "":
            continue
        if not part or not set(part).issubset(base64url_chars):
            return False

    return True


# Compatibility alias
parse_token = parse_jwt
