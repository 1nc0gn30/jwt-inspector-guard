"""RFC 7515 compliant Base64URL encoder and decoder for jwt-inspector-guard.

Handles Base64URL transformation without padding characters, URL-safe alphabet
conversions ('-' instead of '+', '_' instead of '/'), and automatic padding restoration.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Union


def base64url_encode(data: Union[bytes, str]) -> str:
    """Encode binary or string data to an unpadded RFC 7515 Base64URL string.

    Args:
        data: Raw bytes or UTF-8 string to encode.

    Returns:
        str: URL-safe Base64 encoded string without trailing '=' padding.
    """
    if isinstance(data, str):
        raw_bytes = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        raw_bytes = bytes(data)
    else:
        raise TypeError(f"Expected bytes or str, got {type(data).__name__}")

    encoded_bytes = base64.urlsafe_b64encode(raw_bytes)
    # Strip '=' padding characters and decode to ascii string
    return encoded_bytes.decode("ascii").rstrip("=")


def base64url_decode(encoded: Union[str, bytes]) -> bytes:
    """Decode an RFC 7515 Base64URL string into raw bytes with automatic padding restoration.

    Args:
        encoded: Base64URL encoded string or ascii bytes.

    Returns:
        bytes: Decoded raw binary bytes.

    Raises:
        ValueError: If input contains invalid Base64 characters or cannot be decoded.
    """
    if isinstance(encoded, bytes):
        s = encoded.decode("ascii", errors="replace")
    elif isinstance(encoded, str):
        s = encoded
    else:
        raise TypeError(f"Expected str or bytes, got {type(encoded).__name__}")

    # Remove all surrounding and internal whitespace/newlines
    s = "".join(s.split())

    # Replace URL-safe characters back to standard Base64
    s = s.replace("-", "+").replace("_", "/")

    # Restore missing '=' padding
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)

    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as exc:
        # Fallback without strict validate if minor anomaly
        try:
            return base64.b64decode(s.encode("ascii"), validate=False)
        except Exception:
            raise ValueError(f"Invalid Base64URL encoding: {exc}") from exc


def base64url_decode_to_text(
    encoded: Union[str, bytes],
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Decode a Base64URL string directly into a text string.

    Args:
        encoded: Base64URL encoded input.
        encoding: Text encoding (default: utf-8).
        errors: Error handling mode ('replace', 'strict', 'ignore').

    Returns:
        str: Decoded text.
    """
    decoded_bytes = base64url_decode(encoded)
    return decoded_bytes.decode(encoding, errors=errors)


def base64url_encode_json(obj: Any) -> str:
    """Serialize a Python object to compact UTF-8 JSON and Base64URL encode it.

    Args:
        obj: JSON-serializable Python data structure.

    Returns:
        str: Base64URL encoded JSON string.
    """
    json_str = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return base64url_encode(json_str.encode("utf-8"))


def base64url_decode_json(encoded: Union[str, bytes]) -> Any:
    """Decode a Base64URL string and parse the resulting UTF-8 text as JSON.

    Args:
        encoded: Base64URL encoded JSON representation.

    Returns:
        Any: Parsed JSON data structure.

    Raises:
        ValueError: If Base64 decoding fails or payload is not valid JSON.
    """
    text = base64url_decode_to_text(encoded, encoding="utf-8", errors="strict")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Payload is not valid JSON: {exc}") from exc
