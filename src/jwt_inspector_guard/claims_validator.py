"""Claims validation engine for standard RFC 7519 JWT claims.

Validates expiration (exp), not-before (nbf), issued-at (iat), issuer (iss),
audience (aud), subject (sub), and token identifier (jti) with configurable clock leeway.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Union

from .models import DecodedJWT, ValidationResult


def validate_claims(
    payload: Dict[str, Any],
    expected_issuer: Optional[str] = None,
    expected_audience: Optional[Union[str, List[str]]] = None,
    expected_subject: Optional[str] = None,
    leeway_sec: int = 0,
    current_time: Optional[float] = None,
) -> ValidationResult:
    """Validate standard RFC 7519 claims in a decoded JWT payload.

    Args:
        payload: Decoded claims dictionary.
        expected_issuer: Expected issuer identifier ('iss').
        expected_audience: Expected audience string or list of accepted audiences ('aud').
        expected_subject: Expected subject identifier ('sub').
        leeway_sec: Acceptable clock skew in seconds (default: 0).
        current_time: Reference timestamp in epoch seconds (defaults to system time.time()).

    Returns:
        ValidationResult: Detailed results with error and warning lists.
    """
    now = time.time() if current_time is None else float(current_time)
    errors: List[str] = []
    warnings: List[str] = []
    claims_valid = True
    is_expired = False
    time_to_exp: Optional[float] = None

    if not isinstance(payload, dict):
        return ValidationResult(
            is_valid=False,
            signature_verified=False,
            claims_valid=False,
            expired=False,
            time_to_expiration_sec=None,
            errors=["Payload is not a valid JSON object dictionary."],
            warnings=[],
        )

    # 1. Check Expiration ('exp')
    if "exp" in payload:
        exp_val = payload["exp"]
        if not isinstance(exp_val, (int, float)):
            claims_valid = False
            errors.append(f"Claim 'exp' must be a numeric Unix timestamp, got {type(exp_val).__name__} ({exp_val!r}).")
        else:
            time_to_exp = round(float(exp_val) - now, 2)
            if now > (float(exp_val) + leeway_sec):
                is_expired = True
                claims_valid = False
                drift = now - float(exp_val)
                errors.append(
                    f"Token has expired: 'exp' timestamp {exp_val} passed {drift:.1f}s ago (leeway={leeway_sec}s)."
                )
            elif time_to_exp < 300 and time_to_exp >= 0:
                warnings.append(
                    f"Token is expiring soon: only {time_to_exp:.0f} seconds ({time_to_exp/60:.1f} min) remaining."
                )
    else:
        warnings.append("Missing 'exp' (expiration time) claim; token does not expire.")

    # 2. Check Not Before ('nbf')
    if "nbf" in payload:
        nbf_val = payload["nbf"]
        if not isinstance(nbf_val, (int, float)):
            claims_valid = False
            errors.append(f"Claim 'nbf' must be a numeric Unix timestamp, got {type(nbf_val).__name__} ({nbf_val!r}).")
        else:
            if now < (float(nbf_val) - leeway_sec):
                claims_valid = False
                wait_sec = float(nbf_val) - now
                errors.append(
                    f"Token is not yet valid: 'nbf' timestamp {nbf_val} is {wait_sec:.1f}s in the future (leeway={leeway_sec}s)."
                )

    # 3. Check Issued At ('iat')
    if "iat" in payload:
        iat_val = payload["iat"]
        if not isinstance(iat_val, (int, float)):
            claims_valid = False
            errors.append(f"Claim 'iat' must be a numeric Unix timestamp, got {type(iat_val).__name__} ({iat_val!r}).")
        else:
            if float(iat_val) > (now + leeway_sec):
                claims_valid = False
                future_sec = float(iat_val) - now
                errors.append(
                    f"Token issued in the future: 'iat' timestamp {iat_val} is {future_sec:.1f}s ahead of current time."
                )

    # Cross-claim coherence: exp vs iat
    if "exp" in payload and "iat" in payload:
        if isinstance(payload["exp"], (int, float)) and isinstance(payload["iat"], (int, float)):
            exp_num = float(payload["exp"])
            iat_num = float(payload["iat"])
            if exp_num < iat_num:
                claims_valid = False
                errors.append(
                    f"Chronological anomaly: 'exp' ({exp_num}) is prior to 'iat' ({iat_num})."
                )
            elif exp_num == iat_num:
                warnings.append(
                    f"Token has zero lifetime: 'exp' ({exp_num}) equals 'iat' ({iat_num})."
                )

    # 4. Check Issuer ('iss')
    if expected_issuer is not None:
        if "iss" not in payload:
            claims_valid = False
            errors.append(f"Missing expected issuer claim 'iss' (expected: '{expected_issuer}').")
        else:
            actual_iss = str(payload["iss"])
            if actual_iss != str(expected_issuer):
                claims_valid = False
                errors.append(
                    f"Issuer mismatch: 'iss' is '{actual_iss}', expected '{expected_issuer}'."
                )

    # 5. Check Audience ('aud')
    if expected_audience is not None:
        if "aud" not in payload:
            claims_valid = False
            errors.append("Missing expected audience claim 'aud'.")
        else:
            raw_aud = payload["aud"]
            token_audiences: List[str] = []
            if isinstance(raw_aud, str):
                token_audiences = [raw_aud]
            elif isinstance(raw_aud, (list, tuple, set)):
                token_audiences = [str(item) for item in raw_aud]
            else:
                token_audiences = [str(raw_aud)]

            expected_list: List[str] = (
                [expected_audience] if isinstance(expected_audience, str) else [str(x) for x in expected_audience]
            )

            # Check for any audience overlap
            if not any(exp_aud in token_audiences for exp_aud in expected_list):
                claims_valid = False
                errors.append(
                    f"Audience mismatch: token aud {token_audiences} does not match expected {expected_list}."
                )

    # 6. Check Subject ('sub')
    if expected_subject is not None:
        if "sub" not in payload:
            claims_valid = False
            errors.append(f"Missing expected subject claim 'sub' (expected: '{expected_subject}').")
        else:
            actual_sub = str(payload["sub"])
            if actual_sub != str(expected_subject):
                claims_valid = False
                errors.append(
                    f"Subject mismatch: 'sub' is '{actual_sub}', expected '{expected_subject}'."
                )

    # 7. Check JWT ID ('jti')
    if "jti" in payload:
        jti_val = payload["jti"]
        if not jti_val or not str(jti_val).strip():
            warnings.append("Claim 'jti' (JWT ID) is empty or blank.")

    is_overall_valid = claims_valid and not is_expired and len(errors) == 0

    return ValidationResult(
        is_valid=is_overall_valid,
        signature_verified=False,  # Set by full validator when signature verified
        claims_valid=claims_valid,
        expired=is_expired,
        time_to_expiration_sec=time_to_exp,
        errors=errors,
        warnings=warnings,
    )


def validate_token_claims(
    token: Union[str, DecodedJWT],
    expected_issuer: Optional[str] = None,
    expected_audience: Optional[Union[str, List[str]]] = None,
    expected_subject: Optional[str] = None,
    leeway_sec: int = 0,
    current_time: Optional[float] = None,
) -> ValidationResult:
    """Convenience function to validate claims directly from a token string or DecodedJWT.

    Args:
        token: Raw token string or parsed DecodedJWT object.
        expected_issuer: Expected 'iss'.
        expected_audience: Expected 'aud'.
        expected_subject: Expected 'sub'.
        leeway_sec: Clock skew leeway in seconds.
        current_time: Epoch timestamp override.

    Returns:
        ValidationResult: Outcome of claim checks.
    """
    if isinstance(token, DecodedJWT):
        payload = token.payload
    else:
        from .token_parser import parse_jwt

        decoded = parse_jwt(token)
        if not decoded.is_valid_format:
            return ValidationResult(
                is_valid=False,
                signature_verified=False,
                claims_valid=False,
                expired=False,
                time_to_expiration_sec=None,
                errors=[decoded.error_message or "Invalid token format."],
                warnings=[],
            )
        payload = decoded.payload

    return validate_claims(
        payload=payload,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        expected_subject=expected_subject,
        leeway_sec=leeway_sec,
        current_time=current_time,
    )
