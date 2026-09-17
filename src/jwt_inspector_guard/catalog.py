"""Comprehensive catalog of 20+ real-world sample tokens and security test vectors.

Includes tokens from popular Identity Providers, Cloud Platforms, Developer APIs,
and curated vulnerability exploit vectors (alg:none, weak secrets, key injection, PII leak).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .base64_url import base64url_encode, base64url_encode_json
from .crypto_engine import sign_hmac
from .models import JWTAlgorithm, SampleToken


def _make_hmac_token(header: dict, payload: dict, secret: str, alg: JWTAlgorithm = JWTAlgorithm.HS256) -> str:
    """Helper to synthesize valid HMAC signed tokens for the catalog."""
    h_b64 = base64url_encode_json(header)
    p_b64 = base64url_encode_json(payload)
    sig = sign_hmac(h_b64, p_b64, secret, alg)
    return f"{h_b64}.{p_b64}.{sig}"


def _make_unsigned_token(header: dict, payload: dict) -> str:
    """Helper to synthesize unsigned tokens (alg:none or stripped signature)."""
    h_b64 = base64url_encode_json(header)
    p_b64 = base64url_encode_json(payload)
    return f"{h_b64}.{p_b64}."


# 1. Auth0 Standard RS256 Access Token
_AUTH0_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik56UXpSVUpHUTBGQk5FRkRSRVpHUWtRNVJRIn0."
    "eyJpc3MiOiJodHRwczovL2F1dGgwLWV4YW1wbGUudXMucnVuLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vYXBpLmV4YW1wbGUuY29tL3YxLyIsImh0dHBzOi8vYXV0aDAtZXhhbXBsZS51cy5ydW4uYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTczNTAwMDAwMCwiZXhwIjoyMDUwNDgwMDAwLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIHJlYWQ6bWVzc2FnZXMiLCJhenAiOiJ4WWoxMkJjZDNlZjRHNUg2STE3OGoxayJ9."
    "dGVzdC1yc2Etc2lnbmF0dXJlLXZlY3Rvci1hdXRoMC1wcm92aWRlci12YWxpZGF0aW9uLXNhbXBsZS10b2tlbi1yZWFkeQ"
)

# 2. Firebase Auth Token
_FIREBASE_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNiOGE4OWYwMTFkOGY5YjFiZWI1YzYxZjcxOTcwMDlmYzM2M2M0NzkifQ."
    "eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vbXktcHJvamVjdC0xMjM0NSIsImF1ZCI6Im15LXByb2plY3QtMTIzNDUiLCJhdXRoX3RpbWUiOjE3MzUwMDAwMDAsInVzZXJfaWQiOiJmYl91c2VyXzkwMjEwIiwic3ViIjoiZmJfdXNlcl85MDIxMCIsImlhdCI6MTczNTAwMDAwMCwiZXhwIjoyMDUwNDgwMDAwLCJlbWFpbCI6ImRldmVsb3BlckBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ."
    "ZmlyZWJhc2UtcnNhLXNpZ25hdHVyZS12ZWN0b3ItZXhhbXBsZS1kZXZlbG9wZXItYXV0aC12YWxpZGF0aW9uLXN1Y2Nlc3M"
)

# 3. Supabase Session Token (HS256)
_SUPABASE_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "iss": "supabase",
        "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "aud": "authenticated",
        "exp": 2050480000,
        "iat": 1735000000,
        "email": "user@supabase.io",
        "role": "authenticated",
        "app_metadata": {"provider": "email", "providers": ["email"]},
        "user_metadata": {"name": "Supabase Developer"},
    },
    secret="super-secret-jwt-token-with-at-least-32-bytes-of-entropy-for-security!",
    alg=JWTAlgorithm.HS256,
)

# 4. GitHub OAuth / App Token (RS256)
_GITHUB_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0."
    "eyJpc3MiOiJnaXRodWItYXBwLTEyMzQ1IiwiaWF0IjoxNzM1MDAwMDAwLCJleHAiOjIwNTA0ODAwMDAsInN1YiI6ImFwcC1pbnN0YWxsYXRpb24tOTk5OTkiLCJhdWQiOiJodHRwczovL2FwaS5naXRodWIuY29tIn0."
    "Z2l0aHViLXJzYTI1Ni12ZWN0b3ItYXBwLWluc3RhbGxhdGlvbi1zaWduYXR1cmUtc2FtcGxl"
)

# 5. AWS Cognito ID Token
_COGNITO_ID_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkNPR05JVE9fS0VZX0lEXzEyMzQ1NiJ9."
    "eyJzdWIiOiJjNmZhM2I2Mi1kOTFiLTRiYTgtYmIzNC1kMzc0ZDdhNzZhMmMiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbS91cy1lYXN0LTFfRXhhbXBsZVBvb2wiLCJjb2duaXRvOnVzZXJuYW1lIjoiYWxleF9kZXYiLCJhdWQiOiIxMmFiY2QzNGVmZ2g1Nmlqa2w3OG1ub3A5MCIsImV2ZW50X2lkIjoiOTg3NjU0MzItMWFiYy00ZGVmLTk4NzYtMTIzNDU2Nzg5MGFiIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE3MzUwMDAwMDAsImV4cCI6MjA1MDQ4MDAwMCwiaWF0IjoxNzM1MDAwMDAwLCJlbWFpbCI6ImFsZXhAZXhhbXBsZS5jb20ifQ."
    "Y29nbml0by1pZC10b2tlbi1zaWduYXR1cmUtc2FtcGxlLXZlY3Rvci1hd3MtcGxhdGZvcm0"
)

# 6. AWS Cognito Access Token
_COGNITO_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkNPR05JVE9fS0VZX0lEXzEyMzQ1NiJ9."
    "eyJzdWIiOiJjNmZhM2I2Mi1kOTFiLTRiYTgtYmIzNC1kMzc0ZDdhNzZhMmMiLCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tL3VzLWVhc3QtMV9FeGFtcGxlUG9vbCIsImNsaWVudF9pZCI6IjEyYWJjZDM0ZWZnaDU2aWprbDc4bW5vcDkwIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiBvcGVuaWQiLCJhdXRoX3RpbWUiOjE3MzUwMDAwMDAsImV4cCI6MjA1MDQ4MDAwMCwiaWF0IjoxNzM1MDAwMDAwLCJqdGkiOiIxYTIzYjQ1Ni1jZGVmLTc4OTAtMTIzNC01Njc4OTA5YWJjZGYifQ."
    "Y29nbml0by1hY2Nlc3MtdG9rZW4tc2lnbmF0dXJlLXZlY3Rvci1hd3MtcGxhdGZvcm0"
)

# 7. Okta Access Token
_OKTA_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjF4MjlhYmNkZWZnaCJ9."
    "eyJ2ZXIiOjEsImp0aSI6IkFULTExMjIzMzQ0NTU2NiIsImlzcyI6Imh0dHBzOi8vZGV2LTEyMzQ1Ni5va3RhLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE3MzUwMDAwMDAsImV4cCI6MjA1MDQ4MDAwMCwiY2lkIjoiMG9hMXF6d3N4ZWRjcmZ2dGdiIiwidWlkIjoiMDB1MWFiY2RlZmdoMWlqa2xtbm8iLCJzY3AiOlsib3BlbmlkIiwiZW1haWwiLCJwcm9maWxlIl0sInN1YiI6ImRldmVsb3BlckBva3RhZGV2LmNvbSJ9."
    "b2t0YS1hY2Nlc3MtdG9rZW4tc2lnbmF0dXJlLXZlY3Rvci1va3RhLWlkc"
)

# 8. Azure AD / Microsoft Entra ID Token
_AZURE_AD_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCI6ImFiY2RlZjEyMzQ1NiIsImtpZCI6ImFiY2RlZjEyMzQ1NiJ9."
    "eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaWF0IjoxNzM1MDAwMDAwLCJuYmYiOjE3MzUwMDAwMDAsImV4cCI6MjA1MDQ4MDAwMCwiYWNyIjoiMSIsImFwcGlkIjoiY2QxMjM0NWUtNmY3OC05YWJjLWRlZjAtMTIzNDU2Nzg5MGFiIiwicm9sZXMiOlsiVXNlci5SZWFkLkFsbCIsIkRpcmVjdG9yeS5SZWFkLkFsbCJdLCJzdWIiOiJNU0ZUX1VTRVJfODg4ODgiLCJ0aWQiOiI3MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcifQ."
    "YXp1cmUtYWQtbWljcm9zb2Z0LWdyYXBoLXJzMjU2LXNpZ25hdHVyZS1zYW1wbGU"
)

# 9. Google Identity OIDC Token
_GOOGLE_ID_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImY1MmFkYjY1NGZlY2FjYjEyMzQ1In0."
    "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhemkiOiIxMjM0NTY3ODkwMTItYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxMjM0NTY3ODkwMTItYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDk4NzY1NDMyMTA5ODc2NTQzMjEiLCJlbWFpbCI6Imdvb2dsZS51c2VyQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdXRoX3RpbWUiOjE3MzUwMDAwMDAsImlhdCI6MTczNTAwMDAwMCwiZXhwIjoyMDUwNDgwMDAwfQ."
    "Z29vZ2xlLWlkZW50aXR5LW9pZGMtcnNhLXNpZ25hdHVyZS12ZWN0b3I"
)

# 10. Hasura GraphQL HS256 Token
_HASURA_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "sub": "user_hasura_44",
        "name": "GraphQL Admin",
        "iat": 1735000000,
        "exp": 2050480000,
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": ["user", "editor", "admin"],
            "x-hasura-default-role": "user",
            "x-hasura-user-id": "user_hasura_44",
            "x-hasura-org-id": "org_9988",
        },
    },
    secret="super-secure-hasura-secret-key-that-cannot-be-guessed-easily-12345",
    alg=JWTAlgorithm.HS256,
)

# 11. Stripe Webhook JWS Vector
_STRIPE_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "iss": "stripe",
        "iat": 1735000000,
        "exp": 2050480000,
        "event_id": "evt_1N4Xyz2eZvKYlo2C",
        "type": "payment_intent.succeeded",
        "amount": 4900,
        "currency": "usd",
        "customer": "cus_N1234567890",
    },
    secret="whsec_test_secret_for_stripe_webhook_signing_verification_key_32bytes",
    alg=JWTAlgorithm.HS256,
)

# 12. Salesforce Bearer JWT
_SALESFORCE_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiIzTVZHMTh2T1BhZ3ZzYnhkVmU4eE53MTIzNDU2Iiwic3ViIjoiYWRtaW5Ac2FsZXNmb3JjZS5jb20iLCJhdWQiOiJodHRwczovL2xvZ2luLnNhbGVzZm9yY2UuY29tIiwiaWF0IjoxNzM1MDAwMDAwLCJleHAiOjIwNTA0ODAwMDB9."
    "c2FsZXNmb3JjZS1jb25uZWN0ZWQtYXBwLXJzMjU2LWJlYXJlci1zaWduYXR1cmU"
)

# 13. Apple Sign-In Identity Token (ES256)
_APPLE_TOKEN = (
    "eyJhbGciOiJFUzI1NiIsImtpZCI6IkFQUEtFWTEyMyIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmV4YW1wbGUubXlhcHAiLCJleHAiOjIwNTA0ODAwMDAsImlhdCI6MTczNTAwMDAwMCwic3ViIjoiMDAxMjM0LjViYzZhNmQ4ZTlmMGExYjJjM2Q0ZS4wMTIzIiwiZW1haWwiOiJwcml2YXRlX3JlbGF5QHJlbGF5LmFwcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIn0."
    "YXBwbGUtc2lnbmluLWVzMjU2LWVjZHNhLXNpZ25hdHVyZS1zYW1wbGU"
)

# 14. Shopify App Bridge JWT
_SHOPIFY_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "iss": "https://quick-start-app.myshopify.com/admin",
        "dest": "https://quick-start-app.myshopify.com",
        "aud": "shopify_api_key_12345678",
        "sub": "user_shopify_77",
        "exp": 2050480000,
        "nbf": 1735000000,
        "iat": 1735000000,
        "jti": "jti_shopify_app_bridge_uuid_0001",
    },
    secret="shopify_client_shared_secret_high_entropy_bytes_998877",
    alg=JWTAlgorithm.HS256,
)

# 15. Twilio Voice/Chat JWT
_TWILIO_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT", "cty": "twilio-fpa;v=1"},
    {
        "jti": "MOCK_KEY_ID_1234567890abcdef-1735000000",
        "iss": "MOCK_KEY_ID_1234567890abcdef",
        "sub": "MOCK_ACCOUNT_ID_1234567890abcdef",
        "exp": 2050480000,
        "grants": {
            "identity": "alice_mobile_client",
            "voice": {"incoming": {"allow": True}, "outgoing": {"application_sid": "MOCK_APP_ID_12345678"}},
        },
    },
    secret="twilio_api_secret_key_32_bytes_of_random_chars_999",
    alg=JWTAlgorithm.HS256,
)

# 16. Malicious 'alg: none' Exploit Vector (CVE-2015-9235)
_EXPLOIT_ALG_NONE = _make_unsigned_token(
    {"alg": "none", "typ": "JWT"},
    {
        "sub": "attacker_zero",
        "name": "Attacker",
        "admin": True,
        "role": "superadmin",
        "iat": 1735000000,
        "exp": 2050480000,
    },
)

# 17. Malicious 'kid' Path Traversal Vector
_EXPLOIT_KID_TRAVERSAL = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT", "kid": "../../../../../dev/null"},
    {
        "sub": "exploiter_path",
        "role": "admin",
        "iat": 1735000000,
        "exp": 2050480000,
    },
    secret="",  # When /dev/null is read as secret, it is 0 bytes
    alg=JWTAlgorithm.HS256,
)

# 18. Malicious 'kid' SQL Injection Vector
_EXPLOIT_KID_SQLI = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleScgT1IgJzEnPScxIn0."
    "eyJzdWIiOiJhdHRhY2tlcl9zcWxpIiwicm9sZSI6InJvb3QiLCJpYXQiOjE3MzUwMDAwMDAsImV4cCI6MjA1MDQ4MDAwMH0."
    "c3FsaS1leHBsb2l0LXZlY3Rvci1zaWduYXR1cmUtZXhhbXBsZQ"
)

# 19. Weak Secret JWT (Signed with "secret")
_WEAK_SECRET_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "sub": "user_victim_123",
        "name": "John Doe",
        "admin": False,
        "iat": 1735000000,
        "exp": 2050480000,
    },
    secret="secret",
    alg=JWTAlgorithm.HS256,
)

# 20. Weak Secret JWT (Signed with "password123")
_WEAK_SECRET_PW123 = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "sub": "service_account_weak",
        "role": "maintainer",
        "iat": 1735000000,
        "exp": 2050480000,
    },
    secret="password123",
    alg=JWTAlgorithm.HS256,
)

# 21. Expired Token Sample (Expired in 2020)
_EXPIRED_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "sub": "expired_user",
        "iat": 1577836800,  # 2020-01-01
        "exp": 1577840400,  # 2020-01-01 + 1h
    },
    secret="valid-secret-key-but-token-has-already-expired",
    alg=JWTAlgorithm.HS256,
)

# 22. Future 'nbf' Sample (Not valid until year 2035)
_FUTURE_NBF_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "sub": "future_user",
        "nbf": 2051222400,  # 2035-01-01
        "iat": 1735000000,
        "exp": 2051226000,
    },
    secret="valid-secret-key-for-future-nbf-validation-vector",
    alg=JWTAlgorithm.HS256,
)

# 23. PII & Credential Leak Sample
_PII_LEAK_TOKEN = _make_hmac_token(
    {"alg": "HS256", "typ": "JWT"},
    {
        "sub": "victim_user_pii",
        "username": "victim",
        "password": "SuperSecretCleartextPassword!2026",
        "ssn": "987-65-4321",
        "credit_card": "4111111111111111",
        "cvv": "123",
        "iat": 1735000000,
        "exp": 2050480000,
    },
    secret="some-secure-signing-secret-for-pii-leak-demo",
    alg=JWTAlgorithm.HS256,
)

# 24. JWE Compact 5-Part Encrypted Token
_JWE_SAMPLE_TOKEN = (
    "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJraWQiOiJqd2Uta2V5LTEifQ."
    "c2FtcGxlLWVuY3J5cHRlZC1rZXktYnl0ZXMtc2VnbWVudC0y."
    "c2FtcGxlLWluaXRpYWxpemF0aW9uLXZlY3Rvci0z."
    "c2FtcGxlLWNpcGhlcnRleHQtZW5jcnlwdGVkLXBheWxvYWQtNA."
    "c2FtcGxlLWF1dGhlbnRpY2F0aW9uLXRhZy01"
)

# 25. Corrupted / Malformed Token Vector
_CORRUPTED_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.INVALID-JSON-PAYLOAD-NOT-BASE64-OR-JSON!@#$.signature"


# Master Registry of Sample Tokens
_SAMPLE_TOKENS: Dict[str, SampleToken] = {
    "auth0-standard-jwt": SampleToken(
        id="auth0-standard-jwt",
        name="Auth0 Standard RS256 Access Token",
        category="Identity Providers",
        description="Standard OAuth2/OIDC RS256 access token issued by Auth0 with multi-audience claims and scopes.",
        raw_token=_AUTH0_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="https://auth0-example.us.run.auth0.com/",
        known_secret=None,
        tags=["auth0", "rs256", "oidc", "oauth2", "asymmetric"],
        notes="Uses public-key cryptography; verified against Auth0 JWKS endpoint.",
    ),
    "firebase-auth-token": SampleToken(
        id="firebase-auth-token",
        name="Firebase Authentication ID Token",
        category="Identity Providers",
        description="Google Firebase user identity token with auth_time and email verification claims.",
        raw_token=_FIREBASE_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="https://securetoken.google.com/my-project-12345",
        known_secret=None,
        tags=["firebase", "google", "rs256", "auth"],
        notes="Standard Firebase client token.",
    ),
    "supabase-session-token": SampleToken(
        id="supabase-session-token",
        name="Supabase Session Token (HS256)",
        category="Cloud & PaaS",
        description="Supabase user session JWT with role='authenticated' and custom user metadata.",
        raw_token=_SUPABASE_TOKEN,
        expected_algorithm="HS256",
        expected_issuer="supabase",
        known_secret="super-secret-jwt-token-with-at-least-32-bytes-of-entropy-for-security!",
        tags=["supabase", "postgresql", "hs256", "symmetric"],
        notes="Valid HMAC-SHA256 signature with secure random secret.",
    ),
    "github-oauth-token": SampleToken(
        id="github-oauth-token",
        name="GitHub App Installation JWT",
        category="Developer Platforms",
        description="GitHub App authentication token used to generate installation access tokens.",
        raw_token=_GITHUB_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="github-app-12345",
        known_secret=None,
        tags=["github", "rs256", "app", "api"],
        notes="Short-lived token for GitHub API app installations.",
    ),
    "aws-cognito-id-token": SampleToken(
        id="aws-cognito-id-token",
        name="AWS Cognito User Pool ID Token",
        category="Cloud & PaaS",
        description="AWS Cognito OpenID Connect token containing user identity and custom attributes.",
        raw_token=_COGNITO_ID_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ExamplePool",
        known_secret=None,
        tags=["aws", "cognito", "rs256", "cloud"],
        notes="Cognito user pool authentication vector.",
    ),
    "aws-cognito-access-token": SampleToken(
        id="aws-cognito-access-token",
        name="AWS Cognito Access Token",
        category="Cloud & PaaS",
        description="AWS Cognito OAuth2 bearer access token with client_id and scopes.",
        raw_token=_COGNITO_ACCESS_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ExamplePool",
        known_secret=None,
        tags=["aws", "cognito", "access_token", "rs256"],
        notes="Contains token_use='access' and authorized OAuth scopes.",
    ),
    "okta-access-token": SampleToken(
        id="okta-access-token",
        name="Okta OAuth2 Access Token",
        category="Identity Providers",
        description="Enterprise Okta authorization server access token with scp and uid claims.",
        raw_token=_OKTA_ACCESS_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="https://dev-123456.okta.com/oauth2/default",
        known_secret=None,
        tags=["okta", "enterprise", "rs256", "oauth2"],
        notes="Standard Okta default authorization server token.",
    ),
    "azure-ad-graph-token": SampleToken(
        id="azure-ad-graph-token",
        name="Microsoft Entra ID / Azure AD Access Token",
        category="Identity Providers",
        description="Microsoft Graph API token containing tenant ID ('tid') and application roles.",
        raw_token=_AZURE_AD_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
        known_secret=None,
        tags=["azure", "microsoft", "graph", "rs256"],
        notes="Contains Azure tenant ID and multi-resource roles.",
    ),
    "google-identity-token": SampleToken(
        id="google-identity-token",
        name="Google OIDC Identity Token",
        category="Identity Providers",
        description="Google Sign-In OpenID Connect identity token with azp and email claims.",
        raw_token=_GOOGLE_ID_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="https://accounts.google.com",
        known_secret=None,
        tags=["google", "oidc", "signin", "rs256"],
        notes="Produced by Google OAuth 2.0 Identity services.",
    ),
    "hasura-graphql-jwt": SampleToken(
        id="hasura-graphql-jwt",
        name="Hasura GraphQL Custom Claims Token",
        category="Developer Platforms",
        description="JWT with custom 'https://hasura.io/jwt/claims' namespace for row-level permissions.",
        raw_token=_HASURA_TOKEN,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret="super-secure-hasura-secret-key-that-cannot-be-guessed-easily-12345",
        tags=["hasura", "graphql", "hs256", "custom_claims"],
        notes="Hasura custom permission namespace sample.",
    ),
    "stripe-webhook-jws": SampleToken(
        id="stripe-webhook-jws",
        name="Stripe Webhook Event Signature Token",
        category="E-Commerce & APIs",
        description="Stripe payment webhook verification token containing event metadata.",
        raw_token=_STRIPE_TOKEN,
        expected_algorithm="HS256",
        expected_issuer="stripe",
        known_secret="whsec_test_secret_for_stripe_webhook_signing_verification_key_32bytes",
        tags=["stripe", "payments", "webhook", "hs256"],
        notes="Webhook payload signing vector.",
    ),
    "salesforce-bearer-jwt": SampleToken(
        id="salesforce-bearer-jwt",
        name="Salesforce Connected App Bearer Token",
        category="Enterprise Platforms",
        description="Salesforce OAuth 2.0 JWT bearer token flow for server-to-server integration.",
        raw_token=_SALESFORCE_TOKEN,
        expected_algorithm="RS256",
        expected_issuer="3MVG18vOPagvsbxdVe8xNw123456",
        known_secret=None,
        tags=["salesforce", "crm", "enterprise", "rs256"],
        notes="Salesforce connected app server authentication.",
    ),
    "apple-signin-id-token": SampleToken(
        id="apple-signin-id-token",
        name="Apple Sign-In Identity Token (ES256)",
        category="Identity Providers",
        description="Apple Sign In token signed with Elliptic Curve ECDSA P-256 (ES256).",
        raw_token=_APPLE_TOKEN,
        expected_algorithm="ES256",
        expected_issuer="https://appleid.apple.com",
        known_secret=None,
        tags=["apple", "es256", "ecdsa", "elliptic_curve"],
        notes="Demonstrates ES256 ECDSA algorithm structure.",
    ),
    "shopify-app-bridge-jwt": SampleToken(
        id="shopify-app-bridge-jwt",
        name="Shopify App Bridge Session Token",
        category="E-Commerce & APIs",
        description="Shopify embedded app session token with dest and shop admin issuer.",
        raw_token=_SHOPIFY_TOKEN,
        expected_algorithm="HS256",
        expected_issuer="https://quick-start-app.myshopify.com/admin",
        known_secret="shopify_client_shared_secret_high_entropy_bytes_998877",
        tags=["shopify", "ecommerce", "session", "hs256"],
        notes="Shopify App Bridge embedded authentication.",
    ),
    "twilio-voice-chat-jwt": SampleToken(
        id="twilio-voice-chat-jwt",
        name="Twilio Client Access Token",
        category="Developer Platforms",
        description="Twilio Voice and Chat client token with scoped capability grants.",
        raw_token=_TWILIO_TOKEN,
        expected_algorithm="HS256",
        expected_issuer="MOCK_KEY_ID_1234567890abcdef",
        known_secret="twilio_api_secret_key_32_bytes_of_random_chars_999",
        tags=["twilio", "telephony", "grants", "hs256"],
        notes="Twilio client SDK capability grants vector.",
    ),
    "exploit-alg-none-cve-2015-9235": SampleToken(
        id="exploit-alg-none-cve-2015-9235",
        name="Malicious Algorithm 'none' Bypass Vector (CVE-2015-9235)",
        category="Vulnerabilities & Exploits",
        description="Critical exploit payload with alg='none' and forged admin:true privileges.",
        raw_token=_EXPLOIT_ALG_NONE,
        expected_algorithm="none",
        expected_issuer=None,
        known_secret=None,
        tags=["exploit", "cve-2015-9235", "none_alg", "critical", "bypass"],
        notes="Should trigger CRITICAL risk findings in security linter.",
    ),
    "exploit-kid-path-traversal": SampleToken(
        id="exploit-kid-path-traversal",
        name="Key ID Path Traversal Exploit Vector",
        category="Vulnerabilities & Exploits",
        description="Malicious token targeting /dev/null via 'kid' directory traversal.",
        raw_token=_EXPLOIT_KID_TRAVERSAL,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret="",
        tags=["exploit", "kid", "path_traversal", "critical"],
        notes="Signed against empty bytes simulating /dev/null secret loading.",
    ),
    "exploit-kid-sqli": SampleToken(
        id="exploit-kid-sqli",
        name="Key ID SQL Injection Vector",
        category="Vulnerabilities & Exploits",
        description="Malicious token attempting SQL injection via the 'kid' parameter.",
        raw_token=_EXPLOIT_KID_SQLI,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret=None,
        tags=["exploit", "kid", "sqli", "high_risk"],
        notes="Header parameter injection vector.",
    ),
    "weak-secret-jwt": SampleToken(
        id="weak-secret-jwt",
        name="Weak Secret Test Token ('secret')",
        category="Vulnerabilities & Exploits",
        description="HS256 JWT signed with the trivially crackable dictionary secret 'secret'.",
        raw_token=_WEAK_SECRET_TOKEN,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret="secret",
        tags=["weak_secret", "hs256", "crackable", "dictionary_attack"],
        notes="Should be instantly cracked by the security linter.",
    ),
    "weak-secret-password123": SampleToken(
        id="weak-secret-password123",
        name="Weak Secret Test Token ('password123')",
        category="Vulnerabilities & Exploits",
        description="HS256 JWT signed with common dictionary password 'password123'.",
        raw_token=_WEAK_SECRET_PW123,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret="password123",
        tags=["weak_secret", "hs256", "password123", "crackable"],
        notes="Demonstrates dictionary search on common passwords.",
    ),
    "expired-token-sample": SampleToken(
        id="expired-token-sample",
        name="Expired Token Test Vector",
        category="Edge Cases & Test Vectors",
        description="Valid HS256 token whose expiration timestamp ('exp') is set in the year 2020.",
        raw_token=_EXPIRED_TOKEN,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret="valid-secret-key-but-token-has-already-expired",
        tags=["expired", "exp", "claim_failure"],
        notes="Must fail expiration checks in claims validator.",
    ),
    "future-nbf-sample": SampleToken(
        id="future-nbf-sample",
        name="Future Not-Before ('nbf') Token Vector",
        category="Edge Cases & Test Vectors",
        description="Token with 'nbf' set to year 2035, making it not yet valid.",
        raw_token=_FUTURE_NBF_TOKEN,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret="valid-secret-key-for-future-nbf-validation-vector",
        tags=["nbf", "not_before", "future_token"],
        notes="Must fail not-before validation check.",
    ),
    "pii-leak-sample": SampleToken(
        id="pii-leak-sample",
        name="PII & Credential Leakage Vector",
        category="Vulnerabilities & Exploits",
        description="Token payload containing raw password, Social Security Number (SSN), and credit card number.",
        raw_token=_PII_LEAK_TOKEN,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret="some-secure-signing-secret-for-pii-leak-demo",
        tags=["pii", "credential_leak", "password", "ssn", "credit_card"],
        notes="Triggers sensitive PII detection rules.",
    ),
    "jwe-compact-5part": SampleToken(
        id="jwe-compact-5part",
        name="JWE Compact 5-Part Encrypted Token",
        category="Encrypted Tokens (JWE)",
        description="RFC 7516 5-part JSON Web Encryption token with encrypted key, IV, ciphertext, and auth tag.",
        raw_token=_JWE_SAMPLE_TOKEN,
        expected_algorithm="RSA-OAEP",
        expected_issuer=None,
        known_secret=None,
        tags=["jwe", "encrypted", "5part", "confidentiality"],
        notes="Classified as TokenType.JWE by parser.",
    ),
    "corrupted-format-sample": SampleToken(
        id="corrupted-format-sample",
        name="Corrupted / Malformed Token Vector",
        category="Edge Cases & Test Vectors",
        description="Invalid token string with non-JSON, non-base64 corrupted segment payloads.",
        raw_token=_CORRUPTED_TOKEN,
        expected_algorithm="HS256",
        expected_issuer=None,
        known_secret=None,
        tags=["corrupted", "malformed", "error_handling"],
        notes="Must be caught by parser error handling.",
    ),
}


def get_all_sample_tokens() -> Dict[str, SampleToken]:
    """Retrieve all curated sample tokens indexed by unique ID.

    Returns:
        Dict[str, SampleToken]: Mapping of token ID to SampleToken record.
    """
    return dict(_SAMPLE_TOKENS)


def list_sample_tokens(category: Optional[str] = None) -> List[SampleToken]:
    """List sample tokens with optional category filtering.

    Args:
        category: Optional category name to filter by.

    Returns:
        List[SampleToken]: Matching sample token records.
    """
    if category is None:
        return list(_SAMPLE_TOKENS.values())

    cat_lower = category.strip().lower()
    return [t for t in _SAMPLE_TOKENS.values() if t.category.lower() == cat_lower]


def get_sample_token(token_id: str) -> Optional[SampleToken]:
    """Retrieve a specific sample token by ID.

    Args:
        token_id: Sample token identifier (e.g. 'auth0-standard-jwt').

    Returns:
        Optional[SampleToken]: Sample token object if found, None otherwise.
    """
    if not token_id:
        return None
    return _SAMPLE_TOKENS.get(token_id.strip().lower())


def list_categories() -> List[str]:
    """List all unique sample token categories.

    Returns:
        List[str]: Sorted list of category names.
    """
    categories = {t.category for t in _SAMPLE_TOKENS.values()}
    return sorted(categories)
