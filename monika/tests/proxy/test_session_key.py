"""session_key derivation and bearer decoding (authed / unauthed / malformed)."""

from __future__ import annotations

import jwt as _jwt

from app.detection.context import JWTClaims, derive_session_key
from app.proxy.jwt import decode_bearer

SECRET = "test-secret"


def _bearer(payload: dict, secret: str = SECRET) -> str:
    return "Bearer " + _jwt.encode(payload, secret, algorithm="HS256")


def test_authed_session_key_is_sub() -> None:
    claims = JWTClaims(sub=742, jti="j", role="user")
    assert derive_session_key(claims, "1.2.3.4") == "742"


def test_unauthed_session_key_is_ip() -> None:
    assert derive_session_key(None, "1.2.3.4") == "ip:1.2.3.4"


def test_decode_valid_token() -> None:
    claims = decode_bearer(_bearer({"sub": 742, "jti": "abc", "role": "admin"}), SECRET)
    assert claims == JWTClaims(sub=742, jti="abc", role="admin")


def test_absent_token_is_none() -> None:
    assert decode_bearer(None, SECRET) is None
    assert decode_bearer("", SECRET) is None
    assert decode_bearer("Basic xyz", SECRET) is None


def test_malformed_token_is_none() -> None:
    assert decode_bearer("Bearer not.a.jwt", SECRET) is None


def test_bad_signature_is_none() -> None:
    # Signed with the wrong secret -> signature fails -> None (still forwarded upstream).
    tok = _bearer({"sub": 1, "jti": "j", "role": "user"}, secret="wrong-secret")
    assert decode_bearer(tok, SECRET) is None


def test_missing_sub_is_none() -> None:
    assert decode_bearer(_bearer({"jti": "j", "role": "user"}), SECRET) is None


def test_expired_token_still_decodes() -> None:
    # Business claims are NOT verified: an expired-but-well-signed token yields claims.
    claims = decode_bearer(_bearer({"sub": 5, "jti": "j", "role": "user", "exp": 1}), SECRET)
    assert claims is not None and claims.sub == 5
