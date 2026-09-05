"""Bearer-token decoding for the proxy.

Signature IS verified against the shared MONIKA_JWT_SECRET, but business claims are NOT
(an expired token, wrong-audience token, or bad-signature token still forwards — deciding
what to do is a detector's job, not the proxy's). Any failure yields None, never raises.
"""

from __future__ import annotations

from typing import Any, cast

import jwt as _jwt

from ..detection.context import JWTClaims

# `verify_sub=False` mirrors demo-api: the PRD uses an integer `sub`, which pyjwt>=2.10
# would otherwise reject. exp/aud are not checked here on purpose.
_DECODE_OPTIONS = {
    "verify_signature": True,
    "verify_exp": False,
    "verify_aud": False,
    "verify_sub": False,
}


def decode_bearer(authorization: str | None, secret: str) -> JWTClaims | None:
    """Return JWTClaims if a bearer token verifies its signature, else None.

    A malformed/absent token, a bad signature, or missing sub/jti all yield None.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = _jwt.decode(
            token, secret, algorithms=["HS256"], options=cast("Any", _DECODE_OPTIONS)
        )
    except Exception:
        return None
    try:
        return JWTClaims(
            sub=int(payload["sub"]), jti=str(payload["jti"]), role=str(payload.get("role", "user"))
        )
    except (KeyError, ValueError, TypeError):
        return None
