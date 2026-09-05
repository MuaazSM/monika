"""Compatibility surface for the request/response boundary types.

The models now live in `detection.base` (CLAUDE.md §7). This module re-exports them and
keeps `derive_session_key` — the one canonical session-key function everything downstream
imports.
"""

from __future__ import annotations

from .base import JWTClaims, RequestContext, ResponseContext

__all__ = ["JWTClaims", "RequestContext", "ResponseContext", "derive_session_key"]


def derive_session_key(jwt: JWTClaims | None, ip: str) -> str:
    """The one canonical session key: jwt.sub if authenticated, else ``ip:{ip}``.

    Everything downstream (Redis keys, Signal.session_key, incidents) imports THIS.
    """
    if jwt is not None:
        return str(jwt.sub)
    return f"ip:{ip}"
