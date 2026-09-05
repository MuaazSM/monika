"""Bearer-token parsing.

This decodes the token to identify the caller, but performs NO authorization — the IDOR
and function-level-auth weaknesses depend on routes NOT checking that the caller owns the
resource or holds a role (CLAUDE.md rule 10).
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from .auth import decode_token


def current_claims(request: Request) -> dict[str, Any]:
    """Return JWT claims if a valid bearer token is present; 401 only if absent/invalid."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = header.split(" ", 1)[1].strip()
    try:
        return decode_token(token)
    except Exception as exc:  # noqa: BLE001 - demo API surfaces the reason on purpose
        raise HTTPException(status_code=401, detail="invalid token") from exc
