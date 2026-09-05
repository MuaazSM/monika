"""Login and step-up.

/api/login is the enumeration vector: unknown-user and wrong-password return DISTINCT
messages, and there is no lockout. /api/step-up is the one correct route (used by the
CHALLENGE rung) — it still returns a single generic error.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..auth import issue_token, verify_password

router = APIRouter(prefix="/api", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(body: LoginBody, request: Request) -> dict[str, object]:
    """Issue a 30-minute token. No lockout; distinct errors leak which usernames exist."""
    pool = request.app.state.pool
    row = await pool.fetchrow(
        "SELECT id, role, password_hash FROM demo.users WHERE username = $1",
        body.username,
    )
    if row is None:
        # Enumeration weakness: tells the caller the username is unknown.
        raise HTTPException(status_code=401, detail="unknown user")
    if not verify_password(body.password, row["password_hash"]):
        # ...and distinguishes a wrong password from an unknown user.
        raise HTTPException(status_code=401, detail="incorrect password")

    token = issue_token(sub=row["id"], role=row["role"], ttl_minutes=30)
    return {"access_token": token, "token_type": "bearer", "expires_in": 1800}


@router.post("/step-up")
async def step_up(body: LoginBody, request: Request) -> dict[str, object]:
    """Correct behaviour: re-verify the password, issue a fresh 5-minute token."""
    pool = request.app.state.pool
    row = await pool.fetchrow(
        "SELECT id, role, password_hash FROM demo.users WHERE username = $1",
        body.username,
    )
    if row is None or not verify_password(body.password, row["password_hash"]):
        # Single generic error — the correct-behaviour route does not enumerate.
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = issue_token(sub=row["id"], role=row["role"], ttl_minutes=5)
    return {"access_token": token, "token_type": "bearer", "expires_in": 300}
