"""Admin listing — no role check (CLAUDE.md rule 10). Any valid token (or, per the
function-level-auth story, any caller reaching it) gets every user row."""

from __future__ import annotations

from fastapi import APIRouter, Request

from ..deps import current_claims

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users")
async def list_all_users(request: Request) -> list[dict[str, object]]:
    """No role check: returns all users regardless of the caller's role."""
    current_claims(request)  # token required, role NOT checked
    pool = request.app.state.pool
    rows = await pool.fetch(
        "SELECT id, username, email, password_hash, ssn, role, balance "
        "FROM demo.users ORDER BY id"
    )
    return [dict(r) for r in rows]
