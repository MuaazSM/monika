"""User + order reads. Both are IDOR: a valid token is required, but ownership is NEVER
checked, so any authenticated user can read any other user's full row (including
password_hash and ssn) and their orders (CLAUDE.md rule 10)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..deps import current_claims

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/{user_id}")
async def get_user(user_id: int, request: Request) -> dict[str, object]:
    """IDOR: returns the FULL row for any id — password_hash and ssn included."""
    current_claims(request)  # authenticated, but we never compare to user_id
    pool = request.app.state.pool
    row = await pool.fetchrow(
        "SELECT id, username, email, password_hash, ssn, role, balance "
        "FROM demo.users WHERE id = $1",
        user_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@router.get("/{user_id}/orders")
async def get_orders(user_id: int, request: Request) -> list[dict[str, object]]:
    """IDOR: returns any user's orders, user_id included."""
    current_claims(request)  # again: no ownership check
    pool = request.app.state.pool
    rows = await pool.fetch(
        "SELECT id, user_id, item, amount, status FROM demo.orders "
        "WHERE user_id = $1 ORDER BY id",
        user_id,
    )
    return [dict(r) for r in rows]
