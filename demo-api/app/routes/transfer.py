"""Money transfer — no idempotency key, no amount cap, no balance check
(CLAUDE.md rule 10). Per docs/DECISIONS.md D-11 this route is intentionally
UNMONITORED: no Monika detector covers it, and the README lists it as known-uncovered."""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from ..deps import current_claims

router = APIRouter(prefix="/api", tags=["transfer"])


class TransferBody(BaseModel):
    to_user_id: int
    amount: float


@router.post("/transfer")
async def transfer(body: TransferBody, request: Request) -> dict[str, object]:
    """Move money with no idempotency, no cap, and no balance check."""
    claims = current_claims(request)
    from_id = int(claims["sub"])
    pool = request.app.state.pool
    async with pool.acquire() as conn:
        # No balance check: the sender can go negative. No cap: any amount.
        await conn.execute(
            "UPDATE demo.users SET balance = balance - $1 WHERE id = $2",
            body.amount,
            from_id,
        )
        await conn.execute(
            "UPDATE demo.users SET balance = balance + $1 WHERE id = $2",
            body.amount,
            body.to_user_id,
        )
    return {
        "from": from_id,
        "to": body.to_user_id,
        "amount": body.amount,
        "status": "ok",
    }
