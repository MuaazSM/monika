"""Product search — string-concatenated SQL (CLAUDE.md rule 10).

The query is built by f-string interpolation into a raw SQL statement with NO
parameterisation. This is genuinely injectable:
  ?q=' OR '1'='1                          -> returns every product
  ?q=' UNION SELECT id,username,email,ssn,0,0,0 FROM demo.users --  -> exfiltrates users
Do not 'fix' this to a bound parameter.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api", tags=["search"])


@router.get("/search")
async def search(q: str, request: Request) -> dict[str, object]:
    """Search products by name. Deliberately vulnerable to SQL injection."""
    pool = request.app.state.pool
    # VULNERABLE ON PURPOSE: q is concatenated straight into the SQL text.
    sql = (
        "SELECT id, name, description, category, price, cost_price, supplier_margin "
        f"FROM demo.products WHERE name ILIKE '%{q}%'"
    )
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql)
    return {"query": q, "count": len(rows), "results": [dict(r) for r in rows]}
