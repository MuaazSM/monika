"""Public product catalogue that over-exposes internal fields: cost_price and
supplier_margin are returned alongside the public fields (CLAUDE.md rule 10)."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api", tags=["products"])

_PAGE_SIZE = 20


@router.get("/products")
async def list_products(request: Request, page: int = 1) -> dict[str, object]:
    """Paged catalogue. Leaks cost_price and supplier_margin to anonymous callers."""
    pool = request.app.state.pool
    page = max(page, 1)
    offset = (page - 1) * _PAGE_SIZE
    rows = await pool.fetch(
        "SELECT id, name, description, category, price, cost_price, supplier_margin "
        "FROM demo.products ORDER BY id LIMIT $1 OFFSET $2",
        _PAGE_SIZE,
        offset,
    )
    return {"page": page, "page_size": _PAGE_SIZE, "results": [dict(r) for r in rows]}
