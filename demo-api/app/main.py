"""Demo API — deliberately vulnerable target on port 9000 (CLAUDE.md rule 10).

Never add ownership checks, role checks, rate limits, parameterised queries in /api/search,
lockout, or output filtering. The weaknesses are the product.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import create_pool, ensure_schema
from .routes import admin, auth, products, search, transfer, users


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open the asyncpg pool and ensure the demo schema exists."""
    pool = await create_pool()
    await ensure_schema(pool)
    app.state.pool = pool
    try:
        yield
    finally:
        await pool.close()


def create_app() -> FastAPI:
    app = FastAPI(title="demo-api", version="1.0.0", lifespan=lifespan)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(search.router)
    app.include_router(admin.router)
    app.include_router(products.router)
    app.include_router(transfer.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
