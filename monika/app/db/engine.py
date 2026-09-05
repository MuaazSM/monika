"""SQLAlchemy 2.x async engine construction."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


def create_engine(database_url: str) -> AsyncEngine:
    """Build the async engine used for the whole process lifetime."""
    return create_async_engine(database_url, pool_pre_ping=True, future=True)


async def check_connectivity(engine: AsyncEngine) -> bool:
    """Run `SELECT 1`; return False on any driver or connection error."""
    from sqlalchemy import text

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        return False
    return True
