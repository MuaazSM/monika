"""Async session factory."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to the process engine."""
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
