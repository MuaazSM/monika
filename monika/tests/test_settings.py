"""database_url normalizes to the asyncpg driver regardless of the DSN scheme a managed
Postgres provider (Render, Heroku, ...) hands out."""

from __future__ import annotations

from app.settings import Settings


def test_database_url_adds_asyncpg_driver_to_bare_postgres_scheme() -> None:
    settings = Settings(database_url="postgres://u:p@host/db")

    assert settings.database_url == "postgresql+asyncpg://u:p@host/db"


def test_database_url_adds_asyncpg_driver_to_bare_postgresql_scheme() -> None:
    settings = Settings(database_url="postgresql://u:p@host/db")

    assert settings.database_url == "postgresql+asyncpg://u:p@host/db"


def test_database_url_left_unchanged_when_driver_already_specified() -> None:
    settings = Settings(database_url="postgresql+asyncpg://u:p@host/db")

    assert settings.database_url == "postgresql+asyncpg://u:p@host/db"
