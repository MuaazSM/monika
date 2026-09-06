"""Runtime configuration. Every setting is a MONIKA_* environment variable (CLAUDE.md §6)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Backend settings. Defaults are the docker-compose values from CLAUDE.md §6."""

    model_config = SettingsConfigDict(
        env_prefix="MONIKA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+asyncpg://monika:monika@postgres:5432/monika"

    @field_validator("database_url")
    @classmethod
    def _require_asyncpg_driver(cls, v: str) -> str:
        """Managed Postgres providers (Render, Heroku, ...) hand out bare postgres://
        or postgresql:// DSNs. Both engine.py and alembic/env.py pass this straight to
        SQLAlchemy, which would silently pick the sync psycopg2 driver instead — not
        installed here, and the wrong driver for the async engine either way."""
        for prefix in ("postgres://", "postgresql://"):
            if v.startswith(prefix):
                return "postgresql+asyncpg://" + v[len(prefix) :]
        return v
    redis_url: str = "redis://redis:6379/0"
    upstream_url: str = "http://demo-api:9000"
    jwt_secret: str = "dev-insecure-secret-change-me"

    # Empty API key → explainer disabled, UI shows "unavailable" (rule 1 keeps it advisory only).
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"
    explainer_enabled: bool = True
    # 1 → serve a canned explanation from disk instead of calling the API (demo fallback)
    explainer_fallback: bool = False

    # 10 for demos: ladder decay measured in seconds instead of minutes.
    ladder_time_divisor: int = 1
    rate_floor_rpm: int = 20
    endpoints_config: str = "config/endpoints.yaml"
    # Monika's own base URL, for the Simulator to replay attacks through its own proxy.
    self_url: str = "http://localhost:8000"
    # Comma-separated browser origins allowed to call the control plane (the dashboard).
    cors_origins: str = "http://localhost:3000"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()
