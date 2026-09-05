"""Demo-api configuration. JWT secret is shared with monika via MONIKA_JWT_SECRET."""

from __future__ import annotations

import os

# asyncpg DSN (NOT the SQLAlchemy +asyncpg form). Same Postgres instance as monika.
DATABASE_URL = os.environ.get(
    "DEMO_API_DATABASE_URL", "postgresql://monika:monika@postgres:5432/monika"
)
# Shared with monika so it can verify the tokens this API issues.
JWT_SECRET = os.environ.get("MONIKA_JWT_SECRET", "dev-insecure-secret-change-me")
JWT_ALG = "HS256"
