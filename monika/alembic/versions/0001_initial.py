"""initial — no tables

Establishes the migration chain so `alembic upgrade head` is a no-op until T8 adds
INCIDENT / SIGNAL / OVERRIDE / REQUEST_LOG / SESSION / ENDPOINT_CONFIG.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

revision: str = "0001"
down_revision: str | None = None
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
