"""full PRD §9 data model (T8)

Single migration creating every table in the §9 model, incl. ATTACK_PLAN (Tier 3) so the
whole schema ships at once. Replaces the earlier per-table scaffolding migrations.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: None = None
depends_on: None = None

_UUID = postgresql.UUID(as_uuid=True)
_JSONB = postgresql.JSONB()
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "endpoint_config",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("path_pattern", sa.String(), nullable=False),
        sa.Column("owner_field", sa.String(), nullable=True),
        sa.Column("id_param", sa.String(), nullable=True),
        sa.Column("sensitive_fields", _JSONB, nullable=False, server_default="[]"),
        sa.Column("baseline_rpm_mean", sa.Float(), nullable=False, server_default="0"),
        sa.Column("baseline_rpm_std", sa.Float(), nullable=False, server_default="0"),
        sa.Column("baseline_resp_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("auth_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("admin_only", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "session",
        sa.Column("session_key", sa.String(), primary_key=True),
        sa.Column("ladder_state", sa.String(), nullable=False),
        sa.Column("current_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_signal_at", _TS, nullable=True),
        sa.Column("state_changed_at", _TS, nullable=True),
    )

    op.create_table(
        "incident",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("session_key", sa.String(), sa.ForeignKey("session.session_key"), nullable=False),
        sa.Column(
            "endpoint_id", _UUID, sa.ForeignKey("endpoint_config.id"), nullable=False
        ),
        sa.Column("threat_type", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("action_taken", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("llm_explanation", sa.Text(), nullable=True),
        sa.Column("llm_next_step", sa.Text(), nullable=True),
        sa.Column("created_at", _TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", _TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_incident_dedup", "incident", ["session_key", "threat_type", "created_at"]
    )
    op.create_index("ix_incident_feed", "incident", [sa.text("created_at DESC")])

    op.create_table(
        "signal",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("incident_id", _UUID, sa.ForeignKey("incident.id"), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("evidence", _JSONB, nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("session_key", sa.String(), nullable=False),  # D-07
        sa.Column("endpoint_id", _UUID, nullable=True),  # D-07 (denormalised, no FK)
        sa.Column("created_at", _TS, nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "override",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("incident_id", _UUID, sa.ForeignKey("incident.id"), nullable=False),
        sa.Column("analyst", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", _TS, nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "request_log",
        sa.Column("request_id", sa.String(), primary_key=True),
        sa.Column("session_key", sa.String(), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("resp_bytes", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("action_applied", sa.String(), nullable=False, server_default="allow"),
        sa.Column("label", sa.String(), nullable=True),  # D-06
        sa.Column("created_at", _TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_request_log_created_at", "request_log", ["created_at"])

    op.create_table(
        "attack_plan",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("target_endpoint", sa.String(), nullable=False),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("steps", _JSONB, nullable=False, server_default="[]"),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("last_result", sa.String(), nullable=True),
        sa.Column("created_at", _TS, nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("attack_plan")
    op.drop_index("ix_request_log_created_at", table_name="request_log")
    op.drop_table("request_log")
    op.drop_table("override")
    op.drop_table("signal")
    op.drop_index("ix_incident_feed", table_name="incident")
    op.drop_index("ix_incident_dedup", table_name="incident")
    op.drop_table("incident")
    op.drop_table("session")
    op.drop_table("endpoint_config")
