"""missing indexes: signal(incident_id), request_log(session_key, created_at),
request_log(label, action_applied, created_at)

Implementation-Backend.md Phase 7.1 lists these alongside ix_incident_dedup /
ix_incident_feed / ix_request_log_created_at, which 0002 already created — these three were
missed. signal(incident_id) speeds up the incident-detail signal lookup; the two request_log
composites back the request timeline (session_key, created_at) and the precision panel
(label, action_applied, created_at).

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_index("ix_signal_incident_id", "signal", ["incident_id"])
    op.create_index(
        "ix_request_log_session_created", "request_log", ["session_key", "created_at"]
    )
    op.create_index(
        "ix_request_log_label_action_created",
        "request_log",
        ["label", "action_applied", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_request_log_label_action_created", table_name="request_log")
    op.drop_index("ix_request_log_session_created", table_name="request_log")
    op.drop_index("ix_signal_incident_id", table_name="signal")
