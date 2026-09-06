"""SQLAlchemy models — the full PRD §9 data model (T8).

Column names/types follow §9 exactly. Cross-dialect types (Uuid, JSON) are used so the
model metadata builds on both Postgres (real) and SQLite (unit tests); the single Alembic
migration uses the Postgres-native UUID/JSONB.

DECISIONS.md: REQUEST_LOG.label (D-06); SIGNAL.session_key + endpoint_id (D-07);
ENDPOINT_CONFIG.admin_only (D-10).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base

# JSONB on Postgres (matches the migration and §9), generic JSON on the SQLite test harness.
_JSON = JSON().with_variant(JSONB(), "postgresql")


class EndpointConfigRow(Base):
    """ENDPOINT_CONFIG. Config is yaml-driven; the baseline_* columns are a display
    snapshot refreshed on baseline write (D-03) and never read by a detector."""

    __tablename__ = "endpoint_config"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True)
    method: Mapped[str] = mapped_column(String, nullable=False)
    path_pattern: Mapped[str] = mapped_column(String, nullable=False)
    owner_field: Mapped[str | None] = mapped_column(String, nullable=True)
    id_param: Mapped[str | None] = mapped_column(String, nullable=True)
    sensitive_fields: Mapped[list[str]] = mapped_column(_JSON, nullable=False, default=list)
    baseline_rpm_mean: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    baseline_rpm_std: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    baseline_resp_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    auth_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    admin_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SessionRow(Base):
    """SESSION (D-04). Written on every ladder change for audit/dashboard; Redis
    ladder:{session_key} is authoritative and the proxy never reads this table."""

    __tablename__ = "session"

    session_key: Mapped[str] = mapped_column(String, primary_key=True)
    ladder_state: Mapped[str] = mapped_column(String, nullable=False)
    current_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_signal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    state_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class IncidentRow(Base):
    """INCIDENT. One per (session_key, threat_type, 10-min window) — rule 7. The
    llm_* columns are written asynchronously by the explainer, after the decision."""

    __tablename__ = "incident"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    session_key: Mapped[str] = mapped_column(
        String, ForeignKey("session.session_key"), nullable=False
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("endpoint_config.id"), nullable=False
    )
    threat_type: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    action_taken: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="open")
    llm_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_next_step: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        # dedup lookup (rule 7): find the open incident for this session+threat+window
        Index("ix_incident_dedup", "session_key", "threat_type", "created_at"),
        # incident feed, newest first
        Index("ix_incident_feed", created_at.desc()),
    )


class SignalRow(Base):
    """SIGNAL. session_key + endpoint_id are denormalised on purpose (D-07): signals are
    queried by session during triage, and the incident FK alone can't answer that."""

    __tablename__ = "signal"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("incident.id"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[dict[str, object]] = mapped_column(_JSON, nullable=False)
    request_id: Mapped[str] = mapped_column(String, nullable=False)
    session_key: Mapped[str] = mapped_column(String, nullable=False)  # D-07
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(), nullable=True)  # D-07
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OverrideRow(Base):
    """OVERRIDE. Audit rows — never deleted (rule 6)."""

    __tablename__ = "override"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("incident.id"), nullable=False
    )
    analyst: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RequestLog(Base):
    """REQUEST_LOG. One row per proxied request. label (D-06) feeds the precision panel;
    action_applied is the enforcement actually applied."""

    __tablename__ = "request_log"

    request_id: Mapped[str] = mapped_column(String, primary_key=True)
    session_key: Mapped[str] = mapped_column(String, nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False)
    path: Mapped[str] = mapped_column(String, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    resp_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    action_applied: Mapped[str] = mapped_column(String, nullable=False, default="allow")
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # precision window: "over the last 30 minutes" (§10.4)
        Index("ix_request_log_created_at", "created_at"),
        # incident-detail request timeline: last 50 rows for one session
        Index("ix_request_log_session_created", "session_key", "created_at"),
        # precision panel: attack-labelled rows that reached >= RATE_LIMIT
        Index("ix_request_log_label_action_created", "label", "action_applied", "created_at"),
    )


class AttackPlanRow(Base):
    """ATTACK_PLAN (Tier 3). Created now so the whole model ships in one migration."""

    __tablename__ = "attack_plan"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    target_endpoint: Mapped[str] = mapped_column(String, nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    steps: Mapped[list[object]] = mapped_column(_JSON, nullable=False, default=list)
    source: Mapped[str] = mapped_column(String, nullable=False)
    last_result: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# --------------------------------------------------------------------------------------
# API response models (pydantic). Evidence is returned VERBATIM (rule 5) — never reshaped.
# --------------------------------------------------------------------------------------

from pydantic import BaseModel, ConfigDict  # noqa: E402


class SignalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    category: str
    severity: int
    evidence: dict[str, object]  # raw keys, rendered as-is by the dashboard
    request_id: str
    session_key: str
    endpoint_id: uuid.UUID | None
    created_at: datetime


class OverrideOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    analyst: str
    action: str
    reason: str
    created_at: datetime


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_key: str
    endpoint_id: uuid.UUID
    threat_type: str
    risk_score: int
    confidence: int
    action_taken: str
    status: str
    created_at: datetime
    updated_at: datetime


class RequestLogOut(BaseModel):
    """One REQUEST_LOG row, as rendered in the incident detail's request timeline
    (Implementation-Backend.md Phase 7.1, PRD §10.3 "REQUEST TIMELINE")."""

    model_config = ConfigDict(from_attributes=True)

    request_id: str
    method: str
    path: str
    status_code: int
    resp_bytes: int
    latency_ms: int
    action_applied: str
    label: str | None
    created_at: datetime


class IncidentDetailOut(IncidentOut):
    llm_explanation: str | None
    llm_next_step: str | None
    signals: list[SignalOut]
    overrides: list[OverrideOut]
    # Last 50 REQUEST_LOG rows for this incident's session, oldest first — lets the dashboard
    # show 200s turning into 401/403/429 as the ladder escalates (PRD §10.3, §13.1).
    request_timeline: list[RequestLogOut]


class IncidentListOut(BaseModel):
    items: list[IncidentOut]
    next_cursor: str | None


class SessionStateOut(BaseModel):
    session_key: str
    state: str
    score: int
    last_signal_at: float | None
    signals_5m: int
