"""Incident persistence + dedup (CLAUDE.md rule 7, PRD §9.1).

One incident per (session_key, threat_type, 10-minute window). A new scored request with
score >= 30 updates the matching open incident (risk_score/confidence = max, signals
appended, action_taken = current ladder state) rather than creating a duplicate. Scores
below 30 (SAFE band, §7.2) create nothing.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import Select, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..explainer.job import ExplainerJob
from .models import IncidentRow, OverrideRow, SignalRow
from .threat_type import SignalLike, derive_threat_type

MIN_INCIDENT_SCORE = 30
WINDOW = timedelta(minutes=10)


class IncidentSignal(SignalLike, Protocol):
    """A SignalLike that also carries the request/session/endpoint fields SIGNAL persists."""

    @property
    def request_id(self) -> str: ...

    @property
    def session_key(self) -> str: ...

    @property
    def endpoint_id(self) -> UUID | None: ...


async def record_incident(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    session_key: str,
    endpoint_id: UUID,
    signals: Sequence[IncidentSignal],
    score: int,
    confidence: int,
    action_taken: str,
    now: datetime,
    explainer_queue: asyncio.Queue[ExplainerJob] | None = None,
    endpoint_label: str = "",
) -> tuple[IncidentRow, bool] | None:
    """Create or update the incident for this scored request.

    Returns (incident, created) — created=True on a new row, False on a dedup update — or
    None when the score is below the SAFE band. On a newly-created incident, enqueues an
    ExplainerJob (the incidents ⇢ explainer reach in rule 9) — the score/confidence are
    deliberately NOT included in the job (rule 1).
    """
    if score < MIN_INCIDENT_SCORE:
        return None

    threat_type = derive_threat_type(signals).value
    window_start = now - WINDOW

    async with session_factory() as session:
        existing = (
            await session.execute(
                select(IncidentRow)
                .where(
                    IncidentRow.session_key == session_key,
                    IncidentRow.threat_type == threat_type,
                    IncidentRow.status == "open",
                    IncidentRow.created_at >= window_start,
                )
                .order_by(IncidentRow.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        created = existing is None
        if existing is not None:
            existing.risk_score = max(existing.risk_score, score)
            existing.confidence = max(existing.confidence, confidence)
            existing.action_taken = action_taken
            existing.updated_at = now
            incident = existing
        else:
            incident = IncidentRow(
                id=uuid4(),
                session_key=session_key,
                endpoint_id=endpoint_id,
                threat_type=threat_type,
                risk_score=score,
                confidence=confidence,
                action_taken=action_taken,
                status="open",
                created_at=now,
                updated_at=now,
            )
            session.add(incident)
            await session.flush()

        for s in signals:
            session.add(
                SignalRow(
                    id=uuid4(),
                    incident_id=incident.id,
                    category=s.category,
                    severity=s.severity,
                    evidence=dict(s.evidence),  # stored verbatim (rule 5)
                    request_id=s.request_id,
                    session_key=s.session_key,
                    endpoint_id=s.endpoint_id,
                    created_at=now,
                )
            )
        await session.commit()
        await session.refresh(incident)

    if created and explainer_queue is not None:
        job = ExplainerJob(
            incident_id=incident.id,
            threat_type=threat_type,
            endpoint=endpoint_label,
            signals=[{"category": s.category, "evidence": dict(s.evidence)} for s in signals],
            action_taken=action_taken,
        )
        with contextlib.suppress(asyncio.QueueFull):
            explainer_queue.put_nowait(job)
    return incident, created


# ---- reads (keyset pagination) --------------------------------------------------------


def _encode_cursor(created_at: datetime, incident_id: UUID) -> str:
    raw = f"{created_at.isoformat()}|{incident_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts, iid = raw.rsplit("|", 1)
    return datetime.fromisoformat(ts), UUID(iid)


async def list_incidents(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    status: str | None,
    limit: int,
    cursor: str | None,
) -> tuple[list[IncidentRow], str | None]:
    """Newest-first incidents with keyset pagination on (created_at, id)."""
    stmt = select(IncidentRow).order_by(IncidentRow.created_at.desc(), IncidentRow.id.desc())
    if status is not None:
        stmt = stmt.where(IncidentRow.status == status)
    if cursor is not None:
        ca, iid = _decode_cursor(cursor)
        # (created_at, id) < (ca, iid) — expanded for cross-dialect portability.
        stmt = stmt.where(
            or_(
                IncidentRow.created_at < ca,
                (IncidentRow.created_at == ca) & (IncidentRow.id < iid),
            )
        )
    rows = await _run(session_factory, stmt.limit(limit + 1))
    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = _encode_cursor(items[-1].created_at, items[-1].id) if has_more and items else None
    return items, next_cursor


async def _run(
    session_factory: async_sessionmaker[AsyncSession], stmt: Select[tuple[IncidentRow]]
) -> list[IncidentRow]:
    async with session_factory() as session:
        return list((await session.execute(stmt)).scalars().all())


async def get_incident(
    session_factory: async_sessionmaker[AsyncSession], incident_id: UUID
) -> tuple[IncidentRow, list[SignalRow], list[OverrideRow]] | None:
    """One incident with its signals and overrides (ordered by created_at)."""
    async with session_factory() as session:
        incident = (
            await session.execute(select(IncidentRow).where(IncidentRow.id == incident_id))
        ).scalar_one_or_none()
        if incident is None:
            return None
        signals = list(
            (
                await session.execute(
                    select(SignalRow)
                    .where(SignalRow.incident_id == incident_id)
                    .order_by(SignalRow.created_at)
                )
            ).scalars()
        )
        overrides = list(
            (
                await session.execute(
                    select(OverrideRow)
                    .where(OverrideRow.incident_id == incident_id)
                    .order_by(OverrideRow.created_at)
                )
            ).scalars()
        )
        return incident, signals, overrides
