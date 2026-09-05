"""Explainer worker: writes on success, nulls on timeout, no-op on empty key (PRD §10.5)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.explainer.job import ExplainerJob
from app.explainer.worker import ExplainerWorker
from app.incidents import models as _models  # noqa: F401
from app.incidents.models import EndpointConfigRow, IncidentRow, SessionRow
from app.settings import Settings

PROSE = (
    "One session read records it does not own, the signature of a BOLA sweep. "
    "The sequential ids indicate enumeration.\nNext step: review the session's access."
)
EID = uuid4()
SK = "742"


@pytest.fixture
async def sf():
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _seed_incident(sf) -> IncidentRow:
    async with sf() as s:
        s.add(
            EndpointConfigRow(
                id=EID,
                method="GET",
                path_pattern="/api/users/{id}",
                sensitive_fields=[],
                auth_required=True,
                admin_only=False,
            )
        )
        s.add(SessionRow(session_key=SK, ladder_state="BLOCK", current_score=95))
        inc = IncidentRow(
            id=uuid4(),
            session_key=SK,
            endpoint_id=EID,
            threat_type="BOLA_ENUMERATION",
            risk_score=95,
            confidence=70,
            action_taken="BLOCK",
            status="open",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        s.add(inc)
        await s.commit()
        await s.refresh(inc)
        return inc


def _job(incident_id) -> ExplainerJob:
    return ExplainerJob(
        incident_id=incident_id,
        threat_type="BOLA_ENUMERATION",
        endpoint="GET /api/users/{id}",
        signals=[{"category": "auth", "evidence": {"jwt_sub": 742}}],
        action_taken="BLOCK",
    )


class _Recorder:
    def __init__(self) -> None:
        self.ids: list = []

    async def __call__(self, incident_id) -> None:
        self.ids.append(incident_id)


class _FakeClient:
    def __init__(self, text=None, exc=None):
        self._text, self._exc = text, exc

    async def explain(self, job):
        if self._exc:
            raise self._exc
        return self._text


async def _explanation(sf, incident_id):
    async with sf() as s:
        row = (
            await s.execute(select(IncidentRow).where(IncidentRow.id == incident_id))
        ).scalar_one()
        return row.llm_explanation, row.llm_next_step


async def test_success_writes_both_fields_and_publishes(sf) -> None:
    inc = await _seed_incident(sf)
    rec = _Recorder()
    worker = ExplainerWorker(Settings(anthropic_api_key="k"), sf, _FakeClient(text=PROSE), rec)
    await worker.handle(_job(inc.id))
    expl, nxt = await _explanation(sf, inc.id)
    assert expl.startswith("One session")
    assert nxt == "review the session's access."
    assert rec.ids == [inc.id]  # incident.explained emitted


async def test_timeout_leaves_both_null_incident_readable(sf) -> None:
    inc = await _seed_incident(sf)
    worker = ExplainerWorker(
        Settings(anthropic_api_key="k"), sf, _FakeClient(exc=TimeoutError()), _Recorder()
    )
    await worker.handle(_job(inc.id))
    expl, nxt = await _explanation(sf, inc.id)
    assert expl is None and nxt is None  # unavailable, but the incident still reads fine


async def test_empty_api_key_never_calls_out(sf) -> None:
    inc = await _seed_incident(sf)
    calls = {"n": 0}

    class _Counting:
        async def explain(self, job):
            calls["n"] += 1
            return PROSE

    # create_client returns None for an empty key; simulate that: client=None
    worker = ExplainerWorker(Settings(anthropic_api_key=""), sf, None, _Recorder())
    await worker.handle(_job(inc.id))
    expl, _ = await _explanation(sf, inc.id)
    assert expl is None
    assert calls["n"] == 0  # never constructed/called


async def test_output_guard_nulls_confidence_response(sf) -> None:
    inc = await _seed_incident(sf)
    bad = "This is a sweep. confidence: 87\nNext step: review."
    worker = ExplainerWorker(
        Settings(anthropic_api_key="k"), sf, _FakeClient(text=bad), _Recorder()
    )
    await worker.handle(_job(inc.id))
    expl, nxt = await _explanation(sf, inc.id)
    assert expl is None and nxt is None  # guard rejected -> left null


async def test_fallback_serves_canned_explanation(sf) -> None:
    inc = await _seed_incident(sf)
    rec = _Recorder()
    worker = ExplainerWorker(Settings(anthropic_api_key="", explainer_fallback=True), sf, None, rec)
    await worker.handle(_job(inc.id))
    expl, _ = await _explanation(sf, inc.id)
    assert expl and "authorization" in expl.lower()  # canned IDOR text used, no API call
    assert rec.ids == [inc.id]
