"""Incident dedup + window + SAFE-band behaviour (rule 7, §7.2, §9.1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.incidents.models import IncidentRow, SignalRow
from app.incidents.service import record_incident
from tests.incidents.conftest import ENDPOINT_ID, SESSION_KEY, Sig

T0 = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


async def _count(sf, model) -> int:
    async with sf() as s:
        return (await s.execute(select(func.count()).select_from(model))).scalar_one()


async def _kwargs(**over):
    base = dict(
        session_key=SESSION_KEY,
        endpoint_id=ENDPOINT_ID,
        score=71,
        confidence=85,
        action_taken="RATE_LIMIT",
        now=T0,
    )
    base.update(over)
    return base


async def test_two_signals_same_window_one_incident_max_score(session_factory) -> None:
    # request 1: one auth signal -> BOLA_ENUMERATION
    await record_incident(
        session_factory,
        signals=[Sig("auth", 85, evidence={"jwt_sub": 742})],
        **await _kwargs(score=71, confidence=85, now=T0),
    )
    # request 2: same threat_type (auth), higher score, 3 min later -> updates, no new row
    await record_incident(
        session_factory,
        signals=[Sig("auth", 88, evidence={"jwt_sub": 742})],
        **await _kwargs(score=88, confidence=90, now=T0 + timedelta(minutes=3)),
    )
    assert await _count(session_factory, IncidentRow) == 1
    async with session_factory() as s:
        inc = (await s.execute(select(IncidentRow))).scalar_one()
        assert inc.risk_score == 88  # max(71, 88)
        assert inc.confidence == 90  # max(85, 90)
        assert inc.action_taken == "RATE_LIMIT"
    assert await _count(session_factory, SignalRow) == 2  # both requests' signals appended


async def test_same_threat_11_minutes_later_second_incident(session_factory) -> None:
    await record_incident(
        session_factory, signals=[Sig("auth", 85), Sig("enum", 60)], **await _kwargs(now=T0)
    )
    await record_incident(
        session_factory,
        signals=[Sig("auth", 85), Sig("enum", 60)],
        **await _kwargs(now=T0 + timedelta(minutes=11)),
    )
    assert await _count(session_factory, IncidentRow) == 2  # window expired


async def test_different_threat_same_window_second_incident(session_factory) -> None:
    await record_incident(
        session_factory, signals=[Sig("auth", 85), Sig("enum", 60)], **await _kwargs(now=T0)
    )  # BOLA_ENUMERATION
    await record_incident(
        session_factory,
        signals=[Sig("payload", 80)],
        **await _kwargs(now=T0 + timedelta(minutes=2)),
    )  # SQL_INJECTION
    assert await _count(session_factory, IncidentRow) == 2


async def test_score_29_creates_no_incident(session_factory) -> None:
    result = await record_incident(
        session_factory, signals=[Sig("auth", 29)], **await _kwargs(score=29, now=T0)
    )
    assert result is None
    assert await _count(session_factory, IncidentRow) == 0
    assert await _count(session_factory, SignalRow) == 0
