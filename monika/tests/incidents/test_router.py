"""Incident/session REST routes, incl. keyset pagination without duplicates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.incidents.service import record_incident
from tests.incidents.conftest import ENDPOINT_ID, SESSION_KEY, Sig

T0 = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


async def _seed_incidents(sf, n: int) -> None:
    # n distinct incidents: distinct threat_types / windows so each is its own row
    threats = [
        ([Sig("auth", 85), Sig("enum", 60)], "a"),
        ([Sig("payload", 80)], "b"),
        ([Sig("exposure", 70)], "c"),
    ]
    for i in range(n):
        sigs, _ = threats[i % len(threats)]
        await record_incident(
            sf,
            session_key=SESSION_KEY,
            endpoint_id=ENDPOINT_ID,
            signals=sigs,
            score=71,
            confidence=85,
            action_taken="RATE_LIMIT",
            now=T0 + timedelta(minutes=15 * i),  # separate windows -> distinct incidents
        )


async def test_detail_returns_signals_and_verbatim_evidence(session_factory, client) -> None:
    await record_incident(
        session_factory,
        session_key=SESSION_KEY,
        endpoint_id=ENDPOINT_ID,
        signals=[Sig("auth", 85, evidence={"jwt_sub": 742, "object_owner": 701})],
        score=85,
        confidence=85,
        action_taken="BLOCK",
        now=T0,
    )
    feed = (await client.get("/_monika/incidents")).json()
    incident_id = feed["items"][0]["id"]
    detail = (await client.get(f"/_monika/incidents/{incident_id}")).json()
    assert detail["threat_type"] == "BOLA_ENUMERATION"
    assert len(detail["signals"]) == 1
    # evidence returned verbatim — keys unchanged (rule 5)
    assert detail["signals"][0]["evidence"] == {"jwt_sub": 742, "object_owner": 701}
    assert detail["overrides"] == []


async def test_status_filter(session_factory, client) -> None:
    await _seed_incidents(session_factory, 3)
    resp = (await client.get("/_monika/incidents?status=open")).json()
    assert len(resp["items"]) == 3
    assert (await client.get("/_monika/incidents?status=closed")).json()["items"] == []


async def test_keyset_pagination_no_duplicates(session_factory, client) -> None:
    await _seed_incidents(session_factory, 9)
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        url = "/_monika/incidents?limit=4" + (f"&cursor={cursor}" if cursor else "")
        page = (await client.get(url)).json()
        seen.extend(i["id"] for i in page["items"])
        pages += 1
        cursor = page["next_cursor"]
        if cursor is None:
            break
        assert pages < 10  # guard against loops
    assert len(seen) == 9
    assert len(set(seen)) == 9  # no duplicates across pages
    # newest first: created_at strictly non-increasing
    feed = (await client.get("/_monika/incidents?limit=100")).json()
    times = [i["created_at"] for i in feed["items"]]
    assert times == sorted(times, reverse=True)


async def test_detail_includes_request_timeline_oldest_first(session_factory, client) -> None:
    from app.incidents.models import RequestLog

    await record_incident(
        session_factory,
        session_key=SESSION_KEY,
        endpoint_id=ENDPOINT_ID,
        signals=[Sig("auth", 85)],
        score=85,
        confidence=85,
        action_taken="BLOCK",
        now=T0,
    )
    async with session_factory() as s:
        for i, (status, action) in enumerate([(200, "allow"), (429, "rate_limit"), (403, "block")]):
            s.add(
                RequestLog(
                    request_id=f"r{i}",
                    session_key=SESSION_KEY,
                    method="GET",
                    path="/api/users/701",
                    status_code=status,
                    resp_bytes=100,
                    latency_ms=5,
                    action_applied=action,
                    label="attack:idor",
                    created_at=T0 + timedelta(seconds=i),
                )
            )
        await s.commit()

    feed = (await client.get("/_monika/incidents")).json()
    incident_id = feed["items"][0]["id"]
    detail = (await client.get(f"/_monika/incidents/{incident_id}")).json()
    timeline = detail["request_timeline"]
    assert len(timeline) == 3
    assert [row["status_code"] for row in timeline] == [200, 429, 403]  # oldest first
    assert [row["action_applied"] for row in timeline] == ["allow", "rate_limit", "block"]


async def test_session_route_reads_redis(session_factory, client, app) -> None:
    await app.state.redis.hset(
        "ladder:742",
        mapping={
            "state": "BLOCK",
            "score": 95,
            "last_signal_at": 1000.0,
            "changed_at": 1000.0,
            "signals_5m": 3,
        },
    )
    resp = (await client.get("/_monika/sessions/742")).json()
    assert resp["state"] == "BLOCK"
    assert resp["score"] == 95
    assert resp["signals_5m"] == 3
