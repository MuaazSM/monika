"""SSE broadcaster: event order, drop-oldest, and disconnect cleanup (PRD §7, §10.1)."""

from __future__ import annotations

import pytest

from app.incidents.sse import Broadcaster, event_source
from app.stats.models import StatsOut


def _stats(n: int) -> StatsOut:
    return StatsOut(
        total_requests=n,
        incidents=0,
        blocked=0,
        endpoints_configured=6,
        precision=None,
        recall=None,
        benign_by_rung={},
    )


class _FakeRequest:
    """Minimal Request stand-in: disconnects after `disconnect_after` checks."""

    def __init__(self, disconnect_after: int) -> None:
        self._checks = 0
        self._limit = disconnect_after

    async def is_disconnected(self) -> bool:
        self._checks += 1
        return self._checks > self._limit


async def test_client_receives_events_in_publish_order() -> None:
    # a client connected BEFORE the events sees created -> updated -> explained, in order.
    b = Broadcaster()
    q = b.subscribe()
    inc = _stats(1)
    b.publish("incident.created", inc)
    b.publish("incident.updated", inc)
    b.publish("incident.explained", inc)

    frames = [q.get_nowait() for _ in range(3)]
    types = [f.split("\n", 1)[0] for f in frames]
    assert types == [
        "event: incident.created",
        "event: incident.updated",
        "event: incident.explained",
    ]


async def test_payload_is_verbatim_model_json() -> None:
    b = Broadcaster()
    q = b.subscribe()
    stats = _stats(42)
    b.publish("stats.tick", stats)
    frame = q.get_nowait()
    data_line = frame.split("\n")[1]
    assert data_line == "data: " + stats.model_dump_json()


async def test_slow_client_drops_oldest() -> None:
    b = Broadcaster(max_queue=3)
    q = b.subscribe()
    for i in range(5):  # publish 5 into a size-3 queue
        b.publish("stats.tick", _stats(i))
    assert q.qsize() == 3
    # oldest (0,1) dropped; newest (2,3,4) retained, in order
    kept = [q.get_nowait() for _ in range(3)]
    totals = [f'"total_requests":{i}' in fr for i, fr in zip((2, 3, 4), kept, strict=True)]
    assert all(totals)


async def test_unknown_event_type_rejected() -> None:
    b = Broadcaster()
    with pytest.raises(ValueError, match="unknown SSE event type"):
        b.publish("bogus.event", _stats(1))


async def test_disconnect_removes_queue() -> None:
    b = Broadcaster()
    req = _FakeRequest(disconnect_after=1)
    gen = event_source(b, req, heartbeat=0.01)  # type: ignore[arg-type]
    # first pull yields the ": connected" preamble and subscribes the client
    first = await gen.__anext__()
    assert first == ": connected\n\n"
    assert b.client_count == 1
    # drain until the generator finishes (request reports disconnected)
    with pytest.raises(StopAsyncIteration):
        for _ in range(10):
            await gen.__anext__()
    assert b.client_count == 0  # queue cleaned up on disconnect


async def test_heartbeat_emitted_when_idle() -> None:
    b = Broadcaster()
    req = _FakeRequest(disconnect_after=5)
    gen = event_source(b, req, heartbeat=0.01)
    await gen.__anext__()  # ": connected"
    frame = await gen.__anext__()  # nothing queued -> heartbeat after timeout
    assert frame == ": heartbeat\n\n"
    await gen.aclose()
