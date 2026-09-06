"""Server-sent events for the dashboard (PRD §7 event list, §10.1 /_monika/events).

In-process asyncio broadcast — a set of per-client bounded Queues (CLAUDE.md rule 8: no
Redis pub/sub, no new service). Event payloads are the pydantic REST models serialized
verbatim, so an event is byte-identical to the corresponding REST GET response. Slow
clients drop their OLDEST queued event rather than growing without bound; the queue is
removed on disconnect so a long demo does not leak memory.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from collections.abc import AsyncIterator

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

# The five event types Monika emits (CLAUDE.md §7).
EVENT_TYPES = frozenset(
    {"incident.created", "incident.updated", "incident.explained", "session.changed", "stats.tick"}
)

MAX_QUEUE = 100  # per-client backlog before we start dropping the oldest event
HEARTBEAT_SECONDS = 15
HISTORY_SIZE = 20  # replayed to a client that connects mid-demo (Implementation-Backend.md 8.1)
router = APIRouter(prefix="/_monika", tags=["sse"])


def _frame(event_type: str, data_json: str) -> str:
    """One SSE frame: an `event:` line and a `data:` line, terminated by a blank line."""
    return f"event: {event_type}\ndata: {data_json}\n\n"


class Broadcaster:
    """Fan-out to every connected SSE client via per-client asyncio Queues.

    Also keeps the last HISTORY_SIZE frames so a client that connects mid-demo (opens the
    dashboard after incidents have already started firing) sees recent history immediately
    instead of a blank feed until the next live event.
    """

    def __init__(self, max_queue: int = MAX_QUEUE, history_size: int = HISTORY_SIZE) -> None:
        self._clients: set[asyncio.Queue[str]] = set()
        self._max_queue = max_queue
        self._history: deque[str] = deque(maxlen=history_size)

    def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=self._max_queue)
        self._clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        self._clients.discard(q)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    @property
    def history(self) -> list[str]:
        """The last (up to) HISTORY_SIZE frames, oldest first."""
        return list(self._history)

    def publish(self, event_type: str, payload: BaseModel) -> None:
        """Serialize the REST model verbatim and enqueue to every client (drop-oldest)."""
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown SSE event type: {event_type}")
        frame = _frame(event_type, payload.model_dump_json())
        self._history.append(frame)
        for q in self._clients:
            if q.full():  # slow client — evict its oldest event, don't grow unbounded
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(frame)


async def event_source(
    broadcaster: Broadcaster, request: Request, heartbeat: float = HEARTBEAT_SECONDS
) -> AsyncIterator[str]:
    """Stream frames for one client; heartbeat comment every `heartbeat`s; clean up on exit."""
    q = broadcaster.subscribe()
    # No `await` between subscribe() and reading .history: on a single-threaded asyncio event
    # loop that makes the pair atomic, so no event can land in neither this snapshot nor the
    # live queue (and none can land in both).
    replay = broadcaster.history
    try:
        yield ": connected\n\n"
        for frame in replay:
            yield frame
        while True:
            if await request.is_disconnected():
                break
            try:
                yield await asyncio.wait_for(q.get(), timeout=heartbeat)
            except TimeoutError:
                yield ": heartbeat\n\n"  # keep proxies from closing an idle stream
    finally:
        broadcaster.unsubscribe(q)
        logger.info("sse.client_disconnected", clients=broadcaster.client_count)


@router.get("/events")
async def events(request: Request) -> StreamingResponse:
    """The SSE endpoint. The dashboard never polls; it consumes this stream."""
    return StreamingResponse(
        event_source(request.app.state.broadcaster, request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
