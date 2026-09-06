"""Control-plane read routes for incidents and sessions (PRD §10.1).

Evidence is returned verbatim (rule 5). The sessions route reads the ladder straight from
Redis (D-04: Redis is authoritative; the SESSION table is audit-only) — `incidents` cannot
import `policy`, so it reads the hash by its documented key.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request

from . import service
from .models import (
    IncidentDetailOut,
    IncidentListOut,
    IncidentOut,
    OverrideOut,
    RequestLogOut,
    SessionStateOut,
    SignalOut,
)

router = APIRouter(prefix="/_monika", tags=["incidents"])


@router.get("/incidents", response_model=IncidentListOut)
async def list_incidents(
    request: Request,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = None,
) -> IncidentListOut:
    """Newest-first incident feed with keyset pagination on (created_at, id)."""
    items, next_cursor = await service.list_incidents(
        request.app.state.session_factory, status=status, limit=limit, cursor=cursor
    )
    return IncidentListOut(
        items=[IncidentOut.model_validate(i) for i in items], next_cursor=next_cursor
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(request: Request, incident_id: UUID) -> IncidentDetailOut:
    """One incident with its signals, overrides and (async) LLM explanation."""
    result = await service.get_incident(request.app.state.session_factory, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="incident not found")
    incident, signals, overrides, timeline = result
    return IncidentDetailOut(
        **IncidentOut.model_validate(incident).model_dump(),
        llm_explanation=incident.llm_explanation,
        llm_next_step=incident.llm_next_step,
        signals=[SignalOut.model_validate(s) for s in signals],
        overrides=[OverrideOut.model_validate(o) for o in overrides],
        request_timeline=[RequestLogOut.model_validate(r) for r in timeline],
    )


@router.get("/sessions/{session_key}", response_model=SessionStateOut)
async def get_session(request: Request, session_key: str) -> SessionStateOut:
    """Current ladder state and score, read from Redis (D-04)."""
    raw = await request.app.state.redis.hgetall(f"ladder:{session_key}")
    return SessionStateOut(
        session_key=session_key,
        state=raw.get("state", "NORMAL"),
        score=int(raw.get("score", 0)),
        last_signal_at=float(raw["last_signal_at"]) if raw.get("last_signal_at") else None,
        signals_5m=int(raw.get("signals_5m", 0)),
    )
