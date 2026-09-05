"""Stats endpoint (PRD §10.1). Same StatsOut the SSE stats.tick event carries."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request

from . import service
from .models import StatsOut

router = APIRouter(prefix="/_monika", tags=["stats"])


@router.get("/stats", response_model=StatsOut)
async def get_stats(request: Request) -> StatsOut:
    return await service.compute_stats(request.app.state.session_factory, now=datetime.now(UTC))
