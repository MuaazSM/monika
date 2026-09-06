"""Stats endpoint (PRD §10.1). Same StatsOut the SSE stats.tick event carries."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request

from ..settings import get_settings
from . import service
from .models import StatsOut

router = APIRouter(prefix="/_monika", tags=["stats"])


@router.get("/stats", response_model=StatsOut)
async def get_stats(request: Request) -> StatsOut:
    # admin_only endpoints never accumulate baseline samples (DECISIONS.md D-12: the
    # learning-phase traffic-gen deliberately skips them) — exclude them from the
    # readiness check or `learning` would never clear.
    endpoint_ids = [
        ep.endpoint_id for ep in request.app.state.endpoints.endpoints if not ep.admin_only
    ]
    settings = get_settings()
    return await service.compute_stats(
        request.app.state.session_factory,
        now=datetime.now(UTC),
        redis=request.app.state.redis,
        endpoint_ids=endpoint_ids,
        explainer_available=settings.explainer_enabled
        and (settings.explainer_fallback or bool(settings.anthropic_api_key)),
    )
