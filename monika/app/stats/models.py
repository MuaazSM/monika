"""Stats response model (PRD §10.3 tiles + §10.4 precision panel)."""

from __future__ import annotations

from pydantic import BaseModel


class StatsOut(BaseModel):
    # header tiles (§10.3)
    total_requests: int
    incidents: int
    blocked: int
    endpoints_configured: int
    # precision panel (§10.4), over the last `window_minutes`
    precision: float | None  # null (not 0) when no request reached >= RATE_LIMIT
    recall: float | None  # null (not 0) when no attack scenario ran
    benign_by_rung: dict[str, int]  # benign requests per ladder rung reached
    window_minutes: int = 30
