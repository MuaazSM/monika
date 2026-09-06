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
    # True until every configured endpoint has >= 30 samples (detection.baselines.
    # baselines_ready) — the dashboard's "Learning" badge (CLAUDE.md §11.2 demo checklist).
    learning: bool = False
    # False when MONIKA_ANTHROPIC_API_KEY is empty and no fallback is configured — mirrors
    # ExplainerWorker._raw_explanation's no-op conditions exactly (CLAUDE.md §6).
    explainer_available: bool = False
