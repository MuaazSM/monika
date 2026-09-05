"""The explainer's input — deliberately excludes the risk score and confidence (rule 1:
the model never sees the numbers that drove the decision)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel


class ExplainerJob(BaseModel):
    incident_id: UUID
    threat_type: str
    endpoint: str
    signals: list[dict[str, object]]  # [{"category": ..., "evidence": {...}}]
    action_taken: str
