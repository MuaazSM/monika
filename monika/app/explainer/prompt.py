"""The LLM contract (PRD §10.5). SYSTEM_PROMPT is verbatim — the 'do not assign a
confidence / do not recommend blocking' clauses are load-bearing (rule 1)."""

from __future__ import annotations

import json

from .job import ExplainerJob

# Verbatim from PRD §10.5 — do not paraphrase.
SYSTEM_PROMPT = (
    "You are a security analyst writing for another analyst. You receive structured "
    "evidence from a deterministic detection engine. Write exactly two sentences explaining "
    "what the evidence indicates, then one line starting 'Next step:' with a concrete action. "
    "Do not invent facts, do not state numbers that are not in the evidence, do not assign "
    "a confidence, do not recommend blocking or unblocking. Plain prose, no markdown."
)


def build_user_message(job: ExplainerJob) -> str:
    """The §10.5 user-message JSON shape. Carries NO risk score and NO confidence."""
    return json.dumps(
        {
            "threat_type": job.threat_type,
            "endpoint": job.endpoint,
            "signals": job.signals,
            "action_taken": job.action_taken,
        }
    )
