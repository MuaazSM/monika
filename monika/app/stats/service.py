"""Compute the stats/precision panel from REQUEST_LOG + INCIDENT (PRD §10.4, D-06).

precision = attack-labelled requests that reached >= RATE_LIMIT / all requests that reached
            >= RATE_LIMIT   (last 30 min)
recall    = attack scenarios that produced an incident >= 60 / attack scenarios run
benign_by_rung = benign requests grouped by the enforcement rung they reached
Denominators of zero yield null, never 0.00, so a fresh demo shows no precision.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..detection.baselines import baselines_ready
from ..incidents.models import EndpointConfigRow, IncidentRow, OverrideRow, RequestLog
from .models import StatsOut

WINDOW_MINUTES = 30
# action_applied values that mean "reached >= RATE_LIMIT" on the ladder.
ENFORCED = ("rate_limit", "challenge", "block", "revoke")
BLOCKED = ("block", "revoke")
ATTACK_PREFIX = "attack:"
RECALL_INCIDENT_MIN_SCORE = 60
# Each attack scenario's X-Monika-Label -> the threat_type a correct detection must produce.
SCENARIO_THREAT = {
    "attack:idor": "BOLA_ENUMERATION",
    "attack:stuffing": "CREDENTIAL_STUFFING",
    "attack:sqli": "SQL_INJECTION",
    "attack:scrape": "DATA_EXPOSURE",
    "attack:admin": "FUNCTION_LEVEL_AUTH",
}


async def compute_stats(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    now: datetime,
    redis: Redis,
    endpoint_ids: list[UUID],
    explainer_available: bool = False,
) -> StatsOut:
    window_start = now - timedelta(minutes=WINDOW_MINUTES)

    async with session_factory() as s:
        total_requests = (
            await s.execute(select(func.count()).select_from(RequestLog))
        ).scalar_one()
        incidents = (await s.execute(select(func.count()).select_from(IncidentRow))).scalar_one()
        blocked = (
            await s.execute(
                select(func.count())
                .select_from(RequestLog)
                .where(RequestLog.action_applied.in_(BLOCKED))
            )
        ).scalar_one()
        endpoints_configured = (
            await s.execute(select(func.count()).select_from(EndpointConfigRow))
        ).scalar_one()

        # --- precision (last 30 min) ---
        enforced_total = (
            await s.execute(
                select(func.count())
                .select_from(RequestLog)
                .where(
                    RequestLog.created_at >= window_start,
                    RequestLog.action_applied.in_(ENFORCED),
                )
            )
        ).scalar_one()
        # Sessions an analyst confirmed as false positives (Phase 13) are excluded from the
        # numerator: their enforcement was not a correct detection.
        fp_sessions = (
            select(IncidentRow.session_key)
            .join(OverrideRow, OverrideRow.incident_id == IncidentRow.id)
            .where(OverrideRow.action == "false_positive")
        )
        enforced_attack = (
            await s.execute(
                select(func.count())
                .select_from(RequestLog)
                .where(
                    RequestLog.created_at >= window_start,
                    RequestLog.action_applied.in_(ENFORCED),
                    RequestLog.label.like(f"{ATTACK_PREFIX}%"),
                    RequestLog.session_key.not_in(fp_sessions),
                )
            )
        ).scalar_one()
        precision = enforced_attack / enforced_total if enforced_total else None

        # --- recall (last 30 min): distinct attack scenarios detected / run ---
        run_rows = (
            (
                await s.execute(
                    select(RequestLog.label)
                    .where(
                        RequestLog.created_at >= window_start,
                        RequestLog.label.like(f"{ATTACK_PREFIX}%"),
                    )
                    .distinct()
                )
            )
            .scalars()
            .all()
        )
        scenarios_run: set[str] = {lbl for lbl in run_rows if lbl is not None}
        # A scenario counts as detected only if a session that carried its label produced an
        # incident of the MATCHING threat_type (>=60). Matching by threat_type — not just by
        # session_key — stops one scenario's incident from crediting another that happens to
        # share a session_key (e.g. admin and idor both on sub 742, or unauth scenarios on a
        # shared ip:).
        scenarios_detected: set[str] = set()
        for label in scenarios_run:
            expected = SCENARIO_THREAT.get(label)
            if expected is None:  # unknown scenario label: can't credit a detection
                continue
            detected = (
                await s.execute(
                    select(IncidentRow.id)
                    .join(RequestLog, RequestLog.session_key == IncidentRow.session_key)
                    .where(
                        RequestLog.label == label,
                        RequestLog.created_at >= window_start,
                        IncidentRow.created_at >= window_start,
                        IncidentRow.threat_type == expected,
                        IncidentRow.risk_score >= RECALL_INCIDENT_MIN_SCORE,
                    )
                    .limit(1)
                )
            ).first()
            if detected is not None:
                scenarios_detected.add(label)
        recall = len(scenarios_detected) / len(scenarios_run) if scenarios_run else None

        # --- benign requests per ladder rung (last 30 min) ---
        rung_rows = (
            await s.execute(
                select(RequestLog.action_applied, func.count())
                .where(RequestLog.created_at >= window_start, RequestLog.label == "benign")
                .group_by(RequestLog.action_applied)
            )
        ).all()
        benign_by_rung = {action: count for action, count in rung_rows}

    learning = not await baselines_ready(redis, endpoint_ids)

    return StatsOut(
        total_requests=total_requests,
        incidents=incidents,
        blocked=blocked,
        endpoints_configured=endpoints_configured,
        precision=precision,
        recall=recall,
        benign_by_rung=benign_by_rung,
        window_minutes=WINDOW_MINUTES,
        learning=learning,
        explainer_available=explainer_available,
    )
