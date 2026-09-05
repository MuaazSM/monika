"""Postgres side of endpoint config: upsert the yaml into ENDPOINT_CONFIG on startup and
mirror baseline snapshots on write (display only — DECISIONS.md D-03)."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..incidents.models import EndpointConfigRow, IncidentRow
from .loader import EndpointRegistry
from .models import EndpointOut


async def sync_registry_to_db(
    session_factory: async_sessionmaker[AsyncSession], registry: EndpointRegistry
) -> None:
    """Upsert every configured endpoint so the display table has a row to mirror onto."""
    async with session_factory() as session:
        for ep in registry.endpoints:
            stmt = insert(EndpointConfigRow).values(
                id=ep.endpoint_id,
                method=ep.method,
                path_pattern=ep.path_pattern,
                id_param=ep.id_param,
                owner_field=ep.owner_field,
                auth_required=ep.auth_required,
                admin_only=ep.admin_only,
                sensitive_fields=list(ep.sensitive_fields),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "method": ep.method,
                    "path_pattern": ep.path_pattern,
                    "id_param": ep.id_param,
                    "owner_field": ep.owner_field,
                    "auth_required": ep.auth_required,
                    "admin_only": ep.admin_only,
                    "sensitive_fields": list(ep.sensitive_fields),
                },
            )
            await session.execute(stmt)
        await session.commit()


async def mirror_baseline_to_db(
    session_factory: async_sessionmaker[AsyncSession],
    endpoint_id: UUID,
    rpm_mean: float,
    rpm_std: float,
    bytes_mean: float,
) -> None:
    """Copy the Redis baseline snapshot onto the display row (D-03). Best-effort."""
    async with session_factory() as session:
        await session.execute(
            update(EndpointConfigRow)
            .where(EndpointConfigRow.id == endpoint_id)
            .values(
                baseline_rpm_mean=rpm_mean,
                baseline_rpm_std=rpm_std,
                baseline_resp_bytes=round(bytes_mean),
            )
        )
        await session.commit()


# --- risk map (§13.1): endpoints + baseline snapshot + observed risk level ---

RISK_WINDOW_MINUTES = 30
RED_SCORE = 80  # >= this on any incident -> red
AMBER_SCORE = 30  # any incident (an incident is only created at >= 30) -> amber


def _risk_level(max_score: int | None) -> str:
    if max_score is None:
        return "green"
    if max_score >= RED_SCORE:
        return "red"
    if max_score >= AMBER_SCORE:
        return "amber"
    return "green"


async def list_endpoints(
    session_factory: async_sessionmaker[AsyncSession], *, now: datetime
) -> list[EndpointOut]:
    """Every configured endpoint with its baseline snapshot and a risk_level derived from
    incidents seen on it in the last window. Read-only (D-03: never mutates baselines)."""
    window_start = now - timedelta(minutes=RISK_WINDOW_MINUTES)
    async with session_factory() as session:
        rows = (await session.execute(select(EndpointConfigRow))).scalars().all()
        agg = (
            await session.execute(
                select(
                    IncidentRow.endpoint_id,
                    func.count().label("n"),
                    func.max(IncidentRow.risk_score).label("max_score"),
                )
                .where(IncidentRow.created_at >= window_start)
                .group_by(IncidentRow.endpoint_id)
            )
        ).all()
    by_ep = {eid: (n, max_score) for eid, n, max_score in agg}

    out: list[EndpointOut] = []
    for r in rows:
        n, max_score = by_ep.get(r.id, (0, None))
        out.append(
            EndpointOut(
                id=r.id,
                method=r.method,
                path_pattern=r.path_pattern,
                auth_required=r.auth_required,
                admin_only=r.admin_only,
                sensitive_fields=list(r.sensitive_fields or []),
                baseline_rpm_mean=r.baseline_rpm_mean,
                baseline_rpm_std=r.baseline_rpm_std,
                baseline_resp_bytes=r.baseline_resp_bytes,
                incident_count=n,
                max_risk_score=max_score,
                risk_level=_risk_level(max_score),
            )
        )
    out.sort(key=lambda e: e.path_pattern)
    return out
