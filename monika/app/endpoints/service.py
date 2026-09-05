"""Postgres side of endpoint config: upsert the yaml into ENDPOINT_CONFIG on startup and
mirror baseline snapshots on write (display only — DECISIONS.md D-03)."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..incidents.models import EndpointConfigRow
from .loader import EndpointRegistry


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
