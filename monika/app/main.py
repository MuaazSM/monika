"""App factory and lifespan.

The lifespan owns the two long-lived resources — the Redis connection pool and the SQLAlchemy
async engine — and hands them to request handlers via `request.app.state`.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from .db.engine import check_connectivity, create_engine
from .db.session import create_session_factory
from .detection.base import Detector
from .detection.d1_auth import AuthDetector
from .detection.d2_enum import EnumDetector
from .detection.d3_rate import RateDetector
from .detection.d4_payload import PayloadDetector
from .endpoints.loader import load_registry
from .endpoints.router import router as endpoints_router
from .endpoints.service import sync_registry_to_db
from .explainer.client import create_client as create_explainer_client
from .explainer.job import ExplainerJob
from .explainer.worker import ExplainerWorker, run_worker
from .incidents.models import IncidentDetailOut, IncidentOut, OverrideOut, SignalOut
from .incidents.router import router as incidents_router
from .incidents.service import get_incident
from .incidents.sse import Broadcaster
from .incidents.sse import router as sse_router
from .logging import configure_logging
from .policy.overrides import router as overrides_router
from .policy.reset import router as reset_router
from .proxy.forward import create_client
from .proxy.middleware import router as proxy_router
from .settings import Settings, get_settings
from .simulator.router import router as simulator_router
from .simulator.service import Simulator
from .stats.router import router as stats_router
from .stats.service import compute_stats

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/_monika", tags=["control-plane"])


class HealthResponse(BaseModel):
    """Liveness plus real dependency connectivity."""

    status: str
    redis: bool
    postgres: bool


async def _check_redis(redis: Redis) -> bool:
    """PING Redis; False on any connection error."""
    try:
        return bool(await redis.ping())
    except Exception:
        return False


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Report whether Redis and Postgres are actually reachable right now."""
    redis: Redis = request.app.state.redis
    engine: AsyncEngine = request.app.state.engine

    redis_ok = await _check_redis(redis)
    postgres_ok = await check_connectivity(engine)

    return HealthResponse(
        status="ok" if (redis_ok and postgres_ok) else "degraded",
        redis=redis_ok,
        postgres=postgres_ok,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open the Redis pool and the async engine on startup; close both on shutdown."""
    settings: Settings = app.state.settings

    engine = create_engine(settings.database_url)
    redis: Redis = Redis.from_url(settings.redis_url, decode_responses=True)
    http_client = create_client(settings.upstream_url)
    session_factory = create_session_factory(engine)
    registry = load_registry(settings.endpoints_config)

    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.redis = redis
    app.state.http_client = http_client
    app.state.endpoints = registry
    # D1 needs the admin allow-list; D3 needs the rate floor from settings.
    detectors: list[Detector] = [
        AuthDetector(registry.admin_subs),
        EnumDetector(),
        RateDetector(settings),
        PayloadDetector(),
    ]
    app.state.detectors = detectors
    app.state.broadcaster = Broadcaster()
    app.state.simulator = Simulator(settings)
    explainer_queue: asyncio.Queue[ExplainerJob] = asyncio.Queue(maxsize=1000)
    app.state.explainer_queue = explainer_queue

    # Upsert the yaml config into ENDPOINT_CONFIG so baseline snapshots have a row (D-03).
    await sync_registry_to_db(session_factory, registry)

    # Background task: broadcast stats.tick every 2s (in-process asyncio, rule 8).
    # admin_only endpoints never accumulate baseline samples (DECISIONS.md D-12: the
    # learning-phase traffic-gen deliberately skips them) — exclude them from the
    # readiness check or `learning` would never clear.
    endpoint_ids = [ep.endpoint_id for ep in registry.endpoints if not ep.admin_only]

    async def _stats_ticker() -> None:
        while True:
            await asyncio.sleep(2)
            try:
                stats = await compute_stats(
                    session_factory, now=datetime.now(UTC), redis=redis, endpoint_ids=endpoint_ids
                )
                app.state.broadcaster.publish("stats.tick", stats)
            except Exception:  # a stats hiccup must never kill the ticker
                logger.exception("stats.tick failed")

    ticker = asyncio.create_task(_stats_ticker())

    # Explainer worker (asyncio task, rule 8). It cannot import `incidents` (it's a lower
    # layer), so it publishes incident.explained through this injected callback.
    async def _publish_explained(incident_id: uuid.UUID) -> None:
        parts = await get_incident(session_factory, incident_id)
        if parts is None:
            return
        incident, signals, overrides = parts
        app.state.broadcaster.publish(
            "incident.explained",
            IncidentDetailOut(
                **IncidentOut.model_validate(incident).model_dump(),
                llm_explanation=incident.llm_explanation,
                llm_next_step=incident.llm_next_step,
                signals=[SignalOut.model_validate(s) for s in signals],
                overrides=[OverrideOut.model_validate(o) for o in overrides],
            ),
        )

    explainer_client = create_explainer_client(settings)
    explainer_worker = ExplainerWorker(
        settings, session_factory, explainer_client, _publish_explained
    )
    worker_task = asyncio.create_task(run_worker(explainer_worker, explainer_queue))

    logger.info("monika.startup", upstream=settings.upstream_url, endpoints=len(registry.endpoints))
    try:
        yield
    finally:
        ticker.cancel()
        worker_task.cancel()
        if explainer_client is not None:
            await explainer_client.aclose()
        await http_client.aclose()
        await redis.aclose()
        await engine.dispose()
        logger.info("monika.shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application."""
    configure_logging()
    app = FastAPI(title="Monika", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings or get_settings()
    # The dashboard is a separate origin (browser fetch + SSE); no cookies/credentials involved.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app.state.settings.cors_origin_list,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    app.include_router(incidents_router)
    app.include_router(sse_router)
    app.include_router(stats_router)
    app.include_router(endpoints_router)
    app.include_router(overrides_router)
    app.include_router(reset_router)
    app.include_router(simulator_router)
    app.include_router(proxy_router)
    return app


app = create_app()
