"""Detector D3 — Rate / Behavior (PRD §6.6).

Two rules, both category "rate":
  1. Rate anomaly — the session's current-minute request rate for an endpoint deviates far
     from that endpoint's learned baseline. Fires on z >= 3 OR rpm >= 5*mean, but NEVER
     below the absolute floor (MONIKA_RATE_FLOOR_RPM, default 20) — the floor is what keeps
     a low-traffic endpoint (mean 0.4) from firing at 3 rpm and wrecking precision.
  2. Credential stuffing (sev 75) — on POST /api/login, >= 8 failed (401) responses in 60s
     from one session_key, OR >= 5 distinct usernames from one IP in 60s.
"""

from __future__ import annotations

from redis.asyncio import Redis

from ..endpoints.models import EndpointConfig
from ..settings import Settings
from .base import RequestContext
from .baselines import read_rpm
from .context import derive_session_key
from .signal import Signal

Z_THRESHOLD = 3.0
Z_CAP = 10.0
SEV_MIN = 40
SEV_MAX = 85
LOGIN_BONUS = 10
# Linear slope: 40 at z=3 rising to 85 at z=10 -> 45 severity points over 7 sigma.
_SLOPE = (SEV_MAX - SEV_MIN) / (Z_CAP - Z_THRESHOLD)

STUFFING_FAIL_THRESHOLD = 8
STUFFING_USER_THRESHOLD = 5
STUFFING_SEVERITY = 75
LOGIN_PATH = "/api/login"


def _rate_key(session_key: str, endpoint_id: object, minute: int) -> str:
    return f"rate:{session_key}:{endpoint_id}:{minute}"


class RateDetector:
    """D3. Constructor takes settings (for the absolute rate floor)."""

    name = "d3_rate"

    def __init__(self, settings: Settings) -> None:
        self.rate_floor = settings.rate_floor_rpm

    async def run(self, ctx: RequestContext, redis: Redis) -> list[Signal]:
        signals: list[Signal] = []
        session_key = derive_session_key(ctx.jwt, ctx.ip)
        minute = int(ctx.started_at.timestamp() // 60)

        ep = ctx.endpoint
        if ep is not None:
            rate_sig = await self._rate_signal(ctx, redis, ep, session_key, minute)
            if rate_sig is not None:
                signals.append(rate_sig)

            if ep.method.upper() == "POST" and ep.path_pattern == LOGIN_PATH:
                stuffing_sig = await self._stuffing_signal(ctx, redis, ep, session_key, minute)
                if stuffing_sig is not None:
                    signals.append(stuffing_sig)

        return signals

    async def _rate_signal(
        self, ctx: RequestContext, redis: Redis, ep: EndpointConfig, session_key: str, minute: int
    ) -> Signal | None:
        rpm = int(await redis.get(_rate_key(session_key, ep.endpoint_id, minute)) or 0)
        mean, std, _ = await read_rpm(redis, ep.endpoint_id)

        z = (rpm - mean) / max(std, 1.0)
        fires = z >= Z_THRESHOLD or (mean > 0 and rpm >= 5 * mean)

        # Absolute floor veto — protects the precision number (§6.6).
        if not fires or rpm < self.rate_floor:
            return None

        # Severity from z: 40 at 3-sigma, linear to 85 at 10-sigma, clamped to [40, 85].
        # NOTE: PRD §7.3 labels z=5.1 as "55"; this formula yields ~53.5. The formula is
        # authoritative — the example's 55 does not change its total (base severity is D1's).
        severity = round(min(SEV_MAX, max(SEV_MIN, SEV_MIN + (z - Z_THRESHOLD) * _SLOPE)))
        if ep.path_pattern == LOGIN_PATH:
            severity += LOGIN_BONUS  # credential-stuffing pressure on the login endpoint

        deviation_ratio = round(rpm / mean, 3) if mean > 0 else None
        return Signal(
            category="rate",
            severity=severity,
            evidence={
                "rpm": rpm,
                "baseline_mean": round(mean, 3),
                "baseline_std": round(std, 3),
                "z_score": round(z, 3),
                "deviation_ratio": deviation_ratio,
            },
            request_id=ctx.request_id,
            endpoint_id=ep.endpoint_id,
            session_key=session_key,
        )

    async def _stuffing_signal(
        self, ctx: RequestContext, redis: Redis, ep: EndpointConfig, session_key: str, minute: int
    ) -> Signal | None:
        ip = ctx.ip
        username = None
        if isinstance(ctx.body_json, dict):
            username = ctx.body_json.get("username")

        # record this attempt first, so the current request counts toward the thresholds
        if username is not None:
            ukey = f"login_users:{ip}:{minute}"
            await redis.sadd(ukey, str(username))
            await redis.expire(ukey, 120)
        if ctx.response.status == 401:
            fkey = f"login_fail:{session_key}:{minute}"
            await redis.incr(fkey)
            await redis.expire(fkey, 120)

        # counts over the last ~60s: current minute bucket + previous minute bucket
        fail_vals = await redis.mget(
            f"login_fail:{session_key}:{minute}", f"login_fail:{session_key}:{minute - 1}"
        )
        failures_60s = sum(int(v) for v in fail_vals if v is not None)
        usernames = await redis.sunion(
            [f"login_users:{ip}:{minute}", f"login_users:{ip}:{minute - 1}"]
        )
        usernames_attempted = len(usernames)

        if (
            failures_60s >= STUFFING_FAIL_THRESHOLD
            or usernames_attempted >= STUFFING_USER_THRESHOLD
        ):
            return Signal(
                category="rate",
                severity=STUFFING_SEVERITY,
                evidence={
                    "usernames_attempted": usernames_attempted,
                    "failures_60s": failures_60s,
                },
                request_id=ctx.request_id,
                endpoint_id=ep.endpoint_id,
                session_key=session_key,
            )
        return None
