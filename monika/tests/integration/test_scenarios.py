"""Real-stack scenario gate (PRD §13.2, §12.3, CLAUDE.md §9).

Drives each attack scenario through the running system via POST /_monika/simulate — the
REAL demo API behind the proxy, NOT a mock (§9). Asserts the expected threat_type and a
minimum score per §13.2, and that benign traffic produces no incident >= 30.

Skipped unless the compose stack is up (make up); run it with `make test-int`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

_REPO_ROOT = Path(__file__).resolve().parents[3]
MONIKA = "http://localhost:8000"
PG = "postgresql+asyncpg://monika:monika@localhost:5432/monika"

# (scenario, expected threat_type, minimum score) — PRD §13.2.
ATTACKS = [
    ("idor", "BOLA_ENUMERATION", 90),
    ("stuffing", "CREDENTIAL_STUFFING", 75),
    ("sqli", "SQL_INJECTION", 60),
    ("scrape", "DATA_EXPOSURE", 70),
    ("admin", "FUNCTION_LEVEL_AUTH", 70),
]


def _stack_up() -> bool:
    try:
        return httpx.get(f"{MONIKA}/_monika/health", timeout=2).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _stack_up(), reason="requires the compose stack (make up)")


async def _reset() -> None:
    """Clear incidents/signals/request_log/session and all transient Redis state.

    Redis is flushed via `docker compose exec` (the CONTAINER's redis) rather than a
    localhost:6379 client — on a dev box a Homebrew redis can shadow the exposed port, so a
    host client would flush the wrong instance and leave monika's real state intact.
    """
    engine = create_async_engine(PG)
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE incident, signal, request_log, session CASCADE"))
    await engine.dispose()
    # Delete only transient keys — KEEP baseline:* so D3 has a learned mean to compare against
    # (a flushdb would make D3 fire spuriously on any burst and preempt the D4 scrape rule).
    patterns = (
        "ladder:* blocked_attempts:* enum:* enum_owner:* auth_signals:* rate:* "
        "login_fail:* login_users:* revoked_jti:* exposure_pages:*"
    )
    script = (
        f'for p in {patterns}; do redis-cli --scan --pattern "$p" | xargs -r redis-cli del; done; '
        "redis-cli del denylist:jti"
    )
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "compose",
        "exec",
        "-T",
        "redis",
        "sh",
        "-c",
        script,
        cwd=str(_REPO_ROOT),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()


async def _run_scenario(scenario: str) -> None:
    async with httpx.AsyncClient(base_url=MONIKA, timeout=30) as c:
        resp = await c.post("/_monika/simulate", json={"scenario": scenario})
        assert resp.status_code == 202, resp.text
        run_id = resp.json()["run_id"]
        for _ in range(120):  # poll up to ~60s
            await asyncio.sleep(0.5)
            status = (await c.get(f"/_monika/simulate/{run_id}")).json()["status"]
            if status in ("done", "failed"):
                assert status == "done", f"{scenario} run failed"
                break
        else:
            pytest.fail(f"{scenario} did not finish in time")
        await asyncio.sleep(1)  # let post-forward detection settle


async def _incidents() -> list[dict]:
    async with httpx.AsyncClient(base_url=MONIKA, timeout=10) as c:
        return (await c.get("/_monika/incidents?limit=50")).json()["items"]


@pytest.mark.parametrize(("scenario", "threat_type", "min_score"), ATTACKS)
async def test_attack_scenario(scenario: str, threat_type: str, min_score: int) -> None:
    await _reset()
    await _run_scenario(scenario)
    incidents = await _incidents()
    assert incidents, f"{scenario}: no incident produced"
    top = max(incidents, key=lambda i: i["risk_score"])
    # If a scenario misses, this surfaces the actual threat_type/score for the report.
    assert top["threat_type"] == threat_type, (
        f"{scenario}: expected {threat_type}, got {top['threat_type']} "
        f"(score {top['risk_score']}); all incidents: "
        f"{[(i['threat_type'], i['risk_score']) for i in incidents]}"
    )
    assert top["risk_score"] >= min_score, f"{scenario}: score {top['risk_score']} < {min_score}"


async def test_benign_produces_no_incident() -> None:
    await _reset()
    await _run_scenario("benign")
    incidents = await _incidents()
    high = [i for i in incidents if i["risk_score"] >= 30]
    assert high == [], (
        f"benign produced incidents >= 30: {[(i['threat_type'], i['risk_score']) for i in high]}"
    )
