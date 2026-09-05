"""Table-driven tests for D4 (PRD §6.7)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fakeredis import aioredis

from app.detection.base import JWTClaims, RequestContext, ResponseContext
from app.detection.baselines import _bytes_key
from app.detection.d4_payload import PayloadDetector
from app.endpoints.models import EndpointConfig

NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
SEARCH_EP = EndpointConfig(method="GET", path_pattern="/api/search")
PRODUCTS_EP = EndpointConfig(
    method="GET",
    path_pattern="/api/products",
    sensitive_fields=("cost_price", "supplier_margin"),
)
ADMIN_EP = EndpointConfig(
    method="GET",
    path_pattern="/api/admin/users",
    auth_required=True,
    sensitive_fields=("password_hash", "ssn"),
)


def _ctx(ep, *, query=None, req_body=None, resp_body=None, status=200, bytes_=100):
    return RequestContext(
        request_id="r1",
        method=ep.method,
        path=ep.path_pattern,
        path_params={},
        query=query or {},
        headers={},
        body_json=req_body,
        jwt=JWTClaims(sub=742, jti="j", role="user"),
        ip="1.2.3.4",
        endpoint=ep,
        response=ResponseContext(status=status, bytes=bytes_, body_json=resp_body),
        started_at=NOW,
        latency_ms=1.0,
    )


@pytest.fixture
async def redis():
    r = aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


async def _run(redis, ctx):
    return await PayloadDetector().run(ctx, redis)


def _payload(sigs):
    return [s for s in sigs if s.category == "payload"]


def _exposure(sigs):
    return [s for s in sigs if s.category == "exposure"]


# ---- injection: each pattern family fires ----------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("' OR '1'='1", "sql_tautology"),
        ("x' UNION SELECT username FROM users", "union_select"),
        ("admin'--", "sql_comment"),
        ("1; DROP TABLE users", "stacked_query"),
        ("$ne", "nosql_operator"),
        ("{{7*7}}", "template_command"),
        ("$(whoami)", "template_command"),
    ],
)
async def test_each_pattern_family_fires(redis, value, expected) -> None:
    sigs = await _run(redis, _ctx(SEARCH_EP, query={"q": value}))
    p = _payload(sigs)
    assert len(p) == 1
    assert p[0].evidence["matched_pattern"] == expected
    assert p[0].evidence["parameter"] == "query.q"
    assert set(p[0].evidence) == {"matched_pattern", "parameter", "value_excerpt"}


async def test_nosql_operator_as_body_key(redis) -> None:
    # realistic NoSQL: {"password": {"$ne": ""}} — operator is a KEY
    ctx = _ctx(SEARCH_EP, req_body={"password": {"$ne": ""}})
    p = _payload(await _run(redis, ctx))
    assert p and p[0].evidence["matched_pattern"] == "nosql_operator"


async def test_prose_select_does_not_fire(redis) -> None:
    ctx = _ctx(SEARCH_EP, query={"q": "Select the premium plan or size large today"})
    assert _payload(await _run(redis, ctx)) == []


# ---- injection severity: 60 vs 80 across the 3x-bytes threshold ------------------------


async def test_injection_severity_60_below_threshold(redis) -> None:
    await redis.hset(_bytes_key(SEARCH_EP.endpoint_id), mapping={"mean": 100, "n": 50})
    ctx = _ctx(SEARCH_EP, query={"q": "' OR '1'='1"}, status=200, bytes_=300)  # 300 == 3x, not >
    (sig,) = _payload(await _run(redis, ctx))
    assert sig.severity == 60


async def test_injection_severity_80_above_threshold(redis) -> None:
    await redis.hset(_bytes_key(SEARCH_EP.endpoint_id), mapping={"mean": 100, "n": 50})
    ctx = _ctx(SEARCH_EP, query={"q": "' OR '1'='1"}, status=200, bytes_=301)  # > 3x
    (sig,) = _payload(await _run(redis, ctx))
    assert sig.severity == 80


async def test_value_excerpt_truncated_to_40(redis) -> None:
    long = "' OR '1'='1' " + "A" * 100
    ctx = _ctx(SEARCH_EP, query={"q": long})
    (sig,) = _payload(await _run(redis, ctx))
    assert len(sig.evidence["value_excerpt"]) == 40
    assert sig.evidence["value_excerpt"] == long[:40]


# ---- exposure --------------------------------------------------------------------------


async def test_single_product_read_does_not_fire_exposure(redis) -> None:
    # D-12: a single normal catalogue page (20 items, normal size) is NOT excessive exposure.
    body = {"page": 1, "results": [{"id": 1, "price": 15, "cost_price": 6, "supplier_margin": 9}]}
    assert _exposure(await _run(redis, _ctx(PRODUCTS_EP, resp_body=body))) == []


async def test_oversized_response_fires_exposure_70(redis) -> None:
    # D-12: a response abnormally large vs baseline (a scrape) DOES fire, severity 70.
    await redis.hset(_bytes_key(PRODUCTS_EP.endpoint_id), mapping={"mean": 100, "n": 50})
    body = {"results": [{"id": i, "cost_price": i} for i in range(50)]}  # big, has cost_price
    (sig,) = _exposure(await _run(redis, _ctx(PRODUCTS_EP, resp_body=body, bytes_=5000)))
    assert sig.severity == 70
    assert "cost_price" in sig.evidence["sensitive_fields_present"]
    assert set(sig.evidence) == {"sensitive_fields_present", "response_bytes", "list_length"}


async def test_bulk_list_20_items_does_not_fire(redis) -> None:
    # exactly 20 items, normal size, no baseline -> not bulk, not oversized -> no fire.
    body = [{"password_hash": "x"} for _ in range(20)]
    assert _exposure(await _run(redis, _ctx(ADMIN_EP, resp_body=body, bytes_=100))) == []


async def test_exposure_severity_85_at_21_items(redis) -> None:
    body = [{"password_hash": "x"} for _ in range(21)]
    (sig,) = _exposure(await _run(redis, _ctx(ADMIN_EP, resp_body=body)))
    assert sig.severity == 85
    assert sig.evidence["list_length"] == 21


async def test_404_never_produces_exposure(redis) -> None:
    body = [{"password_hash": "x"} for _ in range(30)]
    assert _exposure(await _run(redis, _ctx(ADMIN_EP, resp_body=body, status=404))) == []


async def test_no_exposure_without_sensitive_keys(redis) -> None:
    body = {"results": [{"id": 1, "price": 15}]}  # no cost_price/supplier_margin
    assert _exposure(await _run(redis, _ctx(PRODUCTS_EP, resp_body=body))) == []


async def test_paged_scrape_fires_exposure_by_breadth(redis) -> None:
    # D-16: reading >20 DISTINCT pages of a sensitive endpoint = a scrape -> exposure 70.
    body = {"results": [{"id": 1, "cost_price": 6}]}
    fired = False
    for page in range(1, 26):  # 25 distinct pages
        ctx = _ctx(PRODUCTS_EP, query={"page": str(page)}, resp_body=body)
        if _exposure(await _run(redis, ctx)):
            fired = True
    assert fired  # crossed the breadth floor


async def test_repeated_same_page_does_not_fire(redis) -> None:
    # Re-reading the SAME page 30x is one distinct resource -> not a scrape -> no fire.
    body = {"results": [{"id": 1, "cost_price": 6}]}
    for _ in range(30):
        ctx = _ctx(PRODUCTS_EP, query={"page": "1"}, resp_body=body)
        assert _exposure(await _run(redis, ctx)) == []


async def test_few_distinct_pages_stays_under_breadth_floor(redis) -> None:
    # Benign browsing of a handful of distinct pages must NOT fire.
    body = {"results": [{"id": 1, "cost_price": 6}]}
    for page in range(1, 6):  # 5 distinct pages
        ctx = _ctx(PRODUCTS_EP, query={"page": str(page)}, resp_body=body)
        assert _exposure(await _run(redis, ctx)) == []
