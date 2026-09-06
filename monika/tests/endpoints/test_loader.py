"""Endpoint loader: uuid5 stability, matching, path-param extraction, admin config."""

from __future__ import annotations

import uuid
from pathlib import Path

from app.endpoints.loader import load_registry
from app.endpoints.models import ENDPOINT_NAMESPACE, EndpointConfig

CONFIG = Path(__file__).resolve().parents[2] / "config" / "endpoints.yaml"


def test_uuid5_stable_across_instances() -> None:
    r1 = load_registry(CONFIG)
    r2 = load_registry(CONFIG)
    ids1 = {(e.method, e.path_pattern): e.endpoint_id for e in r1.endpoints}
    ids2 = {(e.method, e.path_pattern): e.endpoint_id for e in r2.endpoints}
    assert ids1 == ids2


def test_uuid5_matches_manual_derivation() -> None:
    ep = EndpointConfig(method="GET", path_pattern="/api/users/{id}")
    expected = uuid.uuid5(ENDPOINT_NAMESPACE, "GET /api/users/{id}")
    assert ep.endpoint_id == expected


def test_match_extracts_path_params() -> None:
    reg = load_registry(CONFIG)
    ep, params = reg.match("GET", "/api/users/701")
    assert ep is not None and ep.path_pattern == "/api/users/{id}"
    assert params == {"id": "701"}


def test_orders_route_is_distinct_from_user_route() -> None:
    reg = load_registry(CONFIG)
    ep, params = reg.match("GET", "/api/users/701/orders")
    assert ep is not None and ep.path_pattern == "/api/users/{id}/orders"
    assert params == {"id": "701"}


def test_unconfigured_route_returns_none() -> None:
    reg = load_registry(CONFIG)
    ep, params = reg.match("POST", "/api/transfer")  # unmonitored (D-11)
    assert ep is None and params == {}


def test_admin_config_and_subs() -> None:
    reg = load_registry(CONFIG)
    ep, _ = reg.match("GET", "/api/admin/users")
    assert ep is not None and ep.admin_only is True
    assert 749 in reg.admin_subs


def test_six_configured_endpoints() -> None:
    reg = load_registry(CONFIG)
    assert len(reg.endpoints) == 6


def test_update_swaps_config_and_matcher_sees_it_immediately() -> None:
    # PUT /_monika/endpoints/{id}: the very next match() must return the new config, so
    # editing sensitive_fields actually changes detection, not just the display row.
    reg = load_registry(CONFIG)
    target, _ = reg.match("GET", "/api/products")
    assert target is not None
    new_ep = reg.update(
        target.endpoint_id,
        owner_field="vendor_id",
        sensitive_fields=("cost_price", "supplier_margin", "internal_notes"),
        auth_required=True,
    )
    assert new_ep is not None
    assert new_ep.endpoint_id == target.endpoint_id  # stable id across the swap

    matched, _ = reg.match("GET", "/api/products")
    assert matched is not None
    assert matched.owner_field == "vendor_id"
    assert matched.sensitive_fields == ("cost_price", "supplier_margin", "internal_notes")
    assert matched.auth_required is True
    # unrelated fields (method/path_pattern/id_param/admin_only) are untouched
    assert matched.method == target.method
    assert matched.path_pattern == target.path_pattern


def test_update_unknown_id_returns_none() -> None:
    reg = load_registry(CONFIG)
    result = reg.update(
        uuid.uuid4(), owner_field=None, sensitive_fields=(), auth_required=False
    )
    assert result is None
