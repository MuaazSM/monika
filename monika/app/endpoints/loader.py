"""Load config/endpoints.yaml into an EndpointRegistry and resolve live requests."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import EndpointConfig


class EndpointRegistry:
    """The set of configured endpoints plus the admin allow-list (D-10)."""

    def __init__(self, endpoints: list[EndpointConfig], admin_subs: list[int]) -> None:
        self.endpoints = endpoints
        self.admin_subs = set(admin_subs)
        self._by_method: dict[str, list[EndpointConfig]] = {}
        for ep in endpoints:
            self._by_method.setdefault(ep.method.upper(), []).append(ep)

    def match(self, method: str, path: str) -> tuple[EndpointConfig | None, dict[str, str]]:
        """Resolve a live (method, path) to its config and extracted path params."""
        for ep in self._by_method.get(method.upper(), []):
            params = ep.match_path(path)
            if params is not None:
                return ep, params
        return None, {}


def load_registry(config_path: str | Path) -> EndpointRegistry:
    """Parse the yaml. Raises if the file is missing or malformed."""
    data = yaml.safe_load(Path(config_path).read_text())
    endpoints = [EndpointConfig(**e) for e in data.get("endpoints", [])]
    admin_subs = list(data.get("admin_subs", []))
    return EndpointRegistry(endpoints, admin_subs)
