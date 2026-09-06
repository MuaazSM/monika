"""create_app wiring: CORS is configured for the dashboard's browser origin."""

from __future__ import annotations

from app.main import create_app
from app.settings import Settings


def test_cors_middleware_allows_configured_origins() -> None:
    app = create_app(Settings(jwt_secret="test-secret", cors_origins="http://localhost:3000"))

    cors = next(m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware")

    assert cors.kwargs["allow_origins"] == ["http://localhost:3000"]


def test_cors_origin_list_splits_and_trims_csv() -> None:
    settings = Settings(cors_origins=" http://localhost:3000 ,http://example.com")

    assert settings.cors_origin_list == ["http://localhost:3000", "http://example.com"]
