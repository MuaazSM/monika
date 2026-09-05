# Monika — CLAUDE.md §4.
# Targets whose subject does not exist yet echo the ticket that delivers them and exit 0.

.PHONY: up down logs test test-int lint lint-arch lint-py lint-ts seed demo reset fastmode types openapi help

s ?=

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

up: ## docker compose up --build
	docker compose up --build -d

down: ## docker compose down -v
	docker compose down -v

logs: ## tail one service: make logs s=monika
	@test -n "$(s)" || { echo "usage: make logs s=<service>"; exit 1; }
	docker compose logs -f $(s)

lint: lint-py lint-ts ## ruff + mypy (backend), eslint + tsc (frontend)

lint-py:
	cd monika && uv run ruff check . && uv run ruff format --check . && uv run mypy

lint-ts:
	@if [ -d dashboard ]; then \
		cd dashboard && pnpm lint && pnpm exec tsc --noEmit; \
	else \
		echo "lint (frontend): not implemented yet (T11 — dashboard/ does not exist)"; \
	fi

lint-arch: ## import-linter contracts (module direction)
	cd monika && uv run lint-imports

test: ## pytest (monika/tests)
	@if ls monika/tests/**/test_*.py monika/tests/test_*.py >/dev/null 2>&1; then \
		cd monika && uv run pytest; \
	else \
		echo "test: not implemented yet (T5 — no tests until the detectors land)"; \
	fi

test-int: ## integration tests; requires `make up` running
	@if [ -d monika/tests/integration ]; then \
		cd monika && uv run pytest tests/integration; \
	else \
		echo "test-int: not implemented yet (T9 — needs traffic-gen scenarios)"; \
	fi

seed: ## re-run demo-api seed + baseline learning phase
	docker compose up -d postgres redis migrate demo-api monika
	docker compose run --rm seed          # demo-api users/orders/products
	docker compose run --rm seed-baselines   # 3-minute benign learning phase (§6.3)

openapi: ## export demo-api/openapi.json from the app
	cd demo-api && uv run python export_openapi.py

demo: ## run a traffic-gen scenario: make demo s=idor
	@test -n "$(s)" || { echo "usage: make demo s=<idor|benign>"; exit 1; }
	docker compose run --rm traffic-gen python -m traffic_gen $(s)

reset: ## truncate tables, flush redis, re-seed baselines
	@echo "reset: not implemented yet (T8 — no tables exist before the incident service)"

fastmode: ## MONIKA_LADDER_TIME_DIVISOR=10 for demos
	@echo "fastmode: not implemented yet (T7 — the ladder has no decay to speed up yet)"

types: ## regenerate dashboard/lib/types.ts from the OpenAPI schema
	@echo "types: not implemented yet (T11 — dashboard/ does not exist)"
