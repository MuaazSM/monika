# Monika — CLAUDE.md §4.

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
	cd dashboard && pnpm lint && pnpm build && pnpm exec tsc --noEmit

lint-arch: ## import-linter contracts (module direction)
	cd monika && uv run lint-imports

test: ## pytest (monika/tests)
	cd monika && uv run pytest --ignore=tests/integration

test-int: ## integration tests; requires `make up` running
	cd monika && uv run pytest tests/integration

seed: ## re-run demo-api seed + baseline learning phase
	docker compose up -d postgres redis migrate demo-api monika
	docker compose run --rm seed          # demo-api users/orders/products
	docker compose run --rm seed-baselines   # 3-minute benign learning phase (§6.3)

openapi: ## export demo-api/openapi.json from the app
	cd demo-api && uv run python export_openapi.py

demo: ## run a traffic-gen scenario: make demo s=idor
	@test -n "$(s)" || { echo "usage: make demo s=<idor|benign>"; exit 1; }
	docker compose run --rm traffic-gen python -m traffic_gen $(s)

reset: ## truncate tables (never overridden incidents — rule 6), flush redis, re-seed baselines
	docker compose exec -T postgres psql -U monika -d monika -c "\
		DELETE FROM signal WHERE incident_id NOT IN (SELECT incident_id FROM override); \
		DELETE FROM incident WHERE id NOT IN (SELECT incident_id FROM override); \
		DELETE FROM request_log; \
		DELETE FROM session; \
		DELETE FROM attack_plan;"
	docker compose exec -T redis redis-cli FLUSHALL
	docker compose run --rm seed-baselines

fastmode: ## MONIKA_LADDER_TIME_DIVISOR=10 for demos
	MONIKA_LADDER_TIME_DIVISOR=10 docker compose up --build -d monika

types: ## regenerate dashboard/lib/types.gen.ts from monika's OpenAPI schema
	cd monika && uv run python export_openapi.py
	cd dashboard && pnpm exec openapi-typescript ../monika/openapi.json -o lib/types.gen.ts
