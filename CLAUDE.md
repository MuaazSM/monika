# CLAUDE.md — Monika

Monika is an adaptive API security gateway built for the "API Security & Threat Control" hackathon track. This file tells you (Claude Code or any AI coding agent) how the repo is structured, what the non-negotiable design rules are, how to run and test things, and what to do when you're unsure.

**Source of truth:** `docs/Monika_PRD.pdf` (v1.0, locked). If this file and the PRD disagree, the PRD wins and this file has a bug — fix it here.

---

## 1. What Monika is, in three sentences

A FastAPI reverse proxy sits in front of a deliberately vulnerable demo API, captures every request+response, and runs four deterministic detectors (auth/BOLA, enumeration, rate/behavior, payload/exposure). Signals become a 0–100 risk score, which drives a per-session response ladder: `NORMAL → OBSERVE → RATE_LIMIT → CHALLENGE → BLOCK → REVOKE`. A Next.js dashboard shows every incident with its evidence, lets an analyst override, and displays an LLM-written explanation that arrives *after* the decision was enforced.

## 2. Non-negotiable design rules

These are the things judges will probe and the things that are easiest to accidentally break. Do not violate them, even if a task seems to call for it. If a task requires violating one, stop and say so.

1. **The LLM never decides.** `monika/app/explainer/` is the only module allowed to call the Anthropic API. It runs asynchronously after an incident is persisted. It produces prose only. It must never emit a number, a score, a confidence, or an action, and nothing in `proxy/`, `detection/`, `scoring/`, or `policy/` may import from `explainer/`.
2. **Scoring is a pure function.** `scoring/score.py::score(signals, session_state) -> int` has no I/O and no side effects. Formula: `min(100, max_category_severity + corr_bonus[distinct_categories] + min(10, 2 * signals_last_5m))` with `corr_bonus = {1:0, 2:10, 3:18, 4:25, 5:25}`. Do not change to an additive sum.
3. **Confidence is engine-computed.** `scoring/confidence.py`: `min(99, 40 + 15*distinct_categories + 5*min(prior_signals_5m,4) + 10*[any z_score >= 5])`. Never sourced from the model.
4. **Enforcement is one request behind detection.** The proxy checks ladder state *before* forwarding, forwards, then detects on the request+response pair. The only pre-forward hard check is the JWT `jti` denylist (REVOKE). Don't "optimize" detection into the pre-forward path — D1 and D4 need the response body.
5. **Every signal carries evidence.** A `Signal` without a populated `evidence` dict is a bug. Evidence keys per detector are fixed in PRD §6.4–6.7 and rendered verbatim by the dashboard.
6. **Overrides are audited and immediate.** Every override writes an `OVERRIDE` row and mutates Redis ladder state in the same request. Never delete override rows.
7. **One incident per (session_key, threat_type, 10-min window).** New signals update the existing incident (score = max, signals appended). Don't create duplicates.
8. **No new infrastructure.** No Kafka, Celery, Kubernetes, Elasticsearch, LangChain, or additional services. Single FastAPI process, Redis, Postgres, Next.js. Background work uses `asyncio` tasks inside the FastAPI process.
9. **Module dependencies are one-way.** `proxy → detection → scoring → policy → incidents ⇢ explainer`. A lower module never imports a higher one. Run `make lint-arch` (import-linter) before committing.
10. **The demo API stays vulnerable.** Never "fix" `demo-api/`. Its weaknesses are the point. If a detector is failing, fix the detector.

## 3. Repository layout

```
monika/
├── CLAUDE.md                      ← you are here
├── README.md                      ← judge-facing: architecture, security logic, trade-offs, how to run
├── docs/                          ← LOCAL ONLY, gitignored (see §12)
│   ├── Monika_PRD.pdf / .docx     ← locked spec
│   ├── diagrams/*.mmd, *.png      ← mermaid sources; copy .mmd into README when embedding
│   ├── Implementation-Backend.md
│   ├── Implementation-Frontend.md
│   └── GATES.md
├── docker-compose.yml
├── Makefile                       ← up, down, test, lint, seed, demo, reset
├── .env.example
├── monika/                        ← control plane + proxy (Python 3.12, FastAPI)
│   ├── app/
│   │   ├── main.py                ← app factory, lifespan (Redis/PG pools, explainer task)
│   │   ├── settings.py            ← pydantic-settings; MONIKA_* env vars
│   │   ├── proxy/                 ← middleware.py, forward.py, enforce.py, jwt.py
│   │   ├── detection/             ← signal.py, base.py, d1_auth.py, d2_enum.py, d3_rate.py, d4_payload.py, engine.py, baselines.py
│   │   ├── scoring/               ← score.py, confidence.py
│   │   ├── policy/                ← ladder.py (state machine), overrides.py, denylist.py
│   │   ├── incidents/             ← models.py, service.py, sse.py, router.py
│   │   ├── explainer/             ← worker.py, prompt.py, client.py
│   │   ├── endpoints/             ← config loader (yaml), router.py (Tier 2 edit)
│   │   ├── stats/                 ← router.py (tiles + precision)
│   │   ├── openapi_import/        ← Tier 3
│   │   ├── redteam/               ← Tier 3
│   │   └── db/                    ← engine.py, session.py, base.py
│   ├── config/endpoints.yaml
│   ├── alembic/
│   ├── tests/                     ← pytest; mirrors app/ layout
│   └── pyproject.toml
├── demo-api/                      ← deliberately vulnerable target (FastAPI, port 9000)
│   ├── app/main.py, routes/, seed.py, openapi.json (exported)
│   └── pyproject.toml
├── traffic-gen/                   ← benign.py, seed_baselines.py, scenarios/, cli.py
└── dashboard/                     ← Next.js 15 (App Router), TypeScript, Tailwind, shadcn/ui, Recharts
    ├── app/                       ← routes: /, /incidents, /incidents/[id], /endpoints, /simulator, /settings
    ├── components/
    ├── lib/api.ts, lib/sse.ts, lib/types.ts
    ├── fixtures/                  ← JSON fixtures matching PRD §10.1 shapes (used before backend is ready)
    └── package.json
```

## 4. Commands

```bash
make up            # docker compose up --build (postgres, redis, demo-api seed, migrations, monika, dashboard, traffic-gen benign)
make down          # compose down -v
make logs s=monika # tail one service
make test          # pytest (monika/tests) inside the container
make test-int      # integration tests: requires `make up` running
make lint          # ruff + mypy (backend), eslint + tsc (frontend)
make lint-arch     # import-linter contracts (module direction)
make seed          # re-run demo-api seed + baseline learning phase
make demo s=idor   # run a traffic-gen scenario: idor | stuffing | sqli | scrape | admin | benign
make reset         # truncate incidents/signals/overrides/request_log, flush redis, re-seed baselines
make fastmode      # sets MONIKA_LADDER_TIME_DIVISOR=10 for demos (decay in seconds instead of minutes)
```

Local without Docker (backend): `cd monika && uv sync && uv run uvicorn app.main:app --reload --port 8000` with `REDIS_URL` and `DATABASE_URL` pointing at running services.

Local without Docker (frontend): `cd dashboard && pnpm i && pnpm dev` — set `NEXT_PUBLIC_MONIKA_URL=http://localhost:8000`. With `NEXT_PUBLIC_USE_FIXTURES=1` the app renders from `fixtures/` and needs no backend.

## 5. Ports and URLs

| Service   | Port | Notes |
|-----------|------|-------|
| dashboard | 3000 | Next.js |
| monika    | 8000 | `/api/*` is proxied to demo-api; `/_monika/*` is the control plane; `/_monika/events` is SSE |
| demo-api  | 9000 | never expose in demo; only monika talks to it |
| postgres  | 5432 | db `monika`, user `monika` |
| redis     | 6379 | db 0 |

## 6. Environment variables

All backend settings are `MONIKA_*` and live in `monika/app/settings.py`. Key ones:

```
MONIKA_DATABASE_URL=postgresql+asyncpg://monika:monika@postgres:5432/monika
MONIKA_REDIS_URL=redis://redis:6379/0
MONIKA_UPSTREAM_URL=http://demo-api:9000
MONIKA_JWT_SECRET=<shared with demo-api>
MONIKA_ANTHROPIC_API_KEY=            # empty → explainer disabled, UI shows "unavailable"
MONIKA_ANTHROPIC_MODEL=claude-sonnet-4-6
MONIKA_EXPLAINER_ENABLED=true
MONIKA_LADDER_TIME_DIVISOR=1         # 10 for demos
MONIKA_RATE_FLOOR_RPM=20
MONIKA_ENDPOINTS_CONFIG=config/endpoints.yaml
```

Never commit a real API key. `.env` is gitignored; `.env.example` has every key with a blank or safe default.

## 7. Key contracts (copy these exactly)

### Signal (`monika/app/detection/signal.py`)
```python
class Signal(BaseModel):
    category: Literal["auth", "enum", "rate", "payload", "exposure"]
    severity: int                     # 0-100
    evidence: dict[str, Any]
    request_id: str
    endpoint_id: UUID | None
    session_key: str                  # jwt.sub if authenticated else f"ip:{ip}"
```

### Detector interface (`monika/app/detection/base.py`)
```python
class Detector(Protocol):
    name: str
    async def run(self, ctx: RequestContext, redis: Redis) -> list[Signal]: ...
```
`RequestContext` carries: `request_id, method, path, path_params, query, headers, body_json, jwt (sub, jti, role) | None, ip, endpoint (EndpointConfig | None), response (status, bytes, body_json | None), started_at, latency_ms, label`.

### Ladder states
`NORMAL, OBSERVE, RATE_LIMIT, CHALLENGE, BLOCK, REVOKE` — an `enum.StrEnum` in `policy/ladder.py`. Transition table is PRD §8.1 and is encoded as data (`TRANSITIONS: list[Transition]`), not as a chain of ifs, so tests can iterate it.

### Redis keys
```
baseline:{endpoint_id}:rpm                        HASH mean,std,n
baseline:{endpoint_id}:bytes                      HASH mean,n
rate:{session_key}:{endpoint_id}:{minute}         INT  TTL 120
rate:{session_key}:{minute}                       INT  TTL 120
enum:{session_key}:{endpoint_id}                  ZSET member=object_id score=ts, TTL 300
enum_owner:{session_key}:{endpoint_id}            ZSET member=owner_value score=ts, TTL 300  (D1 writes, D2 reads)
exposure_pages:{session_key}:{endpoint_id}          ZSET member=page score=ts, TTL 60  (D4 scrape breadth in 30s window, D-16)
auth_signals:{session_key}:{minute}               INT  TTL 300  (D1 auth-signal count; 5m escalation term)
login_fail:{session_key}:{minute}                 INT  TTL 120
login_users:{ip}:{minute}                         SET  TTL 120
ladder:{session_key}                              HASH state,score,last_signal_at,changed_at,signals_5m
blocked_attempts:{session_key}                    INT  TTL 300  (D-14 persistence counter → REVOKE)
revoked_jti:{session_key}                         SET  TTL 3600  (jti(s) revoked per session; unblock clears from denylist, T13)
denylist:jti                                      SET
```

### SSE events (`/_monika/events`)
`incident.created`, `incident.updated`, `incident.explained`, `session.changed`, `stats.tick` (every 2 s). Payloads are the same JSON shapes as the REST GET responses for the affected resource. The dashboard never polls.

### Control-plane routes
See PRD §10.1. Prefix is `/_monika`. Responses are Pydantic models in `incidents/models.py`, `endpoints/models.py`, `stats/models.py`; the frontend `lib/types.ts` is generated from the OpenAPI schema (`make types`).

## 8. Coding conventions

**Python**
- 3.12, `uv` for deps, `ruff` (line length 100) + `mypy --strict` on `app/`.
- Async everywhere in the request path. `redis.asyncio`, `asyncpg` via SQLAlchemy 2.x async.
- Pydantic v2 for all boundary types. No dicts crossing module boundaries except `Signal.evidence`.
- Detectors are stateless classes; all state is Redis. Constructor takes settings only.
- Tests: `pytest-asyncio`, `fakeredis` for unit tests, real compose stack for `tests/integration/`. Freeze time with `freezegun` for ladder decay tests.
- Log with `structlog`, JSON output, always include `request_id` and `session_key` when available.

**TypeScript**
- Next.js 15 App Router, TS strict, `pnpm`.
- Server components by default; client components only for SSE consumers, charts, and forms.
- All backend types come from `lib/types.ts` (generated). Don't hand-write API shapes.
- shadcn/ui for primitives; Tailwind only, no CSS modules. Dark theme is the only theme.
- State: a single `IncidentStore` (zustand) fed by `lib/sse.ts`; pages read from it. No react-query polling.

**Git** — see §12 for the full rules.
- **Backend work is trunk-based: commit directly to `main`. Do not create per-ticket branches.** Reference the ticket ID (PRD §11.3) in the commit message instead: `feat(t05): detectors D1-D4 (PRD §6.4-6.7)`.
- **Frontend work is the one exception**: it lives on its own branch and lands via a PR into `main`. The PR description must say which PRD section it implements and which acceptance check it satisfies.
- Conventional commits everywhere.
- Tier 3 work is not merged until Gate 2 is signed off in `docs/GATES.md` (local file).

## 9. Testing rules

- Every detector has a table-driven boundary test (fires / doesn't fire on either side of each threshold). PRD §12.1 lists the required cases; they are the minimum.
- `tests/scoring/test_score.py` must contain the worked example from PRD §7.3 asserting `100`.
- `tests/policy/test_ladder.py` iterates `TRANSITIONS` and asserts every row.
- Integration: `tests/integration/test_scenarios.py` runs each traffic-gen scenario and asserts `threat_type` and `score >= min_score` from PRD §13.2, and the benign run produces no incident ≥ 30.
- Don't mock the demo API in integration tests; it's part of the system under test.

## 10. When you're unsure

- **Threshold or formula question** → PRD §6–§8. If the PRD is silent, pick the conservative option (fewer false positives) and leave a `# PRD-GAP:` comment so it gets logged in §14.3.
- **UI question** → PRD §10.3 lists MUSTs per screen; `docs/Implementation-Frontend.md` has the component breakdown.
- **"Should this be a new service/queue/library?"** → No (rule 8).
- **Something needs the LLM to "decide"** → It doesn't (rule 1). Reframe as engine evidence + prose.
- **Task would change the demo API** → Don't (rule 10).

## 11. Demo-day checklist (run before every rehearsal)

1. `make reset && make up` — wait for `traffic-gen: learning phase complete` in logs.
2. Dashboard Overview shows no "Learning" badge, precision 1.00, tiles ticking.
3. `MONIKA_LADDER_TIME_DIVISOR=10` is set (fast decay).
4. `MONIKA_ANTHROPIC_API_KEY` is set; run `make demo s=idor` once and confirm the explanation arrives; if the API is flaky, `MONIKA_EXPLAINER_FALLBACK=1` serves the cached IDOR explanation.
5. Run the 90-second script (PRD §13.1) end-to-end. Twice.

---

## 12. Git and repository rules

### 12.1 Remote and identity

The repository lives at `https://github.com/MuaazSM/monika`. **All pushes go through the `MuaazSM` GitHub account only.** Teammates work on branches locally and hand off via patches or by pushing to their own fork and opening a PR into `MuaazSM/monika`; nobody else pushes to `origin` directly.

First-time setup (run once by MuaazSM):

```bash
git init
git add .
git commit -m "chore: initial scaffold"
git remote add origin https://github.com/MuaazSM/monika.git
git branch -M main
git push -u origin main
```

Before pushing, confirm the identity on the machine:

```bash
git config user.name    # must be MuaazSM
git config user.email   # must be the email attached to the MuaazSM GitHub account
gh auth status          # if using gh: must show MuaazSM
```

If either is wrong, set it for this repo only (`git config user.name "MuaazSM"`, `git config user.email "<email>"`) — do not change global config on a shared machine.

### 12.2 No AI co-author trailers

Commits must not carry any `Co-Authored-By:` line, "Generated with Claude", or similar attribution. This applies to every commit, including ones made by Claude Code or any other agent.

- When committing from Claude Code, always pass the message explicitly and **omit the trailer**. Do not accept the default commit message.
- A pre-commit hook enforces it. Add to `.githooks/commit-msg` and enable with `git config core.hooksPath .githooks`:

```bash
#!/usr/bin/env bash
if grep -qiE '^(Co-Authored-By:|.*Generated with Claude|.*Claude Code)' "$1"; then
  echo "commit rejected: remove AI co-author / attribution lines from the message" >&2
  exit 1
fi
```

- If a trailer slips in: `git commit --amend` before pushing. If it's already pushed, `git rebase -i` to reword, then `git push --force-with-lease` — only MuaazSM does this, and only on a feature branch, never on `main`.

### 12.3 What is not committed

The PRD, the implementation plans, the diagram sources, the gate log, and any other planning material stay local. `.gitignore` must contain:

```gitignore
# planning / spec material — local only
docs/
*.pdf
*.docx
Implementation-*.md
GATES.md

# secrets and local env
.env
.env.*
!.env.example

# usual suspects
node_modules/
.next/
__pycache__/
*.pyc
.venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
dist/
*.log
.DS_Store
```

Consequences to keep in mind:
- The README is the only judge-facing document in the repo. Anything from the PRD that judges need (architecture, detector logic, ladder table, trade-offs, demo script) must be **rewritten into the README**, not linked. When embedding a diagram, paste the mermaid source into a fenced ```` ```mermaid ```` block in the README so GitHub renders it — the `.png` files are not committed.
- `docs/GATES.md` is local; the Gate 1 / Gate 2 sign-off is still required, it just lives on the team's machines and in the PR descriptions.
- `CLAUDE.md` itself is committed (it's the working agreement for the repo). If the team decides it also counts as a trail, rename it to `AGENTS.md` and update the reference in the README; nothing else depends on the filename.

### 12.4 Branch protection on `main`

**Timing matters.** Backend work commits directly to `main` (§8), so protection that requires a PR would block every backend commit. Leave `main` unprotected until the backend reaches Gate 2, then enable it before the frontend PR is opened.

Set on GitHub by MuaazSM at that point: require PR, require the CI workflow (`lint`, `test`) to pass, no force-push, no deletion. `main` must always be demoable.