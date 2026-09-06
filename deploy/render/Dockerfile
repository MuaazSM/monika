# Combined image for Render's free Web Service tier (no Private Service needed).
#
# Runs demo-api and monika as two processes in one container. demo-api binds to
# 127.0.0.1 only, so it is reachable from monika inside this container but never
# from the network Render exposes publicly (CLAUDE.md rule 10: demo-api stays
# internal, only monika talks to it).
#
# Build context must be the repo root (both demo-api/ and monika/ are copied in).

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY --from=ghcr.io/astral-sh/uv:0.8.14 /uv /usr/local/bin/uv

WORKDIR /app

COPY demo-api/pyproject.toml demo-api/pyproject.toml
RUN cd demo-api && uv sync --no-dev --no-install-project
COPY demo-api/ demo-api/
RUN cd demo-api && uv sync --no-dev

COPY monika/pyproject.toml monika/pyproject.toml
RUN cd monika && uv sync --no-dev --no-install-project
COPY monika/ monika/
RUN cd monika && uv sync --no-dev

# Baseline-learning script (PRD §6.3). It only needs httpx/redis/pyyaml, all already in
# monika's venv, so it runs with `monika/.venv/bin/python` rather than a third venv.
COPY traffic-gen/seed_baselines.py traffic-gen/seed_baselines.py

COPY deploy/render/start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 8000
CMD ["/app/start.sh"]
