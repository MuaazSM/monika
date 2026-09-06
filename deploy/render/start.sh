#!/usr/bin/env sh
# Boots demo-api (localhost-only), monika (public), then runs the baseline-learning
# phase against monika's own public port in the background. Everything lives in one
# Render free Web Service — no Private Service / Job / Background Worker needed.
set -eu

PORT="${PORT:-8000}"

cd /app/demo-api
.venv/bin/python -m app.seed
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 9000 &
DEMO_PID=$!

cd /app/monika
.venv/bin/alembic upgrade head
# The Simulator (app/simulator/service.py) replays scenarios through Monika's own proxy via
# MONIKA_SELF_URL, which defaults to localhost:8000 — wrong here since Render assigns $PORT
# dynamically. Without this, every Simulator run fails with a connection error.
MONIKA_SELF_URL="http://127.0.0.1:$PORT" \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "$PORT" &
MONIKA_PID=$!

trap 'kill "$DEMO_PID" "$MONIKA_PID" 2>/dev/null' TERM INT

(
  MONIKA_URL="http://127.0.0.1:$PORT" \
  ENDPOINTS_CONFIG=/app/monika/config/endpoints.yaml \
  SEED_DURATION_S="${SEED_DURATION_S:-180}" \
  /app/monika/.venv/bin/python /app/traffic-gen/seed_baselines.py
) &

wait "$MONIKA_PID"
