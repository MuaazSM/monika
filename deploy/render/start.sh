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
