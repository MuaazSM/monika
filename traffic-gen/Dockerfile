FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_LINK_MODE=copy PATH="/app/.venv/bin:$PATH"
COPY --from=ghcr.io/astral-sh/uv:0.8.14 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml ./
RUN uv sync --no-install-project
COPY . .
CMD ["python", "seed_baselines.py"]
