# syntax=docker/dockerfile:1
# ── builder: install Python dependencies with uv ──────────────────────────────
FROM python:3.14-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Dependency layer – rebuilt only when pyproject.toml or uv.lock change.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Application code
COPY . .
RUN uv sync --frozen --no-dev


# ── runtime: lean image without build tools ────────────────────────────────────
FROM python:3.14-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN useradd --create-home --shell /bin/false appuser

COPY --from=builder /app /app

USER appuser

EXPOSE 8000

# Default to 2 workers; override at runtime with WEB_CONCURRENCY.
CMD ["sh", "-c", "exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers ${WEB_CONCURRENCY:-2} --timeout 30"]
