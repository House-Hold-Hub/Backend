# HouseHoldHub Backend

Django 5.2 LTS / Python 3.14 service (Django REST Framework, PostgreSQL, django-allauth).
Baseline: Documentation `ADR-010`, `ADR-011`, `technology-baseline.md`. Exact versions live in
`pyproject.toml` and `uv.lock`.

## Setup

```bash
uv sync                      # installs from uv.lock on Python 3.14
cp .env.example .env         # then export the variables into your environment
export DJANGO_SECRET_KEY=...  # required; no default
uv run python manage.py check
uv run pytest
```

Configuration is environment-only (see `.env.example`). The default topology is same-origin,
so no CORS configuration is included; a cross-origin deployment needs an explicit CORS/credential review.

The `accounts.User` model is a UUID-keyed skeleton; its completion and the initial migration
are tracked in Backend#2.
