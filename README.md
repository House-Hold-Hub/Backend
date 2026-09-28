# HouseHoldHub Backend

Django backend scaffold for the HouseHoldHub MVP engineering foundation.

## Baseline

The repository targets the Documentation-owned Python 3.14 / Django 5.2 LTS baseline, with Django REST Framework, django-allauth and PostgreSQL as the approved backend technology families. Exact runtime and dependency selections are owned here by `.python-version`, the requirements manifests, and their compiled lockfiles.

The custom `users.User` model uses a UUID primary key and is configured through `AUTH_USER_MODEL` before any application migration is generated.

Same-origin frontend/API deployment is the default. No CORS layer is configured; a future cross-origin topology requires an explicit CORS and credential review.

## Containerized local runtime

This repository owns the Backend service Dockerfile and service-local runtime configuration only. Full-stack Docker Compose and deployment manifests belong to the Infrastructure repository.

Build the Backend image directly from this repository:

```bash
docker build --tag householdhub-backend .
```

Create a local runtime environment file:

```bash
cp .env.example .env
```

The example values are development-only. When the Backend runs inside Docker, set `POSTGRES_HOST` in `.env` to a PostgreSQL host that is reachable from the container; the image does not assume a Compose service name or provision PostgreSQL itself.

Run the service without Docker Compose:

```bash
docker run --rm \
  --name householdhub-backend \
  --publish 8000:8000 \
  --env-file .env \
  householdhub-backend
```

The container command intentionally uses Django's development server for the local M0 runtime. Production process-server and deployment-target choices remain outside this issue.

## Development checks

Create a Python 3.14 virtual environment, install the development lockfile, then run:

```bash
python manage.py check
pytest
ruff check .
ruff format --check .
mypy .
```

Dependency locks are generated with `pip-tools` from `requirements.in` and `requirements-dev.in`.

This scaffold intentionally does not add DRF routing/permissions, full-stack Docker Compose, or GitHub Actions; those belong to subsequent repository-owned issues.
