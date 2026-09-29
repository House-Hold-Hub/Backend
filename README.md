# HouseHoldHub Backend

Django backend scaffold for the HouseHoldHub MVP engineering foundation.

## Baseline

The repository targets the Documentation-owned Python 3.14 / Django 5.2 LTS baseline, with Django REST Framework, django-allauth and PostgreSQL as the approved backend technology families. Exact runtime and dependency selections are owned here by `.python-version`, the requirements manifests, and their compiled lockfiles.

The custom `users.User` model uses a UUID primary key and is configured through `AUTH_USER_MODEL` before any application migration is generated.

Same-origin frontend/API deployment is the default. No CORS layer is configured; a future cross-origin topology requires an explicit CORS and credential review.

## API contract foundation

DRF is mounted under `/api/v1/`, matching the Documentation-owned OpenAPI server base path. M0-B3 intentionally adds no feature endpoint or model serializer; those arrive with their dedicated implementation issues.

The canonical route and wire contract remains `House-Hold-Hub/Documentation/api/openapi.yaml`. This repository does not generate or publish a competing schema. Instead, `api/openapi-contract.lock.toml` pins an exact Documentation commit and Git blob. The contract check downloads that immutable revision, verifies the blob identity, discovers the Backend's implemented DRF operations, and fails if any implemented method/path is absent from the pinned contract.

Run the cross-repository drift check with:

```bash
python manage.py check_openapi_contract
```

The household permission foundation is fail-closed: a view must resolve an active membership before household access is granted, and object-level authorization runs only after the object is confirmed to belong to that membership's household. Concrete Membership queries and feature-specific authorization remain with the feature issues that introduce those models and operations.

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

Create a Docker network shared by the one-shot migration command and the long-running service:

```bash
docker network create householdhub-local
```

Apply the committed migrations before starting the service:

```bash
docker run --rm \
  --network householdhub-local \
  --env-file .env \
  householdhub-backend \
  python manage.py migrate
```

Run the service without Docker Compose using the same environment and network:

```bash
docker run --rm \
  --name householdhub-backend \
  --network householdhub-local \
  --publish 8000:8000 \
  --env-file .env \
  householdhub-backend
```

The container command intentionally uses Django's development server for the local M0 runtime. Production process-server and deployment-target choices remain outside this issue.

## Development checks

Create a Python 3.14 virtual environment, install the development lockfile, then run:

```bash
python manage.py check
python manage.py check_openapi_contract
pytest
ruff check .
ruff format --check .
mypy .
```

Dependency locks are generated with `pip-tools` from `requirements.in` and `requirements-dev.in`.

This M0 foundation intentionally does not add feature endpoints, all-model serializer stubs, full-stack Docker Compose, or a repository-local GitHub Actions workflow.
