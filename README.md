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
pytest
ruff check .
ruff format --check .
mypy .
```

Dependency locks are generated with `pip-tools` from `requirements.in` and `requirements-dev.in`.

## DRF foundation and API contract check

All application API routes are mounted below `/api/v1`. DRF uses page-number pagination with `page` as the page selector, `limit` as the page-size selector, a default size of 20, and a maximum size of 100, matching the canonical OpenAPI parameter contract.

`api.permissions.HouseholdScopedPermission` is a fail-closed base permission. A view must resolve an active household membership through `get_active_household_membership(request)` before access is granted. Object authorization is evaluated only after that membership exists; the base object hook denies by default.

The Documentation repository remains the only authoritative OpenAPI source. This repository deliberately does not check in or generate a competing schema. With the Documentation repository available as a sibling checkout, run:

```bash
python manage.py check_api_contract ../Documentation/api/openapi.yaml
```

The checker validates the configured `/api/v1` mount and requires every implemented Backend method/path pair to exist in the canonical contract. Contract-only operations are allowed while the MVP is delivered incrementally; placeholder endpoints are not created merely to satisfy the full future route inventory. Django `path()`/`include()` routing, standard converters (`str`, `int`, `slug`, `uuid`), DRF `APIView`/`@api_view`, and DRF ViewSet action mappings are supported. Unsupported routing constructs, including regex routes, fail closed with a clear error rather than being guessed at.

Repository-local GitHub Actions wiring is intentionally not added here; that belongs to Backend issue #5. Full-stack Docker Compose remains owned by Infrastructure.
