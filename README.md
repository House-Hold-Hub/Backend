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

## Docker

### Build

```bash
docker build -t householdhub-backend .
```

### Run

The container requires a reachable PostgreSQL instance and at minimum `DJANGO_SECRET_KEY`.
All database settings default to the values in `settings.py` but should be overridden at runtime.

```bash
docker run --rm \
  -e DJANGO_SECRET_KEY=<secret> \
  -e DJANGO_ALLOWED_HOSTS=localhost \
  -e POSTGRES_HOST=<host> \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_DB=householdhub \
  -e POSTGRES_USER=householdhub \
  -e POSTGRES_PASSWORD=<password> \
  -p 8000:8000 \
  householdhub-backend
```

Run pending migrations before the first start (or after schema changes):

```bash
docker run --rm \
  -e DJANGO_SECRET_KEY=<secret> \
  -e POSTGRES_HOST=<host> \
  -e POSTGRES_PASSWORD=<password> \
  householdhub-backend \
  python manage.py migrate
```

### Required environment variables

| Variable | Default | Notes |
|---|---|---|
| `DJANGO_SECRET_KEY` | — | **Required.** No default. |
| `DJANGO_DEBUG` | `false` | Set `true` only for local development. |
| `DJANGO_ALLOWED_HOSTS` | (empty) | Comma-separated hostnames. Required when `DEBUG=false`. |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | (empty) | Required behind a TLS proxy. |
| `DJANGO_SECURE_COOKIES` | `true` when `DEBUG=false` | Set `false` for plain-HTTP local runs. |
| `POSTGRES_HOST` | `localhost` | External PostgreSQL host. |
| `POSTGRES_PORT` | `5432` | |
| `POSTGRES_DB` | `householdhub` | |
| `POSTGRES_USER` | `householdhub` | |
| `POSTGRES_PASSWORD` | (empty) | |

The `accounts.User` model is a UUID-keyed skeleton; its completion and the initial migration
are tracked in Backend#2.

## API (`/api/v1`)

The wire contract is owned by Documentation (`api/openapi.yaml`, ADR-014). Backend implements it and
publishes no schema of its own: there is no schema endpoint and no generated OpenAPI artifact.

Foundation in `apps/api`:

- DRF with JSON-only rendering/parsing, Django cookie-session authentication, `IsAuthenticated` as the
  default permission, `page`/`limit` pagination (`{"data": [...], "meta": {"page", "limit", "total"}}`,
  invalid values are 400) and `ErrorResponse` bodies for every error.
- Every API view extends `apps.api.views.ApiView` (or mixes in `ContractViewMixin`). CSRF is enforced on
  all unsafe methods, public ones included; an unauthenticated call to a protected operation is still 401.
- Household-scoped permissions (`apps.api.permissions.HouseholdScopedPermission`): 401 when unauthenticated,
  404 when the caller has no active membership (identical for nonexistent households) before any action
  or object rule is evaluated, 403 for an action denied inside the household. Everything defaults to
  deny, and `resolve_membership` must be provided by the Membership app (Backend#12).
- Routes are added to `apps/api/urls.py` as operations are implemented. No operation is stubbed.

### Contract check

`contract/documentation-revision.json` pins the Documentation commit and the SHA-256 of
`api/openapi.yaml`. Backend keeps no copy of the contract.

```bash
git -C ../Documentation checkout <pinned commit>   # or any checkout whose api/openapi.yaml matches the pin
uv run python manage.py check_api_contract --spec ../Documentation/api/openapi.yaml
```

The command refuses a contract file that differs from the pin, then discovers the implemented operations
from the live URLconf and fails when any of them diverges (missing from the contract, wrong path-parameter
type, public/protected mismatch, missing contract base view, missing pagination, unversioned or unverifiable
routes). Operations not implemented yet are only counted. There is no allowlist or baseline, so future
divergences cannot be masked. The foundation (server prefix, session cookie, CSRF header, pagination
parameters, `ErrorResponse` codes) is always checked. CI runs it in `.github/workflows/api-contract.yml`,
checking out the pinned Documentation commit; the general lint/test workflow is Backend#5.

To adopt a newer contract, in the same PR as the code that needs it:

```bash
git -C ../Documentation rev-parse HEAD
git -C ../Documentation show <sha>:api/openapi.yaml | shasum -a 256
```

then update `commit` and `sha256` in `contract/documentation-revision.json`.

Not verifiable statically (covered by per-operation API tests as operations land): response status codes,
request/response bodies and field nullability. The check is exercised with
`HOUSEHOLDHUB_OPENAPI_SPEC=<path> uv run pytest` against the real contract in addition to the CI step.
