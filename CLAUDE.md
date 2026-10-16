# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

The HouseHoldHub Backend: a Django 5.2 LTS / Python 3.14 service (Django REST Framework, PostgreSQL via psycopg 3,
django-allauth), one of the five HouseHoldHub repositories (Backend, Frontend, Infrastructure, Automation,
Documentation: ADR-009). `apps/accounts` holds the custom user and `apps/api` the `/api/v1` plumbing and the
contract checker. Routes arrive with their feature issues, never as stubs.

Decisions and the wire contract live in Documentation (`../Documentation` when cloned alongside): `api/openapi.yaml`,
`architecture/adr/ADR-0NN-*.md` (cited by number throughout the code), `architecture/technology-baseline.md`,
`product/permissions-matrix.md`, `security/security-model.md`. `Backend#N` / `Automation#N` are GitHub issues in the
House-Hold-Hub organisation; live issues, not Markdown, are authoritative for status.

## Commands

Settings read only `os.environ` (nothing loads `.env`) and `DJANGO_SECRET_KEY` has no default, so every command needs
it in the environment, pytest and mypy included.

```bash
uv sync                                    # runtime + dev deps from uv.lock (CI: uv sync --frozen)
export DJANGO_SECRET_KEY=dev               # or: cp .env.example .env && set -a && . ./.env && set +a

uv run ruff check .                        # CI "Lint"
uv run mypy .                              # CI "Type check" (django-stubs + djangorestframework-stubs plugins)
uv run pytest                              # CI "Test"; CI adds --cov (informational, no threshold)
uv run pytest apps/api/tests/test_csrf.py::test_safe_requests_need_no_csrf_token
uv run pytest -k pagination

# CI "Contract drift": ../Documentation must be at the commit pinned in contract/documentation-revision.json
uv run python manage.py check_api_contract --spec ../Documentation/api/openapi.yaml
HOUSEHOLDHUB_OPENAPI_SPEC=../Documentation/api/openapi.yaml uv run pytest   # also runs the real-contract test

uv run python manage.py makemigrations     # works offline; migrate/runserver need PostgreSQL per POSTGRES_*
docker build -t householdhub-backend .     # run and migrate invocations: README "Docker"
```

- Without the key, pytest stops with `ImportError: Missing required environment variable: DJANGO_SECRET_KEY` and mypy
  with `INTERNAL ERROR ... Error constructing plugin instance of NewSemanalDjangoPlugin`. The `setdefault` in the
  root `conftest.py` does not help: pytest-django imports settings before any conftest is loaded.
- The database engine is hard-coded to PostgreSQL (no SQLite fallback), so `django_db` tests need a reachable server;
  CI provides a `postgres:17` service with database and user `householdhub`. Tests that authenticate a user need
  the database too (the verification gate reads allauth's `EmailAddress`); in-memory membership fixtures remain.
- No formatter is enforced and the code is not `ruff format`-clean: don't reformat code you aren't changing. E501 is
  ignored; migrations are excluded from ruff and mypy.
- CI never builds the Docker image, so verify Dockerfile changes locally. Commit `uv.lock` with every dependency
  change (`uv add`): CI installs with `--frozen` and OSV-Scanner fails on any known vulnerability in it.

## Architecture

### Documentation owns the contract; Backend proves conformance

`api/openapi.yaml` in Documentation is the only API definition (ADR-014). Backend keeps no copy and publishes no
schema (no schema endpoint, no drf-spectacular, no generated file); `test_no_backend_generated_schema_is_published`
fails if any `openapi*`/`swagger*` YAML or JSON file exists in this tree, so keep contract checkouts outside it (the
`Contract drift` job checks out into `documentation/` but runs no tests). A contract change merges in Documentation
before or together with the Backend code that needs it.

`contract/documentation-revision.json` pins the Documentation commit and the file's SHA-256, and `check_api_contract`
refuses any other bytes. To adopt a newer contract, update `commit` and `sha256` in the same PR as the code that needs
it (`git -C ../Documentation show <sha>:api/openapi.yaml | shasum -a 256`).

`apps/api/contract.py` discovers implemented operations from the live URLconf, with no allowlist or baseline: a route
is checked from the moment it exists, and contract operations not implemented yet are only counted. Per operation it
checks that method and path are in the contract, path converters against parameter schemas (`format: uuid` needs
`<uuid:...>`, `type: integer` needs `<int:...>`), public versus protected against `security: []` (by probing the
view's permissions with an anonymous user), the `ContractViewMixin` base, session authentication on protected
operations, and `PageLimitPagination` on operations with `page`/`limit` parameters. The foundation is always checked: server
`/api/v1`, the `sessionid` cookie, the `X-CSRFToken` header, Page/Limit bounds, `PageMeta` fields and
`ErrorResponse.code` against `ErrorCode`. Status codes, bodies and nullability cannot be checked statically;
per-operation API tests cover them.

### Request pipeline (`REST_FRAMEWORK` in `config/settings.py`, `apps/api`)

Defaults are fail-closed: JSON-only parsers and renderers, `ApiSessionAuthentication` (Django database-backed cookie
sessions, ADR-004/ADR-011) as the only authenticator and `IsAuthenticated` as the default permission. A public
operation opts out with `AllowAny` and must be `security: []` in the contract.

- `views.ContractViewMixin` (`ApiView`) is the mandatory base of every `/api/v1` view. After authentication and
  permission checks it enforces CSRF on every unsafe method, anonymous ones (login, signup) included, so an
  unauthenticated call to a protected operation is 401 and a missing token is 403.
- `errors.exception_handler` makes every error body `{"code", "message"[, "fields"]}` with fixed 401/403/404 messages
  that never reveal whether something exists. Authentication failures are 401 (DRF would answer 403 for session
  auth); validation and parse errors are 400 `VALIDATION_ERROR`, never 422, with `fields` flattened to dotted paths
  (`items.0.qty`); 409 is `CONFLICT`; throttling is 429 with `Retry-After`; other `APIException`s keep their status.
  Non-API exceptions fall through to Django, where `handlers.py` (`handler404`/`handler500` in `config/urls.py`)
  answers JSON under `/api/` and Django's default pages elsewhere.
- `pagination.PageLimitPagination` returns `{"data": [...], "meta": {"page", "limit", "total"}}` (limit default 20,
  max 100). Invalid values are 400, not clamped; a page past the end is empty, never 404.

### Verification gate (`views.ContractViewMixin`)

`check_permissions` rejects (403 `AUTHORIZATION_ERROR`) an authenticated account that is disabled or lacks a verified
allauth email *before* the view's permission classes run, so household classes cannot turn it into a 404 or skip it.
Anonymous callers still get 401 from the permission classes. A view opts out only with `allow_unverified = True`: public
operations (a restricted session may call them) and the pre-verification lifecycle in
`contract.UNVERIFIED_ACCESS_OPERATIONS`; `check_api_contract` reports `UNVERIFIED_ACCESS` for any other protected
operation that sets it. Tests that authenticate must use a verified, saved user (the `user` fixture / `make_user`):
the gate reads the database, so an unsaved `User` is denied.

### Sessions and revocation (`apps/accounts/sessions.py`)

The session engine is Django's database store on `accounts.Session`, whose indexed `user` column is the ADR-011
user-session registry: `SessionStore` writes it from the payload on every save, so revoke by deleting rows filtered by
`user_id` and never decode `session_data`. Use `revoke_all_sessions` / `revoke_other_sessions` /
`rotate_and_revoke_others`, which lock the user row (`FOR NO KEY UPDATE`) like the store's `save()` and `cycle_key()`
do; an unlocked delete can miss a session being rotated concurrently. `signals.py` wires the allauth events of the
revocation matrix; a database trigger from `0003_session_registry` deletes every session when `User.is_active`
changes, including through `QuerySet.update`. Session state that must survive an identity rotation is listed in
`ROTATION_PRESERVED_KEYS`; the invitation intent goes only through `set_invitation_intent`. Tests use one `Client`
per browser (`test_sessions.py`) and threads on separate connections for races (`test_session_concurrency.py`).

### Household-scoped authorization (`apps/api/permissions.py`)

`HouseholdScopedPermission` fixes the evaluation order (ADR-005, ADR-012): 401 when unauthenticated; 404 without an
*active* membership of the URL's `household_id` (a foreign household is indistinguishable from a nonexistent one, and
no action or object rule runs); 403 when the action rule denies; for objects, 404 unless the object's `household_id`
matches the URL, then 403 when the object rule denies. Membership is resolved once per request and cached on
`request.household_membership`. Everything denies by default: `resolve_membership` raises `NotImplementedError` until
the Membership app provides it, and subclasses encode `product/permissions-matrix.md` in
`has_action_permission` / `has_object_action_permission`. A route without the `household_id` kwarg raises
`ImproperlyConfigured`. There is no PostgreSQL RLS and permission classes don't filter querysets: list views must
filter by household themselves.

### Transactional email (`apps/email_delivery`, ADR-015)

Send only through `service.queue_email()` inside the domain `transaction.atomic()` (it refuses otherwise): it
persists a minimal `EmailDelivery` row and submits via `on_commit` through the provider-neutral
`adapter.EmailProvider` with a bounded timeout. `_submit` claims the row (`pending` -> `submitting`) before the
provider call, never raises for provider errors, and stores `accepted` (provider acceptance only, never "delivered"),
`failed` (not accepted) or `unknown` (timeout/interrupted/unexpected) with a fixed `error_class`. Never store or log
the recipient, token, URL, body or exception text; `test_sensitive_data.py` pins the column allowlist, so adding a
column needs security review. Providers raise only the `ProviderError` subclasses in `adapter.py`. D02 is open: the
default provider is `UnconfiguredProvider`; tests install `testing.RecordingProvider` through the `use_provider`
fixture. Recovery is a new delivery from the owning flow plus the `reconcile_email_deliveries` command.

### Authentication and rate limits (`apps/accounts/views.py`, `apps/ratelimit`, ADR-016)

Signup and login call `ratelimit.limiter.consume` *outside* the domain transaction (a rolled-back request still
counts) with actions from `AUTH_RATE_LIMITS`; never count through Django's cache API or allauth's limiter (off: not
atomic, unkeyed hashes, 400 instead of 429). Login reserves a failure slot before checking the password and clears it on
success. Both establish the session with `sessions.establish_session`, which keeps only a valid invitation intent.
Signup issues the verification bearer through `verification.issue_email_verification` inside its transaction;
Backend#35 consumes `EmailVerificationBearer` by `bearer_digest`. Request serializers derive from
`api.serializers.StrictSerializer` (unknown fields, non-strings and unpaired surrogates are 400).

### Tests

pytest-django with `config.settings`; tests live beside the code (`apps/<app>/tests/` or `apps/<app>/test_*.py`).
`apps/api/tests/support.py` is a test-only URLconf with throwaway views and the in-memory `MEMBERSHIPS` / `OBJECTS` /
`CALLS` state (cleared by an autouse fixture). Inside `apps/api/tests`, the `client` and `csrf_client` fixtures are
`APIClient`s bound to that URLconf, shadowing pytest-django's `client`. Contract tests build synthetic specs and
URLconfs (`base_spec()`, `urlconf()` in `test_contract_check.py`) rather than reading the real contract.

## Adding an `/api/v1` operation

1. The operation must exist in the pinned contract; if it doesn't, change Documentation first and bump the pin in
   this PR.
2. Subclass `ApiView`, or put `ContractViewMixin` leftmost on a DRF generic view or viewset, and keep the default
   authentication. Setting `pagination_class` on `ApiView` or `ViewSet` only satisfies `check_api_contract`: those
   bases never invoke a paginator, so a paginated operation on them must set
   `pagination_class = PageLimitPagination` and also paginate explicitly (instantiate it and call
   `paginate_queryset()` and `get_paginated_response()`). Generic views and `GenericViewSet` inherit the class, and
   their list mixin paginates; a custom action on them must still call `paginate_queryset()` itself.
3. Route it in `apps/api/urls.py` (mounted at `api/v1/`) with `path()`, no trailing slash, and converters matching
   the contract, e.g. `households/<uuid:household_id>/tasks`. Of the DRF routers only
   `SimpleRouter(trailing_slash=False, use_regex_path=False)` passes the check (set `lookup_value_converter = "uuid"`
   for UUID lookups); `DefaultRouter` and regex routes fail it.
4. Household routes use a `HouseholdScopedPermission` subclass. Test status codes, bodies, and authorization and
   validation failures, then run `check_api_contract`.

## Constraints from Documentation (`architecture/technology-baseline.md`)

- PostgreSQL is the only datastore: no Redis, Celery, queue or worker. Scheduled jobs (household purge, session
  cleanup) are idempotent management commands that Infrastructure/Automation schedule. Transactional email goes
  through a provider-neutral adapter called synchronously after commit (ADR-015).
- `accounts.User` is an `AbstractUser` with a UUID primary key, the normalized email as `USERNAME_FIELD` (unique, with
  DB check constraints that keep it canonical), a single `name` display field, and no `username`/`first_name`/
  `last_name`, bespoke password, `google_id` or `email_verified` field. Verified email and provider identities use
  allauth `EmailAddress` / `SocialAccount`; `User.is_email_verified` derives from `EmailAddress` for the account's
  current email (`apps/accounts/test_user_model.py`, `test_allauth_integration.py` guard this). Create users with
  `User.objects.create_user(email=..., name=...)`; verified fixtures come from the root `conftest.py` `make_user`.
- The topology is same-origin, so no CORS is configured; a cross-origin deployment needs an explicit CORS and
  credential review. Environment variables and defaults are tabled in the README; with `DJANGO_DEBUG=false` the
  cookies default to Secure and `DJANGO_ALLOWED_HOSTS` is required.

## CI and git workflow

- Required checks on `main`: `Lint`, `Type check`, `Test` (`ci.yml`), `Contract drift` (`api-contract.yml`, which
  sparse-checks out the pinned Documentation file), `Secret scan / scan` and `Dependency security / scan`
  (`gates.yml`, calling Automation's reusable workflows pinned by full commit SHA: bump it deliberately, never to a
  branch or moving tag).
- Check names are an interface: renaming a job or workflow silently drops branch protection, so update the
  protection in the same change. Never add `paths:` filters; a required check skipped that way stays pending forever.
- Branches are `<type>/<issue>-<slug>` (`feature/`, `chore/`), commit subjects follow Conventional Commits with
  `Refs #N` or `Closes #N` in the body (`Refs House-Hold-Hub/Automation#2` across repositories), and pull requests
  target `main`.
