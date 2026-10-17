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

## CI

`.github/workflows/ci.yml` runs on `pull_request` and `workflow_dispatch` with Python 3.14 and `uv sync --frozen`.
Tool versions are pinned by `uv.lock`; configuration lives in `pyproject.toml`.

| Job (status check name) | Command |
|---|---|
| `Lint` | `uv run ruff check .` |
| `Type check` | `DJANGO_SECRET_KEY=x uv run mypy .` (mypy + django-stubs + djangorestframework-stubs) |
| `Test` | `uv run pytest --cov` against a PostgreSQL 17 service container |

Coverage (pytest-cov) is informational only: the table appears in the workflow run summary linked from the PR
checks, and `coverage.xml` is uploaded as an artifact. There is no percentage threshold.

### Gates (secret scan and dependency security)

`.github/workflows/gates.yml` runs on `pull_request` and on pushes to `main` and calls the shared reusable
workflows of Automation (Automation#2, `docs/shared-gates.md`), pinned by full commit SHA of Automation `main`.
Bump the SHA deliberately; never reference a branch or a moving tag.

| Status check name | Gate |
|---|---|
| `Secret scan / scan` | Gitleaks over the commits a pull request adds (older history is scanned on pushes to `main`); findings are redacted. Uses `.gitleaks.toml` if present, else the built-in rules |
| `Dependency security / scan` | OSV-Scanner over `uv.lock`; fails on any known vulnerability, no severity threshold |

Not repeated here on purpose: lint, type-check and tests (`ci.yml`), contract drift (`api-contract.yml`) and OpenAPI
validation (the specification is owned and validated by Documentation, ADR-014). There is no coverage threshold.

### Branch protection

Required checks on `main`: `Lint`, `Type check`, `Test`, `Contract drift`, `Secret scan / scan` and
`Dependency security / scan`, all bound to GitHub Actions. A pull request is required (0 approvals), administrators
are not exempt, and force-push and branch deletion are disallowed. Job and workflow names are stable: renaming one
changes the published check name and silently drops the protection, so update the protection in the same change.
Do not add `paths:` filters to these workflows; a required check skipped by a path filter stays pending forever.

### GitHub-native security features

Secret scanning, push protection and Dependabot security updates are **repository settings**, not code. They cannot
be required status checks (push protection can reject a push, alerts never block a merge), and this repository's
workflows cannot enable them. When last checked through the API (`security_and_analysis`, 2026-10-16) all were
**disabled** (secret scanning, push protection, non-provider patterns, validity checks, Dependabot security updates),
and the gates above did not change that. Until a repository administrator enables them, the two checks above are the
only automated coverage, and a secret pushed straight to a branch is detected only once a pull request is opened.

Locally (with PostgreSQL reachable per `.env.example`):

```bash
uv run ruff check .
DJANGO_SECRET_KEY=x uv run mypy .
DJANGO_SECRET_KEY=x uv run pytest --cov
```

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
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_DB=householdhub \
  -e POSTGRES_USER=householdhub \
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

### Identity (`apps/accounts`)

`accounts.User` is the UUID-keyed authentication principal (ADR-010, ADR-011): the normalized email
(whitespace trimmed, lower case, no provider-specific rewriting) is the unique login identity, enforced by a
unique index plus a database check that only canonical addresses are stored; `name` is the display name; passwords
are Django's; provider identities are allauth `SocialAccount` rows. `is_active` is the disabled state. Email
verification is not stored on the user: `User.is_email_verified` reads allauth's `EmailAddress` (a verified row for
the account's current email), so there is no duplicate flag.

Verification gate: `apps.api.views.ContractViewMixin` answers 403 to an authenticated account that is disabled or
has no verified email before the view's permission classes run, unless the view sets `allow_unverified = True`.
Only public operations and the verification lifecycle the contract allows before verification (`getCurrentUser`,
`resendEmailVerification`, `logout`) may set it; `check_api_contract` fails any other operation that does.

### Transactional email (`apps/email_delivery`)

ADR-015: `queue_email(message, template=..., subject_type=..., subject_id=...)` runs inside the domain
`transaction.atomic()`, persists an `EmailDelivery` row with the domain state and registers
`transaction.on_commit()`. After the commit one bounded synchronous call goes to the provider-neutral adapter
(`adapter.EmailProvider`, timeout `EMAIL_DELIVERY["TIMEOUT_SECONDS"]`), and the outcome is stored. A rollback
discards the row and the email; a provider failure never raises into the caller and never undoes the commit.

| Status | Meaning |
|---|---|
| `pending` | Recorded; the post-commit callback has not claimed it |
| `submitting` | Claimed and persisted before the provider call (a leftover means the process was interrupted) |
| `accepted` | The provider accepted the submission. **Not** confirmation of inbox delivery |
| `failed` | Not accepted (`rejected`, `unavailable`, `not_configured`, `not_submitted`): safe to resend |
| `unknown` | Outcome unknowable (`timeout`, `interrupted`, `unexpected`): treat as possibly sent |

`failed` and `unknown` are recoverable by the owning flow issuing a new delivery (resend with a fresh token); the
message is never stored, so a record cannot be replayed. `manage.py reconcile_email_deliveries` (idempotent;
schedule it like the other cleanup commands) settles records an interrupted process left behind. Records hold only
identifiers, status, attempt count/timing, the provider request id and a fixed error class: no recipient, token,
link or body, and the logs carry the delivery id only. No queue, Redis, Celery or worker is involved.

The managed provider is still open (D02): the default `UnconfiguredProvider` records `failed`/`not_configured`,
and `apps.email_delivery.testing.RecordingProvider` is the test double. `EMAIL_DELIVERY` is a settings constant,
not environment variables, so Infrastructure's `.env.example` is unaffected.

### Sessions and revocation (`apps/accounts/sessions.py`)

Sessions are Django's database-backed sessions (`SESSION_ENGINE = "apps.accounts.sessions"`, 14-day expiry) stored
in `accounts.Session`, whose indexed `user` column is the user-session registry (ADR-011). The engine writes the
column whenever it writes the payload, so revocation deletes rows by owner without decoding or scanning payloads, and
a revoked cookie is anonymous on its next request.

| Event | Result | Wired through |
|---|---|---|
| Logout | Current session revoked | `logout()` |
| Password reset | All sessions revoked | allauth `password_reset` |
| Authenticated password change or set | Current rotated, others revoked | allauth `password_changed` / `password_set` |
| Primary-email change | Current rotated, others revoked | allauth `email_changed` |
| Google link or unlink | Current rotated, others revoked | allauth `social_account_added` / `social_account_removed` |
| Disable (`is_active` false) | All sessions revoked | database trigger (any write path) |
| Restoration (`is_active` true) | All sessions revoked; fresh login required | database trigger |

`revoke_all_sessions`, `revoke_other_sessions` and `rotate_and_revoke_others` are the reusable entry points (for
example for a future soft deletion). Rotation at an identity change keeps only the approved keys
(`ROTATION_PRESERVED_KEYS`: Django's authentication keys and expiry override, allauth's authentication records and
the invitation intent) and rotates the CSRF token. Signup and login go through `establish_session`, whose new
session keeps only a valid invitation intent from the previous one (anonymous, same account or another account).
The ADR-013 invitation intent is set only through `set_invitation_intent(session, invitation_id: UUID, generation: int)`,
so a bearer token cannot be stored there. Django's authentication hash still invalidates sessions after any password
change. Expired rows are removed by the scheduled `python manage.py clearsessions`.

### Authentication (`apps/accounts/views.py`, Backend#8)

`getCsrfToken`, `signup`, `login`, `logout` and `getCurrentUser` are routed under `/api/v1/auth/`. Every response is
`Cache-Control: private, no-store`, and every unsafe call, public ones included, needs `X-CSRFToken`.

- **Signup** validates the ADR-016 password policy (15 to 128 code points, common-password and email/name
  similarity checks, no composition rules), then in one transaction creates the user, its unverified allauth
  `EmailAddress`, an `EmailVerificationBearer` (only the SHA-256 digest of a 256-bit bearer, 24 h) and the
  `EmailDelivery`. The email, whose link carries the bearer only in the URI fragment
  (`FRONTEND_EMAIL_VERIFICATION_PATH`), is submitted after the commit; a failure leaves the account and a
  recoverable delivery. The response reports the delivery's honest status. A registered address is 409.
- **Login** uses Django's `ModelBackend` (hashes for unknown addresses too, refuses disabled accounts). An
  unverified account gets a restricted session: the verification gate keeps everything but the pre-verification
  lifecycle closed.
- **Logout** flushes the session, invitation intent included.

### Email verification and primary-email change (`apps/accounts/verification.py`, `email_change.py`, Backend#35)

Two separate lifecycles with separate bearer tables, so neither accepts the other's bearer. Bearers carry 256 bits,
are stored only as SHA-256 digests, travel only in the email's URI fragment and the POST body, and every unusable
one (unknown, expired, consumed, superseded) gets the same response.

- **`verifyEmail`** (public, `POST /api/v1/auth/email/verify`) consumes an `EmailVerificationBearer` (24 h) and marks
  the allauth `EmailAddress` verified in one transaction, under the account and bearer row locks, so a bearer is
  consumed exactly once. Unusable bearers are 400, an already verified account 409. The bearer never logs anyone in:
  only when the browser's own session is that account's restricted session is it rotated (keeping its invitation
  intent); a cross-device verification creates no session and touches no other.
- **`resendEmailVerification`** (restricted sessions allowed) issues a new bearer, superseding the old one, and a new
  delivery whose honest status it returns; a failed delivery is recovered by resending. Verified accounts get 409.
- **`requestPrimaryEmailChange`** and **`verifyPrimaryEmailChange`** (verified accounts only) both need an
  authentication in the current session within `ACCOUNT_REAUTHENTICATION_TIMEOUT` (ADR-016: 5 minutes; no exemption
  for passwordless accounts), else 403. The request stores a `PrimaryEmailChange` (1 h), supersedes any earlier one,
  emails the new address (`FRONTEND_PRIMARY_EMAIL_CHANGE_PATH`) and binds the change to the session through
  `session_binding`, an HMAC of the session key under `SECRET_KEY` stored on the row (never the key, and no
  session write, so overlapping requests of one session cannot leave a stale binding). The current address stays
  in effect and the new one is not reserved. A current or used address is 409. The verification must come from
  the same session; in one transaction it consumes the bearer, makes the new address the only, verified primary
  `EmailAddress`, rotates the current session, revokes all others (allauth `email_changed`) and queues a security
  notice to the previous address (no link or new address), submitted only after the commit. Anything else,
  including an address taken meanwhile, is 409 and changes nothing, notice included.

Rate limits (ADR-016) are `verify_email_ip`, `resend_email_verification_user`, `email_change_user`,
`email_change_email` and `verify_email_change_user` in `AUTH_RATE_LIMITS`.

### Password recovery and change (`apps/accounts/password_recovery.py`, Backend#36)

`requestPasswordReset`, `resetPassword` and `changePassword` (`/api/v1/auth/forgot-password`, `reset-password`,
`change-password`). The reset bearer is a separate `PasswordResetBearer` lifecycle: 256 bits, only its SHA-256 digest
stored, 1 hour (`AUTH_PASSWORD_RESET_LIFETIME_SECONDS`), mailed only in the URI fragment of
`FRONTEND_PASSWORD_RESET_PATH` and sent back in the POST body. A new request, a reset and a password change all
supersede an earlier bearer; consumption is atomic with the password change under the account and bearer row locks.

- **`requestPasswordReset`** (public) answers `202` with one fixed body for every syntactically valid address. Unknown,
  disabled and passwordless (Google-only) accounts get no bearer and no email. The email of an eligible account (an
  unverified one too: it proves mailbox ownership) is queued with the bearer and submitted after the HTTP response
  was closed, on its own thread and connection (`DeferredSubmissions`, still commit -> bounded provider call ->
  durable status of ADR-015), so a slow or failing provider neither delays the caller nor keeps a web worker busy.
  Background capacity is bounded per process by `EMAIL_DELIVERY["MAX_BACKGROUND_SUBMISSIONS"]` (4) with no queue, and
  it is *uniform*: every valid request, eligible or not, takes one slot for exactly
  `EMAIL_DELIVERY["BACKGROUND_SLOT_SECONDS"]` (6 s, above the provider timeout) whatever the provider's latency, and
  is refused identically when none is free. Otherwise one caller could occupy slots to learn, from whether its own
  email was submitted, whether another address has an account. A refused submission does no database work: its
  delivery stays `pending` and `reconcile_email_deliveries` settles it as `failed` / `not_submitted`. The threads are
  non-daemon (a graceful shutdown waits at most the hold), and a killed process leaves `submitting` / `pending`,
  which the same command settles honestly. The response never comes sooner than
  `AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS` to cover the database work only an existing account does. A failed
  delivery is recovered by requesting again. Limits: `password_reset_ip` (20/h) and `password_reset_email` (3/h, counted
  for unknown addresses too, same `429`).
- **`resetPassword`** (public) validates the ADR-016 policy (a policy failure is a retryable `400` field error and leaves
  the bearer usable), consumes the bearer, sets the password and revokes every session through allauth
  `password_reset`, the caller's own included. Every unusable bearer (unknown, expired, consumed, superseded, another
  purpose, address changed, disabled account) is the same `400`; an account with no usable password is `409`. It never
  logs anyone in and never verifies the email. Limit: `reset_password_ip` (20 per 5 min).
- **`changePassword`** verifies the current password (a wrong one is `400` on `current_password`, so the client does not
  mistake it for an expired session; an account without a usable password is `409`), applies the new one under the
  account lock (a concurrent change makes the current password stale) and rotates the current session while
  revoking the others (allauth `password_changed`). The contract declares no `429`, so it has no limit (ADR-016).

### Rate limiting (`apps/ratelimit`, ADR-016)

`limiter.consume(action, ...)` takes a slot of each rate in `AUTH_RATE_LIMITS` with a single
`INSERT ... ON CONFLICT DO UPDATE ... WHERE hits < limit RETURNING` per rate, so concurrent requests can never exceed
a limit; a refusal is `429 RATE_LIMITED` with `Retry-After`. Keys are HMAC-SHA256 under `SECRET_KEY` (no address or
IP is stored), the client IP is the peer address unless `RATE_LIMIT_TRUSTED_PROXY_COUNT` names trusted proxies, and
IPv6 clients are grouped per /64. A database failure fails the request (closed). django-allauth's limiter is off
(`ACCOUNT_RATE_LIMITS = False`). Ended windows are deleted by the scheduled, idempotent
`python manage.py clear_expired_rate_limits`.

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
checking out the pinned Documentation commit; lint, type-check and tests run in `.github/workflows/ci.yml` (see CI).

To adopt a newer contract, in the same PR as the code that needs it:

```bash
git -C ../Documentation rev-parse HEAD
git -C ../Documentation show <sha>:api/openapi.yaml | shasum -a 256
```

then update `commit` and `sha256` in `contract/documentation-revision.json`.

Not verifiable statically (covered by per-operation API tests as operations land): response status codes,
request/response bodies and field nullability. The check is exercised with
`HOUSEHOLDHUB_OPENAPI_SPEC=<path> uv run pytest` against the real contract in addition to the CI step.
