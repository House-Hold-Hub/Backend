"""Session engine, rotation and revocation for the ADR-011 session lifecycle.

``SESSION_ENGINE = "apps.accounts.sessions"`` stores Django's database-backed sessions in
``accounts.Session``, whose indexed ``user`` column is the user-session registry. The engine writes
the column from the payload whenever it writes the payload, so revocation is a ``DELETE`` by that
column: no payload is decoded or scanned, and a deleted row makes the cookie anonymous on its next
request (Django finds no session).

Revocation matrix (ADR-011, security model, PRD Identity IA-FR-012 to IA-FR-016):

=====================================  ===============================================================
Event                                  Mechanism
=====================================  ===============================================================
Normal logout                          ``django.contrib.auth.logout`` (``session.flush()`` deletes it)
Password reset                         ``revoke_all_sessions`` (allauth ``password_reset``)
Authenticated password change          ``rotate_and_revoke_others`` (allauth ``password_changed`` and
                                       ``password_set``)
Primary-email change                   ``rotate_and_revoke_others`` (allauth ``email_changed``)
OAuth link or unlink                   ``rotate_and_revoke_others`` (``social_account_added`` and
                                       ``social_account_removed``)
Account disable or soft deletion       Disable: the ``is_active`` trigger (migration 0003). Soft
                                       deletion has no model yet; it calls ``revoke_all_sessions``.
Account restoration                    The same trigger deletes every session when ``is_active``
                                       becomes true, so only a fresh login creates one.
=====================================  ===============================================================

The receivers live in ``signals.py``. Recent reauthentication, required before a primary-email change
and before linking or unlinking, is enforced by the endpoints that perform those changes with
``recently_authenticated``.

Concurrency: every write that gives a row an owner, every rotation of an owned session and every
revocation take a row lock on the owning ``User`` (``FOR NO KEY UPDATE``, which an ``UPDATE`` of the
user also takes). A rotation that started before a revocation therefore either commits first, and its
new row is then deleted, or finds its old row gone and carries no state into the new key. A request
that loaded a session before it was revoked cannot write it back: Django's update raises
``UpdateError`` (``SessionInterrupted``, 400) because the row no longer exists.

Django's authentication hash stays in force: a session whose hash no longer matches the password is
flushed by ``django.contrib.auth.get_user`` on its next request.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from allauth.account.authentication import AUTHENTICATION_METHODS_SESSION_KEY
from asgiref.sync import sync_to_async
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY, get_user_model, login, logout
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.db import SessionStore as DatabaseSessionStore
from django.core.exceptions import ValidationError
from django.db import router, transaction
from django.middleware.csrf import rotate_token
from django.utils.crypto import salted_hmac

if TYPE_CHECKING:
    from .models import Session

INVITATION_INTENT_SESSION_KEY = "householdhub_invitation_intent"
SESSION_BINDING_SALT = "householdhub.accounts.session-binding"

# The only session state that survives ``rotate_session`` (security model: "Only explicitly approved,
# non-secret state may survive rotation"). Django's authentication keys and expiry override keep the
# session what it was; allauth's authentication records keep allauth's reauthentication behaviour
# unchanged; the invitation intent is the ADR-013 handoff. Anything else is dropped.
ROTATION_PRESERVED_KEYS = frozenset(
    {
        SESSION_KEY,
        BACKEND_SESSION_KEY,
        HASH_SESSION_KEY,
        "_session_expiry",
        AUTHENTICATION_METHODS_SESSION_KEY,
        INVITATION_INTENT_SESSION_KEY,
    }
)


def _owner_id(data: Any) -> Any:
    """The authenticated user id a session payload claims, as a primary-key value, or ``None``."""
    value = data.get(SESSION_KEY)
    if value is None:
        return None
    try:
        return get_user_model()._meta.pk.to_python(value)
    except ValidationError:
        return None


def _lock_account(user_id: Any, using: str):
    """Lock the user row for the rest of the transaction; ``None`` when the user no longer exists."""
    return get_user_model()._default_manager.using(using).select_for_update(no_key=True).filter(pk=user_id).first()


def _session_model():
    from .models import Session

    return Session


class SessionStore(DatabaseSessionStore):
    """Django's database session store, writing the ``Session.user`` registry column."""

    def __init__(self, session_key: str | None = None) -> None:
        super().__init__(session_key)
        self._row_owner_id: Any = None  # owner of the stored row, as last loaded or written
        self._owner_to_write: Any = None

    @classmethod
    def get_model_class(cls):
        return _session_model()

    def _get_session_from_db(self):
        row = cast("Session | None", super()._get_session_from_db())  # type: ignore[misc]
        self._row_owner_id = row.user_id if row is not None else None
        return row

    def create_model_instance(self, data):
        instance = cast("Session", super().create_model_instance(data))
        instance.user_id = self._owner_to_write
        return instance

    def save(self, must_create: bool = False) -> None:
        if self.session_key is None:
            return self.create()
        owner = _owner_id(self._get_session(no_load=must_create))  # type: ignore[attr-defined]
        using = router.db_for_write(self.model)
        with transaction.atomic(using=using):
            if owner is not None and (must_create or owner != self._row_owner_id):
                # A new owner: serialize with revocations and never reference a deleted user.
                account = _lock_account(owner, using)
                owner = account.pk if account is not None else None
            self._owner_to_write = owner
            super().save(must_create=must_create)
        self._row_owner_id = owner

    def cycle_key(self) -> None:
        """New key, same data, unless the session was revoked while this request held it.

        For an owned session the old row is deleted first under the account lock. If it is already
        gone (revoked, or the user deleted), the new key starts empty instead of resurrecting it.
        """
        data = self._session  # type: ignore[attr-defined]
        old_key = self.session_key
        owner = _owner_id(data)
        using = router.db_for_write(self.model)
        with transaction.atomic(using=using):
            if owner is not None:
                alive = _lock_account(owner, using) is not None
                if old_key is not None:
                    deleted, _ = self.model._default_manager.using(using).filter(session_key=old_key).delete()
                    alive = alive and deleted > 0
                    old_key = None
                if not alive:
                    data = {}
            self._session_cache = data
            self.create()
            if old_key:
                self.delete(old_key)

    # The async API must not bypass the registry column or the rotation rules.
    async def asave(self, must_create: bool = False) -> None:
        await sync_to_async(self.save)(must_create)

    async def acycle_key(self) -> None:
        await sync_to_async(self.cycle_key)()


# ---- revocation and rotation ----------------------------------------------------------------------


def _is_session_of(request, user) -> bool:
    session = getattr(request, "session", None)
    return session is not None and _owner_id(session) == user.pk


def revoke_all_sessions(user, *, request=None) -> int:
    """Delete every session of ``user``; returns how many were deleted.

    When ``request`` carries one of those sessions it is also logged out, so the response does not
    try to save a session that no longer exists and the rest of the request runs anonymously.
    """
    Session = _session_model()
    using = router.db_for_write(Session)
    with transaction.atomic(using=using):
        _lock_account(user.pk, using)
        deleted, _ = Session._default_manager.using(using).filter(user_id=user.pk).delete()
    if request is not None and _is_session_of(request, user):
        logout(request)
    return deleted


def revoke_other_sessions(user, *, keep_session_key: str | None) -> int:
    """Delete every session of ``user`` except ``keep_session_key``; returns how many were deleted."""
    Session = _session_model()
    using = router.db_for_write(Session)
    with transaction.atomic(using=using):
        _lock_account(user.pk, using)
        sessions = Session._default_manager.using(using).filter(user_id=user.pk)
        if keep_session_key:
            sessions = sessions.exclude(session_key=keep_session_key)
        deleted, _ = sessions.delete()
    return deleted


def rotate_session(request) -> bool:
    """Give the request's session a new key that carries only ``ROTATION_PRESERVED_KEYS``.

    Also rotates the CSRF token, as ``login()`` does. Returns ``False`` when the session had been
    revoked meanwhile: it is then anonymous and so is ``request.user``.
    """
    session = request.session
    for key in [key for key in session.keys() if key not in ROTATION_PRESERVED_KEYS]:
        del session[key]
    if INVITATION_INTENT_SESSION_KEY in session and get_invitation_intent(session) is None:
        del session[INVITATION_INTENT_SESSION_KEY]  # malformed: never carried forward
    session.cycle_key()
    rotate_token(request)
    if SESSION_KEY not in session:
        request.user = AnonymousUser()
        return False
    return True


def rotate_and_revoke_others(request, user) -> int:
    """Identity-security boundary: rotate the current session of ``user``, revoke all the others.

    The current session keeps its login with an authentication hash recomputed from the stored
    password, so a password change preserves it. When ``request`` has no session of ``user`` (for
    example a change confirmed from another browser) there is no current session to keep and every
    session of the account is revoked. Returns how many sessions were revoked.
    """
    Session = _session_model()
    using = router.db_for_write(Session)
    keep = None
    with transaction.atomic(using=using):
        account = _lock_account(user.pk, using)
        if account is not None and _is_session_of(request, user):
            request.session[HASH_SESSION_KEY] = account.get_session_auth_hash()
            if rotate_session(request):
                keep = request.session.session_key
        return revoke_other_sessions(user, keep_session_key=keep)


def establish_session(request, user, *, backend: str) -> None:
    """Authentication boundary of signup and login: log ``user`` in under a new session key.

    The new session carries nothing from the old one except a valid pending invitation intent (ADR-011,
    ADR-013), whether the browser was anonymous, signed in as the same account or as another one; the
    old session row is deleted by the key rotation. ``login()`` also rotates the CSRF token. The
    password authentication is recorded the way django-allauth does, so its recent-reauthentication
    checks (Backend#35) see it.
    """
    from allauth.account.internal.flows.login import record_authentication

    session = request.session
    intent = get_invitation_intent(session)
    session.clear()
    login(request, user, backend=backend)
    if intent is not None:
        set_invitation_intent(session, intent.invitation_id, intent.generation)
    record_authentication(request, user, method="password")


def recently_authenticated(request) -> bool:
    """Whether the current session authenticated within ``ACCOUNT_REAUTHENTICATION_TIMEOUT`` (ADR-016: 5 minutes).

    Reads the authentication records django-allauth keeps in the session (``establish_session`` writes
    them through ``record_authentication``), so only an authentication performed *in this session* counts.
    Unlike allauth's ``did_recently_authenticate`` it never waives the check for an account without a
    usable password: anything that cannot be established is ``False``.
    """
    from allauth.account import app_settings
    from allauth.account.authentication import get_authentication_records

    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated or _owner_id(request.session) != user.pk:
        return False
    records = get_authentication_records(request)
    if not isinstance(records, list) or not records or not isinstance(records[-1], dict):
        return False
    at = records[-1].get("at")
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        return False
    return time.time() - at < app_settings.REAUTHENTICATION_TIMEOUT


def session_binding(request) -> str | None:
    """A keyed digest identifying the request's current session, or ``None`` when it has no key yet.

    Binds a database record to the session that created it (the pending primary-email change) without
    writing the session or persisting its key: HMAC-SHA256 under ``SECRET_KEY`` cannot be turned back into
    the key, and it changes whenever the key rotates (login, identity-security boundaries), so a binding
    never carries over into another session. Being derived rather than stored, it needs no session write and
    cannot be overwritten by a concurrent request of the same session.
    """
    key = getattr(getattr(request, "session", None), "session_key", None)
    if not key:
        return None
    return salted_hmac(SESSION_BINDING_SALT, key, algorithm="sha256").hexdigest()


# ---- invitation intent (ADR-013) -------------------------------------------------------------------


@dataclass(frozen=True)
class InvitationIntent:
    """The non-secret, generation-bound reference a successful invitation exchange leaves in the session.

    It is never the bearer token or anything that can stand in for it: only the Invitation identifier
    and the token generation that was validated, which acceptance must revalidate against the current
    Invitation (ADR-013).
    """

    invitation_id: uuid.UUID
    generation: int


def _valid_generation(value: Any) -> bool:
    return type(value) is int and value >= 0


def set_invitation_intent(session, invitation_id: uuid.UUID, generation: int) -> InvitationIntent:
    if not isinstance(invitation_id, uuid.UUID):
        raise TypeError("invitation_id must be a UUID.")
    if not _valid_generation(generation):
        raise TypeError("generation must be a non-negative integer.")
    session[INVITATION_INTENT_SESSION_KEY] = {"invitation_id": str(invitation_id), "generation": generation}
    return InvitationIntent(invitation_id, generation)


def get_invitation_intent(session) -> InvitationIntent | None:
    stored = session.get(INVITATION_INTENT_SESSION_KEY)
    if not isinstance(stored, dict) or set(stored) != {"invitation_id", "generation"}:
        return None
    try:
        invitation_id = uuid.UUID(stored["invitation_id"])
    except (TypeError, ValueError, AttributeError):
        return None
    if not _valid_generation(stored["generation"]):
        return None
    return InvitationIntent(invitation_id, stored["generation"])


def clear_invitation_intent(session) -> None:
    session.pop(INVITATION_INTENT_SESSION_KEY, None)
