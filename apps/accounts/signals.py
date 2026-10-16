"""django-allauth lifecycle events wired to the ADR-011 revocation matrix (``sessions.py``).

Logout needs no receiver (``logout()`` deletes the session) and neither do disable and restoration
(the ``is_active`` trigger). Each receiver runs in the request that performed the change.
"""

from collections.abc import Callable
from typing import Any

from .sessions import revoke_all_sessions, rotate_and_revoke_others


def on_password_reset(sender, request, user, **kwargs):
    revoke_all_sessions(user, request=request)


def on_password_changed(sender, request, user, **kwargs):
    # Covers allauth's password change and password set (a first password for a social-only account).
    rotate_and_revoke_others(request, user)


def on_email_changed(sender, request, user, **kwargs):
    rotate_and_revoke_others(request, user)


def on_social_account_added(sender, request, sociallogin, **kwargs):
    rotate_and_revoke_others(request, sociallogin.user)


def on_social_account_removed(sender, request, socialaccount, **kwargs):
    rotate_and_revoke_others(request, socialaccount.user)


def connect():
    from allauth.account import signals as account_signals
    from allauth.socialaccount import signals as social_signals

    receivers: list[tuple[Any, Callable[..., Any]]] = [
        (account_signals.password_reset, on_password_reset),
        (account_signals.password_changed, on_password_changed),
        (account_signals.password_set, on_password_changed),
        (account_signals.email_changed, on_email_changed),
        (social_signals.social_account_added, on_social_account_added),
        (social_signals.social_account_removed, on_social_account_removed),
    ]
    for signal, receiver in receivers:
        # dispatch_uid is per signal, so one receiver may serve two signals.
        signal.connect(receiver, dispatch_uid=f"accounts.sessions.{receiver.__name__}")
