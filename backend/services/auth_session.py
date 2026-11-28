"""Helpers for keeping owner and customer authentication state independent.

Both identities live in the same signed Flask browser session, but use
separate key namespaces. Clearing one identity must never clear the other.
"""

USER_AUTH_SESSION_KEYS = (
    "account_id",
    "account_email",
    "session_version",
)

ADMIN_AUTH_SESSION_KEYS = (
    "phishguard_admin_user_id",
    "phishguard_admin_email",
    "phishguard_admin_session_version",
)


def clear_user_auth_session(session):
    """Remove only customer authentication state; preserve owner and CSRF state."""
    for key in USER_AUTH_SESSION_KEYS:
        session.pop(key, None)


def clear_admin_auth_session(session):
    """Remove only owner authentication state; preserve customer and CSRF state."""
    for key in ADMIN_AUTH_SESSION_KEYS:
        session.pop(key, None)
