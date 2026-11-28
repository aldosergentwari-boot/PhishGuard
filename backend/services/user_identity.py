import secrets
from flask import session


def get_browser_identity():
    """Return the persistent anonymous identity for this browser session."""
    user_id = session.get("phishguard_user_id")
    if not isinstance(user_id, str) or not user_id:
        user_id = secrets.token_urlsafe(32)
        session["phishguard_user_id"] = user_id
    session.permanent = True
    return user_id


def get_current_user_id():
    """Return an account owner when signed in, otherwise the browser identity."""
    account_id = session.get("account_id")
    if isinstance(account_id, int) and account_id > 0:
        return f"account:{account_id}"
    return get_browser_identity()
