import secrets
from flask import session


def get_current_user_id():
    """
    Gives each browser session a private, persistent identity.
    No account or login is required.
    """
    user_id = session.get("phishguard_user_id")

    if not isinstance(user_id, str) or not user_id:
        user_id = secrets.token_urlsafe(32)
        session["phishguard_user_id"] = user_id

    # Keep the browser identity across browser restarts.
    session.permanent = True

    return user_id
