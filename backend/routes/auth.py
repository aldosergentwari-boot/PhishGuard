import hashlib
import secrets

from flask import Blueprint, jsonify, request, session

from backend.database.auth_service import auth_service
from backend.services.user_identity import get_browser_identity

auth_bp = Blueprint("auth", __name__)


@auth_bp.get("/api/auth/csrf")
def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return jsonify({"success": True, "csrf_token": token})


@auth_bp.before_app_request
def protect_auth_mutations():
    # Reject stale/revoked account sessions before any route can use account_id.
    account_id = session.get("account_id")
    if account_id is not None:
        user = auth_service.get_user(account_id) if isinstance(account_id, int) and account_id > 0 else None
        if (
            not user
            or session.get("session_version") != user.get("session_version", 0)
            or session.get("account_email") != user.get("email")
        ):
            session.clear()

    protected = {
        ("POST", "/api/auth/register"),
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/logout"),
        ("POST", "/api/billing/checkout"),
        ("DELETE", "/api/history"),
    }
    if (request.method, request.path) in protected or (
        request.method == "DELETE" and request.path.startswith("/api/history/")
    ):
        expected = session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            return jsonify({"success": False, "error": "Security token missing or invalid. Refresh and try again."}), 403


def _payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _rate_limited(operation, email):
    normalized = email.strip().lower() if isinstance(email, str) else ""
    ip = request.remote_addr or "unknown"
    ip_bucket = hashlib.sha256(f"{operation}:ip:{ip}".encode()).hexdigest()
    email_bucket = hashlib.sha256(f"{operation}:email:{normalized}".encode()).hexdigest()
    return not (
        auth_service.allow_auth_attempt(ip_bucket, limit=30) and
        auth_service.allow_auth_attempt(email_bucket, limit=8)
    )


def _establish_session(user):
    session.clear()
    session["account_id"] = user["id"]
    session["account_email"] = user["email"]
    session["session_version"] = user.get("session_version", 0)
    session.permanent = True


def _claim_anonymous_history(user_id, anonymous_id):
    from backend.database.history_service import get_history_service
    service = get_history_service()
    with service.get_connection() as db:
        db.execute(
            "UPDATE scan_history SET owner_id=? WHERE owner_id=?",
            (f"account:{user_id}", anonymous_id),
        )


@auth_bp.post("/api/auth/register")
def register():
    data = _payload()
    if _rate_limited("register", data.get("email")):
        return jsonify({"success": False, "error": "Too many registration attempts. Try again in 15 minutes."}), 429
    try:
        user = auth_service.create_user(data.get("email"), data.get("password"))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    anonymous_id = get_browser_identity()
    _claim_anonymous_history(user["id"], anonymous_id)
    _establish_session(user)
    return jsonify({"success": True, "user": {"id": user["id"], "email": user["email"]},
                    "plan": "free"}), 201


@auth_bp.post("/api/auth/login")
def login():
    data = _payload()
    if _rate_limited("login", data.get("email")):
        return jsonify({"success": False, "error": "Too many login attempts. Try again in 15 minutes."}), 429
    password = data.get("password")
    if not isinstance(password, str):
        return jsonify({"success": False, "error": "Invalid email or password."}), 401
    user = auth_service.authenticate(data.get("email"), password)
    if not user:
        return jsonify({"success": False, "error": "Invalid email or password."}), 401
    anonymous_id = get_browser_identity()
    _claim_anonymous_history(user["id"], anonymous_id)
    _establish_session(user)
    return jsonify({"success": True, "user": {"id": user["id"], "email": user["email"]}}), 200


@auth_bp.get("/api/auth/me")
def current_user():
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": True, "authenticated": False, "user": None}), 200
    user = auth_service.get_user(user_id)
    if not user or session.get("session_version") != user.get("session_version", 0):
        session.clear()
        return jsonify({"success": True, "authenticated": False, "user": None}), 200
    from backend.services.plan_service import get_account_plan
    return jsonify({"success": True, "authenticated": True,
                    "user": {"id": user["id"], "email": user["email"], "created_at": user["created_at"]},
                    "subscription": get_account_plan(user["id"])}), 200


@auth_bp.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out."}), 200
