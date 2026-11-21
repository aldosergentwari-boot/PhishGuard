import hashlib
import secrets
import os
import time
from flask import Blueprint, jsonify, request, session
from backend.database.auth_service import auth_service
from backend.services.user_identity import get_browser_identity
from backend.services.email_service import send_password_reset_email

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
    if request.path in ("/api/auth/register", "/api/auth/login", "/api/auth/logout", "/api/auth/password-reset/request", "/api/auth/password-reset/confirm") and request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            return jsonify({"success": False, "error": "Security token missing or invalid. Refresh and try again."}), 403



def _auth_rate_limited(operation, email):
    normalized_email = (email or "").strip().lower()
    client_ip = request.remote_addr or "unknown"
    ip_bucket = hashlib.sha256(f"{operation}:ip:{client_ip}".encode()).hexdigest()
    email_bucket = hashlib.sha256(f"{operation}:email:{normalized_email}".encode()).hexdigest()
    ip_allowed = auth_service.allow_auth_attempt(ip_bucket, limit=30, window_seconds=900)
    email_allowed = auth_service.allow_auth_attempt(email_bucket, limit=8, window_seconds=900)
    return not (ip_allowed and email_allowed)

def _payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@auth_bp.post("/api/auth/register")
def register():
    data = _payload()
    if _auth_rate_limited("register", data.get("email")):
        return jsonify({"success": False, "error": "Too many registration attempts. Try again in 15 minutes."}), 429
    try:
        user = auth_service.create_user(data.get("email"), data.get("password"))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    # Move only this browser's anonymous scans into the new account.
    anonymous_id = get_browser_identity()
    account_owner = f"account:{user['id']}"
    from backend.database.history_service import get_history_service
    service = get_history_service()
    with service.get_connection() as db:
        db.execute(
            "UPDATE scan_history SET owner_id = ? WHERE owner_id = ?",
            (account_owner, anonymous_id)
        )

    session.clear()
    session["account_id"] = user["id"]
    session["account_email"] = user["email"]
    session["session_version"] = user.get("session_version", 0)
    session.permanent = True
    return jsonify({"success": True, "user": user}), 201


@auth_bp.post("/api/auth/login")
def login():
    data = _payload()
    if _auth_rate_limited("login", data.get("email")):
        return jsonify({"success": False, "error": "Too many login attempts. Try again in 15 minutes."}), 429
    user = auth_service.authenticate(data.get("email"), data.get("password"))
    if not user:
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    anonymous_id = get_browser_identity()
    account_owner = f"account:{user['id']}"
    from backend.database.history_service import get_history_service
    service = get_history_service()
    with service.get_connection() as db:
        db.execute(
            "UPDATE scan_history SET owner_id = ? WHERE owner_id = ?",
            (account_owner, anonymous_id)
        )

    session.clear()
    session["account_id"] = user["id"]
    session["account_email"] = user["email"]
    session["session_version"] = user.get("session_version", 0)
    session.permanent = True
    return jsonify({"success": True, "user": user}), 200


@auth_bp.get("/api/auth/me")
def current_user():
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": True, "authenticated": False, "user": None}), 200
    user = auth_service.get_user(user_id)
    if not user or session.get("session_version") != user.get("session_version", 0):
        session.clear()
        return jsonify({"success": True, "authenticated": False, "user": None}), 200
    return jsonify({"success": True, "authenticated": True, "user": {
        "id": user["id"], "email": user["email"], "created_at": user["created_at"]
    }}), 200


@auth_bp.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out."}), 200

@auth_bp.post("/api/auth/password-reset/request")
def request_password_reset():
    data = _payload()
    email = (data.get("email") or "").strip().lower()
    if _auth_rate_limited("password-reset", email):
        return jsonify({"success": True, "message": "If that account exists, a reset link will be sent."}), 200

    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = time.time() + 1800
    created = auth_service.create_password_reset(email, token_hash, expires_at)
    if created:
        base_url = os.getenv("PUBLIC_APP_URL", "").rstrip("/")
        if base_url.startswith("https://"):
            try:
                send_password_reset_email(email, f"{base_url}/reset-password?token={raw_token}")
            except Exception:
                pass
    return jsonify({
        "success": True,
        "message": "If that account exists, a reset link will be sent."
    }), 200


@auth_bp.post("/api/auth/password-reset/confirm")
def confirm_password_reset():
    data = _payload()
    token = data.get("token")
    password = data.get("password")
    if not isinstance(token, str) or not token or len(token) > 256:
        return jsonify({"success": False, "error": "Invalid or expired reset link."}), 400
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        changed = auth_service.consume_password_reset(token_hash, password)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    if not changed:
        return jsonify({"success": False, "error": "Invalid or expired reset link."}), 400
    return jsonify({
        "success": True,
        "message": "Password updated. Please sign in with your new password."
    }), 200
