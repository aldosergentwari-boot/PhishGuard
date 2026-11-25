import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, redirect, request, session
from werkzeug.security import generate_password_hash

from backend.database.auth_service import auth_service
from backend.services.user_identity import get_browser_identity
from backend.services import email_service
from backend.services.profile_utils import USERNAME_RE, validate_profile_image

auth_bp = Blueprint("auth", __name__)


def _token_digest(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _issue_email_token(user_id, purpose, expires_in):
    raw_token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + expires_in).isoformat()
    auth_service.create_email_token(
        user_id, purpose, _token_digest(raw_token), expires_at
    )
    return raw_token


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
        ("POST", "/api/auth/profile"),
        ("POST", "/api/auth/verification/resend"),
        ("POST", "/api/auth/password-reset/request"),
        ("POST", "/api/auth/password-reset/confirm"),
        ("POST", "/api/admin/password-reset/request"),
        ("POST", "/api/admin/password-reset/confirm"),
        ("POST", "/api/admin/login"),
        ("POST", "/api/admin/logout"),
        ("POST", "/api/admin/profile"),
        ("POST", "/api/admin/scan-credits"),
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
    # Rotate the CSRF token whenever authentication state changes. Keeping a
    # fresh token in the new session avoids a tokenless interval after login.
    session.clear()
    session["csrf_token"] = secrets.token_urlsafe(32)
    session["account_id"] = user["id"]
    session["account_email"] = user["email"]
    session["session_version"] = user.get("session_version", 0)
    session.permanent = True


def _claim_anonymous_history(user_id, anonymous_id):
    from backend.database.history_service import get_history_service
    service = get_history_service()
    with service.get_connection() as db:
        account_owner = f"account:{user_id}"
        db.execute(
            "UPDATE scan_history SET owner_id=? WHERE owner_id=?",
            (account_owner, anonymous_id),
        )
        # Move quota records with claimed guest history; never drop usage
        # when a guest converts their browser history into an account.
        db.execute(
            "UPDATE scan_usage SET owner_id=? WHERE owner_id=?",
            (account_owner, anonymous_id),
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

    raw_token = _issue_email_token(user["id"], "verify_email", timedelta(hours=24))
    email_sent = email_service.send_verification_email(user["email"], raw_token)
    anonymous_id = get_browser_identity()
    _claim_anonymous_history(user["id"], anonymous_id)
    _establish_session(user)
    return jsonify({
        "success": True,
        "user": {"id": user["id"], "email": user["email"], "email_verified": False},
        "plan": "free",
        "email_verification_required": True,
        "email_sent": email_sent,
        "message": (
            "Account created. Check your email to verify your address."
            if email_sent else
            "Account created. Email delivery is not configured or is temporarily unavailable. You can request another verification email later."
        ),
    }), 201


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
    return jsonify({
        "success": True,
        "user": {
            "id": user["id"], "email": user["email"],
            "email_verified": user["email_verified"],
        },
    }), 200


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
    return jsonify({
        "success": True, "authenticated": True,
        "user": {
            "id": user["id"], "email": user["email"],
            "created_at": user["created_at"],
            "email_verified": bool(user["email_verified"]),
            "username": user.get("username"),
            "profile_image": user.get("profile_image"),
        },
        "subscription": get_account_plan(user["id"]),
    }), 200


@auth_bp.post("/api/auth/profile")
def update_user_profile():
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": False, "error": "Sign in to update your profile."}), 401
    data = _payload()
    username = data.get("username")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username.strip()):
        return jsonify({"success": False, "error": "Username must be 3–24 characters using letters, numbers, dots, underscores or hyphens."}), 400
    username = username.strip()
    try:
        profile_image = validate_profile_image(data.get("profile_image"))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    try:
        with auth_service.connection() as db:
            db.execute("UPDATE users SET username=?, profile_image=? WHERE id=? AND is_active=1",
                       (username, profile_image, user_id))
    except Exception as exc:
        import sqlite3
        if isinstance(exc, sqlite3.IntegrityError):
            return jsonify({"success": False, "error": "That username is already taken. Choose another one."}), 409
        raise
    user = auth_service.get_user(user_id)
    return jsonify({"success": True, "message": "Profile updated successfully.",
                    "user": {"username": user.get("username"), "profile_image": user.get("profile_image")}}), 200


@auth_bp.post("/api/auth/verification/resend")
def resend_verification():
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": False, "error": "Sign in to request email verification."}), 401
    user = auth_service.get_user(user_id)
    if not user or user.get("email_verified"):
        return jsonify({"success": True, "message": "If verification is needed, an email will be sent."}), 200
    if _rate_limited("verify", user["email"]):
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429
    raw_token = _issue_email_token(user_id, "verify_email", timedelta(hours=24))
    sent = email_service.send_verification_email(user["email"], raw_token)
    return jsonify({
        "success": True,
        "email_sent": sent,
        "message": "Verification email sent." if sent else "Email delivery is unavailable. Check the mail settings and try again.",
    }), 200


@auth_bp.get("/api/auth/verify-email")
def verify_email():
    raw_token = request.args.get("token", "")
    valid_shape = isinstance(raw_token, str) and 20 <= len(raw_token) <= 200
    verified = auth_service.verify_email_token(_token_digest(raw_token)) if valid_shape else False
    return redirect("/?email_verified=1" if verified else "/?email_verified=0")


@auth_bp.post("/api/auth/password-reset/request")
def request_password_reset():
    data = _payload()
    email = data.get("email")
    if _rate_limited("password-reset", email):
        # Keep the same response to avoid account enumeration.
        return jsonify({"success": True, "message": "If an account matches that address, password reset instructions will be sent."}), 200
    if isinstance(email, str):
        user = None
        normalized = email.strip().lower()
        if len(normalized) <= 254:
            with auth_service.connection() as db:
                row = db.execute(
                    "SELECT id,email FROM users WHERE email=? AND is_active=1",
                    (normalized,),
                ).fetchone()
            user = dict(row) if row else None
        if user:
            raw_token = _issue_email_token(user["id"], "password_reset", timedelta(minutes=30))
            email_service.send_password_reset_email(user["email"], raw_token)
    return jsonify({
        "success": True,
        "message": "If an account matches that address, password reset instructions will be sent.",
    }), 200


@auth_bp.post("/api/auth/password-reset/confirm")
def confirm_password_reset():
    data = _payload()
    raw_token = data.get("token")
    password = data.get("password")
    if not isinstance(raw_token, str) or not 20 <= len(raw_token) <= 200:
        return jsonify({"success": False, "error": "This password reset link is invalid or has expired."}), 400
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return jsonify({"success": False, "error": "Password must contain 12 to 128 characters."}), 400
    password_hash = generate_password_hash(password, method="scrypt")
    changed = auth_service.reset_password_with_token(
        _token_digest(raw_token), password_hash
    )
    if not changed:
        return jsonify({"success": False, "error": "This password reset link is invalid or has expired."}), 400
    session.clear()
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({
        "success": True,
        "message": "Password updated. Sign in using your new password.",
    }), 200


@auth_bp.post("/api/auth/logout")
def logout():
    session.clear()
    # Leave the anonymous browser session with a fresh token so the next
    # sign-in or password-reset request starts from a valid CSRF state.
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"success": True, "message": "Logged out."}), 200
