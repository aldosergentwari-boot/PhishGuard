import calendar
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session
from werkzeug.security import generate_password_hash

from backend.services import email_service
from backend.services.profile_utils import validate_profile_image

from backend.database.auth_service import auth_service
from backend.services.auth_session import clear_admin_auth_session

admin_bp = Blueprint("admin", __name__)


def _owner_reset_token(user_id):
    raw_token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    auth_service.create_email_token(user_id, "admin_password_reset",
        hashlib.sha256(raw_token.encode("utf-8")).hexdigest(), expires_at)
    return raw_token


def _authorized_admin():
    """Require a live owner session tied to the configured owner account."""
    owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower()
    user_id = session.get("phishguard_admin_user_id")
    if not owner_email or not isinstance(user_id, int) or user_id < 1:
        return False
    with auth_service.connection() as db:
        user = db.execute(
            """SELECT id, email, is_active, email_verified, session_version
               FROM users WHERE id=?""",
            (user_id,),
        ).fetchone()
    authorized = bool(
        user
        and user["is_active"]
        and user["email_verified"]
        and user["email"].lower() == owner_email
        and session.get("phishguard_admin_email") == user["email"]
        and session.get("phishguard_admin_session_version") == user["session_version"]
    )
    if authorized:
        # Keep the owner cookie alive during normal dashboard use. Account
        # deactivation, password reset, logout and session-version changes
        # still revoke access immediately.
        session.permanent = True
        session.modified = True
    return authorized


@admin_bp.get("/admin/login")
def admin_login_page():
    if _authorized_admin():
        return redirect("/admin")
    return render_template("admin_login.html")


@admin_bp.get("/admin")
def admin_dashboard_page():
    if not _authorized_admin():
        return redirect("/admin/login")
    return render_template("admin_dashboard.html", owner_email=session.get("phishguard_admin_email", ""))




@admin_bp.get("/admin/reset-password")
def admin_reset_password_page():
    return render_template("admin_reset_password.html")


@admin_bp.post("/api/admin/password-reset/request")
def request_admin_password_reset():
    data = request.get_json(silent=True)
    email = data.get("email") if isinstance(data, dict) else None
    owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower()
    bucket = hashlib.sha256(
        f"owner-password-reset:{request.remote_addr or 'unknown'}:{str(email).strip().lower() if isinstance(email, str) else ''}".encode()
    ).hexdigest()
    if not auth_service.allow_auth_attempt(bucket, limit=5, window_seconds=900):
        return jsonify({"success": True, "message": "If the owner address matches, reset instructions will be sent."}), 200
    if isinstance(email, str) and owner_email and email.strip().lower() == owner_email:
        with auth_service.connection() as db:
            row = db.execute("SELECT id,email FROM users WHERE LOWER(email)=? AND is_active=1 AND email_verified=1", (owner_email,)).fetchone()
        if row:
            email_service.send_admin_password_reset_email(row["email"], _owner_reset_token(row["id"]))
    return jsonify({"success": True, "message": "If the owner address matches, reset instructions will be sent."}), 200


@admin_bp.post("/api/admin/password-reset/confirm")
def confirm_admin_password_reset():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON object is required."}), 400
    raw_token, password = data.get("token"), data.get("password")
    if not isinstance(raw_token, str) or not 20 <= len(raw_token) <= 200:
        return jsonify({"success": False, "error": "This admin reset link is invalid or has expired."}), 400
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return jsonify({"success": False, "error": "Password must contain 12 to 128 characters."}), 400
    owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower()
    if not owner_email:
        return jsonify({"success": False, "error": "Owner login is not configured."}), 503
    with auth_service.connection() as db:
        owner = db.execute("SELECT id FROM users WHERE LOWER(email)=? AND is_active=1 AND email_verified=1", (owner_email,)).fetchone()
    if not owner:
        return jsonify({"success": False, "error": "Owner account is unavailable."}), 400
    changed = auth_service.reset_password_with_token(
        hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        generate_password_hash(password, method="scrypt"),
        purpose="admin_password_reset", expected_user_id=owner["id"])
    if not changed:
        return jsonify({"success": False, "error": "This admin reset link is invalid or has expired."}), 400
    # The owner password reset revokes the owner identity only. Preserve any
    # customer session in another tab and keep the shared CSRF token stable.
    clear_admin_auth_session(session)
    return jsonify({"success": True, "message": "Admin password updated. Sign in from the owner login page.", "redirect": "/admin/login"}), 200


@admin_bp.post("/api/admin/login")
def admin_login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON object is required."}), 400
    email = data.get("email")
    password = data.get("password")
    owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower()
    if not owner_email:
        return jsonify({"success": False, "error": "Owner login is not configured on this server."}), 503
    bucket = hashlib.sha256(
        f"owner-login:{request.remote_addr or 'unknown'}:{str(email).strip().lower() if isinstance(email, str) else ''}".encode()
    ).hexdigest()
    if not auth_service.allow_auth_attempt(bucket, limit=6, window_seconds=900):
        return jsonify({"success": False, "error": "Too many sign-in attempts. Try again later."}), 429
    user = auth_service.authenticate(email, password)
    if (
        not user
        or user["email"].lower() != owner_email
        or not user.get("email_verified")
    ):
        return jsonify({"success": False, "error": "Invalid owner credentials or owner email is not verified."}), 401
    # Keep an already signed-in customer account active in this browser.
    # Do not rotate the shared CSRF token: other open tabs still rely on it.
    session["phishguard_admin_user_id"] = user["id"]
    session["phishguard_admin_email"] = user["email"]
    session["phishguard_admin_session_version"] = user.get("session_version", 0)
    session.permanent = True
    return jsonify({"success": True, "redirect": "/admin"}), 200


@admin_bp.post("/api/admin/logout")
def admin_logout():
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Owner authorization required."}), 401
    # Owner logout must not sign the customer out of this browser.
    clear_admin_auth_session(session)
    return jsonify({"success": True}), 200


@admin_bp.get("/api/admin/profile")
def admin_profile():
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Owner authorization required."}), 401
    user = auth_service.get_user(session["phishguard_admin_user_id"])
    return jsonify({"success": True, "profile": {
        "email": user["email"], "full_name": user.get("full_name"),
        "profile_image": user.get("admin_profile_image")
    }}), 200


@admin_bp.post("/api/admin/profile")
def update_admin_profile():
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Owner authorization required."}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON object is required."}), 400
    full_name = data.get("full_name")
    if not isinstance(full_name, str) or not 2 <= len(full_name.strip()) <= 80:
        return jsonify({"success": False, "error": "Full name must contain 2 to 80 characters."}), 400
    try:
        profile_image = validate_profile_image(data.get("profile_image"))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    user_id = session["phishguard_admin_user_id"]
    with auth_service.connection() as db:
        db.execute("UPDATE users SET full_name=?, admin_profile_image=? WHERE id=? AND is_active=1",
                   (full_name.strip(), profile_image, user_id))
    user = auth_service.get_user(user_id)
    return jsonify({"success": True, "message": "Admin profile updated successfully.",
                    "profile": {"email": user["email"], "full_name": user.get("full_name"),
                                "profile_image": user.get("admin_profile_image")}}), 200


@admin_bp.post("/api/admin/scan-credits")
def grant_scan_credits():
    """Grant extra scans to an account until the end of the current UTC month."""
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Admin authorization required."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON object is required."}), 400

    email = data.get("email")
    scans = data.get("scans")
    reason = data.get("reason", "")

    if not isinstance(email, str) or not email.strip() or len(email.strip()) > 254:
        return jsonify({"success": False, "error": "Provide the user's registered email address."}), 400
    if isinstance(scans, bool) or not isinstance(scans, int) or not 1 <= scans <= 10000:
        return jsonify({"success": False, "error": "scans must be an integer from 1 to 10000."}), 400
    if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 200:
        return jsonify({"success": False, "error": "Provide a reason of up to 200 characters."}), 400

    with auth_service.connection() as db:
        user = db.execute(
            "SELECT id, email FROM users WHERE email=? COLLATE NOCASE AND is_active=1",
            (email.strip(),),
        ).fetchone()

    if user is None:
        return jsonify({"success": False, "error": "Active account not found."}), 404
    if user["email"].strip().lower() == os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower():
        return jsonify({"success": False, "error": "Owner account is excluded from customer scan-credit management."}), 400

    now = datetime.now(timezone.utc)
    last_day = calendar.monthrange(now.year, now.month)[1]
    expires_at = datetime(
        now.year, now.month, last_day, 23, 59, 59, tzinfo=timezone.utc
    ).isoformat()

    auth_service.grant_admin_scans(
        user["id"], scans, reason.strip(), expires_at
    )

    # Reset only this account's short-window identity bucket. The shared IP
    # bucket remains in place to protect other visitors on the same network.
    owner_id = f"account:{user['id']}"
    digest = hmac.new(
        str(current_app.secret_key).encode("utf-8"),
        owner_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    with auth_service.connection() as db:
        db.execute(
            "DELETE FROM auth_rate_limits WHERE bucket=?",
            (f"scan-identity:{digest}",),
        )

    return jsonify({
        "success": True,
        "message": "Admin scan credits granted.",
        "user": {"id": user["id"], "email": user["email"]},
        "granted_scans": scans,
        "expires_at": expires_at,
        "note": "Bonus scans increase this account's monthly quota. The shared IP safety limit is unchanged.",
    }), 200


@admin_bp.get("/api/admin/overview")
def admin_overview():
    """Return a small operational summary for the authenticated owner console."""
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Admin authorization required."}), 401

    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()

    with auth_service.connection() as db:
        owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower()
        active_accounts = db.execute(
            "SELECT COUNT(*) FROM users WHERE is_active=1 AND LOWER(email)<>?",
            (owner_email,),
        ).fetchone()[0]
        active_subscriptions = db.execute(
            """SELECT COUNT(*) FROM subscriptions s JOIN users u ON u.id=s.user_id
               WHERE s.status='active' AND s.plan_id IN ('pro','business')
                 AND LOWER(u.email)<>?
                 AND (s.current_period_end IS NULL OR s.current_period_end>?)
                 AND s.id=(SELECT MAX(s2.id) FROM subscriptions s2 WHERE s2.user_id=s.user_id)""",
            (owner_email, now.isoformat()),
        ).fetchone()[0]
        # Scan usage is an operational metric; scan_usage has owner_id, not user_id.
        scans_this_month = db.execute(
            """SELECT COUNT(*) FROM scan_usage WHERE scanned_at>=? AND owner_id<>?""",
            (month_start, f"account:{session['phishguard_admin_user_id']}"),
        ).fetchone()[0]
        bonus_scans_this_month = db.execute(
            "SELECT COALESCE(SUM(granted_scans), 0) FROM admin_scan_grants WHERE created_at>=?",
            (month_start,),
        ).fetchone()[0]
        payment_rows = db.execute(
            """SELECT p.status, COUNT(*) AS count FROM payment_transactions p
               JOIN users u ON u.id=p.user_id WHERE LOWER(u.email)<>? GROUP BY p.status""",
            (owner_email,),
        ).fetchall()

    return jsonify({
        "success": True,
        "overview": {
            "active_accounts": active_accounts,
            "active_subscriptions": active_subscriptions,
            "scans_this_month": scans_this_month,
            "bonus_scans_granted_this_month": bonus_scans_this_month,
            "payment_transactions": {
                row["status"]: row["count"] for row in payment_rows
            },
            "period_start": month_start,
            "period_timezone": "UTC",
        },
    }), 200


@admin_bp.get("/api/admin/users")
def admin_users():
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Owner authorization required."}), 401
    try:
        limit = min(max(int(request.args.get("limit", "50")), 1), 100)
        offset = max(int(request.args.get("offset", "0")), 0)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid pagination values."}), 400
    with auth_service.connection() as db:
        rows = db.execute(
            """SELECT u.id, u.email, u.created_at, u.is_active, u.email_verified,
                      s.plan_id, s.status AS subscription_status
               FROM users u
               LEFT JOIN subscriptions s ON s.id=(
                   SELECT MAX(s2.id) FROM subscriptions s2 WHERE s2.user_id=u.id
               )
               WHERE LOWER(u.email)<>?
               ORDER BY u.created_at DESC LIMIT ? OFFSET ?""",
            (os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower(), limit, offset),
        ).fetchall()
        total = db.execute("SELECT COUNT(*) FROM users WHERE LOWER(email)<>?",
                           (os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower(),)).fetchone()[0]
    return jsonify({"success": True, "users": [dict(row) for row in rows],
                    "total": total, "limit": limit, "offset": offset}), 200


@admin_bp.get("/api/admin/payments")
def admin_payments():
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Owner authorization required."}), 401
    try:
        limit = min(max(int(request.args.get("limit", "50")), 1), 100)
        offset = max(int(request.args.get("offset", "0")), 0)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid pagination values."}), 400
    with auth_service.connection() as db:
        rows = db.execute(
            """SELECT p.id, u.email, p.plan_id, p.amount, p.currency,
                      p.payment_method, p.status, p.created_at
               FROM payment_transactions p
               JOIN users u ON u.id=p.user_id
               WHERE LOWER(u.email)<>?
               ORDER BY p.created_at DESC LIMIT ? OFFSET ?""",
            (os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower(), limit, offset),
        ).fetchall()
        total = db.execute("""SELECT COUNT(*) FROM payment_transactions p JOIN users u ON u.id=p.user_id
                              WHERE LOWER(u.email)<>?""",
                           (os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower(),)).fetchone()[0]
    return jsonify({"success": True, "payments": [dict(row) for row in rows],
                    "total": total, "limit": limit, "offset": offset}), 200
