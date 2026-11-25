import calendar
import hashlib
import hmac
import os
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session

from backend.database.auth_service import auth_service

admin_bp = Blueprint("admin", __name__)


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
    return bool(
        user
        and user["is_active"]
        and user["email_verified"]
        and user["email"].lower() == owner_email
        and session.get("phishguard_admin_email") == user["email"]
        and session.get("phishguard_admin_session_version") == user["session_version"]
    )


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
    session.clear()
    session["phishguard_admin_user_id"] = user["id"]
    session["phishguard_admin_email"] = user["email"]
    session["phishguard_admin_session_version"] = user.get("session_version", 0)
    session.permanent = True
    return jsonify({"success": True, "redirect": "/admin"}), 200


@admin_bp.post("/api/admin/logout")
def admin_logout():
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Owner authorization required."}), 401
    session.clear()
    return jsonify({"success": True}), 200


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
               WHERE s.status='active' AND LOWER(u.email)<>?""",
            (owner_email,),
        ).fetchone()[0]
        scans_this_month = db.execute(
            """SELECT COUNT(*) FROM scan_usage su JOIN users u ON u.id=su.user_id
               WHERE su.scanned_at>=? AND LOWER(u.email)<>?""",
            (month_start, owner_email),
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
