import calendar
import hashlib
import hmac
import os
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from backend.database.auth_service import auth_service

admin_bp = Blueprint("admin", __name__)


def _authorized_admin():
    configured = os.getenv("PHISHGUARD_ADMIN_TOKEN", "").strip()
    supplied = request.headers.get("X-Admin-Token", "")
    return (
        len(configured) >= 32
        and bool(supplied)
        and hmac.compare_digest(configured, supplied)
    )


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
        active_accounts = db.execute(
            "SELECT COUNT(*) FROM users WHERE is_active=1"
        ).fetchone()[0]
        active_subscriptions = db.execute(
            "SELECT COUNT(*) FROM subscriptions WHERE status='active'"
        ).fetchone()[0]
        scans_this_month = db.execute(
            "SELECT COUNT(*) FROM scan_usage WHERE scanned_at>=?",
            (month_start,),
        ).fetchone()[0]
        bonus_scans_this_month = db.execute(
            "SELECT COALESCE(SUM(granted_scans), 0) FROM admin_scan_grants WHERE created_at>=?",
            (month_start,),
        ).fetchone()[0]
        payment_rows = db.execute(
            "SELECT status, COUNT(*) AS count FROM payment_transactions GROUP BY status"
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
