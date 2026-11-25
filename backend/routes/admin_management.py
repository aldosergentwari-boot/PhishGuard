"""Extended owner-management APIs for PhishGuard.

All mutations require an authenticated owner session and the session CSRF token.
"""
import calendar
import secrets
import os
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, session

from backend.database.auth_service import auth_service
from backend.routes.admin import _authorized_admin

admin_management_bp = Blueprint("admin_management", __name__)


def _ensure_tables(db):
    db.execute("""CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT,
        details TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at DESC)")
    db.execute("""CREATE TABLE IF NOT EXISTS user_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'account',
        read_at TEXT,
        created_at TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_user_notifications_user ON user_notifications(user_id, created_at DESC)")


def _guard(mutate=False):
    if not _authorized_admin():
        return jsonify({"success": False, "error": "Owner authorization required."}), 401
    if mutate:
        expected = session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            return jsonify({"success": False, "error": "Security token missing or invalid."}), 403
    return None


def _audit(db, action, target_type, target_id="", details=""):
    db.execute(
        """INSERT INTO admin_audit_log(actor_user_id,action,target_type,target_id,details,created_at)
           VALUES (?,?,?,?,?,?)""",
        (session["phishguard_admin_user_id"], action, target_type, str(target_id), details[:500],
         datetime.now(timezone.utc).isoformat()),
    )


def _owner_email():
    return os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower()


def _json():
    value = request.get_json(silent=True)
    return value if isinstance(value, dict) else {}


def _page():
    try:
        limit = min(max(int(request.args.get("limit", 25)), 1), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (TypeError, ValueError):
        return None, None
    return limit, offset


@admin_management_bp.get("/api/admin/management/users")
def management_users():
    denied = _guard()
    if denied: return denied
    limit, offset = _page()
    if limit is None:
        return jsonify({"success": False, "error": "Invalid pagination."}), 400
    search = request.args.get("q", "").strip()[:254]
    status = request.args.get("status", "").lower()
    plan = request.args.get("plan", "").lower()
    if status not in ("", "active", "suspended", "verified", "unverified"):
        return jsonify({"success": False, "error": "Invalid account filter."}), 400
    if plan not in ("", "guest", "free", "pro", "business"):
        return jsonify({"success": False, "error": "Invalid plan filter."}), 400
    clauses, args = ["LOWER(u.email) <> ?"], [_owner_email()]
    if search:
        clauses.append("u.email LIKE ?")
        args.append(f"%{search}%")
    if status == "active": clauses.append("u.is_active=1")
    if status == "suspended": clauses.append("u.is_active=0")
    if status == "verified": clauses.append("u.email_verified=1")
    if status == "unverified": clauses.append("u.email_verified=0")
    if plan:
        clauses.append("COALESCE(s.plan_id,'free')=?")
        args.append(plan)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with auth_service.connection() as db:
        _ensure_tables(db)
        rows = db.execute(
            f"""SELECT u.id,u.email,u.created_at,u.is_active,u.email_verified,
                       COALESCE(s.plan_id,'free') AS plan_id,s.status AS subscription_status,
                       s.current_period_end
                FROM users u LEFT JOIN subscriptions s ON s.id=(
                    SELECT MAX(s2.id) FROM subscriptions s2 WHERE s2.user_id=u.id
                ){where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?""",
            (*args, limit, offset),
        ).fetchall()
        total = db.execute(f"SELECT COUNT(*) FROM users u LEFT JOIN subscriptions s ON s.id=(SELECT MAX(s2.id) FROM subscriptions s2 WHERE s2.user_id=u.id){where}", args).fetchone()[0]
    from backend.services.plan_service import get_account_plan, get_usage
    users = []
    for row in rows:
        item = dict(row)
        plan_id = get_account_plan(item["id"])["plan_id"]
        item["scan_usage"] = get_usage(f"account:{item['id']}", plan_id)
        users.append(item)
    return jsonify({"success": True, "users": users, "total": total, "limit": limit, "offset": offset})


@admin_management_bp.post("/api/admin/management/users/<int:user_id>/scan-limit")
def set_user_scan_limit(user_id):
    denied = _guard(True)
    if denied: return denied
    data = _json()
    monthly_limit = data.get("monthly_limit")
    reason = data.get("reason", "")
    if monthly_limit is not None and (
        isinstance(monthly_limit, bool) or not isinstance(monthly_limit, int)
        or monthly_limit < 0 or monthly_limit > 100000
    ):
        return jsonify({"success": False, "error": "Monthly scan limit must be a whole number from 0 to 100000, or null to restore the plan default."}), 400
    if not isinstance(reason, str) or len(reason.strip()) < 3 or len(reason) > 200:
        return jsonify({"success": False, "error": "Provide a reason between 3 and 200 characters."}), 400

    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        _ensure_tables(db)
        user = db.execute("SELECT id,email FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return jsonify({"success": False, "error": "User not found."}), 404
        if user["email"].strip().lower() == _owner_email():
            return jsonify({"success": False, "error": "Owner account is not a customer account."}), 400

        if monthly_limit is None:
            db.execute("DELETE FROM admin_scan_limit_overrides WHERE user_id=?", (user_id,))
            details = "Restored plan default: " + reason.strip()
            action = "user.scan_limit_reset"
            message = "Your monthly URL scan allowance has been restored to the standard limit for your current plan."
        else:
            db.execute(
                """INSERT INTO admin_scan_limit_overrides(user_id,monthly_limit,reason,updated_by,updated_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(user_id) DO UPDATE SET monthly_limit=excluded.monthly_limit,
                       reason=excluded.reason,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                (user_id, monthly_limit, reason.strip(), session["phishguard_admin_user_id"], now),
            )
            details = f"Monthly scan limit set to {monthly_limit}: {reason.strip()}"
            action = "user.scan_limit_updated"
            message = f"Your monthly URL scan allowance has been set to {monthly_limit:,} scans. Existing bonus scans, if any, are added separately."

        _audit(db, action, "user", user_id, details)
        db.execute(
            "INSERT INTO user_notifications(user_id,title,message,category,created_at) VALUES (?,?,?,?,?)",
            (user_id, "Monthly scan allowance updated", message, "account", now),
        )

    from backend.services.plan_service import get_account_plan, get_usage
    plan_id = get_account_plan(user_id)["plan_id"]
    usage = get_usage(f"account:{user_id}", plan_id)
    return jsonify({"success": True, "user_id": user_id, "monthly_limit": monthly_limit, "usage": usage})


@admin_management_bp.post("/api/admin/management/users/<int:user_id>/status")
def set_user_status(user_id):
    denied = _guard(True)
    if denied: return denied
    data = _json()
    active = data.get("active")
    reason = data.get("reason", "")
    if not isinstance(active, bool) or not isinstance(reason, str) or len(reason.strip()) < 3 or len(reason) > 200:
        return jsonify({"success": False, "error": "Provide active=true/false and a reason (3–200 characters)."}), 400
    if user_id == session.get("phishguard_admin_user_id") and not active:
        return jsonify({"success": False, "error": "The owner cannot suspend their own account."}), 400
    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        _ensure_tables(db)
        user = db.execute("SELECT id,email,is_active FROM users WHERE id=?", (user_id,)).fetchone()
        if not user: return jsonify({"success": False, "error": "User not found."}), 404
        if user["email"].strip().lower() == _owner_email():
            return jsonify({"success": False, "error": "Owner account is not a customer account."}), 400
        db.execute("UPDATE users SET is_active=?,session_version=session_version+1 WHERE id=?", (int(active), user_id))
        _audit(db, "user.activated" if active else "user.suspended", "user", user_id, reason.strip())
        db.execute(
            "INSERT INTO user_notifications(user_id,title,message,category,created_at) VALUES (?,?,?,?,?)",
            (user_id, "Account status updated",
             "Your account has been reactivated." if active else "Your account has been suspended. Contact support if you believe this is an error.",
             "account", now),
        )
    return jsonify({"success": True, "user_id": user_id, "is_active": active})


@admin_management_bp.post("/api/admin/management/users/<int:user_id>/plan")
def set_user_plan(user_id):
    denied = _guard(True)
    if denied: return denied
    data = _json()
    plan = data.get("plan_id")
    reason = data.get("reason", "")
    if plan not in ("free", "pro", "business") or not isinstance(reason, str) or len(reason.strip()) < 3 or len(reason) > 200:
        return jsonify({"success": False, "error": "Choose Free, Pro, or Business and provide a reason."}), 400
    now = datetime.now(timezone.utc)
    months = {"free": 0, "pro": 1, "business": 7}[plan]
    end = None
    if months:
        index = now.month - 1 + months
        year, month = now.year + index // 12, index % 12 + 1
        day = min(now.day, calendar.monthrange(year, month)[1])
        end = now.replace(year=year, month=month, day=day).isoformat()
    stamp = now.isoformat()
    with auth_service.connection() as db:
        _ensure_tables(db)
        user = db.execute("SELECT id,email FROM users WHERE id=? AND is_active=1", (user_id,)).fetchone()
        if not user: return jsonify({"success": False, "error": "Active user not found."}), 404
        if user["email"].strip().lower() == _owner_email():
            return jsonify({"success": False, "error": "Owner account is not a customer account."}), 400
        # A manual plan override replaces the previous active plan; it must not
        # leave multiple active subscriptions for the same customer.
        db.execute(
            "UPDATE subscriptions SET status='cancelled',updated_at=? WHERE user_id=? AND status='active'",
            (stamp, user_id),
        )
        db.execute(
            """INSERT INTO subscriptions(user_id,plan_id,status,billing_interval_months,started_at,
               current_period_end,provider,provider_subscription_id,created_at,updated_at)
               VALUES (?,?, 'active', ?,?,?, 'admin', ?,?,?)""",
            (user_id, plan, months, stamp, end, f"admin-{secrets.token_hex(16)}", stamp, stamp),
        )
        _audit(db, "subscription.plan_changed", "user", user_id, f"{plan}: {reason.strip()}")
        db.execute(
            "INSERT INTO user_notifications(user_id,title,message,category,created_at) VALUES (?,?,?,?,?)",
            (user_id, "Your PhishGuard plan changed", f"Your account plan is now {plan.title()}.", "subscription", stamp),
        )
    return jsonify({"success": True, "user_id": user_id, "plan_id": plan, "current_period_end": end})


@admin_management_bp.get("/api/admin/management/payments")
def management_payments():
    denied = _guard()
    if denied: return denied
    limit, offset = _page()
    if limit is None: return jsonify({"success": False, "error": "Invalid pagination."}), 400
    status = request.args.get("status", "").lower()
    q = request.args.get("q", "").strip()[:254]
    if status and status not in ("pending", "successful", "failed", "cancelled"):
        return jsonify({"success": False, "error": "Invalid payment status."}), 400
    clauses, args = ["LOWER(u.email) <> ?"], [_owner_email()]
    if status: clauses.append("p.status=?"); args.append(status)
    if q: clauses.append("u.email LIKE ?"); args.append(f"%{q}%")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with auth_service.connection() as db:
        rows = db.execute(
            f"""SELECT p.id,p.user_id,u.email,p.plan_id,p.amount,p.currency,p.payment_method,
                       p.status,p.tx_ref,p.provider_transaction_id,p.created_at,p.updated_at
                FROM payment_transactions p JOIN users u ON u.id=p.user_id{where}
                ORDER BY p.created_at DESC LIMIT ? OFFSET ?""", (*args,limit,offset)
        ).fetchall()
        total = db.execute(
            f"SELECT COUNT(*) FROM payment_transactions p JOIN users u ON u.id=p.user_id{where}", args
        ).fetchone()[0]
    return jsonify({"success": True, "payments": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset})


@admin_management_bp.get("/api/admin/management/payments/<int:payment_id>")
def payment_detail(payment_id):
    denied = _guard()
    if denied: return denied
    with auth_service.connection() as db:
        row = db.execute(
            """SELECT p.*,u.email FROM payment_transactions p JOIN users u ON u.id=p.user_id
               WHERE p.id=? AND LOWER(u.email)<>?""",
            (payment_id, _owner_email()),
        ).fetchone()
    if not row: return jsonify({"success": False, "error": "Payment not found."}), 404
    return jsonify({"success": True, "payment": dict(row)})


@admin_management_bp.get("/api/admin/management/analytics")
def management_analytics():
    denied = _guard()
    if denied: return denied
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1,hour=0,minute=0,second=0,microsecond=0).isoformat()
    with auth_service.connection() as db:
        owner = _owner_email()
        users = db.execute("SELECT COUNT(*) FROM users WHERE LOWER(email)<>?", (owner,)).fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND LOWER(email)<>?", (owner,)).fetchone()[0]
        paid = db.execute("""SELECT COUNT(*) FROM subscriptions s JOIN users u ON u.id=s.user_id
            WHERE LOWER(u.email)<>? AND s.status='active' AND s.plan_id IN ('pro','business')
            AND (s.current_period_end IS NULL OR s.current_period_end>?)
            AND s.id=(SELECT MAX(s2.id) FROM subscriptions s2 WHERE s2.user_id=s.user_id)""",
            (owner, now.isoformat())).fetchone()[0]
        revenue = db.execute("""SELECT COALESCE(SUM(p.amount),0) FROM payment_transactions p JOIN users u ON u.id=p.user_id
            WHERE LOWER(u.email)<>? AND p.status='successful'""", (owner,)).fetchone()[0]
        monthly = db.execute("""SELECT COALESCE(SUM(p.amount),0) FROM payment_transactions p JOIN users u ON u.id=p.user_id
            WHERE LOWER(u.email)<>? AND p.status='successful' AND p.created_at>=?""", (owner, month_start)).fetchone()[0]
        # Scan usage is an operational metric; scan_usage stores an identity key, not users.user_id.
        scans = db.execute("SELECT COUNT(*) FROM scan_usage WHERE scanned_at>=?", (month_start,)).fetchone()[0]
        payment_counts = db.execute("""SELECT p.status,COUNT(*) AS n FROM payment_transactions p JOIN users u ON u.id=p.user_id
            WHERE LOWER(u.email)<>? GROUP BY p.status""", (owner,)).fetchall()
    return jsonify({"success": True, "analytics": {
        "total_users": users, "active_users": active, "paid_subscribers": paid,
        "conversion_rate": round((paid / users * 100), 2) if users else 0,
        "lifetime_revenue": round(revenue, 2), "revenue_this_month": round(monthly, 2),
        "scans_this_month": scans, "payment_counts": {r["status"]: r["n"] for r in payment_counts},
        "currency_note": "Revenue is the sum of recorded transaction amounts; compare currencies separately where multiple currencies are used."
    }})


@admin_management_bp.get("/api/admin/management/audit")
def management_audit():
    denied = _guard()
    if denied: return denied
    limit, offset = _page()
    if limit is None: return jsonify({"success": False, "error": "Invalid pagination."}), 400
    with auth_service.connection() as db:
        _ensure_tables(db)
        rows = db.execute(
            """SELECT a.id,a.actor_user_id,u.email AS actor_email,a.action,a.target_type,
                      a.target_id,a.details,a.created_at FROM admin_audit_log a
               LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT ? OFFSET ?""",
            (limit,offset),
        ).fetchall()
        total = db.execute("SELECT COUNT(*) FROM admin_audit_log").fetchone()[0]
    return jsonify({"success": True, "events": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset})


@admin_management_bp.get("/api/admin/management/subscriptions")
def management_subscriptions():
    denied = _guard()
    if denied: return denied
    limit, offset = _page()
    if limit is None: return jsonify({"success": False, "error": "Invalid pagination."}), 400
    with auth_service.connection() as db:
        rows = db.execute(
            """SELECT s.id,s.user_id,u.email,s.plan_id,s.status,s.started_at,s.current_period_end,
                      s.provider,s.created_at FROM subscriptions s JOIN users u ON u.id=s.user_id
               WHERE LOWER(u.email)<>? ORDER BY s.created_at DESC LIMIT ? OFFSET ?""", (_owner_email(),limit,offset)
        ).fetchall()
        total = db.execute("SELECT COUNT(*) FROM subscriptions s JOIN users u ON u.id=s.user_id WHERE LOWER(u.email)<>?", (_owner_email(),)).fetchone()[0]
    return jsonify({"success": True, "subscriptions": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset})


@admin_management_bp.post("/api/admin/management/subscriptions/<int:subscription_id>/cancel")
def cancel_subscription(subscription_id):
    denied = _guard(True)
    if denied: return denied
    data = _json()
    reason = data.get("reason", "")
    if not isinstance(reason,str) or len(reason.strip())<3 or len(reason)>200:
        return jsonify({"success": False, "error": "Provide a cancellation reason."}),400
    now=datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        _ensure_tables(db)
        row=db.execute("""SELECT s.id,s.user_id,s.plan_id,u.email FROM subscriptions s
            JOIN users u ON u.id=s.user_id WHERE s.id=?""",(subscription_id,)).fetchone()
        if not row: return jsonify({"success":False,"error":"Subscription not found."}),404
        if row["email"].strip().lower() == _owner_email():
            return jsonify({"success":False,"error":"Owner is not a customer subscription."}),400
        db.execute("UPDATE subscriptions SET status='cancelled',updated_at=? WHERE id=?",(now,subscription_id))
        _audit(db,"subscription.cancelled","subscription",subscription_id,reason.strip())
        db.execute("INSERT INTO user_notifications(user_id,title,message,category,created_at) VALUES (?,?,?,?,?)",
                   (row["user_id"],"Subscription cancelled",f"Your {row['plan_id'].title()} subscription has been cancelled.", "subscription",now))
    return jsonify({"success":True,"subscription_id":subscription_id})


@admin_management_bp.post("/api/admin/management/notifications")
def send_user_notification():
    denied = _guard(True)
    if denied: return denied
    data=_json()
    user_id=data.get("user_id")
    title=data.get("title","")
    message=data.get("message","")
    category=data.get("category","account")
    if (isinstance(user_id,bool) or not isinstance(user_id,int) or not isinstance(title,str)
        or not 3<=len(title.strip())<=100 or not isinstance(message,str) or not 3<=len(message.strip())<=1000
        or category not in ("account","subscription","payment","security")):
        return jsonify({"success":False,"error":"Provide a valid user, title, message and category."}),400
    now=datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        _ensure_tables(db)
        recipient=db.execute("SELECT email FROM users WHERE id=?",(user_id,)).fetchone()
        if not recipient: return jsonify({"success":False,"error":"User not found."}),404
        if recipient["email"].strip().lower() == _owner_email():
            return jsonify({"success":False,"error":"Customer notifications cannot target the owner."}),400
        db.execute("INSERT INTO user_notifications(user_id,title,message,category,created_at) VALUES (?,?,?,?,?)",
                   (user_id,title.strip(),message.strip(),category,now))
        _audit(db,"notification.created","user",user_id,title.strip())
    return jsonify({"success":True})


@admin_management_bp.get("/api/account/notifications")
def account_notifications():
    """Return the signed-in customer's own in-app notifications."""
    user_id = session.get("account_id")
    if not isinstance(user_id, int) or user_id < 1:
        return jsonify({"success": False, "error": "Sign in to view your notifications."}), 401

    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        _ensure_tables(db)
        db.execute(
            "UPDATE user_notifications SET read_at=? WHERE user_id=? AND read_at IS NULL",
            (now, user_id),
        )
        rows = db.execute(
            """SELECT id,title,message,category,read_at,created_at
               FROM user_notifications WHERE user_id=? ORDER BY id DESC LIMIT 50""",
            (user_id,),
        ).fetchall()
    return jsonify({"success": True, "notifications": [dict(row) for row in rows]}), 200


@admin_management_bp.get("/api/admin/management/notifications")
def list_user_notifications():
    denied = _guard()
    if denied: return denied
    try: user_id=int(request.args.get("user_id",""))
    except ValueError: return jsonify({"success":False,"error":"Valid user_id is required."}),400
    with auth_service.connection() as db:
        _ensure_tables(db)
        rows=db.execute("SELECT id,user_id,title,message,category,read_at,created_at FROM user_notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",(user_id,)).fetchall()
    return jsonify({"success":True,"notifications":[dict(r) for r in rows]})
