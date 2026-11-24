from datetime import datetime, timezone
import calendar

from backend.database.auth_service import auth_service

# Initial product limits; keep centralized so they can be tuned without changing routes.
PLAN_LIMITS = {
    "guest": {"scans_per_month": 10, "history_records": 10},
    "free": {"scans_per_month": 50, "history_records": 50},
    "pro": {"scans_per_month": 2000, "history_records": 2000},
    "business": {"scans_per_month": 10000, "history_records": 10000},
}

PLANS = {
    "guest": {
        "name": "Guest", "price_usd": 0, "billing_interval_months": 0,
        "features": ["Up to 10 URL scans per UTC calendar month", "No account required; create a free account to continue scanning"]
    },
    "free": {
        "name": "Free", "price_usd": 0, "billing_interval_months": 0,
        "features": ["URL scanning with a risk score and security indicators", "Up to 50 visible scan-history records", "Ads may be shown when the publisher is approved"]
    },
    "pro": {
        "name": "Pro", "price_usd": 4.99, "billing_interval_months": 1,
        "features": ["Up to 2,000 scans per month", "CSV scan-history export", "Up to 2,000 visible scan-history records", "Ad-free dashboard"]
    },
    "business": {
        "name": "Business", "price_usd": 19.99, "billing_interval_months": 7,
        "features": ["Up to 10,000 scans per month", "CSV scan-history export", "Up to 10,000 visible scan-history records", "Ad-free dashboard"]
    },
}


def get_account_plan(user_id):
    with auth_service.connection() as db:
        row = db.execute("""SELECT plan_id,status,billing_interval_months,
            current_period_end,provider FROM subscriptions
            WHERE user_id=? ORDER BY id DESC LIMIT 1""", (user_id,)).fetchone()
    if not row:
        return {"plan_id": "free", "status": "active",
                "limits": PLAN_LIMITS["free"], **PLANS["free"]}
    plan_id = row["plan_id"] if row["plan_id"] in PLANS else "free"
    status = row["status"]
    if status != "active":
        plan_id = "free"
    if plan_id != "free" and row["current_period_end"]:
        expiry = datetime.fromisoformat(row["current_period_end"])
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            plan_id = "free"
            status = "expired"
    return {
        "plan_id": plan_id, "status": status,
        "billing_interval_months": row["billing_interval_months"],
        "current_period_end": row["current_period_end"],
        "provider": row["provider"],
        "limits": PLAN_LIMITS[plan_id], **PLANS[plan_id]
    }


def get_usage(owner_id, plan_id="free"):
    """Count scans in the current UTC calendar month for this browser/account."""
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    limits = PLAN_LIMITS.get(plan_id, PLAN_LIMITS["free"])
    bonus_scans = 0
    user_id = None
    if isinstance(owner_id, str) and owner_id.startswith("account:"):
        try:
            user_id = int(owner_id.split(":", 1)[1])
        except ValueError:
            user_id = None

    with auth_service.connection() as db:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_history'"
        ).fetchone()
        if not exists:
            used = 0
        else:
            used = db.execute(
                "SELECT COUNT(*) FROM scan_history WHERE owner_id=? AND scanned_at>=?",
                (owner_id, month_start)
            ).fetchone()[0]

        grants_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='admin_scan_grants'"
        ).fetchone()
        if user_id and grants_table:
            bonus_scans = db.execute(
                "SELECT COALESCE(SUM(granted_scans), 0) FROM admin_scan_grants WHERE user_id=? AND expires_at>?",
                (user_id, now.isoformat()),
            ).fetchone()[0]

    effective_limit = limits["scans_per_month"] + bonus_scans
    return {
        "scans_used": used,
        "scans_limit": effective_limit,
        "plan_scans_limit": limits["scans_per_month"],
        "admin_bonus_scans": bonus_scans,
        "scans_remaining": max(0, effective_limit - used),
        "history_limit": limits["history_records"],
        "period": "calendar_month_utc",
        "period_starts_at": month_start,
    }


def can_scan(owner_id, plan_id="free"):
    usage = get_usage(owner_id, plan_id)
    return usage["scans_used"] < usage["scans_limit"], usage


def activate_subscription(user_id, plan_id, provider, provider_subscription_id, period_start=None):
    """Internal provider-webhook entry point. Never call from a public client route."""
    if plan_id not in ("pro", "business"):
        raise ValueError("Only paid plans can be activated.")
    if not provider or not provider_subscription_id:
        raise ValueError("Verified provider identifiers are required.")
    start = period_start or datetime.now(timezone.utc)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    months = PLANS[plan_id]["billing_interval_months"]
    month_index = start.month - 1 + months
    year = start.year + month_index // 12
    month = month_index % 12 + 1
    day = min(start.day, calendar.monthrange(year, month)[1])
    end = start.replace(year=year, month=month, day=day)
    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        db.execute("""INSERT INTO subscriptions(user_id,plan_id,status,billing_interval_months,
            started_at,current_period_end,provider,provider_subscription_id,created_at,updated_at)
            VALUES (?,?, 'active', ?,?,?,?,?,?,?)
            ON CONFLICT(provider_subscription_id) DO UPDATE SET
            plan_id=excluded.plan_id,status='active',billing_interval_months=excluded.billing_interval_months,
            current_period_end=excluded.current_period_end,updated_at=excluded.updated_at""",
            (user_id,plan_id,months,start.isoformat(),end.isoformat(),provider,provider_subscription_id,now,now))
