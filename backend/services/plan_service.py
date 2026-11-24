from datetime import datetime, timedelta, timezone

from backend.database.auth_service import auth_service

# Public prices are USD. Business intentionally renews every seven months.
PLANS = {
    "free": {
        "name": "Free", "price_usd": 0, "billing_interval_months": 0,
        "features": ["Basic URL scanning", "Basic risk result", "Limited scan history", "Ads may be shown"]
    },
    "pro": {
        "name": "Pro", "price_usd": 4.99, "billing_interval_months": 1,
        "features": ["Higher scan limits", "Detailed threat reports", "Report export", "Ad-free experience", "Extended scan history"]
    },
    "business": {
        "name": "Business", "price_usd": 19.99, "billing_interval_months": 7,
        "features": ["Higher usage limits", "API access", "Team reporting", "Advanced analytics", "Priority support"]
    },
}


def get_account_plan(user_id):
    with auth_service.connection() as db:
        row = db.execute("""SELECT plan_id,status,billing_interval_months,
            current_period_end,provider FROM subscriptions
            WHERE user_id=? ORDER BY id DESC LIMIT 1""", (user_id,)).fetchone()
    if not row:
        return {"plan_id": "free", "status": "active", **PLANS["free"]}
    plan_id = row["plan_id"] if row["plan_id"] in PLANS else "free"
    # Expired paid subscriptions fall back to Free; no client can self-activate a plan.
    if plan_id != "free" and row["current_period_end"]:
        expiry = datetime.fromisoformat(row["current_period_end"])
        if expiry <= datetime.now(timezone.utc):
            plan_id = "free"
    return {
        "plan_id": plan_id, "status": row["status"],
        "billing_interval_months": row["billing_interval_months"],
        "current_period_end": row["current_period_end"],
        "provider": row["provider"], **PLANS[plan_id]
    }


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
    # Calendar-month arithmetic without adding an external dependency.
    month_index = start.month - 1 + months
    year = start.year + month_index // 12
    month = month_index % 12 + 1
    import calendar
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
