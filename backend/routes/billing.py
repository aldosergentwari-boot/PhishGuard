from flask import Blueprint, jsonify, redirect, request, session, render_template
import os
import re
import json
from datetime import datetime, timezone
from urllib.parse import urlencode

from backend.database.auth_service import auth_service
from backend.services.plan_service import (
    PLANS, PLAN_LIMITS, get_account_plan, get_usage
)
from backend.services.user_identity import get_current_user_id

billing_bp = Blueprint("billing", __name__)


@billing_bp.get("/api/billing/plans")
def list_plans():
    public_plans = {
        key: {**value, "limits": PLAN_LIMITS[key]}
        for key, value in PLANS.items()
    }
    return jsonify({
        "success": True,
        "currency": "USD",
        "plans": public_plans,
        "checkout": {"enabled": False, "manual_requests": True, "provider": None, "card": False, "mobile_money": False, "mobile_money_provider": None, "mobile_money_prices_rwf": {}},
    }), 200


@billing_bp.get("/api/billing/me")
def current_subscription():
    owner_id = get_current_user_id()
    user_id = session.get("account_id")
    if user_id:
        plan = get_account_plan(user_id)
    else:
        plan = {"plan_id": "guest", "status": "active",
                "limits": PLAN_LIMITS["guest"], **PLANS["guest"]}
    usage = get_usage(owner_id, plan["plan_id"])
    return jsonify({
        "success": True,
        "authenticated": bool(user_id),
        "plan": plan,
        "usage": usage
    }), 200


@billing_bp.get("/api/billing/payments")
def account_payment_history():
    """Return only the signed-in account's recent payment records."""
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": False, "error": "Sign in to view payment history."}), 401
    with auth_service.connection() as db:
        rows = db.execute(
            """SELECT id,plan_id,amount,currency,payment_method,status,provider,created_at,updated_at
               FROM payment_transactions WHERE user_id=?
               ORDER BY created_at DESC,id DESC LIMIT 20""",
            (user_id,),
        ).fetchall()
    return jsonify({"success": True, "payments": [dict(row) for row in rows]}), 200


@billing_bp.post("/api/billing/checkout")
def create_paid_checkout():
    """Online checkout is retired; use owner-reviewed subscription requests."""
    return jsonify({"success":False,"code":"MANUAL_SUBSCRIPTION_ONLY","error":"Online payments are disabled. Choose Request subscription from Plans."}),410

@billing_bp.get("/api/billing/callback")
def payment_callback():
    return jsonify({"success":False,"error":"Automated payment callbacks are disabled."}),410


@billing_bp.post("/api/billing/webhook")
def flutterwave_webhook():
    return jsonify({"success":False,"error":"Automated payment webhooks are disabled."}),410


@billing_bp.post("/api/billing/palmkash/callback")
def palmkash_callback():
    return jsonify({"success":False,"error":"Automated payment callbacks are disabled."}),410


@billing_bp.get("/api/billing/payments/<path:tx_ref>/status")
def payment_status(tx_ref):
    """Read-only access to historical payments; this route never activates a plan."""
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success":False,"error":"Sign in to view payment status."}),401
    with auth_service.connection() as db:
        payment = db.execute("SELECT status,plan_id,amount,currency,provider FROM payment_transactions WHERE tx_ref=? AND user_id=?",(tx_ref,user_id)).fetchone()
    if not payment:
        return jsonify({"success":False,"error":"Payment record not found."}),404
    return jsonify({"success":True,**dict(payment)}),200


def _ensure_subscription_request_table(db):
    db.execute("""CREATE TABLE IF NOT EXISTS subscription_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        plan_id TEXT NOT NULL CHECK(plan_id IN ('pro','business')),
        customer_name TEXT NOT NULL,
        customer_email TEXT NOT NULL,
        phone_number TEXT NOT NULL,
        payment_method TEXT NOT NULL,
        message TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','cancelled')),
        admin_note TEXT NOT NULL DEFAULT '',
        payment_reference TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        reviewed_at TEXT,
        reviewed_by INTEGER REFERENCES users(id)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_subscription_requests_status ON subscription_requests(status,created_at DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_subscription_requests_user ON subscription_requests(user_id,created_at DESC)")
    db.execute("""CREATE TABLE IF NOT EXISTS user_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'account',
        read_at TEXT,
        created_at TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS admin_inbox_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        event_type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        read_at TEXT,
        created_at TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_admin_inbox_created ON admin_inbox_notifications(created_at DESC)")


@billing_bp.get("/subscription/request")
def subscription_request_page():
    plan = request.args.get("plan", "").strip().lower()
    if plan not in ("pro", "business"):
        return redirect("/?page=pricing")
    return render_template("subscription_request.html", selected_plan=plan, owner_email=os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip())


@billing_bp.post("/api/billing/requests")
def create_subscription_request():
    user_id = session.get("account_id")
    if not isinstance(user_id, int) or user_id < 1:
        return jsonify({"success": False, "error": "Sign in to your PhishGuard account before requesting a paid subscription.", "code": "AUTH_REQUIRED"}), 401
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    plan_id = str(data.get("plan_id") or "").strip().lower()
    customer_name = str(data.get("customer_name") or "").strip()
    phone = str(data.get("phone_number") or "").strip()
    method = str(data.get("payment_method") or "").strip().lower()
    message = str(data.get("message") or "").strip()
    if plan_id not in ("pro", "business"):
        return jsonify({"success": False, "error": "Choose Pro or Business."}), 400
    if not 2 <= len(customer_name) <= 80:
        return jsonify({"success": False, "error": "Enter your full name (2–80 characters)."}), 400
    if not 7 <= len(phone) <= 24 or not re.fullmatch(r"[+0-9() .-]{7,24}", phone):
        return jsonify({"success": False, "error": "Enter a valid phone number with country code if possible."}), 400
    if method not in ("mtn_momo", "airtel_money", "bank_transfer", "other"):
        return jsonify({"success": False, "error": "Choose a valid preferred payment method."}), 400
    if len(message) > 1000:
        return jsonify({"success": False, "error": "Message must be 1,000 characters or fewer."}), 400

    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        _ensure_subscription_request_table(db)
        user = db.execute("SELECT id,email,full_name,username FROM users WHERE id=? AND is_active=1", (user_id,)).fetchone()
        if not user:
            return jsonify({"success": False, "error": "Active account not found. Please sign in again."}), 401
        pending = db.execute("SELECT id FROM subscription_requests WHERE user_id=? AND status='pending' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
        if pending:
            return jsonify({"success": False, "error": "You already have a pending subscription request. Please wait for the owner to respond.", "request_id": pending["id"]}), 409
        cur = db.execute("""INSERT INTO subscription_requests
            (user_id,plan_id,customer_name,customer_email,phone_number,payment_method,message,status,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,'pending',?,?)""",
            (user_id,plan_id,customer_name,user["email"],phone,method,message,now,now))
        request_id = cur.lastrowid
        db.execute("INSERT INTO user_notifications(user_id,title,message,category,created_at) VALUES (?,?,?,?,?)",
            (user_id,"Subscription request received",f"Your {plan_id.title()} subscription request was received. The PhishGuard owner will contact you with payment instructions.", "subscription",now))
        db.execute("""INSERT INTO admin_inbox_notifications
            (user_id,event_type,title,message,metadata_json,created_at)
            VALUES (?,?,?,?,?,?)""",
            (user_id,"subscription_request",
             f"New {plan_id.title()} subscription request",
             f"{customer_name} ({user['email']}) requested the {plan_id.title()} plan via {method}.",
             json.dumps({
                 "request_id": cur.lastrowid, "plan_id": plan_id,
                 "customer_name": customer_name, "customer_email": user["email"],
                 "phone_number": phone, "payment_method": method, "message": message
             }), now))
    # The subscription request is the primary action. Do not email the owner
    # automatically; the customer may optionally prepare a separate email later.
    try:
        from backend.services.email_service import send_subscription_request_received_email
        send_subscription_request_received_email(user["email"], plan_id, request_id)
    except Exception:
        # Request creation and the admin inbox record must not depend on email delivery.
        pass
    return jsonify({
        "success": True,
        "request_id": request_id,
        "message": "Your request has been sent to the PhishGuard admin. You can optionally prepare an email separately."
    }), 201


@billing_bp.get("/subscription/request/<int:request_id>/email")
def subscription_request_email_page(request_id):
    user_id = session.get("account_id")
    if not isinstance(user_id, int) or user_id < 1:
        return redirect("/?auth=login")
    with auth_service.connection() as db:
        _ensure_subscription_request_table(db)
        row = db.execute(
            """SELECT id,user_id,plan_id,customer_name,customer_email,phone_number,
                      payment_method,message,status,created_at
               FROM subscription_requests WHERE id=? AND user_id=?""",
            (request_id, user_id),
        ).fetchone()
    if not row:
        return jsonify({"success": False, "error": "Subscription request not found."}), 404

    details = dict(row)
    owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip()
    plan = "Pro" if details["plan_id"] == "pro" else "Business"
    price = "$4.99 per month" if details["plan_id"] == "pro" else "$19.99 for 7 months"
    body = (
        "Dear PhishGuard Owner,\n\n"
        "I hope this message finds you well.\n\n"
        f"I am writing to formally request a {plan} subscription for my PhishGuard account.\n\n"
        "My subscription details are:\n"
        f"Full name: {details['customer_name']}\n"
        f"Account email: {details['customer_email']}\n"
        f"Request reference: #{details['id']}\n"
        f"Requested plan: {plan}\n"
        f"Plan price: {price}\n"
        f"Contact phone: {details['phone_number']}\n"
        f"Preferred payment method: {details['payment_method'].replace('_', ' ').title()}\n"
        f"Additional information: {details['message'] or 'None'}\n\n"
        "Kindly review my request and share the payment instructions and any further steps required to complete the subscription.\n\n"
        "I understand that my account will only be upgraded after payment has been independently verified and approved.\n\n"
        "Thank you for your time and assistance.\n\n"
        "Yours faithfully,\n"
        f"{details['customer_name']}"
    )
    mailto_url = (
        "mailto:" + owner_email + "?" + urlencode({
            "subject": f"PhishGuard {plan} subscription request #{request_id}",
            "body": body,
        })
    ) if owner_email else ""
    return render_template(
        "subscription_request_email.html",
        details=details,
        plan=plan,
        price=price,
        owner_email=owner_email,
        email_body=body,
        mailto_url=mailto_url,
    )


@billing_bp.post("/api/billing/requests/<int:request_id>/send-email")
def send_subscription_request_email_now(request_id):
    """Send the signed-in customer's reviewed subscription request to the owner."""
    user_id = session.get("account_id")
    if not isinstance(user_id, int) or user_id < 1:
        return jsonify({"success": False, "error": "Sign in before sending this email."}), 401

    owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip()
    if not owner_email:
        return jsonify({"success": False, "error": "The PhishGuard owner email is not configured yet."}), 503

    # Limit repeat sends for this account/request while still allowing a retry
    # after a temporary provider failure.
    if not auth_service.allow_auth_attempt(f"subscription-email:{user_id}:{request_id}", limit=3):
        return jsonify({"success": False, "error": "This email has been attempted too many times. Please try again later."}), 429

    with auth_service.connection() as db:
        _ensure_subscription_request_table(db)
        row = db.execute(
            """SELECT id,user_id,plan_id,customer_name,customer_email,phone_number,
                      payment_method,message,status
               FROM subscription_requests WHERE id=? AND user_id=?""",
            (request_id, user_id),
        ).fetchone()
    if not row:
        return jsonify({"success": False, "error": "Subscription request not found."}), 404
    if row["status"] != "pending":
        return jsonify({"success": False, "error": "This subscription request is no longer pending."}), 409

    try:
        from backend.services.email_service import send_subscription_request_email
        sent = send_subscription_request_email(owner_email, {**dict(row), "request_id": request_id})
    except Exception:
        sent = False
    if not sent:
        return jsonify({"success": False, "error": "The email could not be delivered right now. Please try again later."}), 503
    return jsonify({"success": True, "message": "Your subscription email has been sent to the PhishGuard owner."}), 200
