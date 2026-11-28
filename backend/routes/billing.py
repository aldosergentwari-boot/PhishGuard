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
    return render_template("subscription_request.html", selected_plan=plan)


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
    owner_email = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip()
    email_sent = False
    try:
        from backend.services.email_service import send_subscription_request_email, send_subscription_request_received_email
        if owner_email:
            email_sent = send_subscription_request_email(owner_email, {
                "request_id": request_id, "plan_id": plan_id, "customer_name": customer_name,
                "customer_email": user["email"], "user_id": user_id, "phone_number": phone,
                "payment_method": method, "message": message, "created_at": now
            })
        send_subscription_request_received_email(user["email"], plan_id, request_id)
    except Exception:
        email_sent = False
    mail_body = (
        f"PhishGuard subscription request #{request_id}\n"
        f"Name: {customer_name}\nAccount email: {user['email']}\nAccount ID: {user_id}\n"
        f"Plan: {plan_id.title()}\nPhone: {phone}\nPreferred payment: {method}\n"
        f"Message: {message or '(none)'}"
    )
    mailto_url = ("mailto:" + owner_email + "?" + urlencode({"subject": f"PhishGuard {plan_id.title()} subscription request #{request_id}", "body": mail_body})) if owner_email else ""
    return jsonify({"success": True, "request_id": request_id, "email_sent": bool(email_sent), "mailto_url": mailto_url,
        "message": "Your request has been saved. The owner will contact you with payment instructions."}), 201
