from flask import Blueprint, jsonify, redirect, request, session

from backend.database.auth_service import auth_service
from backend.services.plan_service import (
    PLANS, PLAN_LIMITS, get_account_plan, get_usage
)
from backend.services.user_identity import get_current_user_id
from backend.services.flutterwave_service import (
    FlutterwaveError, checkout_availability,
    validate_webhook_signature, verify_and_activate,
)
from backend.services.palmkash_service import (
    PalmKashError,
    verify_and_activate as palmkash_verify_and_activate,
    refresh_payment as palmkash_refresh_payment,
)

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
        "checkout": checkout_availability(),
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
    """Keep new paid checkout closed until the approved UrubutoPay integration is deployed.

    Legacy provider callback and payment-history routes remain available so old
    transactions can still be verified and audited. They are never selected for
    new customer checkout.
    """
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": False, "error": "Sign in before choosing a paid plan."}), 401

    payload = request.get_json(silent=True)
    payload = payload if isinstance(payload, dict) else {}
    plan_id = str(payload.get("plan_id") or "").strip().lower()
    if plan_id not in ("pro", "business"):
        return jsonify({"success": False, "error": "Choose a valid paid plan."}), 400

    # UrubutoPay merchant approval and API credentials are intentionally external
    # launch requirements. Do not fall back to PalmKash or Flutterwave.
    return jsonify({
        "success": False,
        "code": "PAYMENTS_NOT_AVAILABLE",
        "error": "Paid checkout is temporarily unavailable while PhishGuard completes its approved payment-provider setup.",
        "provider": "urubutopay",
    }), 503

@billing_bp.get("/api/billing/callback")
def payment_callback():
    # Legacy callback: a browser redirect is not proof of payment; verify server-side.
    tx_ref = request.args.get("tx_ref", "")
    transaction_id = request.args.get("transaction_id", "")
    if request.args.get("status", "").lower() != "successful":
        return redirect("/?payment=not_completed")
    try:
        verify_and_activate(tx_ref, transaction_id)
    except (FlutterwaveError, TypeError, ValueError):
        return redirect("/?payment=verification_failed")
    return redirect("/?payment=success")

@billing_bp.post("/api/billing/webhook")
def flutterwave_webhook():
    signature = request.headers.get("verif-hash", "")
    if not validate_webhook_signature(signature):
        return jsonify({"success": False, "error": "Invalid webhook signature."}), 401
    payload = request.get_json(silent=True)
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    tx_ref = data.get("tx_ref")
    transaction_id = data.get("id")
    if not tx_ref or not transaction_id:
        return jsonify({"success": False, "error": "Invalid webhook payload."}), 400
    try:
        verify_and_activate(str(tx_ref), str(transaction_id))
    except (FlutterwaveError, TypeError, ValueError):
        # Acknowledge only verified/recognized events; provider retries may be
        # useful for temporary verification API failures.
        return jsonify({"success": False, "error": "Webhook transaction could not be verified."}), 400
    return jsonify({"success": True}), 200



@billing_bp.post("/api/billing/palmkash/callback")
def palmkash_callback():
    """Accept a PalmKash notification only after checking its status server-to-server."""
    payload = request.get_json(silent=True)
    payload = payload if isinstance(payload, dict) else {}
    client_reference = str(payload.get("client_reference") or "").strip()
    provider_reference = str(payload.get("reference") or "").strip()
    if not client_reference or not provider_reference:
        return jsonify({"success": False, "error": "Payment reference is missing."}), 400
    try:
        result = palmkash_verify_and_activate(client_reference, provider_reference)
    except PalmKashError:
        return jsonify({"success": False, "error": "Payment could not be verified."}), 400
    return jsonify({"success": True, **result}), 200


@billing_bp.get("/api/billing/payments/<path:tx_ref>/status")
def payment_status(tx_ref):
    """Allow a signed-in customer to refresh only their own payment status."""
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": False, "error": "Sign in to view payment status."}), 401
    with auth_service.connection() as db:
        row = db.execute(
            "SELECT provider FROM payment_transactions WHERE tx_ref=? AND user_id=?",
            (tx_ref, user_id),
        ).fetchone()
    if not row:
        return jsonify({"success": False, "error": "Payment record not found."}), 404
    if row["provider"] == "palmkash":
        try:
            result = palmkash_refresh_payment(tx_ref, user_id)
        except PalmKashError as exc:
            return jsonify({"success": False, "error": str(exc)}), 502
        return jsonify({"success": True, **result}), 200
    with auth_service.connection() as db:
        payment = db.execute(
            "SELECT status,plan_id,amount,currency,provider FROM payment_transactions WHERE tx_ref=? AND user_id=?",
            (tx_ref, user_id),
        ).fetchone()
    return jsonify({"success": True, **dict(payment)}), 200
