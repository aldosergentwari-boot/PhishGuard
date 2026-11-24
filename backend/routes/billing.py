from flask import Blueprint, jsonify, redirect, request, session

from backend.services.plan_service import (
    PLANS, PLAN_LIMITS, get_account_plan, get_usage
)
from backend.services.user_identity import get_current_user_id
from backend.services.flutterwave_service import (
    FlutterwaveError, create_checkout, is_configured,
    validate_webhook_signature, verify_and_activate,
)

billing_bp = Blueprint("billing", __name__)


@billing_bp.get("/api/billing/plans")
def list_plans():
    public_plans = {
        key: {**value, "limits": PLAN_LIMITS[key]}
        for key, value in PLANS.items()
    }
    return jsonify({"success": True, "currency": "USD", "plans": public_plans}), 200


@billing_bp.get("/api/billing/me")
def current_subscription():
    owner_id = get_current_user_id()
    user_id = session.get("account_id")
    if user_id:
        plan = get_account_plan(user_id)
    else:
        plan = {"plan_id": "free", "status": "active",
                "limits": PLAN_LIMITS["free"], **PLANS["free"]}
    usage = get_usage(owner_id, plan["plan_id"])
    return jsonify({
        "success": True,
        "authenticated": bool(user_id),
        "plan": plan,
        "usage": usage
    }), 200


@billing_bp.post("/api/billing/checkout")
def create_paid_checkout():
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": False, "error": "Sign in before choosing a paid plan."}), 401
    if not is_configured():
        return jsonify({"success": False, "error": "Flutterwave checkout is not configured yet."}), 503
    payload = request.get_json(silent=True)
    payload = payload if isinstance(payload, dict) else {}
    try:
        result = create_checkout(
            user_id=user_id,
            email=session.get("account_email", ""),
            plan_id=payload.get("plan_id"),
            method=payload.get("payment_method"),
            phone_number=payload.get("phone_number"),
        )
    except FlutterwaveError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    return jsonify({"success": True, **result}), 200


@billing_bp.get("/api/billing/callback")
def payment_callback():
    # A browser redirect is not proof of payment; verify with Flutterwave.
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
