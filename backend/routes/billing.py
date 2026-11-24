from flask import Blueprint, jsonify, session

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
def checkout_not_configured():
    # No payment provider has been selected/configured yet. Never accept a
    # client-supplied plan as proof of payment or activate entitlements here.
    if not session.get("account_id"):
        return jsonify({"success": False, "error": "Sign in before choosing a paid plan."}), 401
    return jsonify({"success": False,
                    "error": "Paid checkout is not available yet. Payment provider integration is pending."}), 503
