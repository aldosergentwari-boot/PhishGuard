from flask import Blueprint, jsonify, session

from backend.services.plan_service import PLANS, get_account_plan

billing_bp = Blueprint("billing", __name__)


@billing_bp.get("/api/billing/plans")
def list_plans():
    return jsonify({"success": True, "currency": "USD", "plans": PLANS}), 200


@billing_bp.get("/api/billing/me")
def current_subscription():
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": True, "authenticated": False,
                        "plan": {"plan_id": "free", **PLANS["free"]}}), 200
    return jsonify({"success": True, "authenticated": True,
                    "plan": get_account_plan(user_id)}), 200


@billing_bp.post("/api/billing/checkout")
def checkout_not_configured():
    # No payment provider has been selected/configured yet. Never accept a
    # client-supplied plan as proof of payment or activate entitlements here.
    if not session.get("account_id"):
        return jsonify({"success": False, "error": "Sign in before choosing a paid plan."}), 401
    return jsonify({"success": False,
                    "error": "Paid checkout is not available yet. Payment provider integration is pending."}), 503
