"""Flutterwave hosted checkout and server-side transaction verification.

No subscription is activated from browser-supplied payment status. A payment is
only accepted after Flutterwave's transaction verification API confirms it.
"""
import hmac
import os
import secrets
from datetime import datetime, timezone

import requests

from backend.database.auth_service import auth_service
from backend.services.plan_service import PLANS, activate_subscription

API_BASE = "https://api.flutterwave.com/v3"


class FlutterwaveError(Exception):
    pass


def _config(name, default=""):
    return os.getenv(name, default).strip()


def is_configured():
    return bool(_config("FLW_SECRET_KEY") and _config("FLW_SECRET_HASH"))


def _amount_for(plan_id, method):
    if plan_id not in ("pro", "business"):
        raise FlutterwaveError("Choose a paid plan.")
    if method == "card":
        return round(float(PLANS[plan_id]["price_usd"]), 2), "USD"
    if method == "mobile_money":
        raw = _config(f"FLW_{plan_id.upper()}_PRICE_RWF")
        if not raw:
            raise FlutterwaveError(
                "Mobile Money pricing is not configured yet. Please use card payment."
            )
        try:
            amount = int(raw)
        except ValueError as exc:
            raise FlutterwaveError("The Mobile Money price configuration is invalid.") from exc
        if amount <= 0:
            raise FlutterwaveError("The Mobile Money price configuration is invalid.")
        return amount, "RWF"
    raise FlutterwaveError("Choose a supported payment method.")


def _provider_request(method, path, *, payload=None):
    secret = _config("FLW_SECRET_KEY")
    if not secret:
        raise FlutterwaveError("Flutterwave checkout is not configured.")
    try:
        response = requests.request(
            method,
            f"{API_BASE}{path}",
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
            json=payload,
            timeout=20,
        )
        response.raise_for_status()
        body = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise FlutterwaveError("Unable to contact the payment provider. Please try again.") from exc
    if body.get("status") != "success":
        raise FlutterwaveError("The payment provider could not process this request.")
    return body.get("data") or {}


def create_checkout(user_id, email, plan_id, method, phone_number=None):
    amount, currency = _amount_for(plan_id, method)
    tx_ref = f"phishguard-{user_id}-{secrets.token_urlsafe(18)}"
    callback = _config("FLW_REDIRECT_URL")
    if not callback:
        raise FlutterwaveError("The payment return URL has not been configured.")
    payload = {
        "tx_ref": tx_ref,
        "amount": amount,
        "currency": currency,
        "redirect_url": callback,
        "customer": {"email": email},
        "customizations": {
            "title": "PhishGuard subscription",
            "description": f"{PLANS[plan_id]['name']} subscription",
            "logo": _config("FLW_LOGO_URL"),
        },
        "meta": {"user_id": int(user_id), "plan_id": plan_id, "payment_method": method},
        "payment_options": "card" if method == "card" else "mobilemoneyrwanda",
    }
    if method == "mobile_money":
        phone = (phone_number or "").strip()
        if not phone or len(phone) < 9 or len(phone) > 16 or not phone.replace("+", "").isdigit():
            raise FlutterwaveError("Enter a valid MTN or Airtel phone number.")
        payload["country"] = "RW"
        payload["customer"]["phonenumber"] = phone

    data = _provider_request("POST", "/payments", payload=payload)
    checkout_url = data.get("link")
    if not checkout_url or not checkout_url.startswith("https://"):
        raise FlutterwaveError("The payment provider did not return a valid checkout link.")

    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        db.execute(
            """INSERT INTO payment_transactions
            (user_id,plan_id,tx_ref,amount,currency,payment_method,status,created_at,updated_at)
            VALUES (?,?,?,?,?,?,'pending',?,?)""",
            (user_id, plan_id, tx_ref, amount, currency, method, now, now),
        )
    return {"checkout_url": checkout_url, "tx_ref": tx_ref, "amount": amount, "currency": currency}


def verify_and_activate(tx_ref, transaction_id):
    """Verify a transaction directly with Flutterwave, then activate once."""
    if not tx_ref or not transaction_id:
        raise FlutterwaveError("Payment reference is missing.")
    data = _provider_request("GET", f"/transactions/{transaction_id}/verify")
    with auth_service.connection() as db:
        payment = db.execute(
            "SELECT * FROM payment_transactions WHERE tx_ref=?", (tx_ref,)
        ).fetchone()
    if not payment:
        raise FlutterwaveError("This payment reference is not recognized.")
    if payment["status"] == "successful":
        return {"already_processed": True, "plan_id": payment["plan_id"]}
    if (
        str(data.get("tx_ref", "")) != tx_ref
        or str(data.get("status", "")).lower() != "successful"
        or str(data.get("currency", "")).upper() != payment["currency"]
        or float(data.get("amount", 0)) < float(payment["amount"])
        or str(data.get("id", "")) != str(transaction_id)
    ):
        raise FlutterwaveError("Payment verification failed. No subscription was activated.")

    # Subscription upsert is keyed by the verified provider transaction ID.
    # It is safe to retry if the callback/webhook is delivered more than once.
    try:
        period_start = datetime.fromisoformat(
            str(data.get("created_at") or payment["created_at"]).replace("Z", "+00:00")
        )
    except ValueError:
        period_start = datetime.now(timezone.utc)
    activate_subscription(
        payment["user_id"], payment["plan_id"], "flutterwave",
        f"flutterwave-tx-{transaction_id}", period_start=period_start,
    )
    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        db.execute(
            """UPDATE payment_transactions SET status='successful',
            provider_transaction_id=?,updated_at=? WHERE tx_ref=? AND status='pending'""",
            (str(transaction_id), now, tx_ref),
        )
    return {"already_processed": False, "plan_id": payment["plan_id"]}


def validate_webhook_signature(signature):
    expected = _config("FLW_SECRET_HASH")
    return bool(expected and signature and hmac.compare_digest(expected, signature))
