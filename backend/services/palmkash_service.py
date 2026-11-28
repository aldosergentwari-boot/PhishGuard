"""PalmKash Rwanda Mobile Money collections.

All credentials remain server-side. A callback is only a notification: a payment
is activated after the transaction status is re-checked against PalmKash.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone

import requests

from backend.database.auth_service import auth_service
from backend.services.plan_service import PLANS, activate_subscription
from backend.services.financial_ledger import record_verified_payment

API_BASE = "https://dashboard.palmkash.com/api/v1"


class PalmKashError(Exception):
    """Safe, user-displayable payment-provider error."""


def _config(name):
    return os.getenv(name, "").strip()


def _price(plan_id):
    if plan_id not in ("pro", "business"):
        raise PalmKashError("Choose a paid plan.")
    raw = _config(f"PK_{plan_id.upper()}_PRICE_RWF")
    if not raw.isdigit() or int(raw) <= 0:
        raise PalmKashError("Rwanda Mobile Money pricing is not configured for this plan.")
    return int(raw)


def is_configured():
    return bool(
        _config("PK_API_TOKEN")
        and _config("PK_MERCHANT_KEY")
        and _config("PK_CALLBACK_URL").startswith("https://")
    )


def checkout_availability():
    ready = is_configured()
    prices_ready = all(
        _config(f"PK_{plan.upper()}_PRICE_RWF").isdigit()
        and int(_config(f"PK_{plan.upper()}_PRICE_RWF") or "0") > 0
        for plan in ("pro", "business")
    )
    prices = {
        plan: int(_config(f"PK_{plan.upper()}_PRICE_RWF"))
        if _config(f"PK_{plan.upper()}_PRICE_RWF").isdigit()
        and int(_config(f"PK_{plan.upper()}_PRICE_RWF") or "0") > 0
        else None
        for plan in ("pro", "business")
    }
    return {
        "mobile_money": ready and prices_ready,
        "prices_rwf": prices,
    }


def normalize_phone_number(value):
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 10 and digits.startswith("0"):
        digits = "250" + digits[1:]
    elif len(digits) == 9:
        digits = "250" + digits
    if len(digits) != 12 or not digits.startswith("250"):
        raise PalmKashError("Enter a valid Rwanda MTN or Airtel number.")
    if digits[3:5] not in ("72", "73", "78", "79"):
        raise PalmKashError("Use a Rwanda MTN (078/079) or Airtel (072/073) number.")
    return digits


def _signed_request(path, payload):
    merchant_key = _config("PK_MERCHANT_KEY")
    api_token = _config("PK_API_TOKEN")
    if not merchant_key or not api_token:
        raise PalmKashError("PalmKash merchant approval and API credentials are still pending.")

    # Sign the exact compact JSON bytes sent over the wire. PalmKash requires
    # HMAC-SHA256(timestamp + '.' + canonical_body, merchant_key).
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    timestamp = str(int(time.time()))
    signature = hmac.new(
        merchant_key.encode("utf-8"),
        f"{timestamp}.{body}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
        "X-Merchant-Key": merchant_key,
        "X-Timestamp": timestamp,
        "X-Signature": signature,
    }
    try:
        response = requests.post(
            f"{API_BASE}{path}",
            data=body.encode("utf-8"),
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise PalmKashError("Unable to contact PalmKash. Please try again shortly.") from exc
    if not isinstance(result, dict):
        raise PalmKashError("PalmKash returned an invalid response.")
    return result


def _get_payment_status(reference):
    result = _signed_request(
        "/payments/get-payment-status",
        {"merchant_id": _config("PK_MERCHANT_KEY"), "reference": reference},
    )
    status = str(result.get("status", "")).lower()
    if status not in ("pending", "completed", "failed"):
        raise PalmKashError("PalmKash returned an unrecognized payment status.")
    returned_reference = str(result.get("reference", "")).strip()
    if not returned_reference:
        raise PalmKashError("PalmKash did not return a payment reference.")
    return status, returned_reference


def create_payment(user_id, plan_id, phone_number):
    if not is_configured():
        raise PalmKashError("PalmKash merchant approval and API credentials are still pending.")
    amount = _price(plan_id)
    phone = normalize_phone_number(phone_number)
    client_reference = f"phishguard-{int(user_id)}-{secrets.token_urlsafe(18)}"
    now = datetime.now(timezone.utc).isoformat()

    # Record the pending order before contacting the provider, so every
    # initiated collection has a durable local reference for reconciliation.
    with auth_service.connection() as db:
        db.execute(
            """INSERT INTO payment_transactions
               (user_id,plan_id,tx_ref,amount,currency,payment_method,status,provider,created_at,updated_at)
               VALUES (?,?,?,?,?,'mobile_money','pending','palmkash',?,?,?)""",
            (user_id, plan_id, client_reference, amount, "RWF", client_reference, now, now),
        )

    try:
        result = _signed_request(
            "/payments/make-payment",
            {
                "merchant_id": _config("PK_MERCHANT_KEY"),
                "phone_number": phone,
                "amount": amount,
                "currency": "RWF",
                "client_reference": client_reference,
                "callback_url": _config("PK_CALLBACK_URL"),
            },
        )
    except PalmKashError:
        # The request may have reached PalmKash even if the response timed out.
        # Keep it pending and reconcile using our client_reference rather than
        # falsely marking a potentially collected payment as failed.
        return {
            "tx_ref": client_reference,
            "provider_reference": None,
            "status": "pending",
            "amount": amount,
            "currency": "RWF",
            "reconciliation_pending": True,
        }

    status = str(result.get("status", "")).lower()
    provider_reference = str(result.get("reference", "")).strip()
    if status == "failed":
        with auth_service.connection() as db:
            db.execute(
                "UPDATE payment_transactions SET status='failed',updated_at=? WHERE tx_ref=? AND status='pending'",
                (datetime.now(timezone.utc).isoformat(), client_reference),
            )
        raise PalmKashError("PalmKash did not accept the payment request.")
    if status != "pending" or not provider_reference:
        raise PalmKashError("PalmKash returned an incomplete payment reference.")
    with auth_service.connection() as db:
        db.execute(
            """UPDATE payment_transactions SET provider_transaction_id=?,updated_at=?
               WHERE tx_ref=? AND provider='palmkash' AND status='pending'""",
            (provider_reference, datetime.now(timezone.utc).isoformat(), client_reference),
        )
    return {
        "tx_ref": client_reference,
        "provider_reference": provider_reference,
        "status": "pending",
        "amount": amount,
        "currency": "RWF",
    }


def _verify_and_apply(client_reference, provider_reference=None, user_id=None):
    with auth_service.connection() as db:
        query = "SELECT * FROM payment_transactions WHERE tx_ref=? AND provider='palmkash'"
        args = [client_reference]
        if user_id is not None:
            query += " AND user_id=?"
            args.append(user_id)
        payment = db.execute(query, args).fetchone()
    if not payment:
        raise PalmKashError("This PalmKash payment reference is not recognized.")
    if payment["status"] == "successful":
        record_verified_payment(client_reference)
        return {"status": "successful", "already_processed": True, "plan_id": payment["plan_id"]}

    stored_reference = str(payment["provider_transaction_id"] or "")
    if not stored_reference:
        raise PalmKashError("The PalmKash payment is awaiting reconciliation.")
    if stored_reference == client_reference:
        # The initiation request may have timed out after PalmKash accepted it.
        # Their status endpoint also accepts our client_reference.
        status, verified_reference = _get_payment_status(client_reference)
        if provider_reference and verified_reference != provider_reference:
            raise PalmKashError("PalmKash payment reference did not match the pending order.")
    else:
        if provider_reference and stored_reference != provider_reference:
            raise PalmKashError("PalmKash payment reference did not match the pending order.")
        status, verified_reference = _get_payment_status(stored_reference)
        if verified_reference != stored_reference:
            raise PalmKashError("PalmKash payment reference did not match the pending order.")

    now = datetime.now(timezone.utc).isoformat()
    if status == "failed":
        with auth_service.connection() as db:
            db.execute(
                "UPDATE payment_transactions SET status='failed',provider_transaction_id=?,updated_at=? WHERE tx_ref=? AND status='pending'",
                (verified_reference, now, client_reference),
            )
        return {"status": "failed", "plan_id": payment["plan_id"]}
    if status != "completed":
        with auth_service.connection() as db:
            db.execute(
                "UPDATE payment_transactions SET provider_transaction_id=?,updated_at=? WHERE tx_ref=? AND status='pending'",
                (verified_reference, now, client_reference),
            )
        return {"status": "pending", "plan_id": payment["plan_id"]}

    activate_subscription(
        payment["user_id"],
        payment["plan_id"],
        "palmkash",
        f"palmkash-{verified_reference}",
        period_start=datetime.now(timezone.utc),
    )
    with auth_service.connection() as db:
        db.execute(
            """UPDATE payment_transactions
               SET status='successful',provider_transaction_id=?,updated_at=?
               WHERE tx_ref=? AND provider='palmkash' AND status='pending'""",
            (verified_reference, now, client_reference),
        )
    record_verified_payment(client_reference)
    return {"status": "successful", "already_processed": False, "plan_id": payment["plan_id"]}

def verify_and_activate(client_reference, provider_reference):
    """Verify provider state before activating a plan; safe for repeated callbacks."""
    if not client_reference or not provider_reference:
        raise PalmKashError("Payment reference is missing.")
    return _verify_and_apply(client_reference, provider_reference)


def refresh_payment(client_reference, user_id):
    """Refresh a customer's own pending PalmKash payment from the provider."""
    with auth_service.connection() as db:
        row = db.execute(
            """SELECT provider_transaction_id,status FROM payment_transactions
               WHERE tx_ref=? AND user_id=? AND provider='palmkash'""",
            (client_reference, user_id),
        ).fetchone()
    if not row:
        raise PalmKashError("Payment record not found.")
    if row["status"] != "pending":
        with auth_service.connection() as db:
            payment = db.execute(
                "SELECT status,plan_id,amount,currency,provider FROM payment_transactions WHERE tx_ref=?",
                (client_reference,),
            ).fetchone()
        return dict(payment)
    result = _verify_and_apply(
        client_reference,
        None if row["provider_transaction_id"] == client_reference else row["provider_transaction_id"],
        user_id=user_id,
    )
    with auth_service.connection() as db:
        payment = db.execute(
            "SELECT status,plan_id,amount,currency,provider FROM payment_transactions WHERE tx_ref=?",
            (client_reference,),
        ).fetchone()
    return {**dict(payment), **result}
