import hashlib
import hmac
import json

import pytest

from backend.services import palmkash_service as palm


def test_normalize_rwanda_mobile_numbers():
    assert palm.normalize_phone_number("0788123456") == "250788123456"
    assert palm.normalize_phone_number("250788123456") == "250788123456"
    assert palm.normalize_phone_number("788123456") == "250788123456"
    assert palm.normalize_phone_number("+250 72 812 3456") == "250728123456"


@pytest.mark.parametrize("phone", ["", "123456789", "250701234567", "078123", "07881234567"])
def test_reject_invalid_or_unsupported_rwanda_mobile_numbers(phone):
    with pytest.raises(palm.PalmKashError):
        palm.normalize_phone_number(phone)


def test_palmkash_checkout_requires_approval_credentials_and_both_prices(monkeypatch):
    for key in ("PK_API_TOKEN", "PK_MERCHANT_KEY", "PK_CALLBACK_URL",
                "PK_PRO_PRICE_RWF", "PK_BUSINESS_PRICE_RWF"):
        monkeypatch.delenv(key, raising=False)
    assert palm.checkout_availability() == {
        "mobile_money": False,
        "prices_rwf": {"pro": None, "business": None},
    }

    monkeypatch.setenv("PK_API_TOKEN", "test-token")
    monkeypatch.setenv("PK_MERCHANT_KEY", "test-merchant-key")
    monkeypatch.setenv("PK_CALLBACK_URL", "https://example.com/api/billing/palmkash/callback")
    monkeypatch.setenv("PK_PRO_PRICE_RWF", "2500")
    monkeypatch.setenv("PK_BUSINESS_PRICE_RWF", "9000")
    assert palm.checkout_availability() == {
        "mobile_money": True,
        "prices_rwf": {"pro": 2500, "business": 9000},
    }


def test_palmkash_request_signs_exact_json_body(monkeypatch):
    monkeypatch.setenv("PK_API_TOKEN", "test-token")
    monkeypatch.setenv("PK_MERCHANT_KEY", "test-merchant-key")
    monkeypatch.setattr(palm.time, "time", lambda: 1700000000)

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"status": "pending", "reference": "provider-ref"}

    captured = {}

    def fake_post(url, *, data, headers, timeout):
        captured.update(url=url, data=data, headers=headers, timeout=timeout)
        return FakeResponse()

    monkeypatch.setattr(palm.requests, "post", fake_post)
    payload = {
        "merchant_id": "test-merchant-key",
        "phone_number": "250788123456",
        "amount": 2500,
        "currency": "RWF",
        "client_reference": "phishguard-test",
        "callback_url": "https://example.com/callback",
    }

    result = palm._signed_request("/payments/make-payment", payload)

    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    expected = hmac.new(
        b"test-merchant-key",
        b"1700000000." + body,
        hashlib.sha256,
    ).hexdigest()
    assert result["reference"] == "provider-ref"
    assert captured["data"] == body
    assert captured["headers"]["X-Timestamp"] == "1700000000"
    assert captured["headers"]["X-Signature"] == expected
    assert captured["headers"]["Authorization"] == "Bearer test-token"
