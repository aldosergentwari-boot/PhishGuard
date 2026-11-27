import pytest

from backend.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module
    import backend.database.history_service as history_module
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "phishguard_test.db")
    monkeypatch.setattr(history_module, "DATABASE_PATH", tmp_path / "phishguard_test.db")
    monkeypatch.setattr(history_module, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(history_module, "_history_service", None)
    app = create_app()
    app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with app.test_client() as test_client:
        yield test_client


def register(client):
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/auth/register",
        json={"email": "billing@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201
    return csrf


def test_checkout_is_disabled_until_urubutopay_is_approved(client, monkeypatch):
    register(client)
    monkeypatch.delenv("FLW_SECRET_KEY", raising=False)
    monkeypatch.delenv("FLW_SECRET_HASH", raising=False)
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/billing/checkout",
        json={"plan_id": "pro", "payment_method": "card"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 503


def test_checkout_stays_disabled_even_if_legacy_flutterwave_is_configured(client, monkeypatch):
    import backend.services.flutterwave_service as service

    register(client)
    monkeypatch.setenv("FLW_SECRET_KEY", "legacy-test-secret")
    monkeypatch.setenv("FLW_SECRET_HASH", "legacy-test-hash")
    monkeypatch.setenv("FLW_REDIRECT_URL", "https://example.test/api/billing/callback")
    monkeypatch.setattr(service, "_provider_request", lambda *args, **kwargs: {
        "link": "https://checkout.flutterwave.com/should-not-be-used"
    })
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/billing/checkout",
        json={"plan_id": "pro", "payment_method": "card", "provider": "flutterwave"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert response.get_json()["code"] == "PAYMENTS_NOT_AVAILABLE"
    with service.auth_service.connection() as db:
        count = db.execute("SELECT COUNT(*) FROM payment_transactions").fetchone()[0]
    assert count == 0


def test_checkout_never_falls_back_to_palmkash_for_new_mobile_money_payments(client, monkeypatch):
    import backend.services.palmkash_service as service

    register(client)
    monkeypatch.setenv("PK_API_TOKEN", "legacy-token")
    monkeypatch.setenv("PK_MERCHANT_KEY", "legacy-merchant")
    monkeypatch.setenv("PK_CALLBACK_URL", "https://example.test/callback")
    monkeypatch.setenv("PK_PRO_PRICE_RWF", "2500")
    monkeypatch.setenv("PK_BUSINESS_PRICE_RWF", "9000")
    monkeypatch.setattr(service, "create_payment", lambda **kwargs: {
        "checkout_url": "https://legacy.example.test"
    })
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/billing/checkout",
        json={"plan_id": "pro", "payment_method": "mobile_money", "provider": "palmkash"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert response.get_json()["code"] == "PAYMENTS_NOT_AVAILABLE"

def test_invalid_webhook_signature_is_rejected(client, monkeypatch):
    monkeypatch.setenv("FLW_SECRET_HASH", "expected-secret-hash")
    response = client.post(
        "/api/billing/webhook",
        json={"data": {"id": 123, "tx_ref": "unknown"}},
        headers={"verif-hash": "wrong-hash"},
    )
    assert response.status_code == 401


def test_payment_verification_rejects_amount_or_currency_mismatch(client, monkeypatch):
    import backend.services.flutterwave_service as service

    register(client)
    with service.auth_service.connection() as db:
        db.execute(
            """INSERT INTO payment_transactions
            (user_id,plan_id,tx_ref,amount,currency,payment_method,status,created_at,updated_at)
            VALUES (1,'pro','known-ref',4.99,'USD','card','pending','now','now')"""
        )
    monkeypatch.setattr(service, "_provider_request", lambda *args, **kwargs: {
        "id": 456, "tx_ref": "known-ref", "status": "successful",
        "currency": "RWF", "amount": 5000,
    })
    with pytest.raises(service.FlutterwaveError):
        service.verify_and_activate("known-ref", "456")


def test_valid_verified_payment_activates_subscription_once(client, monkeypatch):
    import backend.services.flutterwave_service as service

    register(client)
    with service.auth_service.connection() as db:
        db.execute(
            """INSERT INTO payment_transactions
            (user_id,plan_id,tx_ref,amount,currency,payment_method,status,created_at,updated_at)
            VALUES (1,'pro','verified-ref',4.99,'USD','card','pending','now','now')"""
        )
    monkeypatch.setattr(service, "_provider_request", lambda *args, **kwargs: {
        "id": 789, "tx_ref": "verified-ref", "status": "successful",
        "currency": "USD", "amount": 4.99,
    })
    activations = []
    monkeypatch.setattr(service, "activate_subscription",
                        lambda *args, **kwargs: activations.append((args, kwargs)))
    result = service.verify_and_activate("verified-ref", "789")
    assert result["plan_id"] == "pro"
    assert result["already_processed"] is False
    assert len(activations) == 1
    with service.auth_service.connection() as db:
        row = db.execute(
            "SELECT status,provider_transaction_id FROM payment_transactions WHERE tx_ref='verified-ref'"
        ).fetchone()
    assert row["status"] == "successful"
    assert row["provider_transaction_id"] == "789"
