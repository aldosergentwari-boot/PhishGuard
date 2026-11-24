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


def test_checkout_is_disabled_until_flutterwave_is_configured(client, monkeypatch):
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


def test_checkout_creates_pending_transaction_and_returns_hosted_link(client, monkeypatch):
    import backend.services.flutterwave_service as service

    register(client)
    monkeypatch.setenv("FLW_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FLW_SECRET_HASH", "test-hash")
    monkeypatch.setenv("FLW_REDIRECT_URL", "https://example.test/api/billing/callback")
    monkeypatch.setattr(service, "_provider_request", lambda *args, **kwargs: {
        "link": "https://checkout.flutterwave.com/test"
    })
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/billing/checkout",
        json={"plan_id": "pro", "payment_method": "card"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["checkout_url"] == "https://checkout.flutterwave.com/test"
    assert body["amount"] == 4.99
    assert body["currency"] == "USD"
    with service.auth_service.connection() as db:
        row = db.execute(
            "SELECT status,plan_id,amount,currency FROM payment_transactions WHERE tx_ref=?",
            (body["tx_ref"],),
        ).fetchone()
    assert row["status"] == "pending"
    assert row["plan_id"] == "pro"


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
