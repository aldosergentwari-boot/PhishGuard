import pytest

from backend.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "auth_test.db")
    app = create_app()
    app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with app.test_client() as test_client:
        yield test_client


def _csrf(client):
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    return response.get_json()["csrf_token"]


def test_plan_catalog_has_confirmed_seven_month_business_term(client):
    response = client.get("/api/billing/plans")
    assert response.status_code == 200
    plans = response.get_json()["plans"]
    assert plans["free"]["price_usd"] == 0
    assert plans["pro"]["price_usd"] == 4.99
    assert plans["pro"]["billing_interval_months"] == 1
    assert plans["business"]["price_usd"] == 19.99
    assert plans["business"]["billing_interval_months"] == 7


def test_anonymous_visitors_receive_guest_plan(client):
    response = client.get("/api/billing/me")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["authenticated"] is False
    assert payload["plan"]["plan_id"] == "guest"
    assert payload["usage"]["scans_limit"] == 10


def test_registration_creates_free_subscription(client):
    token = _csrf(client)
    response = client.post(
        "/api/auth/register",
        json={"email": "tester@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 201
    assert response.get_json()["plan"] == "free"
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True
    assert me["subscription"]["plan_id"] == "free"


def test_auth_mutations_require_csrf(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "tester@example.com", "password": "correct horse battery"},
    )
    assert response.status_code == 403


def test_paid_checkout_cannot_be_activated_by_client(client):
    token = _csrf(client)
    registered = client.post(
        "/api/auth/register",
        json={"email": "tester@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert registered.status_code == 201
    token = _csrf(client)
    response = client.post(
        "/api/billing/checkout",
        json={"plan_id": "business", "price_usd": 0.01},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 503
    assert client.get("/api/billing/me").get_json()["plan"]["plan_id"] == "free"



def test_ads_are_disabled_by_default(client, monkeypatch):
    for key in ("ADS_ENABLED", "ADSENSE_APPROVED", "ADSENSE_CLIENT_ID", "ADSENSE_SLOT_ID"):
        monkeypatch.delenv(key, raising=False)
    response = client.get("/api/ads/config")
    assert response.status_code == 200
    assert response.get_json()["enabled"] is False


def test_ads_require_approval_and_valid_publisher_configuration(client, monkeypatch):
    monkeypatch.setenv("ADS_ENABLED", "true")
    monkeypatch.setenv("ADSENSE_APPROVED", "true")
    monkeypatch.setenv("ADSENSE_CLIENT_ID", "ca-pub-1234567890123456")
    monkeypatch.setenv("ADSENSE_SLOT_ID", "1234567890")
    response = client.get("/api/ads/config")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["enabled"] is True
    assert payload["provider"] == "adsense"
    assert payload["client_id"] == "ca-pub-1234567890123456"


def test_ads_never_enable_without_publisher_approval(client, monkeypatch):
    monkeypatch.setenv("ADS_ENABLED", "true")
    monkeypatch.setenv("ADSENSE_APPROVED", "false")
    monkeypatch.setenv("ADSENSE_CLIENT_ID", "ca-pub-1234567890123456")
    monkeypatch.setenv("ADSENSE_SLOT_ID", "1234567890")
    response = client.get("/api/ads/config")
    assert response.status_code == 200
    assert response.get_json()["enabled"] is False



def test_payment_history_requires_sign_in(client):
    response = client.get("/api/billing/payments")
    assert response.status_code == 401


def test_payment_history_returns_only_the_signed_in_users_records(client):
    token = _csrf(client)
    registered = client.post(
        "/api/auth/register",
        json={"email": "payments@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert registered.status_code == 201
    from backend.database.auth_service import auth_service
    with auth_service.connection() as db:
        db.execute(
            """INSERT INTO payment_transactions
            (user_id,plan_id,tx_ref,amount,currency,payment_method,status,created_at,updated_at)
            VALUES (1,'pro','private-payment-ref',4.99,'USD','card','successful','2026-11-25T12:00:00+00:00','2026-11-25T12:00:00+00:00')"""
        )
    response = client.get("/api/billing/payments")
    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload["payments"]) == 1
    assert payload["payments"][0]["plan_id"] == "pro"
    assert payload["payments"][0]["status"] == "successful"
    assert "tx_ref" not in payload["payments"][0]


def test_admin_monetization_status_is_private(client):
    response = client.get("/api/admin/management/monetization")
    assert response.status_code == 401


def test_verified_new_subscription_supersedes_previous_active_period(client):
    token = _csrf(client)
    registered = client.post(
        "/api/auth/register",
        json={"email": "renewal@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert registered.status_code == 201

    from backend.services.plan_service import activate_subscription, get_account_plan
    from datetime import datetime, timezone
    start = datetime.now(timezone.utc)
    activate_subscription(1, "pro", "test", "provider-period-one", period_start=start)
    activate_subscription(1, "business", "test", "provider-period-two", period_start=start)

    from backend.database.auth_service import auth_service
    with auth_service.connection() as db:
        rows = db.execute(
            "SELECT plan_id,status FROM subscriptions WHERE user_id=1 ORDER BY id"
        ).fetchall()
    assert [(row["plan_id"], row["status"]) for row in rows] == [
        ("free", "superseded"),
        ("pro", "superseded"),
        ("business", "active"),
    ]
    assert get_account_plan(1)["plan_id"] == "business"
