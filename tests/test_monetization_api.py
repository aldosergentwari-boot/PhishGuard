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


def test_anonymous_visitors_receive_free_plan(client):
    response = client.get("/api/billing/me")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["authenticated"] is False
    assert payload["plan"]["plan_id"] == "free"


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
