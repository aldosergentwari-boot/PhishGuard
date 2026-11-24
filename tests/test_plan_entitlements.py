from datetime import datetime, timezone

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


def test_plan_limits_are_returned_by_billing_api(client):
    response = client.get("/api/billing/plans")
    assert response.status_code == 200
    plans = response.get_json()["plans"]
    assert plans["free"]["limits"] == {"scans_per_month": 50, "history_records": 50}
    assert plans["pro"]["limits"] == {"scans_per_month": 2000, "history_records": 2000}
    assert plans["business"]["price_usd"] == 19.99
    assert plans["business"]["billing_interval_months"] == 7
    assert plans["business"]["limits"] == {"scans_per_month": 10000, "history_records": 10000}


def test_account_page_is_available(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b'id="page-account"' in response.data
    assert b'id="registerForm"' in response.data
    assert b'id="loginForm"' in response.data


def test_free_account_receives_monthly_usage(client):
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    registered = client.post(
        "/api/auth/register",
        json={"email": "usage@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": csrf},
    )
    assert registered.status_code == 201
    usage = client.get("/api/billing/me").get_json()["usage"]
    assert usage["scans_used"] == 0
    assert usage["scans_limit"] == 50
    assert usage["scans_remaining"] == 50


def test_scan_api_blocks_requests_when_plan_quota_is_exhausted(client, monkeypatch):
    import backend.services.plan_service as plans
    monkeypatch.setattr(plans, "can_scan", lambda owner_id, plan_id: (
        False,
        {"scans_used": 50, "scans_limit": 50, "scans_remaining": 0}
    ))
    response = client.post(
        "/api/analyze",
        json={"url": "https://example.com", "mode": "offline"},
    )
    assert response.status_code == 429
    payload = response.get_json()
    assert payload["code"] == "SCAN_LIMIT_REACHED"
    assert payload["usage"]["scans_remaining"] == 0


def test_history_service_respects_maximum_visible_records(tmp_path, monkeypatch):
    import backend.database.history_service as history_module
    monkeypatch.setattr(history_module, "DATABASE_PATH", tmp_path / "history.db")
    monkeypatch.setattr(history_module, "DATABASE_DIR", tmp_path)
    service = history_module.HistoryService()
    for index in range(3):
        service.save_scan({
            "url": f"https://example{index}.com",
            "final_prediction": "LEGITIMATE",
            "final_risk_score": 1,
            "ml_result": {"confidence": 99},
            "local_intelligence": {"domain": f"example{index}.com"},
        }, owner_id="account:1")
    result = service.get_history("account:1", limit=10, max_records=2)
    assert result["total"] == 2
    assert len(result["scans"]) == 2
    oldest_id = min(row["id"] for row in service.get_history(
        "account:1", limit=10
    )["scans"])
    assert service.get_scan(oldest_id, "account:1", max_records=2) is None
