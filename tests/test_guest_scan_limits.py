import pytest

from backend.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


@pytest.mark.parametrize("endpoint", ["/api/analyze", "/api/predict"])
def test_guest_scan_limit_requires_registration(client, monkeypatch, endpoint):
    from backend.services import plan_service

    def deny_guest(owner_id, plan_id):
        assert isinstance(owner_id, str) and not owner_id.startswith("account:")
        assert plan_id == "guest"
        return False, {
            "scans_used": 10,
            "scans_limit": 10,
            "scans_remaining": 0,
            "period": "calendar_month_utc",
        }

    monkeypatch.setattr(plan_service, "can_scan", deny_guest)
    response = client.post(endpoint, json={"url": "https://example.com"})
    payload = response.get_json()

    assert response.status_code == 429
    assert payload["success"] is False
    assert payload["code"] == "GUEST_SCAN_LIMIT_REACHED"
    assert payload["registration_required"] is True
    assert payload["plan"] == "guest"
    assert payload["usage"]["scans_limit"] == 10


def test_guest_plan_has_ten_scans_per_month():
    from backend.services.plan_service import PLAN_LIMITS

    assert PLAN_LIMITS["guest"]["scans_per_month"] == 10
    assert PLAN_LIMITS["guest"]["history_records"] == 10


def test_anonymous_billing_usage_reports_guest_plan(client):
    response = client.get("/api/billing/me")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["authenticated"] is False
    assert payload["plan"]["plan_id"] == "guest"
    assert payload["usage"]["scans_limit"] == 10
