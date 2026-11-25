import backend.database.auth_service as auth_module
from backend.app import create_app
from backend.database.auth_service import auth_service
from backend.services.plan_service import get_usage


def test_admin_can_grant_bonus_scans_to_a_registered_account(
    monkeypatch, tmp_path
):
    database_path = tmp_path / "admin-scans.sqlite3"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", database_path)
    monkeypatch.setenv("PHISHGUARD_ADMIN_TOKEN", "test-admin-token-that-is-at-least-32-chars")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-admin-tests")

    app = create_app()
    user = auth_service.create_user(
        "scan-user@example.com",
        "A-Strong-Test-Password-123!",
    )

    response = app.test_client().post(
        "/api/admin/scan-credits",
        headers={"X-Admin-Token": "test-admin-token-that-is-at-least-32-chars"},
        json={
            "email": "scan-user@example.com",
            "scans": 25,
            "reason": "Customer support goodwill allowance",
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["granted_scans"] == 25
    assert payload["user"]["id"] == user["id"]

    usage = get_usage(f"account:{user['id']}", "free")
    assert usage["plan_scans_limit"] == 50
    assert usage["admin_bonus_scans"] == 25
    assert usage["scans_limit"] == 75
    assert usage["scans_remaining"] == 75


def test_admin_scan_credit_endpoint_rejects_invalid_token(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "admin-auth.sqlite3")
    monkeypatch.setenv("PHISHGUARD_ADMIN_TOKEN", "test-admin-token-that-is-at-least-32-chars")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-admin-tests")

    app = create_app()
    response = app.test_client().post(
        "/api/admin/scan-credits",
        headers={"X-Admin-Token": "wrong-token"},
        json={
            "email": "scan-user@example.com",
            "scans": 25,
            "reason": "test",
        },
    )

    assert response.status_code == 401


def test_owner_console_is_available_without_exposing_admin_token():
    app = create_app()
    response = app.test_client().get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'id="page-admin"' in html
    assert 'id="adminCreditForm"' in html
    assert 'id="adminToken"' in html
    assert 'data-page="admin"' in html
