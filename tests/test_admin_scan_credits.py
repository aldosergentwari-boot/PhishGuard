from datetime import datetime, timezone

import backend.database.auth_service as auth_module
from backend.app import create_app
from backend.database.auth_service import auth_service
from backend.services.plan_service import get_usage


OWNER_EMAIL = "phishguard-owner@example.com"
OWNER_PASSWORD = "A-Strong-Owner-Password-123!"


def _owner_client(monkeypatch, tmp_path, filename="admin.sqlite3"):
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / filename)
    monkeypatch.setenv("PHISHGUARD_OWNER_EMAIL", OWNER_EMAIL)
    monkeypatch.delenv("PHISHGUARD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-admin-tests")
    app = create_app()
    user = auth_service.create_user(OWNER_EMAIL, OWNER_PASSWORD)
    with auth_service.connection() as db:
        db.execute("UPDATE users SET email_verified=1 WHERE id=?", (user["id"],))
    client = app.test_client()
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/admin/login",
        json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    # Login rotates the session and clears the pre-login CSRF token.
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    return app, client, user, csrf


def test_owner_login_requires_verified_configured_owner(monkeypatch, tmp_path):
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "owner-login.sqlite3")
    monkeypatch.setenv("PHISHGUARD_OWNER_EMAIL", OWNER_EMAIL)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-admin-tests")
    app = create_app()
    auth_service.create_user(OWNER_EMAIL, OWNER_PASSWORD)
    client = app.test_client()
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/admin/login",
        json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 401
    assert client.get("/admin").status_code == 302


def test_admin_dashboard_and_management_apis_require_owner_session(monkeypatch, tmp_path):
    app, client, user, csrf = _owner_client(monkeypatch, tmp_path)
    assert client.get("/admin").status_code == 200
    assert client.get("/api/admin/overview").status_code == 200
    assert client.get("/api/admin/users").status_code == 200
    assert client.get("/api/admin/payments").status_code == 200

    other = app.test_client()
    assert other.get("/api/admin/overview").status_code == 401
    assert other.get("/admin").status_code == 302


def test_admin_can_grant_bonus_scans_to_registered_account(monkeypatch, tmp_path):
    _, client, owner, csrf = _owner_client(monkeypatch, tmp_path, "grant.sqlite3")
    customer = auth_service.create_user("scan-user@example.com", "A-Strong-Test-Password-123!")
    response = client.post(
        "/api/admin/scan-credits",
        headers={"X-CSRF-Token": csrf},
        json={
            "email": "scan-user@example.com",
            "scans": 25,
            "reason": "Customer support goodwill allowance",
        },
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["granted_scans"] == 25
    assert payload["user"]["id"] == customer["id"]
    usage = get_usage(f"account:{customer['id']}", "free")
    assert usage["plan_scans_limit"] == 50
    assert usage["admin_bonus_scans"] == 25
    assert usage["scans_limit"] == 75
    assert usage["scans_remaining"] == 75


def test_admin_overview_returns_operational_counts(monkeypatch, tmp_path):
    _, client, owner, csrf = _owner_client(monkeypatch, tmp_path, "overview.sqlite3")
    with auth_service.connection() as db:
        db.execute(
            "INSERT INTO scan_usage(owner_id, scanned_at) VALUES (?, ?)",
            (f"account:{owner['id']}", datetime.now(timezone.utc).isoformat()),
        )
    overview = client.get("/api/admin/overview").get_json()["overview"]
    # The owner remains authenticated but is not counted as a customer.
    assert overview["active_accounts"] == 0
    assert overview["active_subscriptions"] == 0
    assert overview["scans_this_month"] == 1
    assert overview["period_timezone"] == "UTC"


def test_public_website_does_not_expose_owner_console(monkeypatch, tmp_path):
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "public.sqlite3")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-admin-tests")
    app = create_app()
    response = app.test_client().get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'id="page-admin"' not in html
    assert 'data-page="admin"' not in html
    assert "Owner Console" not in html
    client_redirect = app.test_client().get("/admin/login")
    assert client_redirect.status_code == 200
