from datetime import datetime, timezone

import backend.database.auth_service as auth_module
from backend.app import create_app
from backend.database.auth_service import auth_service


OWNER_EMAIL = "owner-management@example.com"
OWNER_PASSWORD = "A-Strong-Owner-Password-123!"


def owner_client(monkeypatch, tmp_path):
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "owner-management.sqlite3")
    monkeypatch.setenv("PHISHGUARD_OWNER_EMAIL", OWNER_EMAIL)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-management-tests")
    app = create_app()
    owner = auth_service.create_user(OWNER_EMAIL, OWNER_PASSWORD)
    with auth_service.connection() as db:
        db.execute("UPDATE users SET email_verified=1 WHERE id=?", (owner["id"],))
    client = app.test_client()
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    assert client.post("/api/admin/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD},
                       headers={"X-CSRF-Token": csrf}).status_code == 200
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    return app, client, owner, csrf


def test_management_user_search_suspend_and_audit(monkeypatch, tmp_path):
    app, client, owner, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("customer@example.com", "A-Strong-Customer-Password-123!")
    listing = client.get("/api/admin/management/users?q=customer")
    assert listing.status_code == 200
    assert listing.get_json()["total"] == 1

    response = client.post(f"/api/admin/management/users/{customer['id']}/status",
        json={"active": False, "reason": "Customer requested account suspension"},
        headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    with auth_service.connection() as db:
        row = db.execute("SELECT is_active,session_version FROM users WHERE id=?", (customer["id"],)).fetchone()
        assert row["is_active"] == 0
        assert row["session_version"] == 1
    events = client.get("/api/admin/management/audit").get_json()["events"]
    assert events[0]["action"] == "user.suspended"


def test_management_plan_change_and_notification(monkeypatch, tmp_path):
    _, client, _, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("plan-user@example.com", "A-Strong-Customer-Password-123!")
    response = client.post(f"/api/admin/management/users/{customer['id']}/plan",
        json={"plan_id": "pro", "reason": "Approved manual support upgrade"},
        headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.get_json()["plan_id"] == "pro"
    assert client.get("/api/admin/management/analytics").status_code == 200
    notification = client.post("/api/admin/management/notifications",
        json={"user_id": customer["id"], "title": "Plan update", "message": "Your plan was updated."},
        headers={"X-CSRF-Token": csrf})
    assert notification.status_code == 200
    items = client.get(f"/api/admin/management/notifications?user_id={customer['id']}")
    assert items.status_code == 200
    assert items.get_json()["notifications"][0]["title"] == "Plan update"


def test_management_mutations_require_csrf_and_owner(monkeypatch, tmp_path):
    _, client, _, _ = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("csrf-user@example.com", "A-Strong-Customer-Password-123!")
    response = client.post(f"/api/admin/management/users/{customer['id']}/status",
        json={"active": False, "reason": "Support request"})
    assert response.status_code == 403
