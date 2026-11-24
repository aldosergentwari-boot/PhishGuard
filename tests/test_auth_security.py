import sqlite3

import pytest

from backend.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module
    import backend.config as config_module
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "auth_security.db")
    monkeypatch.setattr(config_module, "DATABASE_PATH", tmp_path / "auth_security.db")
    app = create_app()
    app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with app.test_client() as test_client:
        yield test_client


def csrf(client):
    return client.get("/api/auth/csrf").get_json()["csrf_token"]


def register(client):
    token = csrf(client)
    response = client.post(
        "/api/auth/register",
        json={"email": "secure@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 201


def test_history_delete_requires_csrf(client):
    register(client)
    response = client.delete("/api/history/123")
    assert response.status_code == 403


def test_history_clear_requires_csrf(client):
    register(client)
    response = client.delete("/api/history")
    assert response.status_code == 403


def test_history_delete_accepts_valid_csrf(client):
    register(client)
    token = csrf(client)
    response = client.delete("/api/history/123", headers={"X-CSRF-Token": token})
    # The request passes CSRF and reaches the owner-scoped history handler.
    assert response.status_code == 404


def test_stale_session_is_cleared_before_billing_or_history_access(client, tmp_path):
    register(client)
    with client.session_transaction() as session:
        account_id = session["account_id"]

    import backend.database.auth_service as auth_module
    with sqlite3.connect(auth_module.DATABASE_PATH) as db:
        db.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (account_id,))

    response = client.get("/api/billing/me")
    assert response.status_code == 200
    assert response.get_json()["authenticated"] is False


def test_login_rejects_non_string_password_without_server_error(client):
    register(client)
    token = csrf(client)
    response = client.post(
        "/api/auth/login",
        json={"email": "secure@example.com", "password": {"unexpected": "object"}},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid email or password."
