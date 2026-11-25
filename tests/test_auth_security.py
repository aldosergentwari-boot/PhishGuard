import sqlite3

import pytest

from backend.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module
    import backend.database.history_service as history_module
    import backend.config as config_module

    database_path = tmp_path / "auth_security.db"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(config_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(history_module, "_history_service", None)

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


def test_history_clear_with_valid_csrf_deletes_only_current_users_records(client):
    register(client)
    with client.session_transaction() as session:
        account_id = session["account_id"]

    from backend.database.history_service import get_history_service

    sample_result = {
        "url": "https://owned-example.test/login",
        "final_prediction": "PHISHING",
        "final_risk_score": 95.0,
        "detection_mode": "OFFLINE",
        "decision_sources": ["test"],
        "ml_result": {"confidence": 95.0, "indicators": []},
        "local_intelligence": {"domain": "owned-example.test", "indicators": []},
    }
    service = get_history_service()
    own_id = service.save_scan(sample_result, f"account:{account_id}")
    other_id = service.save_scan(sample_result, "account:another-user")

    token = csrf(client)
    response = client.delete(
        "/api/history",
        headers={"X-CSRF-Token": token},
    )

    assert response.status_code == 200
    assert response.get_json()["deleted_count"] == 1
    assert service.get_scan(own_id, f"account:{account_id}") is None
    assert service.get_scan(other_id, "account:another-user") is not None
    from backend.services.plan_service import get_usage
    usage = get_usage(f"account:{account_id}", "free")
    assert usage["scans_used"] == 1
    assert usage["scans_remaining"] == 49

    # The billing endpoint feeding the dashboard meter must report the same
    # persistent usage even after the visible history has been cleared.
    meter_response = client.get("/api/billing/me")
    assert meter_response.status_code == 200
    meter_usage = meter_response.get_json()["usage"]
    assert meter_usage["scans_used"] == 1
    assert meter_usage["scans_limit"] == 50
    assert meter_usage["scans_remaining"] == 49


def test_history_delete_accepts_valid_csrf(client):
    register(client)
    token = csrf(client)
    response = client.delete("/api/history/123", headers={"X-CSRF-Token": token})
    assert response.status_code == 404


def test_stale_session_is_cleared_before_billing_or_history_access(client):
    register(client)
    with client.session_transaction() as session:
        account_id = session["account_id"]

    import backend.database.auth_service as auth_module
    with sqlite3.connect(auth_module.DATABASE_PATH) as db:
        db.execute(
            "UPDATE users SET session_version = session_version + 1 WHERE id = ?",
            (account_id,),
        )

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


def test_registration_rejects_non_string_email_without_server_error(client):
    token = csrf(client)
    response = client.post(
        "/api/auth/register",
        json={"email": {"unexpected": "object"}, "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "Enter a valid email address."



def test_repeated_login_logout_cycles_keep_csrf_and_session_in_sync(client):
    register(client)

    for _ in range(3):
        token = csrf(client)
        logout_response = client.post(
            "/api/auth/logout",
            json={},
            headers={"X-CSRF-Token": token},
        )
        assert logout_response.status_code == 200
        assert client.get("/api/auth/me").get_json()["authenticated"] is False

        # The anonymous session after logout must be able to obtain a fresh
        # token and sign in again without refreshing the browser.
        token = csrf(client)
        login_response = client.post(
            "/api/auth/login",
            json={"email": "secure@example.com", "password": "correct horse battery"},
            headers={"X-CSRF-Token": token},
        )
        assert login_response.status_code == 200
        assert client.get("/api/auth/me").get_json()["authenticated"] is True


def test_password_reset_requires_csrf_and_invalidates_old_password(client):
    import hashlib
    from datetime import datetime, timedelta, timezone

    from backend.database.auth_service import auth_service

    register(client)
    raw_token = "test-password-reset-token-123456789"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    auth_service.create_email_token(
        1, "password_reset", hashlib.sha256(raw_token.encode()).hexdigest(), expires_at
    )

    rejected = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": raw_token, "password": "a completely new password"},
    )
    assert rejected.status_code == 403

    token = csrf(client)
    changed = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": raw_token, "password": "a completely new password"},
        headers={"X-CSRF-Token": token},
    )
    assert changed.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is False

    # Reset links are single-use, and only the new password can authenticate.
    token = csrf(client)
    reused = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": raw_token, "password": "another different password"},
        headers={"X-CSRF-Token": token},
    )
    assert reused.status_code == 400

    token = csrf(client)
    old_login = client.post(
        "/api/auth/login",
        json={"email": "secure@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert old_login.status_code == 401

    token = csrf(client)
    new_login = client.post(
        "/api/auth/login",
        json={"email": "secure@example.com", "password": "a completely new password"},
        headers={"X-CSRF-Token": token},
    )
    assert new_login.status_code == 200
