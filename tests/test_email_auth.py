import pytest

from backend.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module
    import backend.database.history_service as history_module
    import backend.config as config_module

    database_path = tmp_path / "email_auth.db"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(config_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(history_module, "_history_service", None)

    app = create_app()
    app.config.update(TESTING=True, SECRET_KEY="email-auth-test-secret")
    with app.test_client() as test_client:
        yield test_client


def csrf(client):
    return client.get("/api/auth/csrf").get_json()["csrf_token"]


def register(client):
    token = csrf(client)
    response = client.post(
        "/api/auth/register",
        json={"email": "member@example.com", "password": "correct horse battery"},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 201
    return response


def test_registration_creates_hashed_verification_token(client, monkeypatch):
    import backend.services.email_service as email_service
    sent = {}
    monkeypatch.setattr(
        email_service, "send_verification_email",
        lambda email, token: sent.update(email=email, token=token) or True,
    )

    response = register(client)
    assert response.get_json()["email_sent"] is True
    assert sent["email"] == "member@example.com"

    import backend.database.auth_service as auth_module
    with auth_module.auth_service.connection() as db:
        row = db.execute(
            "SELECT token_hash,purpose,used_at FROM account_email_tokens"
        ).fetchone()
    assert row["purpose"] == "verify_email"
    assert row["token_hash"] != sent["token"]
    assert row["used_at"] is None


def test_verification_link_is_single_use(client, monkeypatch):
    import backend.services.email_service as email_service
    sent = {}
    monkeypatch.setattr(
        email_service, "send_verification_email",
        lambda email, token: sent.update(token=token) or True,
    )
    register(client)

    first = client.get("/api/auth/verify-email", query_string={"token": sent["token"]})
    second = client.get("/api/auth/verify-email", query_string={"token": sent["token"]})
    assert first.status_code == 302
    assert first.location.endswith("/?email_verified=1")
    assert second.location.endswith("/?email_verified=0")

    current = client.get("/api/auth/me").get_json()
    assert current["user"]["email_verified"] is True


def test_password_reset_is_generic_and_invalidates_old_sessions(client, monkeypatch):
    import backend.services.email_service as email_service
    sent = {}
    monkeypatch.setattr(
        email_service, "send_password_reset_email",
        lambda email, token: sent.update(email=email, token=token) or True,
    )
    register(client)

    # A reset request uses the same public response whether the account exists or not.
    token = csrf(client)
    known = client.post(
        "/api/auth/password-reset/request",
        json={"email": "member@example.com"},
        headers={"X-CSRF-Token": token},
    )
    unknown = client.post(
        "/api/auth/password-reset/request",
        json={"email": "nobody@example.com"},
        headers={"X-CSRF-Token": token},
    )
    assert known.status_code == unknown.status_code == 200
    assert known.get_json()["message"] == unknown.get_json()["message"]
    assert sent["email"] == "member@example.com"

    reset_csrf = csrf(client)
    changed = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": sent["token"], "password": "a much safer new password"},
        headers={"X-CSRF-Token": reset_csrf},
    )
    assert changed.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is False

    csrf_token = csrf(client)
    login = client.post(
        "/api/auth/login",
        json={"email": "member@example.com", "password": "a much safer new password"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert login.status_code == 200


def test_password_reset_token_cannot_be_reused(client, monkeypatch):
    import backend.services.email_service as email_service
    sent = {}
    monkeypatch.setattr(
        email_service, "send_password_reset_email",
        lambda email, token: sent.update(token=token) or True,
    )
    register(client)
    token = csrf(client)
    client.post(
        "/api/auth/password-reset/request",
        json={"email": "member@example.com"},
        headers={"X-CSRF-Token": token},
    )
    payload = {"token": sent["token"], "password": "a much safer new password"}
    reset_csrf = csrf(client)
    assert client.post(
        "/api/auth/password-reset/confirm",
        json=payload,
        headers={"X-CSRF-Token": reset_csrf},
    ).status_code == 200

    # A successful reset rotates the anonymous session token as well.
    reset_csrf = csrf(client)
    assert client.post(
        "/api/auth/password-reset/confirm",
        json=payload,
        headers={"X-CSRF-Token": reset_csrf},
    ).status_code == 400


def test_password_reset_rejects_short_password(client, monkeypatch):
    import backend.services.email_service as email_service
    sent = {}
    monkeypatch.setattr(
        email_service, "send_password_reset_email",
        lambda email, token: sent.update(token=token) or True,
    )
    register(client)
    token = csrf(client)
    client.post(
        "/api/auth/password-reset/request",
        json={"email": "member@example.com"},
        headers={"X-CSRF-Token": token},
    )
    reset_csrf = csrf(client)
    response = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": sent["token"], "password": "short"},
        headers={"X-CSRF-Token": reset_csrf},
    )
    assert response.status_code == 400



def test_email_service_builds_verification_and_fragment_reset_links(monkeypatch):
    import backend.services.email_service as email_service

    captured = []
    monkeypatch.setenv("MAIL_SERVER", "smtp-relay.brevo.com")
    monkeypatch.setenv("MAIL_PORT", "587")
    monkeypatch.setenv("MAIL_USERNAME", "smtp-login")
    monkeypatch.setenv("MAIL_PASSWORD", "smtp-secret")
    monkeypatch.setenv("MAIL_DEFAULT_SENDER", "security@example.com")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://phishguard.example")
    monkeypatch.setattr(
        email_service, "_send",
        lambda subject, recipient, text_body, html_body:
            captured.append((subject, text_body, html_body)) or True,
    )

    assert email_service.send_verification_email("member@example.com", "verify-token_123")
    assert email_service.send_password_reset_email("member@example.com", "reset-token_456")
    assert "https://phishguard.example/api/auth/verify-email?token=verify-token_123" in captured[0][1]
    assert "https://phishguard.example/#reset_token=reset-token_456" in captured[1][1]


def test_brevo_api_transport_uses_https_and_api_key(monkeypatch):
    import json
    import backend.services.email_service as email_service

    captured = {}
    class FakeResponse:
        status = 201
        def __enter__(self): return self
        def __exit__(self, *args): return False

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = {key.lower(): value for key, value in request.header_items()}
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setenv("BREVO_API_KEY", "test-brevo-api-key")
    monkeypatch.setenv("MAIL_DEFAULT_SENDER", "security@example.com")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://phishguard.example")
    monkeypatch.delenv("MAIL_USERNAME", raising=False)
    monkeypatch.delenv("MAIL_PASSWORD", raising=False)
    monkeypatch.setattr(email_service, "urlopen", fake_urlopen)

    assert email_service.send_verification_email("member@example.com", "verify-token_123")
    assert captured["url"] == "https://api.brevo.com/v3/smtp/email"
    assert captured["headers"]["api-key"] == "test-brevo-api-key"
    assert captured["payload"]["to"] == [{"email": "member@example.com"}]
    assert "verify-token_123" in captured["payload"]["textContent"]
    assert captured["timeout"] == 15
