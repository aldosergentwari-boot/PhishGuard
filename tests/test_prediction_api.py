import pytest

from backend.app import create_app


@pytest.fixture
def client():

    app = create_app()

    app.config["TESTING"] = True

    with app.test_client() as client:

        yield client


def test_home_endpoint(client):

    response = client.get("/")

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert b"PhishGuard" in response.data


def test_health_endpoint(client):

    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "healthy"


def test_missing_url(client):

    response = client.post(
        "/api/predict",
        json={}
    )

    assert response.status_code == 400


def test_empty_url(client):

    response = client.post(
        "/api/predict",
        json={"url": ""}
    )

    assert response.status_code == 400


def test_invalid_url_type(client):

    response = client.post(
        "/api/predict",
        json={"url": 12345}
    )

    assert response.status_code == 400


def test_unsupported_scheme(client):

    response = client.post(
        "/api/predict",
        json={"url": "ftp://example.com"}
    )

    assert response.status_code == 400


def test_url_with_credentials(client):

    response = client.post(
        "/api/predict",
        json={"url": "https://user:password@example.com"}
    )

    assert response.status_code == 400


def test_valid_url_prediction(client):

    response = client.post(
        "/api/predict",
        json={
            "url": "https://www.google.com"
        }
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True

    result = data["data"]

    assert result["prediction"] in [
        "PHISHING",
        "LEGITIMATE"
    ]

    assert 0 <= result["risk_score"] <= 100

    assert 0 <= result["confidence"] <= 100

    assert isinstance(result["indicators"], list)

def test_www_and_non_www_have_identical_prediction(client):

    with_www = client.post(
        "/api/predict",
        json={"url": "https://www.instagram.com"}
    )

    without_www = client.post(
        "/api/predict",
        json={"url": "https://instagram.com"}
    )

    assert with_www.status_code == 200
    assert without_www.status_code == 200

    first = with_www.get_json()["data"]
    second = without_www.get_json()["data"]

    assert first["prediction"] == second["prediction"] == "LEGITIMATE"
    assert first["risk_score"] == second["risk_score"]


def test_url_without_scheme_is_accepted_and_normalized(client):

    response = client.post(
        "/api/predict",
        json={"url": "instagram.com"}
    )

    assert response.status_code == 200

    data = response.get_json()["data"]

    assert data["prediction"] == "LEGITIMATE"
    assert data["risk_score"] < 50


def test_offline_analyze_endpoint_saves_history(client, tmp_path, monkeypatch):

    import backend.database.history_service as history_module

    database_dir = tmp_path / "database"
    database_path = database_dir / "test_scans.db"

    monkeypatch.setattr(history_module, "DATABASE_DIR", database_dir)
    monkeypatch.setattr(history_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "_history_service", None)

    response = client.post(
        "/api/analyze",
        json={"url": "instagram.com"}
    )

    assert response.status_code == 200

    payload = response.get_json()
    result = payload["data"]

    assert result["final_prediction"] == "LEGITIMATE"
    assert result["url"] == "instagram.com"
    assert result["scan_id"] == 1
    assert database_path.exists()


def test_known_brand_impersonation_is_flagged_by_prediction_api(client):
    response = client.post(
        "/api/predict",
        json={"url": "https://paypal-login-security-check.example.com"}
    )

    assert response.status_code == 200
    result = response.get_json()["data"]
    assert result["prediction"] == "PHISHING"
    assert result["final_prediction"] == "PHISHING"
    assert result["risk_score"] >= 50


def test_session_cookie_secure_is_configurable(monkeypatch):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    secure_app = create_app()
    assert secure_app.config["SESSION_COOKIE_SECURE"] is True

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    local_app = create_app()
    assert local_app.config["SESSION_COOKIE_SECURE"] is False


def test_baseline_security_headers_are_present(client):
    response = client.get("/api/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in response.headers["Permissions-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_oversized_request_body_is_rejected(client):
    response = client.post(
        "/api/predict",
        data=b"x" * (16 * 1024 + 1),
        content_type="application/json",
    )

    assert response.status_code == 413


def test_account_register_login_and_logout(client, tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module
    import backend.database.history_service as history_module

    db_path = tmp_path / "accounts.db"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", db_path)
    monkeypatch.setattr(history_module, "DATABASE_PATH", db_path)
    monkeypatch.setattr(history_module, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(history_module, "_history_service", None)
    auth_module.auth_service.initialize()

    def post_with_csrf(path, payload):
        token = client.get("/api/auth/csrf").get_json()["csrf_token"]
        return client.post(path, json=payload, headers={"X-CSRF-Token": token})

    registered = post_with_csrf(
        "/api/auth/register",
        {"email": "serge@example.com", "password": "A-strong-test-password-2026"}
    )
    assert registered.status_code == 201
    assert registered.get_json()["user"]["email"] == "serge@example.com"

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.get_json()["authenticated"] is True

    logged_out = post_with_csrf("/api/auth/logout", {})
    assert logged_out.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is False

    logged_in = post_with_csrf(
        "/api/auth/login",
        {"email": "serge@example.com", "password": "A-strong-test-password-2026"}
    )
    assert logged_in.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is True


def test_account_mutations_require_csrf_token(client):
    response = client.post(
        "/api/auth/logout",
        json={},
    )
    assert response.status_code == 403


def test_account_registration_rejects_weak_password(client, tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module

    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "accounts.db")
    auth_module.auth_service.initialize()

    token = client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = client.post(
        "/api/auth/register",
        json={"email": "weak@example.com", "password": "short"},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 400


def test_auth_service_rate_limit_resets_after_window(tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module

    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "rate-limit.db")
    auth_module.auth_service.initialize()

    assert auth_module.auth_service.allow_auth_attempt("test-bucket", limit=2, window_seconds=900)
    assert auth_module.auth_service.allow_auth_attempt("test-bucket", limit=2, window_seconds=900)
    assert not auth_module.auth_service.allow_auth_attempt("test-bucket", limit=2, window_seconds=900)


def test_login_endpoint_returns_429_after_repeated_attempts(client, tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module

    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "login-rate.db")
    auth_module.auth_service.initialize()
    token = client.get("/api/auth/csrf").get_json()["csrf_token"]

    responses = [
        client.post(
            "/api/auth/login",
            json={"email": "limit-test@example.com", "password": "wrong-password"},
            headers={"X-CSRF-Token": token},
        )
        for _ in range(9)
    ]

    assert all(response.status_code == 401 for response in responses[:8])
    assert responses[8].status_code == 429
