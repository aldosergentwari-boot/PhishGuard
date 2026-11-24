import pytest

import backend.app as app_module
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

def test_local_session_key_is_stable_and_cookie_is_http_compatible(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    secret_path = tmp_path / ".phishguard_secret_key"
    monkeypatch.setattr(app_module, "LOCAL_SECRET_KEY_PATH", secret_path)

    first_app = create_app()
    second_app = create_app()

    assert first_app.config["SESSION_COOKIE_SECURE"] is False
    assert first_app.secret_key == second_app.secret_key
    assert secret_path.exists()
    assert first_app.config["PERMANENT_SESSION_LIFETIME"].days == 30


def test_production_session_cookie_is_secure_by_default(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-production-secret")

    app = create_app()

    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_session_cookie_secure_can_be_explicitly_overridden(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("SECRET_KEY", "test-production-secret")

    app = create_app()

    assert app.config["SESSION_COOKIE_SECURE"] is False

