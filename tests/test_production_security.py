import pytest

from backend.app import _session_cookie_secure, app


def test_render_always_uses_secure_session_cookies(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")

    assert _session_cookie_secure() is True


def test_local_session_cookie_setting_can_be_configured(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")

    assert _session_cookie_secure() is True

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    assert _session_cookie_secure() is False


def test_session_cookie_defaults_are_hardened():
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_authenticated_session_lifetime_is_thirty_days():
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 30 * 24 * 60 * 60


def test_public_responses_include_browser_security_headers(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    response = app.test_client().get("/security-disclaimer")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Permissions-Policy"] == (
        "camera=(), microphone=(), geolocation=()"
    )
    assert "Strict-Transport-Security" not in response.headers


def test_render_responses_include_hsts(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    response = app.test_client().get("/security-disclaimer")

    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"



def test_render_app_uses_proxy_fix_for_forwarded_client_ip(monkeypatch):
    from werkzeug.middleware.proxy_fix import ProxyFix
    from backend.app import create_app

    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("SECRET_KEY", "test-production-secret")

    production_app = create_app()

    assert isinstance(production_app.wsgi_app, ProxyFix)
