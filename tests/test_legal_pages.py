from backend.app import app


def test_public_legal_pages_are_available():
    client = app.test_client()

    expected = {
        "/privacy": ("Privacy Policy", "Offline mode", "Brevo"),
        "/terms": ("Terms of Service", "manual renewal", "acceptable use"),
        "/security-disclaimer": ("Security Disclaimer", "not a guarantee", "low risk score"),
    }

    for path, phrases in expected.items():
        response = client.get(path)
        assert response.status_code == 200
        page = response.get_data(as_text=True).lower()
        for phrase in phrases:
            assert phrase.lower() in page


def test_legal_pages_show_support_setup_notice_until_contact_is_configured(monkeypatch):
    monkeypatch.delenv("PUBLIC_SUPPORT_EMAIL", raising=False)
    client = app.test_client()

    response = client.get("/privacy")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Official support email not configured yet." in page
    assert "must configure an official support email" in page


def test_legal_pages_display_configured_support_email(monkeypatch):
    monkeypatch.setenv("PUBLIC_SUPPORT_EMAIL", "help@phishguard.example")
    client = app.test_client()

    response = client.get("/terms")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "help@phishguard.example" in page
    assert "Official support email not configured yet." not in page
