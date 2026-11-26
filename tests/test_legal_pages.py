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


def test_legal_pages_use_the_public_default_support_email_when_unset(monkeypatch):
    monkeypatch.delenv("PUBLIC_SUPPORT_EMAIL", raising=False)
    client = app.test_client()

    response = client.get("/privacy")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "aldosergentwari@gmail.com" in page
    assert 'href="mailto:aldosergentwari@gmail.com"' in page
    assert "Official support email not configured yet." not in page


def test_legal_pages_display_configured_support_email(monkeypatch):
    monkeypatch.setenv("PUBLIC_SUPPORT_EMAIL", "help@phishguard.example")
    client = app.test_client()

    response = client.get("/terms")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "help@phishguard.example" in page
    assert "Official support email not configured yet." not in page



def test_ads_txt_is_generated_from_the_configured_publisher_id(monkeypatch):
    from backend.app import app

    monkeypatch.setenv("ADSENSE_CLIENT_ID", "ca-pub-1234567890123456")
    response = app.test_client().get("/ads.txt")

    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    assert response.get_data(as_text=True) == (
        "google.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0\\n"
    )


def test_ads_txt_is_not_published_without_a_valid_publisher_id(monkeypatch):
    from backend.app import app

    monkeypatch.delenv("ADSENSE_CLIENT_ID", raising=False)
    response = app.test_client().get("/ads.txt")

    assert response.status_code == 404
