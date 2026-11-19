from backend.services.threat_intelligence import ThreatIntelligenceService


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_threat_intelligence_falls_back_cleanly_when_no_keys(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    service = ThreatIntelligenceService()

    result = service.analyze("https://example.com")

    assert result["configured"] is False
    assert result["status"] == "not_configured"
    assert result["match"] is False
    assert result["providers"] == []


def test_urlhaus_positive_match_is_reported(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-key")

    def fake_post(*args, **kwargs):
        assert kwargs["headers"]["Auth-Key"] == "test-key"
        return FakeResponse({"query_status": "ok", "threat": "malware_download"})

    monkeypatch.setattr("backend.services.threat_intelligence.requests.post", fake_post)
    service = ThreatIntelligenceService()

    result = service.analyze("https://malicious.example/payload")

    assert result["configured"] is True
    assert result["match"] is True
    assert result["status"] == "match"
    assert result["providers"][0]["provider"] == "URLhaus"


def test_google_safe_browsing_positive_match_is_reported(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)

    def fake_post(*args, **kwargs):
        assert kwargs["params"] == {"key": "test-key"}
        return FakeResponse({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})

    monkeypatch.setattr("backend.services.threat_intelligence.requests.post", fake_post)
    service = ThreatIntelligenceService()

    result = service.analyze("https://malicious.example/login")

    assert result["match"] is True
    assert result["providers"][0]["details"] == ["SOCIAL_ENGINEERING"]
