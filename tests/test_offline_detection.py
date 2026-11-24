import pytest

from backend.services.local_intelligence import (
    LocalIntelligenceService
)

from backend.services.hybrid_service import (
    HybridDetectionService
)


class FakeModelService:

    def predict(self, url):

        return {
            "url": url,
            "prediction": "LEGITIMATE",
            "risk_score": 10.0,
            "confidence": 90.0,
            "threshold": 0.36,
            "indicators": []
        }


@pytest.fixture
def local_service(tmp_path, monkeypatch):

    import backend.services.local_intelligence as local_module

    intelligence_dir = tmp_path / "intelligence"
    intelligence_dir.mkdir()

    blocklist = intelligence_dir / "blocklist.txt"
    allowlist = intelligence_dir / "allowlist.txt"

    blocklist.write_text(
        "known-bad-example.com\n",
        encoding="utf-8"
    )

    allowlist.write_text(
        "trusted-example.com\n",
        encoding="utf-8"
    )

    monkeypatch.setattr(
        local_module,
        "INTELLIGENCE_DIR",
        intelligence_dir
    )

    monkeypatch.setattr(
        local_module,
        "BLOCKLIST_FILE",
        blocklist
    )

    monkeypatch.setattr(
        local_module,
        "ALLOWLIST_FILE",
        allowlist
    )

    return LocalIntelligenceService()


def test_blocklist_detection(local_service):

    result = local_service.analyze(
        "https://known-bad-example.com/login"
    )

    assert result["blocklist_match"] is True
    assert result["rule_risk_score"] == 100


def test_blocklist_detects_subdomain(local_service):

    result = local_service.analyze(
        "https://secure.known-bad-example.com"
    )

    assert result["blocklist_match"] is True


def test_allowlist_detection(local_service):

    result = local_service.analyze(
        "https://trusted-example.com"
    )

    assert result["allowlist_match"] is True
    assert result["blocklist_match"] is False


def test_local_rules_detect_ip_url(local_service):

    result = local_service.analyze(
        "http://192.0.2.10/login"
    )

    assert any(
        item["name"] == "IP address"
        for item in result["indicators"]
    )


def test_hybrid_engine_works_offline(local_service):

    service = HybridDetectionService.__new__(
        HybridDetectionService
    )

    service.model_service = FakeModelService()
    service.local_service = local_service

    class FakeThreatService:
        configured = False
        def analyze(self, url):
            return {"configured": False, "status": "not_configured", "match": False, "providers": [], "cached": False}

    service.threat_service = FakeThreatService()

    result = service.analyze(
        "https://known-bad-example.com"
    )

    assert result["detection_mode"] == "OFFLINE_ML_AND_LOCAL_RULES"
    assert result["internet_required"] is False
    assert result["final_prediction"] == "PHISHING"


class _PhishingModel:
    """Fake ML model that always says PHISHING (simulates an ML false positive)."""

    def predict(self, url):
        return {"url": url, "prediction": "PHISHING", "risk_score": 80.0,
                "confidence": 80.0, "threshold": 0.36, "indicators": []}


class _NoThreat:
    configured = False

    def analyze(self, url):
        return {"configured": False, "status": "not_configured", "match": False,
                "providers": [], "cached": False}


def _service(local_service):
    service = HybridDetectionService.__new__(HybridDetectionService)
    service.model_service = _PhishingModel()
    service.local_service = local_service
    service.threat_service = _NoThreat()
    return service


def test_allowlist_overrides_ml_false_positive(local_service):
    """A trusted domain must not be flagged only because the ML model said so."""
    result = _service(local_service).analyze("https://trusted-example.com/login")

    assert result["final_prediction"] == "LEGITIMATE"
    assert result["final_risk_score"] == 0
    assert "Trusted domain (local allowlist)" in result["decision_sources"]


def test_blocklist_beats_allowlist(local_service, tmp_path):
    """If a domain is in BOTH lists, the blocklist wins."""
    local_service.blocklist.add("trusted-example.com")

    result = _service(local_service).analyze("https://trusted-example.com")

    assert result["final_prediction"] == "PHISHING"


def test_allowlisted_shared_platform_is_not_trusted(local_service):
    """docs.google.com / sites.google.com host anyone's pages: allowlisting google.com must not trust them."""
    local_service.allowlist.add("google.com")

    result = _service(local_service).analyze("https://sites.google.com/view/fake-bank-login")

    assert result["final_prediction"] == "PHISHING"


def test_blocklist_matches_www_and_non_www_variants(local_service):

    with_www = local_service.analyze(
        "https://www.known-bad-example.com/login"
    )

    without_www = local_service.analyze(
        "https://known-bad-example.com/login"
    )

    assert with_www["blocklist_match"] is True
    assert without_www["blocklist_match"] is True
    assert with_www["rule_risk_score"] == without_www["rule_risk_score"] == 100
    assert with_www["domain"] == without_www["domain"]


def test_allowlist_matches_www_variant(local_service):

    result = local_service.analyze(
        "https://www.trusted-example.com"
    )

    assert result["allowlist_match"] is True
    assert result["rule_risk_score"] == 0


def test_brand_impersonation_detected(local_service):
    result = local_service.analyze("https://www.support-apple.ss-c.us/account/verify")
    assert result["brand_impersonation_match"] is True
    assert result["brand_impersonation"]["brand"] == "apple"
