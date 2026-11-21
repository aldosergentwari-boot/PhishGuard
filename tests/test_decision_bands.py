"""Regression tests for how the final label (LEGITIMATE / SUSPICIOUS / PHISHING)
and the final risk number are decided.

Bands that the label and the number must always agree with:
    LEGITIMATE : risk  < 35
    SUSPICIOUS : risk >= 35 and < 80
    PHISHING   : risk >= 80
"""

import pytest

import backend.services.local_intelligence as local_module
from backend.services.hybrid_service import HybridDetectionService
from backend.services.local_intelligence import LocalIntelligenceService


class FakeModel:
    def __init__(self, prediction, risk_score):
        self.prediction = prediction
        self.risk_score = risk_score

    def predict(self, url):
        return {
            "url": url,
            "prediction": self.prediction,
            "risk_score": self.risk_score,
            "confidence": 90.0,
            "threshold": 0.29,
            "indicators": [],
        }


class NoThreat:
    configured = False

    def analyze(self, url):
        return {
            "configured": False,
            "status": "not_configured",
            "match": False,
            "providers": [],
            "cached": False,
        }


@pytest.fixture
def local_service(tmp_path, monkeypatch):
    directory = tmp_path / "intelligence"
    directory.mkdir()

    blocklist = directory / "blocklist.txt"
    allowlist = directory / "allowlist.txt"
    blocklist.write_text("", encoding="utf-8")
    allowlist.write_text("google.com\npaypal.com\n", encoding="utf-8")

    monkeypatch.setattr(local_module, "INTELLIGENCE_DIR", directory)
    monkeypatch.setattr(local_module, "BLOCKLIST_FILE", blocklist)
    monkeypatch.setattr(local_module, "ALLOWLIST_FILE", allowlist)

    return LocalIntelligenceService()


def analyze(local_service, url, prediction="LEGITIMATE", risk=5.0):
    service = HybridDetectionService.__new__(HybridDetectionService)
    service.model_service = FakeModel(prediction, risk)
    service.local_service = local_service
    service.threat_service = NoThreat()
    return service.analyze(url)


def assert_label_matches_number(result):
    label = result["final_prediction"]
    risk = result["final_risk_score"]

    if label == "PHISHING":
        assert risk >= 80, result
    elif label == "SUSPICIOUS":
        assert 35 <= risk < 80, result
    else:
        assert label == "LEGITIMATE"
        assert risk < 35, result


# --- trusted domains -----------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "https://accounts.google.com/signin",
        "https://secure.paypal.com",
        "https://mail.google.com",
    ],
)
def test_trusted_subdomain_is_not_flagged_by_a_high_ml_score(local_service, url):
    result = analyze(local_service, url, "PHISHING", 98.8)

    assert result["final_prediction"] == "LEGITIMATE"
    assert result["final_risk_score"] == 0
    assert_label_matches_number(result)


# --- label and number always agree ---------------------------------------------

@pytest.mark.parametrize(
    "url, prediction, risk",
    [
        ("https://plain-example.com", "LEGITIMATE", 5.0),
        ("https://plain-example.com", "LEGITIMATE", 46.0),
        ("https://plain-example.com", "PHISHING", 62.0),
        ("https://plain-example.com", "PHISHING", 80.0),
        ("https://plain-example.com", "PHISHING", 100.0),
        ("https://paypal.scammer.com", "LEGITIMATE", 12.0),
        ("https://paypal.scammer.github.io", "LEGITIMATE", 12.0),
        ("https://bit.ly/3abcde", "PHISHING", 100.0),
        ("http://192.168.1.5/login", "PHISHING", 100.0),
    ],
)
def test_label_and_risk_number_always_agree(local_service, url, prediction, risk):
    assert_label_matches_number(analyze(local_service, url, prediction, risk))


# --- brand impersonation -------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "https://paypal.scammer.com",
        "https://irembo-gov-rw.com/login",
        "https://mtn-momo-promo-winner.com",
    ],
)
def test_brand_impersonation_is_phishing(local_service, url):
    result = analyze(local_service, url, "LEGITIMATE", 5.0)

    assert result["final_prediction"] == "PHISHING"
    assert_label_matches_number(result)


def test_brand_on_a_shared_platform_is_only_suspicious(local_service):
    # Anyone can create google.github.io-style names on a shared platform.
    result = analyze(local_service, "https://paypal.github.io", "LEGITIMATE", 5.0)

    assert result["final_prediction"] == "SUSPICIOUS"
    assert_label_matches_number(result)


def test_official_brand_domain_is_not_impersonation(local_service):
    result = analyze(local_service, "https://www.paypal.com/signin", "LEGITIMATE", 1.0)

    assert result["final_prediction"] == "LEGITIMATE"


# --- ML alone is not proof for ambiguous links ---------------------------------

def test_short_link_with_only_ml_evidence_is_suspicious(local_service):
    result = analyze(local_service, "https://bit.ly/3abcde", "PHISHING", 100.0)

    assert result["final_prediction"] == "SUSPICIOUS"
    assert "Short link hides its real destination" in result["decision_sources"]


def test_private_ip_with_only_ml_evidence_is_suspicious(local_service):
    result = analyze(local_service, "http://192.168.1.5/login", "PHISHING", 100.0)

    assert result["final_prediction"] == "SUSPICIOUS"


def test_public_ip_with_ml_evidence_is_still_phishing(local_service):
    result = analyze(local_service, "http://203.0.113.9/login/verify", "PHISHING", 100.0)

    assert result["final_prediction"] == "PHISHING"
