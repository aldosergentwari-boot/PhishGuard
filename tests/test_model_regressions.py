import pytest

from ml.features.extract_features import (
    extract_features,
    normalize_url
)
from backend.services.model_service import PhishingModelService


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("https://www.google.com", "https://google.com"),
        ("https://www.wikipedia.org", "https://wikipedia.org"),
        ("https://www.instagram.com", "https://instagram.com"),
        ("instagram.com", "https://instagram.com"),
    ],
)
def test_canonical_urls_have_identical_features(first, second):
    assert normalize_url(first) == normalize_url(second)
    assert extract_features(first) == extract_features(second)


def test_explicit_http_scheme_is_preserved():
    assert normalize_url("http://www.example.com") == "http://example.com"
    assert extract_features("http://example.com")["has_http"] == 1
    assert extract_features("http://example.com")["has_https"] == 0


@pytest.fixture(scope="module")
def model_service():
    return PhishingModelService()


@pytest.mark.parametrize(
    "url",
    [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://www.instagram.com",
        "https://www.youtube.com",
        "https://www.microsoft.com",
    ],
)
def test_common_legitimate_sites_are_not_flagged(model_service, url):
    service = model_service

    with_www = service.predict(url)
    without_www = service.predict(url.replace("www.", ""))

    assert with_www["prediction"] == "LEGITIMATE"
    assert without_www["prediction"] == "LEGITIMATE"
    assert with_www["risk_score"] == without_www["risk_score"]


def test_scheme_less_input_matches_https_prediction(model_service):
    service = model_service

    scheme_less = service.predict("google.com")
    explicit_https = service.predict("https://google.com")

    assert scheme_less["prediction"] == explicit_https["prediction"]
    assert scheme_less["risk_score"] == explicit_https["risk_score"]


def test_primary_model_uses_character_ngrams_and_numeric_features(model_service):
    service = model_service

    assert "features" in service.model.named_steps
    assert "classifier" in service.model.named_steps
    assert service.metadata["model_version"] == "3.1-hostname-only"


@pytest.mark.parametrize(
    "url",
    [
        "http://192.0.2.10/login/verify",
        "https://amzon.co.jp.fotosvalladolid.com",
        "https://www.support-apple.ss-c.us",
        "https://paypal-login-security-check.example.com",
    ],
)
def test_high_risk_phishing_patterns_are_flagged(model_service, url):
    result = model_service.predict(url)
    assert result["prediction"] == "PHISHING"
    assert result["risk_score"] >= 50


def test_path_query_and_scheme_do_not_change_ml_result():
    """Regression: the dataset has NO legitimate URL with a path/query/http, so a model fed
    the full URL flagged 'https://google.com/' as phishing. The model must only see the host."""
    from backend.services.model_service import get_model_service

    model = get_model_service()
    for host in ("google.com", "wikipedia.org", "irembo.gov.rw", "github.com"):
        base = model.predict(f"https://{host}")
        for variant in (f"https://{host}/", f"https://{host}/a/b?x=1#top", f"http://{host}", f"www.{host}/login"):
            other = model.predict(variant)
            assert other["prediction"] == base["prediction"], variant
            assert other["risk_score"] == base["risk_score"], variant
