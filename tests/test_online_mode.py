"""Tests for online mode: online providers, internet fallback, the mode switch
in the API, and how online evidence changes the final verdict.

No test here touches the real network: requests and sockets are faked.
"""

from datetime import datetime, timedelta, timezone

import pytest
import requests

import backend.database.history_service as history_module
import backend.services.local_intelligence as local_module
import backend.services.threat_intelligence as threat_module
from backend.app import create_app
from backend.services.hybrid_service import (
    HybridDetectionService,
    get_hybrid_service,
)
from backend.services.local_intelligence import LocalIntelligenceService
from backend.services.threat_intelligence import ThreatIntelligenceService


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

FEED = """
https://evil-login.example.net/verify/account
http://bad-host.example.org/
# a comment line

https://pemenang1.blogspot.com/
"""


class FakeResponse:
    def __init__(self, payload=None, text="", status_code=200):
        self.payload = payload
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


def rdap_payload(days_old):
    moment = datetime.now(timezone.utc) - timedelta(days=days_old)
    return {
        "events": [
            {"eventAction": "last changed", "eventDate": "2030-01-01T00:00:00Z"},
            {
                "eventAction": "registration",
                "eventDate": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ]
    }


@pytest.fixture
def threat(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.delenv("OPENPHISH_FEED_URL", raising=False)
    monkeypatch.delenv("ENABLE_DOMAIN_AGE_CHECK", raising=False)
    monkeypatch.delenv("NEW_DOMAIN_DAYS", raising=False)

    service = ThreatIntelligenceService()
    service.feed_url = "https://feed.test/feed.txt"
    return service


def install_fake_get(monkeypatch, feed_text=FEED, rdap_days=3650,
                     rdap_status=200, feed_fails=False):
    calls = {"feed": 0, "rdap": 0}

    def fake_get(url, **kwargs):
        if url == "https://feed.test/feed.txt":
            calls["feed"] += 1
            if feed_fails:
                raise requests.ConnectionError("offline")
            return FakeResponse(text=feed_text)

        if url.startswith("https://rdap.org/domain/"):
            calls["rdap"] += 1
            if rdap_status != 200:
                return FakeResponse(status_code=rdap_status)
            return FakeResponse(payload=rdap_payload(rdap_days))

        raise AssertionError(f"unexpected request: {url}")

    monkeypatch.setattr(threat_module.requests, "get", fake_get)
    return calls


# ----------------------------------------------------------------------------
# threat service: legacy behaviour is unchanged
# ----------------------------------------------------------------------------

def test_default_analyze_makes_no_keyless_requests(threat, monkeypatch):
    calls = install_fake_get(monkeypatch)

    result = threat.analyze("https://example.com")

    assert calls == {"feed": 0, "rdap": 0}
    assert result["status"] == "not_configured"
    assert result["providers"] == []


# ----------------------------------------------------------------------------
# OpenPhish feed
# ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://evil-login.example.net/verify/account", True),
        ("http://www.evil-login.example.net/verify/account/", True),   # www + slash
        ("https://evil-login.example.net/verify/account?x=1", True),    # query ignored
        ("https://evil-login.example.net/other-page", False),           # different page
        ("https://bad-host.example.org/anything/here", True),           # whole host listed
        ("https://pemenang1.blogspot.com/post", True),
        ("https://other-user.blogspot.com/", False),                    # same platform, other site
        ("https://blogspot.com/", False),
        ("https://google.com", False),
    ],
)
def test_feed_matching(threat, monkeypatch, url, expected):
    install_fake_get(monkeypatch)
    threat.domain_age_enabled = False

    result = threat.analyze(url, include_keyless=True)

    assert result["match"] is expected


def test_feed_is_downloaded_once_and_cached(threat, monkeypatch):
    calls = install_fake_get(monkeypatch)
    threat.domain_age_enabled = False

    threat.analyze("https://one.example", include_keyless=True)
    threat.analyze("https://two.example", include_keyless=True)
    threat.analyze("https://three.example", include_keyless=True)

    assert calls["feed"] == 1


def test_feed_failure_is_not_a_match_and_not_an_error(threat, monkeypatch):
    install_fake_get(monkeypatch, feed_fails=True)
    threat.domain_age_enabled = False

    result = threat.analyze("https://evil-login.example.net/verify/account",
                            include_keyless=True)

    assert result["match"] is False
    assert result["status"] == "unavailable"
    assert result["providers"][0]["status"] == "unavailable"


def test_stale_feed_keeps_working_when_download_fails(threat, monkeypatch):
    install_fake_get(monkeypatch)
    threat.domain_age_enabled = False
    threat.analyze("https://first.example", include_keyless=True)

    # one hour later the download fails: the old copy must still be used
    threat._feed_time -= threat.FEED_TTL_SECONDS + 5
    install_fake_get(monkeypatch, feed_fails=True)

    result = threat.analyze("https://evil-login.example.net/verify/account",
                            include_keyless=True)

    assert result["match"] is True


def test_feed_can_be_switched_off(threat, monkeypatch):
    calls = install_fake_get(monkeypatch)
    threat.feed_url = ""
    threat.domain_age_enabled = False

    result = threat.analyze("https://evil-login.example.net/verify/account",
                            include_keyless=True)

    assert calls["feed"] == 0
    assert result["match"] is False


# ----------------------------------------------------------------------------
# RDAP domain age
# ----------------------------------------------------------------------------

def test_new_domain_is_detected(threat, monkeypatch):
    install_fake_get(monkeypatch, rdap_days=3)
    threat.feed_url = ""

    result = threat.analyze("https://brand-new-site.com/login", include_keyless=True)

    assert result["newly_registered"] is True
    assert result["domain_age_days"] == 3
    assert result["match"] is False        # age is a signal, not a reputation hit


def test_old_domain_is_not_new(threat, monkeypatch):
    install_fake_get(monkeypatch, rdap_days=4000)
    threat.feed_url = ""

    result = threat.analyze("https://old-site.com", include_keyless=True)

    assert result["newly_registered"] is False
    assert result["domain_age_days"] >= 4000


def test_domain_age_is_looked_up_for_the_registered_domain_only(threat, monkeypatch):
    seen = []

    def fake_get(url, **kwargs):
        seen.append(url)
        return FakeResponse(payload=rdap_payload(10))

    monkeypatch.setattr(threat_module.requests, "get", fake_get)
    threat.feed_url = ""

    threat.analyze("https://login.secure.shop.example.co.uk/a/b?x=1",
                   include_keyless=True)

    assert seen == ["https://rdap.org/domain/example.co.uk"]


def test_domain_age_is_cached(threat, monkeypatch):
    calls = install_fake_get(monkeypatch, rdap_days=10)
    threat.feed_url = ""

    threat.analyze("https://cached-site.com/a", include_keyless=True)
    threat.analyze("https://cached-site.com/b", include_keyless=True)

    assert calls["rdap"] == 1


@pytest.mark.parametrize("status", [404, 500])
def test_missing_or_broken_rdap_is_harmless(threat, monkeypatch, status):
    install_fake_get(monkeypatch, rdap_status=status)
    threat.feed_url = ""

    result = threat.analyze("https://no-rdap-for-this.rw", include_keyless=True)

    assert result["newly_registered"] is False
    assert result["domain_age_days"] is None
    assert result["match"] is False


def test_ip_addresses_have_no_domain_age(threat, monkeypatch):
    calls = install_fake_get(monkeypatch)
    threat.feed_url = ""

    result = threat.analyze("http://203.0.113.9/login", include_keyless=True)

    assert calls["rdap"] == 0
    assert result["newly_registered"] is False


# ----------------------------------------------------------------------------
# internet check
# ----------------------------------------------------------------------------

def test_is_online_true_when_a_connection_opens(threat, monkeypatch):
    class Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(threat_module.socket, "create_connection",
                        lambda *a, **k: Conn())

    assert threat.is_online() is True


def test_is_online_false_and_cached_when_no_connection(threat, monkeypatch):
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise OSError("no network")

    monkeypatch.setattr(threat_module.socket, "create_connection", refuse)

    assert threat.is_online() is False
    assert threat.is_online() is False
    assert len(attempts) == 2             # two addresses, tried once (then cached)


# ----------------------------------------------------------------------------
# hybrid service
# ----------------------------------------------------------------------------

class FakeModel:
    def __init__(self, prediction="LEGITIMATE", risk=5.0):
        self.prediction, self.risk = prediction, risk

    def predict(self, url):
        return {"url": url, "prediction": self.prediction,
                "risk_score": self.risk, "confidence": 90.0,
                "threshold": 0.29, "indicators": []}


class FakeThreat:
    configured = False

    def __init__(self, internet=True, match=False, newly_registered=False, age=None):
        self.internet = internet
        self.calls = []
        self.result = {
            "configured": False,
            "status": "match" if match else "checked_no_match",
            "match": match,
            "providers": [{"provider": "OpenPhish feed",
                           "status": "match" if match else "no_match",
                           "match": match}],
            "cached": False,
            "domain_age_days": age,
            "newly_registered": newly_registered,
        }

    def is_online(self):
        return self.internet

    def analyze(self, url, include_keyless=False):
        self.calls.append(include_keyless)
        return self.result

    def provider_overview(self):
        return [{"name": "OpenPhish feed", "ready": True,
                 "needs_key": False, "shares": "nothing (list is downloaded)"}]


@pytest.fixture
def local_service(tmp_path, monkeypatch):
    directory = tmp_path / "intelligence"
    directory.mkdir()
    (directory / "blocklist.txt").write_text("", encoding="utf-8")
    (directory / "allowlist.txt").write_text("trusted-example.com\n", encoding="utf-8")
    monkeypatch.setattr(local_module, "INTELLIGENCE_DIR", directory)
    monkeypatch.setattr(local_module, "BLOCKLIST_FILE", directory / "blocklist.txt")
    monkeypatch.setattr(local_module, "ALLOWLIST_FILE", directory / "allowlist.txt")
    return LocalIntelligenceService()


def hybrid(local_service, threat_service, prediction="LEGITIMATE", risk=5.0):
    service = HybridDetectionService.__new__(HybridDetectionService)
    service.model_service = FakeModel(prediction, risk)
    service.local_service = local_service
    service.threat_service = threat_service
    return service


def test_offline_mode_never_touches_the_network(local_service):
    threat_service = FakeThreat(match=True)

    result = hybrid(local_service, threat_service).analyze("https://plain-site.com")

    assert threat_service.calls == []
    assert result["detection_mode"] == "OFFLINE_ML_AND_LOCAL_RULES"
    assert result["online"] == {"requested": False, "internet": None,
                                "used": False, "domain_age_days": None}
    assert result["final_prediction"] == "LEGITIMATE"


def test_online_without_internet_falls_back_to_offline(local_service):
    threat_service = FakeThreat(internet=False, match=True)

    result = hybrid(local_service, threat_service).analyze(
        "https://plain-site.com", online=True)

    assert threat_service.calls == []
    assert result["detection_mode"] == "OFFLINE_FALLBACK_NO_INTERNET"
    assert result["online"]["requested"] is True
    assert result["online"]["used"] is False
    assert result["final_prediction"] == "LEGITIMATE"


def test_online_uses_every_online_source(local_service):
    threat_service = FakeThreat()

    result = hybrid(local_service, threat_service).analyze(
        "https://plain-site.com", online=True)

    assert threat_service.calls == [True]
    assert result["detection_mode"] == "HYBRID_ONLINE_AND_OFFLINE"
    assert result["online"]["used"] is True


def test_feed_match_makes_a_fresh_phishing_url_phishing(local_service):
    # The offline engine sees nothing wrong with this URL ...
    offline = hybrid(local_service, FakeThreat(match=True)).analyze("https://plain-site.com")
    assert offline["final_prediction"] == "LEGITIMATE"

    # ... but the live feed lists it, so online mode flags it.
    online = hybrid(local_service, FakeThreat(match=True)).analyze(
        "https://plain-site.com", online=True)

    assert online["final_prediction"] == "PHISHING"
    assert online["final_risk_score"] == 100
    assert "OpenPhish feed" in online["decision_sources"]


def test_new_domain_alone_is_suspicious_not_phishing(local_service):
    result = hybrid(local_service, FakeThreat(newly_registered=True, age=2)).analyze(
        "https://plain-site.com", online=True)

    assert result["final_prediction"] == "SUSPICIOUS"
    assert 50 <= result["final_risk_score"] < 80
    assert "Domain registered only 2 day(s) ago" in result["indicators"]
    assert result["online"]["domain_age_days"] == 2


def test_new_domain_plus_ml_phishing_is_phishing(local_service):
    result = hybrid(local_service,
                    FakeThreat(newly_registered=True, age=2),
                    prediction="PHISHING", risk=62.0).analyze(
        "https://plain-site.com", online=True)

    assert result["final_prediction"] == "PHISHING"
    assert result["final_risk_score"] >= 80


def test_old_domain_changes_nothing(local_service):
    result = hybrid(local_service, FakeThreat(age=4000)).analyze(
        "https://plain-site.com", online=True)

    assert result["final_prediction"] == "LEGITIMATE"


def test_trusted_domain_is_never_called_new(local_service):
    result = hybrid(local_service,
                    FakeThreat(newly_registered=True, age=1),
                    prediction="PHISHING", risk=90.0).analyze(
        "https://trusted-example.com/login", online=True)

    assert result["final_prediction"] == "LEGITIMATE"
    assert result["final_risk_score"] == 0


@pytest.mark.parametrize("online", [False, True])
@pytest.mark.parametrize(
    "threat_kwargs, prediction, risk",
    [
        ({}, "LEGITIMATE", 5.0),
        ({"match": True}, "LEGITIMATE", 5.0),
        ({"newly_registered": True, "age": 2}, "LEGITIMATE", 5.0),
        ({"newly_registered": True, "age": 2}, "PHISHING", 55.0),
        ({"internet": False}, "PHISHING", 70.0),
    ],
)
def test_label_and_number_agree_in_every_mode(
        local_service, online, threat_kwargs, prediction, risk):
    result = hybrid(local_service, FakeThreat(**threat_kwargs),
                    prediction, risk).analyze("https://plain-site.com", online=online)

    label, number = result["final_prediction"], result["final_risk_score"]

    if label == "PHISHING":
        assert number >= 80
    elif label == "SUSPICIOUS":
        assert 35 <= number < 80
    else:
        assert number < 35


# ----------------------------------------------------------------------------
# API
# ----------------------------------------------------------------------------

@pytest.fixture
def client():
    return create_app().test_client()


@pytest.fixture
def temp_history(tmp_path, monkeypatch):
    directory = tmp_path / "database"
    monkeypatch.setattr(history_module, "DATABASE_DIR", directory)
    monkeypatch.setattr(history_module, "DATABASE_PATH", directory / "t.db")
    monkeypatch.setattr(history_module, "_history_service", None)


@pytest.mark.parametrize("endpoint", ["/api/analyze", "/api/predict"])
@pytest.mark.parametrize("mode", ["fast", 1, None, ""])
def test_invalid_mode_is_rejected(client, endpoint, mode):
    response = client.post(endpoint, json={"url": "example.com", "mode": mode})

    assert response.status_code == 400
    assert "mode" in response.get_json()["error"]


def test_api_defaults_to_offline(client, temp_history, monkeypatch):
    threat_service = FakeThreat(match=True)
    monkeypatch.setattr(get_hybrid_service(), "threat_service", threat_service)

    response = client.post("/api/analyze", json={"url": "https://plain-site.com"})

    assert response.status_code == 200
    assert threat_service.calls == []
    assert response.get_json()["data"]["detection_mode"] == "OFFLINE_ML_AND_LOCAL_RULES"


def test_api_online_mode_uses_online_sources(client, temp_history, monkeypatch):
    threat_service = FakeThreat(match=True)
    monkeypatch.setattr(get_hybrid_service(), "threat_service", threat_service)

    response = client.post("/api/analyze",
                           json={"url": "https://plain-site.com", "mode": "online"})
    data = response.get_json()["data"]

    assert response.status_code == 200
    assert threat_service.calls == [True]
    assert data["detection_mode"] == "HYBRID_ONLINE_AND_OFFLINE"
    assert data["final_prediction"] == "PHISHING"
    assert data["scan_id"] == 1                      # and it was saved to history


def test_predict_endpoint_supports_online_mode(client, monkeypatch):
    threat_service = FakeThreat(match=True)
    monkeypatch.setattr(get_hybrid_service(), "threat_service", threat_service)

    data = client.post("/api/predict",
                       json={"url": "https://plain-site.com", "mode": "online"}
                       ).get_json()["data"]

    assert data["prediction"] == "PHISHING"
    assert data["detection_mode"] == "HYBRID_ONLINE_AND_OFFLINE"


def test_status_endpoint_reports_internet_and_providers(client, monkeypatch):
    import backend.routes.prediction as routes

    monkeypatch.setattr(routes, "get_threat_intelligence_service",
                        lambda: FakeThreat(internet=True))
    data = client.get("/api/status").get_json()

    assert data["success"] is True
    assert data["internet"] is True
    assert data["providers"][0]["name"] == "OpenPhish feed"

    monkeypatch.setattr(routes, "get_threat_intelligence_service",
                        lambda: FakeThreat(internet=False))

    assert client.get("/api/status").get_json()["internet"] is False
