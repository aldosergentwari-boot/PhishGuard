import pytest

from backend.app import create_app


@pytest.fixture
def client():
    return create_app().test_client()


@pytest.mark.parametrize("text", ["hello", "asdfghjkl", "bank", "localhost", "a.b", "hello."])
def test_non_domains_are_rejected_not_called_legitimate(client, text):
    response = client.post("/api/predict", json={"url": text})
    assert response.status_code == 400
    assert response.get_json()["success"] is False


@pytest.mark.parametrize("text", ["example.com", "https://irembo.gov.rw/home", "http://192.168.1.10/login"])
def test_real_domains_and_ips_are_accepted(client, text):
    assert client.post("/api/predict", json={"url": text}).status_code == 200


@pytest.mark.parametrize("text", ["rra-gov-rw-refund.com", "irembo-gov-rw.com/login", "mtn-momo-promo-winner.com"])
def test_rwanda_brand_impersonation_is_flagged(client, text):
    data = client.post("/api/predict", json={"url": text}).get_json()["data"]
    assert data["prediction"] == "PHISHING"


def test_att_impersonation_is_flagged(client):
    data = client.post("/api/predict", json={"url": "https://att-rsshelp.com"}).get_json()["data"]
    assert data["prediction"] == "PHISHING"


@pytest.mark.parametrize("text", ["https://terrace-login.com", "https://smtnews-account.com"])
def test_short_brand_inside_a_longer_word_is_not_a_brand_match(text):
    from backend.services.hybrid_service import get_hybrid_service

    result = get_hybrid_service().analyze(text)
    assert result["local_intelligence"]["brand_impersonation_match"] is False
