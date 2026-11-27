import pytest

from backend.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    import backend.database.auth_service as auth_module
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "auth_test.db")
    app = create_app()
    app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with app.test_client() as test_client:
        yield test_client


def test_legacy_payment_callback_is_retired_and_cannot_activate_a_plan(client):
    response = client.get(
        "/api/billing/callback?status=successful&tx_ref=ref-123&transaction_id=456"
    )
    assert response.status_code == 410
    assert "disabled" in response.get_json()["error"].lower()


def test_legacy_callback_does_not_redirect_to_payment_success(client):
    response = client.get(
        "/api/billing/callback?status=successful&tx_ref=ref-123&transaction_id=456",
        follow_redirects=False,
    )
    assert response.status_code == 410
    assert response.headers.get("Location") is None
