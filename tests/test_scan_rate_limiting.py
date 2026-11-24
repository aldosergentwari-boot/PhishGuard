import backend.database.auth_service as auth_module
import backend.routes.prediction as prediction_module
from backend.database.auth_service import AuthService


def test_scan_rate_limit_allows_limit_then_blocks_and_resets(monkeypatch, tmp_path):
    database_path = tmp_path / "rate-limits.sqlite3"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", database_path)
    now = [1_000.0]
    monkeypatch.setattr(auth_module.time, "time", lambda: now[0])

    service = AuthService()
    service.initialize()

    assert service.allow_scan_attempt("scan:test", limit=2, window_seconds=60)
    assert service.allow_scan_attempt("scan:test", limit=2, window_seconds=60)
    assert not service.allow_scan_attempt("scan:test", limit=2, window_seconds=60)

    now[0] += 61
    assert service.allow_scan_attempt("scan:test", limit=2, window_seconds=60)


def test_prediction_api_returns_429_when_scan_rate_limit_is_exceeded(
    client, monkeypatch
):
    monkeypatch.setattr(
        prediction_module,
        "_scan_rate_limit_exceeded",
        lambda owner_id: True,
    )

    response = client.post(
        "/api/predict",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 429
    assert response.get_json()["code"] == "RATE_LIMIT_EXCEEDED"
    assert response.headers["Retry-After"] == "60"
