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
        lambda owner_id, remote_addr=None: True,
    )

    response = client.post(
        "/api/predict",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 429
    assert response.get_json()["code"] == "RATE_LIMIT_EXCEEDED"
    assert response.headers["Retry-After"] == "60"



def test_scan_rate_limiter_checks_ip_and_identity_buckets(monkeypatch):
    from backend.app import app

    calls = []

    def allow(bucket, limit, window_seconds):
        calls.append((bucket, limit, window_seconds))
        return True

    monkeypatch.setattr(
        prediction_module.auth_service,
        "allow_scan_attempt",
        allow,
    )

    with app.app_context():
        assert prediction_module._scan_rate_limit_exceeded(
            "account:42", "203.0.113.10"
        ) is False

    assert len(calls) == 2
    assert calls[0][0].startswith("scan-ip:")
    assert calls[0][1:] == (300, 60)
    assert calls[1][0].startswith("scan-identity:")
    assert calls[1][1:] == (30, 60)
