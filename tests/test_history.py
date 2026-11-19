
import pytest

import backend.database.history_service as history_module

from backend.database.history_service import HistoryService


@pytest.fixture
def history_service(tmp_path, monkeypatch):

    database_dir = tmp_path / "database"

    database_path = (
        database_dir / "test_history.db"
    )

    monkeypatch.setattr(
        history_module,
        "DATABASE_DIR",
        database_dir
    )

    monkeypatch.setattr(
        history_module,
        "DATABASE_PATH",
        database_path
    )

    return HistoryService()


@pytest.fixture
def sample_result():

    return {
        "url": "https://example.com/login",

        "final_prediction": "LEGITIMATE",

        "final_risk_score": 12.5,

        "detection_mode": "OFFLINE",

        "decision_sources": [
            "No threat detected"
        ],

        "ml_result": {
            "confidence": 98.5,
            "indicators": []
        },

        "local_intelligence": {
            "domain": "example.com",
            "indicators": []
        }
    }


def test_database_is_created(history_service):

    assert history_module.DATABASE_PATH.exists()


def test_save_scan(history_service, sample_result):

    scan_id = history_service.save_scan(
        sample_result
    )

    assert scan_id == 1

    scan = history_service.get_scan(scan_id)

    assert scan is not None

    assert scan["url"] == sample_result["url"]

    assert scan["prediction"] == "LEGITIMATE"

    assert scan["risk_score"] == 12.5


def test_get_history(history_service, sample_result):

    history_service.save_scan(sample_result)

    result = history_service.get_history()

    assert result["total"] == 1

    assert len(result["scans"]) == 1


def test_history_pagination(history_service, sample_result):

    for number in range(5):

        result = sample_result.copy()

        result["url"] = (
            f"https://example{number}.com"
        )

        history_service.save_scan(result)

    page = history_service.get_history(
        limit=2,
        offset=0
    )

    assert page["total"] == 5

    assert len(page["scans"]) == 2


def test_get_nonexistent_scan(history_service):

    result = history_service.get_scan(999)

    assert result is None


def test_delete_scan(history_service, sample_result):

    scan_id = history_service.save_scan(
        sample_result
    )

    deleted = history_service.delete_scan(
        scan_id
    )

    assert deleted is True

    assert history_service.get_scan(scan_id) is None


def test_clear_history(history_service, sample_result):

    history_service.save_scan(sample_result)

    history_service.save_scan(sample_result)

    deleted_count = history_service.clear_history()

    assert deleted_count == 2

    assert history_service.get_history()["total"] == 0
