import pytest

import backend.database.history_service as history_module

from backend.database.history_service import HistoryService

OWNER = "test-owner"
OTHER_OWNER = "another-owner"


@pytest.fixture
def history_service(tmp_path, monkeypatch):
    database_dir = tmp_path / "database"
    database_path = database_dir / "test_history.db"

    monkeypatch.setattr(history_module, "DATABASE_DIR", database_dir)
    monkeypatch.setattr(history_module, "DATABASE_PATH", database_path)

    return HistoryService()


@pytest.fixture
def sample_result():
    return {
        "url": "https://example.com/login",
        "final_prediction": "LEGITIMATE",
        "final_risk_score": 12.5,
        "detection_mode": "OFFLINE",
        "decision_sources": ["No threat detected"],
        "ml_result": {"confidence": 98.5, "indicators": []},
        "local_intelligence": {"domain": "example.com", "indicators": []},
    }


def make_result(sample_result, prediction, number=0):
    result = sample_result.copy()
    result["final_prediction"] = prediction
    result["url"] = f"https://example{number}.com"
    return result


def test_database_is_created(history_service):
    assert history_module.DATABASE_PATH.exists()


def test_save_scan(history_service, sample_result):
    scan_id = history_service.save_scan(sample_result, OWNER)

    assert scan_id == 1

    scan = history_service.get_scan(scan_id, OWNER)

    assert scan is not None
    assert scan["url"] == sample_result["url"]
    assert scan["prediction"] == "LEGITIMATE"
    assert scan["risk_score"] == 12.5


def test_save_scan_requires_owner(history_service, sample_result):
    with pytest.raises(ValueError):
        history_service.save_scan(sample_result, "")


def test_get_history(history_service, sample_result):
    history_service.save_scan(sample_result, OWNER)

    result = history_service.get_history(OWNER)

    assert result["total"] == 1
    assert len(result["scans"]) == 1


def test_history_pagination(history_service, sample_result):
    for number in range(5):
        history_service.save_scan(
            make_result(sample_result, "LEGITIMATE", number), OWNER
        )

    page = history_service.get_history(OWNER, limit=2, offset=0)

    assert page["total"] == 5
    assert len(page["scans"]) == 2


def test_get_nonexistent_scan(history_service):
    assert history_service.get_scan(999, OWNER) is None


def test_delete_scan(history_service, sample_result):
    scan_id = history_service.save_scan(sample_result, OWNER)

    assert history_service.delete_scan(scan_id, OWNER) is True
    assert history_service.get_scan(scan_id, OWNER) is None


def test_clear_history(history_service, sample_result):
    history_service.save_scan(sample_result, OWNER)
    history_service.save_scan(sample_result, OWNER)

    assert history_service.clear_history(OWNER) == 2
    assert history_service.get_history(OWNER)["total"] == 0


def test_owners_cannot_see_each_other(history_service, sample_result):
    scan_id = history_service.save_scan(sample_result, OWNER)

    assert history_service.get_history(OTHER_OWNER)["total"] == 0
    assert history_service.get_scan(scan_id, OTHER_OWNER) is None
    assert history_service.delete_scan(scan_id, OTHER_OWNER) is False


def test_summary_counts_three_categories(history_service, sample_result):
    """Regression test: the donut chart needs phishing, suspicious and
    legitimate counted separately, and they must add up to the total."""
    labels = ["PHISHING"] * 3 + ["SUSPICIOUS"] * 4 + ["LEGITIMATE"] * 4

    for number, label in enumerate(labels):
        history_service.save_scan(
            make_result(sample_result, label, number), OWNER
        )

    summary = history_service.get_history(OWNER, limit=10)["summary"]

    assert summary["total"] == 11
    assert summary["phishing"] == 3
    assert summary["suspicious"] == 4
    assert summary["legitimate"] == 4
    assert (
        summary["phishing"] + summary["suspicious"] + summary["legitimate"]
        == summary["total"]
    )


@pytest.mark.parametrize(
    "filter_name, expected",
    [("all", 11), ("phishing", 3), ("suspicious", 4), ("legitimate", 4)],
)
def test_history_filters(history_service, sample_result, filter_name, expected):
    labels = ["PHISHING"] * 3 + ["SUSPICIOUS"] * 4 + ["LEGITIMATE"] * 4

    for number, label in enumerate(labels):
        history_service.save_scan(
            make_result(sample_result, label, number), OWNER
        )

    result = history_service.get_history(
        OWNER, limit=50, filter_by=filter_name
    )

    assert result["total"] == expected
