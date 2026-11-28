import uuid

import backend.database.history_service as history_module
from desktop import local_storage


def test_desktop_identity_is_persistent_and_install_specific(tmp_path):
    identity_file = tmp_path / "PhishGuard" / "desktop_identity"

    first = local_storage.get_desktop_owner_id(identity_file)
    second = local_storage.get_desktop_owner_id(identity_file)

    assert first == second
    assert first.startswith("desktop:")
    uuid.UUID(first.split(":", 1)[1])


def test_invalid_desktop_identity_is_replaced(tmp_path):
    identity_file = tmp_path / "desktop_identity"
    identity_file.parent.mkdir(parents=True, exist_ok=True)
    identity_file.write_text("not-a-uuid", encoding="utf-8")

    identity = local_storage.get_desktop_owner_id(identity_file)

    assert identity.startswith("desktop:")
    uuid.UUID(identity.split(":", 1)[1])
    assert identity_file.read_text(encoding="utf-8") == identity.split(":", 1)[1]


def test_desktop_scan_history_is_persisted_for_local_identity(
    tmp_path, monkeypatch
):
    database_dir = tmp_path / "database"
    database_path = database_dir / "desktop_history.sqlite3"
    monkeypatch.setattr(history_module, "DATABASE_DIR", database_dir)
    monkeypatch.setattr(history_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "_history_service", None)

    owner_id = "desktop:test-install"
    result = {
        "url": "https://example.com/login",
        "final_prediction": "SUSPICIOUS",
        "final_risk_score": 63.5,
        "detection_mode": "OFFLINE",
        "decision_sources": ["Test indicator"],
        "ml_result": {"confidence": 80.0, "indicators": ["test"]},
        "local_intelligence": {
            "domain": "example.com",
            "indicators": [],
        },
    }

    scan_id = local_storage.save_desktop_scan(result, owner_id=owner_id)
    history = local_storage.get_desktop_history(owner_id=owner_id)

    assert scan_id == 1
    assert history["total"] == 1
    assert history["scans"][0]["url"] == result["url"]
    assert history["scans"][0]["prediction"] == "SUSPICIOUS"
    assert history["scans"][0]["risk_score"] == 63.5
    assert local_storage.get_desktop_history(
        owner_id="desktop:another-install"
    )["total"] == 0
