import sqlite3

import backend.database.auth_service as auth_module
import backend.database.history_service as history_module
import scripts.backup_database as backup_module
from backend.database.auth_service import AuthService
from backend.database.history_service import HistoryService


def test_auth_and_history_share_configured_database(tmp_path, monkeypatch):
    database_path = tmp_path / "persistent" / "nested" / "phishguard.sqlite3"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(history_module, "DATABASE_DIR", database_path.parent)

    AuthService().initialize()
    HistoryService()

    assert database_path.is_file()
    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

    assert {"users", "subscriptions", "payment_transactions", "scan_history"} <= tables


def test_backup_creates_verified_copy(tmp_path, monkeypatch):
    source = tmp_path / "data" / "phishguard.sqlite3"
    source.parent.mkdir(parents=True)
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE sample (value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('persistent-data')")

    monkeypatch.setattr(backup_module, "DATABASE_PATH", source)
    destination = tmp_path / "backup" / "verified.sqlite3"

    result = backup_module.create_backup(destination)

    assert result == destination.resolve()
    with sqlite3.connect(result) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT value FROM sample").fetchone()[0] == "persistent-data"


def test_backup_refuses_to_overwrite_source(tmp_path, monkeypatch):
    source = tmp_path / "phishguard.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE sample (value TEXT)")
    monkeypatch.setattr(backup_module, "DATABASE_PATH", source)

    try:
        backup_module.create_backup(source)
    except ValueError as error:
        assert "different from the source" in str(error)
    else:
        raise AssertionError("A backup must never overwrite the live database.")
