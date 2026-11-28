import sqlite3
from contextlib import closing

import scripts.restore_database as restore_module


def _make_database(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS sample (value TEXT)")
        connection.execute("DELETE FROM sample")
        connection.execute("INSERT INTO sample VALUES (?)", (value,))
        connection.commit()


def test_restore_replaces_database_and_creates_safety_backup(tmp_path, monkeypatch):
    backup = tmp_path / "backup.sqlite3"
    target = tmp_path / "data" / "phishguard.sqlite3"
    _make_database(backup, "from-backup")
    _make_database(target, "current-data")
    monkeypatch.setattr(restore_module, "BASE_DIR", tmp_path / "project")

    restored, safety = restore_module.restore_database(backup, target)

    assert restored == target.resolve()
    assert safety is not None and safety.is_file()
    with closing(sqlite3.connect(target)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT value FROM sample").fetchone()[0] == "from-backup"
    with closing(sqlite3.connect(safety)) as connection:
        assert connection.execute("SELECT value FROM sample").fetchone()[0] == "current-data"


def test_restore_rejects_missing_backup(tmp_path):
    target = tmp_path / "database.sqlite3"
    try:
        restore_module.restore_database(tmp_path / "missing.sqlite3", target)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("A missing backup must not be restored.")


def test_restore_rejects_same_source_and_destination(tmp_path):
    database = tmp_path / "database.sqlite3"
    _make_database(database, "keep-me")

    try:
        restore_module.restore_database(database, database)
    except ValueError as error:
        assert "must be different" in str(error)
    else:
        raise AssertionError("Restore must never replace a database with itself.")
