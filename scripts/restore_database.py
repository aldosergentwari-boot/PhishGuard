"""Safely restore a verified SQLite backup into the configured database.

Stop the PhishGuard application before running this command. Restoring a live
SQLite database while application connections are open is not supported.
"""
import argparse
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from backend.config import BASE_DIR, DATABASE_PATH


def _integrity_check(path):
    with closing(sqlite3.connect(path, timeout=30)) as connection:
        result = connection.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        detail = result[0] if result else "no result"
        raise sqlite3.DatabaseError(f"Database integrity check failed: {detail}")


def _copy_database(source_path, destination_path):
    with closing(sqlite3.connect(source_path, timeout=30)) as source:
        with closing(sqlite3.connect(destination_path, timeout=30)) as target:
            source.backup(target)
            target.commit()


def restore_database(backup, destination=None, safety_backup=True):
    backup_path = Path(backup).expanduser().resolve()
    target_path = Path(destination or DATABASE_PATH).expanduser().resolve()

    if not backup_path.is_file():
        raise FileNotFoundError(f"Backup file was not found: {backup_path}")
    if backup_path == target_path:
        raise ValueError("Restore source and database destination must be different.")

    _integrity_check(backup_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    safety_path = None
    if target_path.is_file() and safety_backup:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safety_path = BASE_DIR / "backups" / f"pre-restore-{stamp}.sqlite3"
        suffix = 1
        while safety_path.exists():
            safety_path = BASE_DIR / "backups" / f"pre-restore-{stamp}-{suffix}.sqlite3"
            suffix += 1
        safety_path.parent.mkdir(parents=True, exist_ok=True)
        _copy_database(target_path, safety_path)
        _integrity_check(safety_path)

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{target_path.name}.restore.",
            suffix=".tmp",
            dir=target_path.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)

        _copy_database(backup_path, temporary_path)
        _integrity_check(temporary_path)

        # Refuse to replace a database with an active/busy WAL writer.
        if target_path.exists():
            with closing(sqlite3.connect(target_path, timeout=5)) as current:
                checkpoint = current.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                if checkpoint and checkpoint[0] != 0:
                    raise sqlite3.OperationalError(
                        "Database is busy. Stop PhishGuard and retry the restore."
                    )

        temporary_path.replace(target_path)
        return target_path, safety_path
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Restore a verified PhishGuard SQLite backup."
    )
    parser.add_argument("backup", help="Path to the verified .sqlite3 backup.")
    parser.add_argument(
        "--database",
        help="Destination database path. Defaults to PHISHGUARD_DATABASE_PATH.",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required to perform the database replacement.",
    )
    parser.add_argument(
        "--no-safety-backup",
        action="store_true",
        help="Skip the automatic pre-restore backup (not recommended).",
    )
    args = parser.parse_args()

    if not args.confirm:
        parser.error("Restore not performed. Add --confirm after stopping PhishGuard.")

    restored, safety = restore_database(
        args.backup,
        destination=args.database,
        safety_backup=not args.no_safety_backup,
    )
    print(f"Database restored and verified: {restored}")
    if safety:
        print(f"Pre-restore safety backup: {safety}")


if __name__ == "__main__":
    main()
