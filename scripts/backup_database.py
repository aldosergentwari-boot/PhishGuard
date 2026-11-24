"""Create a consistent SQLite backup of the configured PhishGuard database.

The SQLite backup API includes committed data from WAL mode and avoids copying a
live database file while it is being written.
"""
import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from backend.config import BASE_DIR, DATABASE_PATH


def create_backup(destination=None):
    source_path = Path(DATABASE_PATH).expanduser().resolve()
    if not source_path.is_file():
        raise FileNotFoundError(
            f"PhishGuard database was not found: {source_path}"
        )

    if destination is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination_path = BASE_DIR / "backups" / f"phishguard-{stamp}.sqlite3"
    else:
        destination_path = Path(destination).expanduser().resolve()

    if destination_path == source_path:
        raise ValueError("Backup destination must be different from the source database.")

    destination_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with sqlite3.connect(source_path, timeout=30) as source:
            with sqlite3.connect(destination_path, timeout=30) as target:
                source.backup(target)
                check = target.execute("PRAGMA integrity_check").fetchone()
                if not check or check[0] != "ok":
                    raise sqlite3.DatabaseError(
                        f"Backup integrity check failed: {check[0] if check else 'no result'}"
                    )
    except Exception:
        # Never leave a partial backup that could be mistaken for a valid one.
        destination_path.unlink(missing_ok=True)
        raise

    return destination_path


def main():
    parser = argparse.ArgumentParser(
        description="Back up the configured PhishGuard SQLite database."
    )
    parser.add_argument(
        "--output",
        help="Optional destination file. Defaults to ./backups with a UTC timestamp.",
    )
    args = parser.parse_args()

    path = create_backup(args.output)
    print(f"Backup created and verified: {path}")


if __name__ == "__main__":
    main()
