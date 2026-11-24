"""Create a consistent SQLite backup of the configured PhishGuard database.

The SQLite backup API includes committed data from WAL mode and avoids copying a
live database file while it is being written.
"""
import argparse
import sqlite3
import tempfile
from contextlib import closing
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
    temporary_path = None

    try:
        # Build beside the destination, then atomically replace it only after
        # SQLite confirms that the completed backup is structurally sound.
        with tempfile.NamedTemporaryFile(
            prefix=f".{destination_path.name}.",
            suffix=".tmp",
            dir=destination_path.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)

        with closing(sqlite3.connect(source_path, timeout=30)) as source:
            with closing(sqlite3.connect(temporary_path, timeout=30)) as target:
                source.backup(target)
                target.commit()
                check = target.execute("PRAGMA integrity_check").fetchone()
                if not check or check[0] != "ok":
                    detail = check[0] if check else "no result"
                    raise sqlite3.DatabaseError(
                        f"Backup integrity check failed: {detail}"
                    )

        temporary_path.replace(destination_path)
        return destination_path
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


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
