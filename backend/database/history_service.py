
import sqlite3
import json

from datetime import datetime, timezone
from contextlib import contextmanager

from backend.config import DATABASE_DIR, DATABASE_PATH


class HistoryService:

    def __init__(self):
        DATABASE_DIR.mkdir(parents=True, exist_ok=True)
        self.initialize_database()

    @contextmanager
    def get_connection(self):
        connection = sqlite3.connect(DATABASE_PATH, timeout=10)
        connection.row_factory = sqlite3.Row

        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize_database(self):
        with self.get_connection() as connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id TEXT,
                    url TEXT NOT NULL,
                    domain TEXT,
                    prediction TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    confidence REAL,
                    detection_mode TEXT,
                    decision_sources TEXT,
                    indicators TEXT,
                    scanned_at TEXT NOT NULL
                )
            """)

            # Safely upgrade an existing database.
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(scan_history)"
                ).fetchall()
            }

            if "owner_id" not in columns:
                connection.execute("""
                    ALTER TABLE scan_history
                    ADD COLUMN owner_id TEXT
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_scan_history_owner
                ON scan_history(owner_id)
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_scan_history_scanned_at
                ON scan_history(scanned_at)
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_scan_history_prediction
                ON scan_history(prediction)
            """)

            # Keep quota accounting after users delete their visible history.
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scan_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    history_scan_id INTEGER UNIQUE
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_usage_owner_time
                ON scan_usage(owner_id, scanned_at)
            """)
            connection.execute("""
                INSERT OR IGNORE INTO scan_usage(owner_id, scanned_at, history_scan_id)
                SELECT owner_id, scanned_at, id FROM scan_history
                WHERE owner_id IS NOT NULL
            """)

    def save_scan(self, result, owner_id):
        if not owner_id:
            raise ValueError("A valid scan owner is required.")

        ml_result = result.get("ml_result", {})
        local_result = result.get("local_intelligence", {})

        indicators = {
            "machine_learning": ml_result.get("indicators", []),
            "local_rules": local_result.get("indicators", [])
        }

        scanned_at = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as connection:
            cursor = connection.execute("""
                INSERT INTO scan_history (
                    owner_id,
                    url,
                    domain,
                    prediction,
                    risk_score,
                    confidence,
                    detection_mode,
                    decision_sources,
                    indicators,
                    scanned_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                owner_id,
                result.get("url"),
                local_result.get("domain"),
                result.get("final_prediction"),
                result.get("final_risk_score", 0),
                ml_result.get("confidence"),
                result.get("detection_mode", "OFFLINE"),
                json.dumps(result.get("decision_sources", [])),
                json.dumps(indicators),
                scanned_at
            ))

            scan_id = cursor.lastrowid
            connection.execute("""
                INSERT INTO scan_usage(owner_id, scanned_at, history_scan_id)
                VALUES (?, ?, ?)
            """, (owner_id, scanned_at, scan_id))
            return scan_id

    @staticmethod
    def serialize_scan(row):
        scan = dict(row)

        scan["decision_sources"] = json.loads(
            scan.get("decision_sources") or "[]"
        )

        scan["indicators"] = json.loads(
            scan.get("indicators") or "{}"
        )

        return scan

    @staticmethod
    def _build_filters(search="", filter_by="all"):
        conditions = []
        parameters = []

        search = (search or "").strip()

        if search:
            escaped = (
                search.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            pattern = f"%{escaped}%"

            conditions.append("""
                (
                    url LIKE ? ESCAPE '\\'
                    OR COALESCE(domain, '') LIKE ? ESCAPE '\\'
                )
            """)

            parameters.extend([pattern, pattern])

        if filter_by == "phishing":
            conditions.append("UPPER(prediction) = 'PHISHING'")

        elif filter_by == "suspicious":
            conditions.append("UPPER(prediction) = 'SUSPICIOUS'")

        elif filter_by == "legitimate":
            conditions.append("UPPER(prediction) = 'LEGITIMATE'")

        where_clause = (
            " AND ".join(conditions)
            if conditions else "1 = 1"
        )

        return where_clause, parameters

    def get_history(
        self,
        owner_id,
        limit=20,
        offset=0,
        search="",
        filter_by="all",
        max_records=None
    ):
        if not owner_id:
            raise ValueError("A valid history owner is required.")

        filters, filter_parameters = self._build_filters(
            search,
            filter_by
        )

        where_clause = f"owner_id = ? AND ({filters})"
        parameters = [owner_id, *filter_parameters]
        if max_records is not None:
            max_records = max(1, int(max_records))
            where_clause = f"owner_id = ? AND id IN (SELECT id FROM scan_history WHERE owner_id = ? ORDER BY id DESC LIMIT ?) AND ({filters})"
            parameters = [owner_id, owner_id, max_records, *filter_parameters]

        with self.get_connection() as connection:

            rows = connection.execute(f"""
                SELECT *
                FROM scan_history
                WHERE {where_clause}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """, (*parameters, limit, offset)).fetchall()

            total = connection.execute(f"""
                SELECT COUNT(*)
                FROM scan_history
                WHERE {where_clause}
            """, parameters).fetchone()[0]

            summary_query = """
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(CASE WHEN UPPER(prediction) = 'PHISHING'
                        THEN 1 ELSE 0 END), 0) AS phishing,
                    COALESCE(SUM(CASE WHEN UPPER(prediction) = 'SUSPICIOUS'
                        THEN 1 ELSE 0 END), 0) AS suspicious,
                    COALESCE(SUM(CASE WHEN UPPER(prediction) = 'LEGITIMATE'
                        THEN 1 ELSE 0 END), 0) AS legitimate
                FROM scan_history
                WHERE owner_id = ?
            """
            summary_parameters = (owner_id,)
            if max_records is not None:
                summary_query = summary_query.replace(
                    "WHERE owner_id = ?",
                    "WHERE owner_id = ? AND id IN (SELECT id FROM scan_history WHERE owner_id = ? ORDER BY id DESC LIMIT ?)"
                )
                summary_parameters = (owner_id, owner_id, max_records)
            summary_row = connection.execute(
                summary_query, summary_parameters
            ).fetchone()

            return {
                "total": total,
                "limit": limit,
                "offset": offset,
                "search": search,
                "filter": filter_by,
                "summary": {
                    "total": summary_row["total"],
                    "phishing": summary_row["phishing"],
                    "suspicious": summary_row["suspicious"],
                    "legitimate": summary_row["legitimate"]
                },
                "scans": [
                    self.serialize_scan(row)
                    for row in rows
                ]
            }

    def get_scan(self, scan_id, owner_id, max_records=None):
        with self.get_connection() as connection:
            if max_records is None:
                row = connection.execute("""
                    SELECT *
                    FROM scan_history
                    WHERE id = ? AND owner_id = ?
                """, (scan_id, owner_id)).fetchone()
            else:
                row = connection.execute("""
                    SELECT *
                    FROM scan_history
                    WHERE id = ? AND owner_id = ?
                      AND id IN (
                          SELECT id FROM scan_history
                          WHERE owner_id = ? ORDER BY id DESC LIMIT ?
                      )
                """, (scan_id, owner_id, owner_id, max(1, int(max_records)))).fetchone()

            if row is None:
                return None

            return self.serialize_scan(row)

    def delete_scan(self, scan_id, owner_id):
        with self.get_connection() as connection:
            cursor = connection.execute("""
                DELETE FROM scan_history
                WHERE id = ? AND owner_id = ?
            """, (scan_id, owner_id))

            return cursor.rowcount > 0

    def clear_history(self, owner_id):
        with self.get_connection() as connection:
            cursor = connection.execute("""
                DELETE FROM scan_history
                WHERE owner_id = ?
            """, (owner_id,))

            return cursor.rowcount


_history_service = None


def get_history_service():
    global _history_service

    if _history_service is None:
        _history_service = HistoryService()

    return _history_service
