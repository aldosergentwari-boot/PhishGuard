
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

    def save_scan(self, result):
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
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

            return cursor.lastrowid

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
            conditions.append("UPPER(prediction) LIKE '%PHISH%'")

        elif filter_by == "legitimate":
            conditions.append("UPPER(prediction) NOT LIKE '%PHISH%'")

        where_clause = (
            "WHERE " + " AND ".join(conditions)
            if conditions else ""
        )

        return where_clause, parameters

    def get_history(
        self,
        limit=20,
        offset=0,
        search="",
        filter_by="all"
    ):
        where_clause, parameters = self._build_filters(
            search,
            filter_by
        )

        with self.get_connection() as connection:

            rows = connection.execute(f"""
                SELECT *
                FROM scan_history
                {where_clause}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """, (*parameters, limit, offset)).fetchall()

            total = connection.execute(f"""
                SELECT COUNT(*)
                FROM scan_history
                {where_clause}
            """, parameters).fetchone()[0]

            summary_row = connection.execute("""
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(
                        CASE
                            WHEN UPPER(prediction) LIKE '%PHISH%'
                            THEN 1 ELSE 0
                        END
                    ), 0) AS phishing,
                    COALESCE(SUM(
                        CASE
                            WHEN UPPER(prediction) NOT LIKE '%PHISH%'
                            THEN 1 ELSE 0
                        END
                    ), 0) AS legitimate
                FROM scan_history
            """).fetchone()

            return {
                "total": total,
                "limit": limit,
                "offset": offset,
                "search": search,
                "filter": filter_by,
                "summary": {
                    "total": summary_row["total"],
                    "phishing": summary_row["phishing"],
                    "legitimate": summary_row["legitimate"]
                },
                "scans": [
                    self.serialize_scan(row)
                    for row in rows
                ]
            }

    def get_scan(self, scan_id):
        with self.get_connection() as connection:
            row = connection.execute("""
                SELECT *
                FROM scan_history
                WHERE id = ?
            """, (scan_id,)).fetchone()

            if row is None:
                return None

            return self.serialize_scan(row)

    def delete_scan(self, scan_id):
        with self.get_connection() as connection:
            cursor = connection.execute("""
                DELETE FROM scan_history
                WHERE id = ?
            """, (scan_id,))

            return cursor.rowcount > 0

    def clear_history(self):
        with self.get_connection() as connection:
            cursor = connection.execute("""
                DELETE FROM scan_history
            """)

            return cursor.rowcount


_history_service = None


def get_history_service():
    global _history_service

    if _history_service is None:
        _history_service = HistoryService()

    return _history_service
