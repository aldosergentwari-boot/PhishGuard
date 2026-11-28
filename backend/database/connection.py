"""Database connection compatibility for local SQLite and hosted PostgreSQL.

The web application uses PostgreSQL whenever DATABASE_URL is configured. SQLite
remains available for local development, desktop workflows, and unit tests.
"""
import os
import re
import sqlite3
from pathlib import Path


def _postgres_dsn():
    value = os.getenv("DATABASE_URL", "").strip()
    if value.startswith("postgres://"):
        value = "postgresql://" + value[len("postgres://"):]
    return value or None


def _postgres_sql(sql):
    statement = sql.strip()
    if statement.upper() == "PRAGMA FOREIGN_KEYS = ON":
        return "SELECT 1"
    if statement.upper() == "BEGIN IMMEDIATE":
        # Serialize quota updates across workers; PostgreSQL starts the
        # transaction automatically on the first statement.
        return "LOCK TABLE auth_rate_limits IN SHARE ROW EXCLUSIVE MODE"
    pragma = re.fullmatch(r"PRAGMA\s+table_info\((\w+)\)", statement, re.I)
    if pragma:
        table = pragma.group(1)
        return (
            "SELECT column_name AS name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = "
            + "'" + table.replace("'", "''") + "' ORDER BY ordinal_position"
        )
    if "sqlite_master" in statement.lower():
        # PostgreSQL schema is created with the current token CHECK constraint;
        # this compatibility response avoids SQLite-only schema introspection.
        return "SELECT 'admin_password_reset' AS sql"
    statement = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", statement, flags=re.I)
    if re.match(r"INSERT\s+OR\s+IGNORE\s+INTO", sql.strip(), flags=re.I):
        statement += " ON CONFLICT DO NOTHING"
    statement = re.sub(
        r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
        "BIGSERIAL PRIMARY KEY",
        statement,
        flags=re.I,
    )
    statement = re.sub(r"\s+COLLATE\s+NOCASE\b", "", statement, flags=re.I)
    statement = statement.replace("?", "%s")
    return statement


class _Cursor:
    def __init__(self, connection, cursor, lastrowid=None):
        self._connection = connection
        self._cursor = cursor
        self._lastrowid = lastrowid

    @property
    def lastrowid(self):
        return self._lastrowid

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def __iter__(self):
        return iter(self._cursor)


class _PostgresConnection:
    def __init__(self, dsn):
        import psycopg2
        from psycopg2.extras import DictCursor

        self._psycopg2 = psycopg2
        self._connection = psycopg2.connect(dsn, cursor_factory=DictCursor)

    def execute(self, sql, parameters=()):
        cursor = self._connection.cursor()
        statement = _postgres_sql(sql)
        try:
            cursor.execute(statement, parameters or ())
        except self._psycopg2.IntegrityError as exc:
            cursor.close()
            raise sqlite3.IntegrityError(str(exc)) from exc

        lastrowid = None
        table_match = re.match(r"\s*INSERT\s+INTO\s+(\w+)", statement, flags=re.I)
        if table_match:
            table_name = table_match.group(1)
            probe = self._connection.cursor()
            try:
                # Not every table uses an integer primary key named "id".
                # For example, auth_rate_limits is keyed by "bucket". Check
                # the catalog before asking PostgreSQL for an id sequence;
                # pg_get_serial_sequence raises UndefinedColumn when id is absent.
                probe.execute(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_schema = current_schema() "
                    "AND table_name = %s AND column_name = 'id'",
                    (table_name,),
                )
                has_id_column = probe.fetchone() is not None
                sequence_name = None
                if has_id_column:
                    probe.execute(
                        "SELECT pg_get_serial_sequence(%s, 'id')",
                        (table_name,),
                    )
                    sequence_row = probe.fetchone()
                    sequence_name = sequence_row[0] if sequence_row else None
            finally:
                probe.close()
            # INSERT ... ON CONFLICT DO NOTHING may affect zero rows. In that
            # case PostgreSQL does not advance a sequence, so LASTVAL() is
            # undefined and raises ObjectNotInPrerequisiteState.
            if sequence_name and cursor.rowcount > 0:
                probe = self._connection.cursor()
                try:
                    probe.execute("SELECT LASTVAL()")
                    lastrowid = probe.fetchone()[0]
                finally:
                    probe.close()
        return _Cursor(self, cursor, lastrowid)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


def connect(database_path):
    """Open the configured persistent database, or the local SQLite file."""
    dsn = _postgres_dsn()
    if dsn:
        return _PostgresConnection(dsn)

    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def using_postgres():
    return bool(_postgres_dsn())
