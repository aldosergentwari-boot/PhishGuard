from backend.database.connection import _postgres_sql


def test_postgres_adapter_translates_sqlite_autoincrement_and_collation():
    statement = _postgres_sql("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE
        )
    """)
    assert "BIGSERIAL PRIMARY KEY" in statement
    assert "COLLATE NOCASE" not in statement


def test_postgres_adapter_translates_placeholders_and_ignore_insert():
    statement = _postgres_sql(
        "INSERT OR IGNORE INTO scan_usage(owner_id, scanned_at) VALUES (?, ?)"
    )
    assert "INSERT INTO scan_usage" in statement
    assert "VALUES (%s, %s)" in statement
    assert statement.endswith("ON CONFLICT DO NOTHING")


def test_postgres_adapter_translates_sqlite_table_introspection():
    statement = _postgres_sql("PRAGMA table_info(users)")
    assert "information_schema.columns" in statement
    assert "table_name = 'users'" in statement


def test_postgres_adapter_uses_transaction_lock_for_atomic_scan_limits():
    assert _postgres_sql("BEGIN IMMEDIATE") == (
        "LOCK TABLE auth_rate_limits IN SHARE ROW EXCLUSIVE MODE"
    )
