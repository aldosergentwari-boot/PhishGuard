import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import generate_password_hash, check_password_hash

from backend.config import DATABASE_PATH


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class AuthService:
    """SQLite-backed account storage sharing the configured persistent DB."""

    @contextmanager
    def connection(self):
        Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(DATABASE_PATH, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def initialize(self):
        with self.connection() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS auth_rate_limits (
                    bucket TEXT PRIMARY KEY,
                    window_started REAL NOT NULL,
                    attempts INTEGER NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at REAL NOT NULL,
                    used_at REAL
                )
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "session_version" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")

    def allow_auth_attempt(self, bucket, limit=8, window_seconds=900):
        """Allow a bounded number of auth attempts per opaque bucket/window."""
        now = time.time()
        with self.connection() as db:
            row = db.execute(
                "SELECT window_started, attempts FROM auth_rate_limits WHERE bucket = ?",
                (bucket,)
            ).fetchone()
            if row is None or now - row["window_started"] >= window_seconds:
                db.execute(
                    """INSERT INTO auth_rate_limits(bucket, window_started, attempts)
                       VALUES (?, ?, 1)
                       ON CONFLICT(bucket) DO UPDATE SET
                       window_started=excluded.window_started, attempts=1""",
                    (bucket, now),
                )
                return True
            if row["attempts"] >= limit:
                return False
            db.execute(
                "UPDATE auth_rate_limits SET attempts = attempts + 1 WHERE bucket = ?",
                (bucket,),
            )
            return True

    def create_user(self, email, password):
        email = (email or "").strip().lower()
        if len(email) > 254 or not EMAIL_RE.match(email):
            raise ValueError("Enter a valid email address.")
        if not isinstance(password, str) or len(password) < 12 or len(password) > 128:
            raise ValueError("Password must contain 12 to 128 characters.")
        password_hash = generate_password_hash(password, method="scrypt")
        try:
            with self.connection() as db:
                cur = db.execute(
                    "INSERT INTO users(email, password_hash, created_at) VALUES (?, ?, ?)",
                    (email, password_hash, datetime.now(timezone.utc).isoformat())
                )
                return {"id": cur.lastrowid, "email": email}
        except sqlite3.IntegrityError:
            raise ValueError("An account with this email already exists.")

    def authenticate(self, email, password):
        email = (email or "").strip().lower()
        with self.connection() as db:
            row = db.execute(
                "SELECT id, email, password_hash, is_active, session_version FROM users WHERE email = ?",
                (email,)
            ).fetchone()
        if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password or ""):
            return None
        return {"id": row["id"], "email": row["email"], "session_version": row["session_version"]}

    def create_password_reset(self, email, token_hash, expires_at):
        email = (email or "").strip().lower()
        with self.connection() as db:
            row = db.execute(
                "SELECT id FROM users WHERE email = ? AND is_active = 1", (email,)
            ).fetchone()
            if not row:
                return False
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (row["id"],))
            db.execute(
                "INSERT INTO password_reset_tokens(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, row["id"], expires_at),
            )
            return True

    def discard_password_reset(self, token_hash):
        """Remove a reset token when its delivery could not be completed."""
        with self.connection() as db:
            db.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL",
                (token_hash,),
            )

    def consume_password_reset(self, token_hash, new_password):
        if not isinstance(new_password, str) or not 12 <= len(new_password) <= 128:
            raise ValueError("Password must contain 12 to 128 characters.")
        password_hash = generate_password_hash(new_password, method="scrypt")
        now = time.time()
        with self.connection() as db:
            row = db.execute(
                """SELECT user_id FROM password_reset_tokens
                   WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?""",
                (token_hash, now),
            ).fetchone()
            if not row:
                return False
            db.execute("UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?", (password_hash, row["user_id"]))
            db.execute("UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ?", (now, token_hash))
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ? AND token_hash != ?",
                       (row["user_id"], token_hash))
            return True

    def get_user(self, user_id):
        with self.connection() as db:
            row = db.execute(
                "SELECT id, email, created_at, session_version FROM users WHERE id = ? AND is_active = 1",
                (user_id,)
            ).fetchone()
        return dict(row) if row else None


auth_service = AuthService()
