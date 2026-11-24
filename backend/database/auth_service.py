import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from backend.config import DATABASE_PATH

EMAIL_RE = re.compile(r"^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")


class AuthService:
    @contextmanager
    def connection(self):
        Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(DATABASE_PATH, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
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
            db.execute("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                session_version INTEGER NOT NULL DEFAULT 0
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS auth_rate_limits (
                bucket TEXT PRIMARY KEY,
                window_started REAL NOT NULL,
                attempts INTEGER NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                plan_id TEXT NOT NULL DEFAULT 'free',
                status TEXT NOT NULL DEFAULT 'active',
                billing_interval_months INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                current_period_end TEXT,
                provider TEXT,
                provider_subscription_id TEXT UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id, status)")

    def allow_auth_attempt(self, bucket, limit=8, window_seconds=900):
        now = time.time()
        with self.connection() as db:
            row = db.execute("SELECT window_started, attempts FROM auth_rate_limits WHERE bucket=?", (bucket,)).fetchone()
            if row is None or now - row["window_started"] >= window_seconds:
                db.execute("""INSERT INTO auth_rate_limits(bucket, window_started, attempts)
                    VALUES (?, ?, 1) ON CONFLICT(bucket) DO UPDATE SET
                    window_started=excluded.window_started, attempts=1""", (bucket, now))
                return True
            if row["attempts"] >= limit:
                return False
            db.execute("UPDATE auth_rate_limits SET attempts=attempts+1 WHERE bucket=?", (bucket,))
            return True

    def create_user(self, email, password):
        email = (email or "").strip().lower()
        if len(email) > 254 or not EMAIL_RE.match(email):
            raise ValueError("Enter a valid email address.")
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            raise ValueError("Password must contain 12 to 128 characters.")
        password_hash = generate_password_hash(password, method="scrypt")
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self.connection() as db:
                cur = db.execute("INSERT INTO users(email,password_hash,created_at) VALUES (?,?,?)", (email,password_hash,now))
                user_id = cur.lastrowid
                db.execute("""INSERT INTO subscriptions(user_id,plan_id,status,billing_interval_months,
                    started_at,created_at,updated_at) VALUES (?,'free','active',0,?,?,?)""", (user_id,now,now,now))
            return {"id": user_id, "email": email, "session_version": 0}
        except sqlite3.IntegrityError as exc:
            raise ValueError("An account with this email already exists.") from exc

    def authenticate(self, email, password):
        email = (email or "").strip().lower()
        with self.connection() as db:
            row = db.execute("SELECT id,email,password_hash,is_active,session_version FROM users WHERE email=?", (email,)).fetchone()
        if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password or ""):
            return None
        return {"id": row["id"], "email": row["email"], "session_version": row["session_version"]}

    def get_user(self, user_id):
        with self.connection() as db:
            row = db.execute("SELECT id,email,created_at,session_version FROM users WHERE id=? AND is_active=1", (user_id,)).fetchone()
        return dict(row) if row else None


auth_service = AuthService()
