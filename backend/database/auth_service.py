import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from backend.config import DATABASE_PATH

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


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
                session_version INTEGER NOT NULL DEFAULT 0,
                email_verified INTEGER NOT NULL DEFAULT 0,
                email_verified_at TEXT
            )""")
            user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "session_version" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
            if "email_verified" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
            if "email_verified_at" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN email_verified_at TEXT")
            db.execute("""CREATE TABLE IF NOT EXISTS account_email_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                purpose TEXT NOT NULL CHECK(purpose IN ('verify_email', 'password_reset')),
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_account_email_tokens_user_purpose ON account_email_tokens(user_id, purpose, used_at)")
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
            db.execute("""CREATE TABLE IF NOT EXISTS payment_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                plan_id TEXT NOT NULL,
                tx_ref TEXT NOT NULL UNIQUE,
                amount REAL NOT NULL,
                currency TEXT NOT NULL,
                payment_method TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                provider_transaction_id TEXT UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_payment_transactions_user ON payment_transactions(user_id, created_at)")

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

    def allow_scan_attempt(self, bucket, limit=30, window_seconds=60):
        """Atomically enforce a fixed-window scan limit across app workers."""
        now = time.time()
        with self.connection() as db:
            # Serialize updates so concurrent requests cannot all pass the limit.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT window_started, attempts FROM auth_rate_limits WHERE bucket=?",
                (bucket,),
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
                "UPDATE auth_rate_limits SET attempts=attempts+1 WHERE bucket=?",
                (bucket,),
            )
            return True

    def create_user(self, email, password):
        if not isinstance(email, str):
            raise ValueError("Enter a valid email address.")
        email = email.strip().lower()
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
            return {"id": user_id, "email": email, "session_version": 0, "email_verified": False}
        except sqlite3.IntegrityError as exc:
            raise ValueError("An account with this email already exists.") from exc

    def authenticate(self, email, password):
        if not isinstance(email, str) or not isinstance(password, str):
            return None
        email = email.strip().lower()
        with self.connection() as db:
            row = db.execute("SELECT id,email,password_hash,is_active,session_version,email_verified FROM users WHERE email=?", (email,)).fetchone()
        if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password or ""):
            return None
        return {"id": row["id"], "email": row["email"], "session_version": row["session_version"], "email_verified": bool(row["email_verified"])}

    def get_user(self, user_id):
        with self.connection() as db:
            row = db.execute("SELECT id,email,created_at,session_version,email_verified,email_verified_at FROM users WHERE id=? AND is_active=1", (user_id,)).fetchone()
        return dict(row) if row else None

    def create_email_token(self, user_id, purpose, token_hash, expires_at):
        if purpose not in ("verify_email", "password_reset"):
            raise ValueError("Unsupported token purpose.")
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as db:
            db.execute(
                "UPDATE account_email_tokens SET used_at=? WHERE user_id=? AND purpose=? AND used_at IS NULL",
                (now, user_id, purpose),
            )
            db.execute(
                """INSERT INTO account_email_tokens(user_id,purpose,token_hash,expires_at,created_at)
                   VALUES (?,?,?,?,?)""",
                (user_id, purpose, token_hash, expires_at, now),
            )

    def verify_email_token(self, token_hash):
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as db:
            row = db.execute(
                """SELECT id,user_id FROM account_email_tokens
                   WHERE purpose='verify_email' AND token_hash=? AND used_at IS NULL AND expires_at>?""",
                (token_hash, now),
            ).fetchone()
            if row is None:
                return False
            changed = db.execute(
                "UPDATE account_email_tokens SET used_at=? WHERE id=? AND used_at IS NULL",
                (now, row["id"]),
            ).rowcount
            if not changed:
                return False
            db.execute(
                "UPDATE users SET email_verified=1,email_verified_at=? WHERE id=?",
                (now, row["user_id"]),
            )
            return True

    def reset_password_with_token(self, token_hash, new_password_hash):
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as db:
            row = db.execute(
                """SELECT id,user_id FROM account_email_tokens
                   WHERE purpose='password_reset' AND token_hash=? AND used_at IS NULL AND expires_at>?""",
                (token_hash, now),
            ).fetchone()
            if row is None:
                return False
            changed = db.execute(
                "UPDATE account_email_tokens SET used_at=? WHERE id=? AND used_at IS NULL",
                (now, row["id"]),
            ).rowcount
            if not changed:
                return False
            db.execute(
                "UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?",
                (new_password_hash, row["user_id"]),
            )
            db.execute(
                "UPDATE account_email_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL",
                (now, row["user_id"]),
            )
            return True


auth_service = AuthService()
