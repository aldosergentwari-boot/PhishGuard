import sqlite3
from datetime import datetime, timezone

import backend.database.auth_service as auth_module
from backend.app import create_app
from backend.database.auth_service import auth_service


OWNER_EMAIL = "owner-management@example.com"
OWNER_PASSWORD = "A-Strong-Owner-Password-123!"


def owner_client(monkeypatch, tmp_path):
    monkeypatch.setattr(auth_module, "DATABASE_PATH", tmp_path / "owner-management.sqlite3")
    monkeypatch.setenv("PHISHGUARD_OWNER_EMAIL", OWNER_EMAIL)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-management-tests")
    app = create_app()
    owner = auth_service.create_user(OWNER_EMAIL, OWNER_PASSWORD)
    with auth_service.connection() as db:
        db.execute("UPDATE users SET email_verified=1 WHERE id=?", (owner["id"],))
    client = app.test_client()
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    assert client.post("/api/admin/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD},
                       headers={"X-CSRF-Token": csrf}).status_code == 200
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    return app, client, owner, csrf


def test_management_user_search_suspend_and_audit(monkeypatch, tmp_path):
    app, client, owner, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("customer@example.com", "A-Strong-Customer-Password-123!")
    listing = client.get("/api/admin/management/users?q=customer")
    assert listing.status_code == 200
    assert listing.get_json()["total"] == 1

    response = client.post(f"/api/admin/management/users/{customer['id']}/status",
        json={"active": False, "reason": "Customer requested account suspension"},
        headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    with auth_service.connection() as db:
        row = db.execute("SELECT is_active,session_version FROM users WHERE id=?", (customer["id"],)).fetchone()
        assert row["is_active"] == 0
        assert row["session_version"] == 1
    events = client.get("/api/admin/management/audit").get_json()["events"]
    assert events[0]["action"] == "user.suspended"


def test_management_plan_change_and_notification(monkeypatch, tmp_path):
    _, client, _, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("plan-user@example.com", "A-Strong-Customer-Password-123!")
    response = client.post(f"/api/admin/management/users/{customer['id']}/plan",
        json={"plan_id": "pro", "reason": "Approved manual support upgrade", "payment_confirmed": True, "payment_reference": "TEST-REF-100"},
        headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.get_json()["plan_id"] == "pro"
    assert client.get("/api/admin/management/analytics").status_code == 200
    notification = client.post("/api/admin/management/notifications",
        json={"user_id": customer["id"], "title": "Plan update", "message": "Your plan was updated."},
        headers={"X-CSRF-Token": csrf})
    assert notification.status_code == 200
    items = client.get(f"/api/admin/management/notifications?user_id={customer['id']}")
    assert items.status_code == 200
    assert items.get_json()["notifications"][0]["title"] == "Plan update"


def test_admin_can_set_and_reset_monthly_scan_limit(monkeypatch, tmp_path):
    from backend.services.plan_service import get_usage

    _, client, owner, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("limited-user@example.com", "A-Strong-Customer-Password-123!")
    headers = {"X-CSRF-Token": csrf}

    listing = client.get("/api/admin/management/users?q=limited-user").get_json()
    row = listing["users"][0]
    assert row["scan_usage"]["scans_limit"] == 50
    assert row["scan_usage"]["admin_limit_override"] is None

    changed = client.post(
        f"/api/admin/management/users/{customer['id']}/scan-limit",
        json={"monthly_limit": 12, "reason": "Temporary support restriction"},
        headers=headers,
    )
    assert changed.status_code == 200
    usage = get_usage(f"account:{customer['id']}", "free")
    assert usage["scans_limit"] == 12
    assert usage["scans_remaining"] == 12
    assert usage["admin_limit_override"] == 12

    auth_service.grant_admin_scans(
        customer["id"], 5, "Additional approved credits",
        "2099-12-31T23:59:59+00:00",
    )
    assert get_usage(f"account:{customer['id']}", "free")["scans_limit"] == 17

    reset = client.post(
        f"/api/admin/management/users/{customer['id']}/scan-limit",
        json={"monthly_limit": None, "reason": "Restore standard plan allowance"},
        headers=headers,
    )
    assert reset.status_code == 200
    restored = get_usage(f"account:{customer['id']}", "free")
    assert restored["admin_limit_override"] is None
    assert restored["scans_limit"] == 55

    owner_block = client.post(
        f"/api/admin/management/users/{owner['id']}/scan-limit",
        json={"monthly_limit": 0, "reason": "Should not affect owner"},
        headers=headers,
    )
    assert owner_block.status_code == 400


def test_management_mutations_require_csrf_and_owner(monkeypatch, tmp_path):
    _, client, _, _ = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("csrf-user@example.com", "A-Strong-Customer-Password-123!")
    response = client.post(f"/api/admin/management/users/{customer['id']}/status",
        json={"active": False, "reason": "Support request"})
    assert response.status_code == 403

def test_owner_is_not_counted_as_customer_and_admin_audit_is_preserved(monkeypatch, tmp_path):
    _, client, owner, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("listed-customer@example.com", "A-Strong-Customer-Password-123!")
    management_users = client.get("/api/admin/management/users").get_json()
    assert management_users["total"] == 1
    assert [row["id"] for row in management_users["users"]] == [customer["id"]]
    legacy_users = client.get("/api/admin/users").get_json()
    assert legacy_users["total"] == 1
    assert [row["id"] for row in legacy_users["users"]] == [customer["id"]]
    analytics = client.get("/api/admin/management/analytics").get_json()["analytics"]
    assert analytics["total_users"] == 1
    assert analytics["active_users"] == 1
    blocked = client.post(f"/api/admin/management/users/{owner['id']}/status",
        json={"active": False, "reason": "Do not suspend owner"},
        headers={"X-CSRF-Token": csrf})
    assert blocked.status_code == 400
    action = client.post(f"/api/admin/management/users/{customer['id']}/status",
        json={"active": False, "reason": "Customer requested suspension"},
        headers={"X-CSRF-Token": csrf})
    assert action.status_code == 200
    audit = client.get("/api/admin/management/audit").get_json()["events"]
    assert audit[0]["actor_user_id"] == owner["id"]
    assert audit[0]["actor_email"] == OWNER_EMAIL
    with auth_service.connection() as db:
        owner_row = db.execute("SELECT is_active,email_verified FROM users WHERE id=?", (owner["id"],)).fetchone()
        assert owner_row["is_active"] == 1 and owner_row["email_verified"] == 1


def test_plan_override_replaces_previous_active_subscription(monkeypatch, tmp_path):
    from backend.services.plan_service import get_account_plan

    _, client, _, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("plan-replace@example.com", "A-Strong-Customer-Password-123!")
    headers = {"X-CSRF-Token": csrf}
    first = client.post(f"/api/admin/management/users/{customer['id']}/plan",
        json={"plan_id": "pro", "reason": "First approved upgrade", "payment_confirmed": True, "payment_reference": "TEST-REF-101"}, headers=headers)
    assert first.status_code == 200
    second = client.post(f"/api/admin/management/users/{customer['id']}/plan",
        json={"plan_id": "business", "reason": "Approved plan replacement", "payment_confirmed": True, "payment_reference": "TEST-REF-102"}, headers=headers)
    assert second.status_code == 200
    with auth_service.connection() as db:
        rows = db.execute("SELECT plan_id,status FROM subscriptions WHERE user_id=? ORDER BY id", (customer["id"],)).fetchall()
    assert rows[-1]["plan_id"] == "business" and rows[-1]["status"] == "active"
    assert all(row["status"] == "cancelled" for row in rows[:-1])
    assert sum(row["status"] == "active" for row in rows) == 1
    assert get_account_plan(customer["id"])["plan_id"] == "business"
    assert client.get("/api/admin/overview").get_json()["overview"]["active_subscriptions"] == 1


def test_customer_can_only_read_their_own_admin_notifications(monkeypatch, tmp_path):
    app, owner_client_instance, _, owner_csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("notice-customer@example.com", "A-Strong-Customer-Password-123!")
    response = owner_client_instance.post("/api/admin/management/notifications",
        json={"user_id": customer["id"], "title": "Security update", "message": "Your account settings were updated.", "category": "security"},
        headers={"X-CSRF-Token": owner_csrf})
    assert response.status_code == 200
    assert owner_client_instance.get("/api/account/notifications").status_code == 401

    customer_client = app.test_client()
    csrf = customer_client.get("/api/auth/csrf").get_json()["csrf_token"]
    login = customer_client.post("/api/auth/login",
        json={"email": "notice-customer@example.com", "password": "A-Strong-Customer-Password-123!"},
        headers={"X-CSRF-Token": csrf})
    assert login.status_code == 200
    csrf = customer_client.get("/api/auth/csrf").get_json()["csrf_token"]
    notices = customer_client.get("/api/account/notifications")
    assert notices.status_code == 200
    body = notices.get_json()
    payload = body["notifications"]
    assert len(payload) == 1
    assert payload[0]["title"] == "Security update"
    assert payload[0]["read_at"] is None
    assert body["unread_count"] == 1
    assert customer_client.get("/api/account/notifications").get_json()["unread_count"] == 1
    marked = customer_client.post(
        f"/api/account/notifications/{payload[0]['id']}/read",
        headers={"X-CSRF-Token": csrf},
    )
    assert marked.status_code == 200
    assert marked.get_json()["unread_count"] == 0
    assert customer_client.get("/api/account/notifications").get_json()["notifications"][0]["read_at"]



def test_owner_can_logout_and_sign_in_repeatedly_with_fresh_csrf(monkeypatch, tmp_path):
    _, client, _, csrf = owner_client(monkeypatch, tmp_path)

    for _ in range(3):
        logged_out = client.post(
            "/api/admin/logout",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert logged_out.status_code == 200
        assert client.get("/admin/login").status_code == 200

        csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
        logged_in = client.post(
            "/api/admin/login",
            json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD},
            headers={"X-CSRF-Token": csrf},
        )
        assert logged_in.status_code == 200
        csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]


def test_owner_password_reset_request_creates_supported_single_use_token(
    monkeypatch, tmp_path
):
    import hashlib
    from datetime import timedelta
    from backend.routes import admin as admin_routes

    _, client, owner, csrf = owner_client(monkeypatch, tmp_path)
    sent = {}

    def capture_reset_email(email, raw_token):
        sent["email"] = email
        sent["token"] = raw_token

    monkeypatch.setattr(
        admin_routes.email_service, "send_admin_password_reset_email", capture_reset_email
    )
    response = client.post(
        "/api/admin/password-reset/request",
        json={"email": OWNER_EMAIL},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    assert sent["email"] == OWNER_EMAIL

    digest = hashlib.sha256(sent["token"].encode("utf-8")).hexdigest()
    with auth_service.connection() as db:
        row = db.execute(
            "SELECT purpose,token_hash,used_at FROM account_email_tokens WHERE user_id=?",
            (owner["id"],),
        ).fetchone()
    assert row["purpose"] == "admin_password_reset"
    assert row["token_hash"] == digest
    assert row["used_at"] is None

    reset_csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    changed = client.post(
        "/api/admin/password-reset/confirm",
        json={"token": sent["token"], "password": "A-New-Strong-Owner-Password-456!"},
        headers={"X-CSRF-Token": reset_csrf},
    )
    assert changed.status_code == 200
    assert client.post(
        "/api/admin/password-reset/confirm",
        json={"token": sent["token"], "password": "Another-Strong-Password-789!"},
        headers={"X-CSRF-Token": client.get("/api/auth/csrf").get_json()["csrf_token"]},
    ).status_code == 400



def test_existing_database_migrates_email_token_constraint(monkeypatch, tmp_path):
    database_path = tmp_path / "legacy-owner-reset.sqlite3"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", database_path)

    with sqlite3.connect(database_path) as db:
        db.execute("""CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )""")
        db.execute(
            "INSERT INTO users(email,password_hash,created_at) VALUES (?,?,?)",
            ("legacy-owner@example.com", "hash", datetime.now(timezone.utc).isoformat()),
        )
        db.execute("""CREATE TABLE account_email_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            purpose TEXT NOT NULL CHECK(purpose IN ('verify_email', 'password_reset')),
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL
        )""")
        db.execute(
            """INSERT INTO account_email_tokens
               (user_id,purpose,token_hash,expires_at,created_at)
               VALUES (1,'password_reset','legacy-hash','2099-01-01T00:00:00+00:00',?)""",
            (datetime.now(timezone.utc).isoformat(),),
        )

    auth_service.initialize()
    with auth_service.connection() as db:
        legacy = db.execute(
            "SELECT purpose,token_hash FROM account_email_tokens WHERE token_hash='legacy-hash'"
        ).fetchone()
        assert legacy["purpose"] == "password_reset"
        assert legacy["token_hash"] == "legacy-hash"
        db.execute(
            """INSERT INTO account_email_tokens
               (user_id,purpose,token_hash,expires_at,created_at)
               VALUES (1,'admin_password_reset','admin-hash','2099-01-01T00:00:00+00:00',?)""",
            (datetime.now(timezone.utc).isoformat(),),
        )



def test_owner_session_survives_dashboard_reloads_and_management_requests(monkeypatch, tmp_path):
    _, client, _, _ = owner_client(monkeypatch, tmp_path)

    for _ in range(4):
        assert client.get("/admin").status_code == 200
        assert client.get("/api/admin/management/analytics").status_code == 200
        with client.session_transaction() as session:
            assert session.permanent is True
            assert session.get("phishguard_admin_user_id") is not None


def test_financial_summary_is_owner_only_and_currency_separated(monkeypatch, tmp_path):
    from backend.services.financial_ledger import record_verified_payment

    app, client, owner, _ = owner_client(monkeypatch, tmp_path)
    anonymous = app.test_client()
    assert anonymous.get("/api/admin/management/financial-summary").status_code == 401

    customer = auth_service.create_user(
        "finance-customer@example.com", "A-Strong-Customer-Password-123!"
    )
    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        db.execute(
            """INSERT INTO payment_transactions
               (user_id,plan_id,tx_ref,amount,currency,payment_method,status,
                provider,created_at,updated_at)
               VALUES (?, 'pro', 'finance-paid-001', 2500, 'RWF',
                       'mobile_money', 'successful', 'palmkash', ?, ?)""",
            (customer["id"], now, now),
        )
    record_verified_payment("finance-paid-001")

    response = client.get("/api/admin/management/financial-summary")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["summary"]["RWF"]["gross_collections_minor"] == 2500
    assert payload["total"] == 1
    assert payload["entries"][0]["tx_ref"] == "finance-paid-001"


def test_financial_reconciliation_requires_owner_csrf_and_is_idempotent(monkeypatch, tmp_path):
    _, client, _, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user(
        "reconcile-customer@example.com", "A-Strong-Customer-Password-123!"
    )
    now = datetime.now(timezone.utc).isoformat()
    with auth_service.connection() as db:
        db.execute(
            """INSERT INTO payment_transactions
               (user_id,plan_id,tx_ref,amount,currency,payment_method,status,
                provider,created_at,updated_at)
               VALUES (?, 'pro', 'reconcile-paid-001', 1250, 'RWF',
                       'mobile_money', 'successful', 'palmkash', ?, ?)""",
            (customer["id"], now, now),
        )

    denied = client.post("/api/admin/management/financial-reconcile", json={})
    assert denied.status_code == 403

    headers = {"X-CSRF-Token": csrf}
    first = client.post(
        "/api/admin/management/financial-reconcile",
        json={"limit": 100},
        headers=headers,
    )
    second = client.post(
        "/api/admin/management/financial-reconcile",
        json={"limit": 100},
        headers=headers,
    )
    assert first.status_code == 200
    assert first.get_json()["created"] == 1
    assert second.status_code == 200
    assert second.get_json()["created"] == 0


def test_admin_cannot_activate_paid_plan_without_payment_confirmation(monkeypatch, tmp_path):
    _, client, _, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("unpaid-user@example.com", "A-Strong-Customer-Password-123!")
    response = client.post(
        f"/api/admin/management/users/{customer['id']}/plan",
        json={"plan_id": "pro", "reason": "Upgrade without payment"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 400
    from backend.services.plan_service import get_account_plan
    assert get_account_plan(customer["id"])["plan_id"] == "free"


def test_customer_can_mark_all_notifications_read(monkeypatch, tmp_path):
    app, owner_client_instance, _, owner_csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user("notice-all@example.com", "A-Strong-Customer-Password-123!")
    for title in ("First update", "Second update"):
        response = owner_client_instance.post(
            "/api/admin/management/notifications",
            json={"user_id": customer["id"], "title": title, "message": "An account update."},
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert response.status_code == 200

    customer_client = app.test_client()
    csrf_token = customer_client.get("/api/auth/csrf").get_json()["csrf_token"]
    assert customer_client.post(
        "/api/auth/login",
        json={"email": "notice-all@example.com", "password": "A-Strong-Customer-Password-123!"},
        headers={"X-CSRF-Token": csrf_token},
    ).status_code == 200
    assert customer_client.get("/api/account/notifications").get_json()["unread_count"] == 2
    csrf_token = customer_client.get("/api/auth/csrf").get_json()["csrf_token"]
    response = customer_client.post(
        "/api/account/notifications/read-all",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert response.status_code == 200
    assert response.get_json()["unread_count"] == 0



def test_owner_and_customer_sessions_coexist_and_logout_independently(monkeypatch, tmp_path):
    _, client, owner, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user(
        "same-browser-customer@example.com", "A-Strong-Customer-Password-123!"
    )

    # Customer login in the same browser must not replace the owner identity.
    customer_login = client.post(
        "/api/auth/login",
        json={
            "email": "same-browser-customer@example.com",
            "password": "A-Strong-Customer-Password-123!",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert customer_login.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is True
    assert client.get("/admin").status_code == 200
    with client.session_transaction() as session:
        assert session["account_id"] == customer["id"]
        assert session["phishguard_admin_user_id"] == owner["id"]
        assert session.permanent is True

    # Customer logout removes only customer credentials; owner remains signed in.
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    customer_logout = client.post(
        "/api/auth/logout", json={}, headers={"X-CSRF-Token": csrf}
    )
    assert customer_logout.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is False
    assert client.get("/admin").status_code == 200

    # Sign the customer in again, then log out the owner only.
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    assert client.post(
        "/api/auth/login",
        json={
            "email": "same-browser-customer@example.com",
            "password": "A-Strong-Customer-Password-123!",
        },
        headers={"X-CSRF-Token": csrf},
    ).status_code == 200
    csrf = client.get("/api/auth/csrf").get_json()["csrf_token"]
    owner_logout = client.post(
        "/api/admin/logout", json={}, headers={"X-CSRF-Token": csrf}
    )
    assert owner_logout.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is True
    assert client.get("/admin").status_code == 302

    with client.session_transaction() as session:
        assert session["account_id"] == customer["id"]
        assert "phishguard_admin_user_id" not in session
        assert session.permanent is True


def test_invalid_customer_session_does_not_clear_owner_session(monkeypatch, tmp_path):
    _, client, owner, csrf = owner_client(monkeypatch, tmp_path)
    customer = auth_service.create_user(
        "stale-session-customer@example.com", "A-Strong-Customer-Password-123!"
    )
    login = client.post(
        "/api/auth/login",
        json={
            "email": "stale-session-customer@example.com",
            "password": "A-Strong-Customer-Password-123!",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert login.status_code == 200

    with auth_service.connection() as db:
        db.execute(
            "UPDATE users SET session_version=session_version+1 WHERE id=?",
            (customer["id"],),
        )

    assert client.get("/api/auth/me").get_json()["authenticated"] is False
    assert client.get("/admin").status_code == 200
    with client.session_transaction() as session:
        assert "account_id" not in session
        assert session["phishguard_admin_user_id"] == owner["id"]
