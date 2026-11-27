import pytest

import backend.database.auth_service as auth_module
from backend.database.auth_service import AuthService
from backend.services import financial_ledger as ledger


@pytest.fixture
def ledger_db(tmp_path, monkeypatch):
    database_path = tmp_path / "phishguard.sqlite3"
    monkeypatch.setattr(auth_module, "DATABASE_PATH", database_path)
    accounts = AuthService()
    accounts.initialize()
    ledger.initialize_ledger()
    user = accounts.create_user("ledger@example.com", "StrongPassword123!")
    return accounts, user["id"]


def _payment(accounts, user_id, tx_ref, amount, currency="RWF", status="successful", provider="palmkash"):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    with accounts.connection() as db:
        cursor = db.execute(
            """INSERT INTO payment_transactions
               (user_id,plan_id,tx_ref,amount,currency,payment_method,status,
                provider,created_at,updated_at)
               VALUES (?, 'pro', ?, ?, ?, 'mobile_money', ?, ?, ?, ?)""",
            (user_id, tx_ref, amount, currency, status, provider, now, now),
        )
    return cursor.lastrowid


def test_only_successful_payment_is_recorded(ledger_db):
    accounts, user_id = ledger_db
    _payment(accounts, user_id, "pending-001", 2500, status="pending")

    with pytest.raises(ledger.LedgerError, match="successful"):
        ledger.record_verified_payment("pending-001")

    assert ledger.get_financial_summary() == {}


def test_verified_payment_is_recorded_once(ledger_db):
    accounts, user_id = ledger_db
    _payment(accounts, user_id, "paid-001", 2500)

    first = ledger.record_verified_payment("paid-001")
    second = ledger.record_verified_payment("paid-001")

    assert first["created"] is True
    assert second["created"] is False
    summary = ledger.get_financial_summary()
    assert summary["RWF"]["gross_collections_minor"] == 2500
    assert summary["RWF"]["net_cash_movement_minor"] == 2500
    assert summary["RWF"]["entry_count"] == 1


def test_reconciliation_backfills_successful_payments_idempotently(ledger_db):
    accounts, user_id = ledger_db
    _payment(accounts, user_id, "paid-002", 19.99, currency="USD")
    _payment(accounts, user_id, "pending-002", 5, currency="USD", status="pending")

    first = ledger.reconcile_successful_payments()
    second = ledger.reconcile_successful_payments()

    assert first == {"checked": 1, "created": 1}
    assert second == {"checked": 0, "created": 0}
    summary = ledger.get_financial_summary()
    assert summary["USD"]["gross_collections_minor"] == 1999
    assert "RWF" not in summary


def test_summary_keeps_currencies_separate(ledger_db):
    accounts, user_id = ledger_db
    _payment(accounts, user_id, "paid-rwf", 2500, currency="RWF")
    _payment(accounts, user_id, "paid-usd", 19.99, currency="USD")

    ledger.reconcile_successful_payments()
    summary = ledger.get_financial_summary()

    assert set(summary) == {"RWF", "USD"}
    assert summary["RWF"]["gross_collections_minor"] == 2500
    assert summary["USD"]["gross_collections_minor"] == 1999


def test_invalid_money_precision_is_rejected(ledger_db):
    accounts, user_id = ledger_db
    _payment(accounts, user_id, "bad-precision", 19.999, currency="USD")

    with pytest.raises(ledger.LedgerError, match="decimal places"):
        ledger.record_verified_payment("bad-precision")


def test_reconciliation_limit_is_validated(ledger_db):
    with pytest.raises(ledger.LedgerError, match="between 1 and 5000"):
        ledger.reconcile_successful_payments(limit=0)



def test_confirmed_provider_fee_reduces_net_without_mixing_currencies(ledger_db):
    accounts, user_id = ledger_db
    payment_id = _payment(accounts, user_id, "paid-with-fee", 2500, currency="RWF")
    ledger.record_verified_payment("paid-with-fee")

    first = ledger.record_confirmed_debit(
        tx_ref="paid-with-fee",
        provider="palmkash",
        entry_type="provider_fee",
        amount=50,
        currency="RWF",
        idempotency_key="provider-fee:palmkash:paid-with-fee",
        payment_transaction_id=payment_id,
        user_id=user_id,
    )
    second = ledger.record_confirmed_debit(
        tx_ref="paid-with-fee",
        provider="palmkash",
        entry_type="provider_fee",
        amount=50,
        currency="RWF",
        idempotency_key="provider-fee:palmkash:paid-with-fee",
        payment_transaction_id=payment_id,
        user_id=user_id,
    )

    assert first["created"] is True
    assert second["created"] is False
    summary = ledger.get_financial_summary()["RWF"]
    assert summary["gross_collections_minor"] == 250000
    assert summary["provider_fees_minor"] == 5000
    assert summary["net_cash_movement_minor"] == 245000


def test_idempotency_key_cannot_be_reused_for_different_amount(ledger_db):
    ledger.record_confirmed_debit(
        tx_ref="payout-001",
        provider="palmkash",
        entry_type="payout",
        amount=1000,
        currency="RWF",
        idempotency_key="payout:001",
    )
    with pytest.raises(ledger.LedgerError, match="different ledger entry"):
        ledger.record_confirmed_debit(
            tx_ref="payout-001",
            provider="palmkash",
            entry_type="payout",
            amount=2000,
            currency="RWF",
            idempotency_key="payout:001",
        )
