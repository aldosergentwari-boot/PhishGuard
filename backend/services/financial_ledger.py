"""Immutable, currency-aware financial ledger for verified PhishGuard payments.

The ledger records only server-verified successful collections. Provider fees,
refunds and payouts are separate debit entries and must be recorded only after
their provider-side outcome has been confirmed.
"""
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from backend.database.auth_service import auth_service

_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_CURRENCY_EXPONENTS = {"JPY": 0, "KWD": 3, "BHD": 3}


class LedgerError(ValueError):
    """Raised when a financial ledger entry is invalid or inconsistent."""


def _to_minor_units(amount, currency):
    try:
        value = Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise LedgerError("Amount must be a valid decimal number.") from exc
    if not value.is_finite() or value <= 0:
        raise LedgerError("Amount must be greater than zero.")
    exponent = _CURRENCY_EXPONENTS.get(currency, 2)
    scale = Decimal(10) ** exponent
    minor = value * scale
    if minor != minor.to_integral_value():
        raise LedgerError(f"Amount has too many decimal places for {currency}.")
    return int(minor)


def initialize_ledger():
    """Create ledger storage and indexes without changing existing payment rows."""
    with auth_service.connection() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS financial_ledger_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_transaction_id INTEGER
                    REFERENCES payment_transactions(id) ON DELETE RESTRICT,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                provider TEXT NOT NULL,
                tx_ref TEXT NOT NULL,
                provider_transaction_id TEXT,
                entry_type TEXT NOT NULL CHECK (
                    entry_type IN ('payment', 'refund', 'payout', 'provider_fee', 'adjustment')
                ),
                direction TEXT NOT NULL CHECK (direction IN ('credit', 'debit')),
                amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
                currency TEXT NOT NULL CHECK (length(currency) = 3),
                idempotency_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                notes TEXT,
                UNIQUE(payment_transaction_id, entry_type)
            )"""
        )
        db.execute(
            """CREATE INDEX IF NOT EXISTS idx_financial_ledger_currency_time
               ON financial_ledger_entries(currency, created_at)"""
        )
        db.execute(
            """CREATE INDEX IF NOT EXISTS idx_financial_ledger_tx_ref
               ON financial_ledger_entries(tx_ref)"""
        )
        db.execute(
            """CREATE INDEX IF NOT EXISTS idx_financial_ledger_user_time
               ON financial_ledger_entries(user_id, created_at)"""
        )


def record_verified_payment(tx_ref):
    """Record one gross collection after its payment row is marked successful.

    Repeated calls are safe. The payment transaction row remains the source of
    truth for amount, currency, user and provider.
    """
    if not isinstance(tx_ref, str) or not tx_ref.strip():
        raise LedgerError("A transaction reference is required.")
    tx_ref = tx_ref.strip()
    with auth_service.connection() as db:
        payment = db.execute(
            """SELECT id,user_id,tx_ref,amount,currency,provider,
                      provider_transaction_id,status
               FROM payment_transactions WHERE tx_ref=?""",
            (tx_ref,),
        ).fetchone()
        if payment is None:
            raise LedgerError("Payment transaction was not found.")
        if payment["status"] != "successful":
            raise LedgerError("Only verified successful payments can enter the ledger.")

        currency = str(payment["currency"] or "").upper()
        if not _CURRENCY_RE.fullmatch(currency):
            raise LedgerError("Payment currency must be a three-letter ISO code.")
        amount_minor = _to_minor_units(payment["amount"], currency)
        provider = str(payment["provider"] or "").strip().lower()
        if not provider:
            raise LedgerError("Payment provider is missing.")

        key = f"payment:{provider}:{tx_ref}"
        existing = db.execute(
            "SELECT * FROM financial_ledger_entries WHERE idempotency_key=?",
            (key,),
        ).fetchone()
        if existing:
            expected = (
                payment["id"], payment["user_id"], provider, tx_ref,
                amount_minor, currency,
            )
            actual = (
                existing["payment_transaction_id"], existing["user_id"],
                existing["provider"], existing["tx_ref"],
                existing["amount_minor"], existing["currency"],
            )
            if actual != expected:
                raise LedgerError("Existing ledger entry does not match its payment.")
            return {"created": False, "entry_id": existing["id"]}

        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            """INSERT INTO financial_ledger_entries
               (payment_transaction_id,user_id,provider,tx_ref,
                provider_transaction_id,entry_type,direction,amount_minor,
                currency,idempotency_key,created_at)
               VALUES (?,?,?,?,?,'payment','credit',?,?,?,?)""",
            (
                payment["id"], payment["user_id"], provider, tx_ref,
                payment["provider_transaction_id"], amount_minor, currency,
                key, now,
            ),
        )
        return {"created": True, "entry_id": cursor.lastrowid}


def reconcile_successful_payments(limit=500):
    """Backfill successful payment rows missing their idempotent ledger entry."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 5000:
        raise LedgerError("Reconciliation limit must be between 1 and 5000.")
    with auth_service.connection() as db:
        rows = db.execute(
            """SELECT p.tx_ref FROM payment_transactions p
               LEFT JOIN financial_ledger_entries l
                 ON l.payment_transaction_id=p.id AND l.entry_type='payment'
               WHERE p.status='successful' AND l.id IS NULL
               ORDER BY p.id ASC LIMIT ?""",
            (limit,),
        ).fetchall()
    created = 0
    for row in rows:
        result = record_verified_payment(row["tx_ref"])
        created += int(result["created"])
    return {"checked": len(rows), "created": created}


def get_financial_summary():
    """Return gross collections and confirmed debits, grouped by currency."""
    with auth_service.connection() as db:
        rows = db.execute(
            """SELECT currency,
                 SUM(CASE WHEN entry_type='payment' AND direction='credit'
                          THEN amount_minor ELSE 0 END) AS gross_collections_minor,
                 SUM(CASE WHEN entry_type='refund' AND direction='debit'
                          THEN amount_minor ELSE 0 END) AS refunds_minor,
                 SUM(CASE WHEN entry_type='payout' AND direction='debit'
                          THEN amount_minor ELSE 0 END) AS payouts_minor,
                 SUM(CASE WHEN entry_type='provider_fee' AND direction='debit'
                          THEN amount_minor ELSE 0 END) AS provider_fees_minor,
                 SUM(CASE WHEN direction='credit' THEN amount_minor
                          ELSE -amount_minor END) AS net_cash_movement_minor,
                 COUNT(*) AS entry_count
               FROM financial_ledger_entries
               GROUP BY currency ORDER BY currency"""
        ).fetchall()
    return {row["currency"]: dict(row) for row in rows}
