# PhishGuard Financial Ledger Foundation

This phase adds an internal, append-only financial record for verified collections.

## What is recorded

- A payment collection is written only after the existing provider service has verified it and the local `payment_transactions` row is marked `successful`.
- Each collection is keyed by provider and local transaction reference. Repeated callbacks do not create another collection.
- Amounts are stored as integer minor units. RWF and JPY use zero decimal places; USD and most currencies use two; KWD and BHD use three.
- Currency totals are never converted or added together.
- Refunds, payouts, provider fees and adjustments are separate debit entries. They must only be recorded after the outcome is confirmed by the provider or an authorized operator. No payout or refund is initiated by this ledger.

## Owner endpoints

- `GET /api/admin/management/financial-summary` returns currency-separated totals and recent entries. It requires an authenticated owner session.
- `POST /api/admin/management/financial-reconcile` backfills successful payment transactions that do not yet have a ledger collection. It requires the owner session and `X-CSRF-Token`. The JSON body may contain `limit` (1–5000; default 500).

## Service operations

- `initialize_ledger()` creates the ledger table and indexes.
- `record_verified_payment(tx_ref)` records a verified successful payment idempotently.
- `reconcile_successful_payments(limit=500)` repairs missed ledger writes from successful local payment rows.
- `record_confirmed_debit(...)` records a provider-confirmed refund, payout, provider fee or adjustment idempotently.
- `get_financial_summary()` returns gross collections, refunds, payouts, provider fees, net revenue and net cash movement per currency, in minor units.

## Important rollout notes

- The ledger does not guess provider fees. Record the actual fee from a verified provider settlement statement.
- Net revenue is gross collections less confirmed refunds and provider fees. Payouts reduce cash movement but are not treated as an operating expense in net revenue.
- No payment credentials, card data, Mobile Money PINs or provider secrets belong in the ledger.
- The local test suite must pass before merging the monetization pull request. The pull request remains unmerged until the owner reviews the changes.
