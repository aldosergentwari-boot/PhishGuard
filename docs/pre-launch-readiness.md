# PhishGuard Pre-Launch Readiness

This checklist separates work that can be completed in the repository from approvals and credentials that must come from RDB and UrubutoPay.

## Operating decisions

- UrubutoPay is the only payment provider intended for new PhishGuard checkouts.
- PalmKash and Flutterwave code and historical transaction records must not be destructively removed. They are legacy integrations and must not be selected for new checkouts.
- Do not activate a paid plan from a browser redirect or a client-supplied payment status. Only a verified UrubutoPay transaction may activate a subscription.
- Do not publish or submit webhook URLs until the matching endpoints are implemented, deployed, and tested against the current UrubutoPay documentation.
- Never commit API keys, TINs, identity documents, bank account numbers, or webhook bearer secrets.

## Work that can be completed before external approval

### 1. Payment and subscription foundation
- [ ] Introduce a provider-neutral checkout contract and make UrubutoPay the only provider eligible for new checkout.
- [ ] Keep legacy provider rows readable for payment history, reconciliation, and financial reporting.
- [ ] Implement UrubutoPay checkout initiation using the current official API specification.
- [ ] Implement authenticated webhook/callback handling, signature or bearer-token verification as specified by UrubutoPay, transaction re-verification, idempotency, and safe retry behavior.
- [ ] Ensure only confirmed successful payments activate subscriptions and create ledger entries.
- [ ] Add payment status refresh, customer payment history, failed/pending states, and clear user-facing messages.
- [ ] Verify plan durations, prices, RWF/USD display, renewal behavior, expiry, and cancellation rules. Do not advertise automatic recurring billing until it is actually enabled and tested.
- [ ] Add tests for duplicate callbacks, forged callbacks, mismatched amount/currency/reference, provider timeouts, pending payments, and repeated subscription activation.

### 2. Customer-facing product
- [ ] Review the landing page, pricing, plan comparison, checkout, account dashboard, and mobile layout as one consistent customer journey.
- [ ] Ensure displayed plan features and quotas match server-side entitlements exactly.
- [ ] Add a clear billing page with current plan, usage, renewal/expiry date, payment history, and support contact.
- [ ] Add accessible loading, empty, success, pending, and error states for checkout and account actions.
- [ ] Ensure Free and Guest limits, scan usage, history retention, and export restrictions are enforced by the backend, not only hidden in the UI.
- [ ] Check desktop/web differences and clearly state which entitlements sync across devices.

### 3. Owner operations and financial controls
- [ ] Complete owner dashboard views for users, subscriptions, payments, revenue by currency, ledger entries, and audit events.
- [ ] Add safe search, pagination, filters, and CSV exports where appropriate.
- [ ] Require owner authorization and CSRF protection for every state-changing management action.
- [ ] Audit every manual subscription change, scan-credit grant, limit override, and financial adjustment.
- [ ] Add reconciliation tools and document how to compare local payment records with UrubutoPay settlement reports.
- [ ] Keep RWF, USD, and other currencies separate; never combine totals without an explicit exchange-rate source.
- [ ] Add database backup/restore and retention procedures for production.

### 4. Security, privacy, and reliability
- [ ] Review authentication, email verification, password reset, session expiry, CSRF, rate limits, and account enumeration protections.
- [ ] Verify production secrets are configured only in Render environment variables.
- [ ] Verify persistent database storage, backup restore, and migration behavior on Render.
- [x] Add health/readiness checks that distinguish app availability from database/model readiness.
- [ ] Add structured, privacy-conscious logs for checkout and webhook failures without logging secrets or full sensitive payloads.
- [ ] Review CORS, trusted proxy handling, HTTPS, security headers, cookie flags, and error responses.
- [ ] Review data deletion/export requests, retention periods, privacy disclosures, and incident-response contacts.

### 5. Release and quality
- [ ] Run the full test suite and fix all failures before merging.
- [ ] Add CI checks for tests, import/compile checks, and dependency/security review.
- [ ] Run production smoke tests for registration, login, scan, history, plan limits, admin access, and payment test mode.
- [ ] Verify deployment rollback and database backup before release.
- [ ] Review README, setup instructions, environment-variable documentation, API documentation, and support/legal pages so they describe the actual implementation.
- [ ] Complete a final release checklist and record the tested commit.

## External items that cannot be fabricated in code

- [ ] RDB approves the company registration and issues the official certificate.
- [ ] The business obtains/uses the correct RRA TIN and an eligible settlement bank account.
- [ ] UrubutoPay approves the merchant/business profile and required documents.
- [ ] UrubutoPay provides the merchant API credentials, webhook/authentication requirements, supported services, and live activation/IP-whitelisting instructions.
- [ ] The production integration is tested with UrubutoPay test credentials and then enabled for live transactions.

## Completed in the current implementation pass

- [x] New paid checkout is blocked server-side regardless of legacy provider environment variables.
- [x] PalmKash and Flutterwave cannot be selected for new purchases; their historical verification paths and transaction records are retained.
- [x] Public plan availability reports paid checkout as pending UrubutoPay merchant approval.
- [x] Customer pricing controls remain disabled while payment approval/integration is pending.
- [x] Owner monetization status reports UrubutoPay as pending instead of advertising legacy checkout readiness.
- [x] README, environment template, and public privacy/terms wording no longer describe legacy providers as active checkout options.
- [x] Regression tests cover attempts to start new payments through either legacy provider.

## Current known blockers

- RDB registration is still reported as **Pending Decision**.
- UrubutoPay business verification is not yet complete.
- The deployed app domain is `https://phishguard-u6zg.onrender.com/`.
- The proposed UrubutoPay webhook paths are not implemented yet and must not be entered in the merchant portal until verified end-to-end.
- GitHub Actions run #769 passed on the current code head: 265 Python tests passed and the dashboard JavaScript syntax check passed.
