# AI-Based Phishing URL Detection System

An offline-first phishing URL detection project with a Flask web dashboard, a Tkinter desktop client, a character n-gram + numeric-feature ML model, local blocklist/allowlist checks, optional live threat-intelligence APIs, and SQLite scan history.

## Main features

- URL analysis using a trained character n-gram model combined with numeric URL features.
- Offline heuristic checks, brand-impersonation checks, and local blocklist/allowlist matching.
- Optional Google Safe Browsing and URLhaus lookups when API credentials are configured.
- Web dashboard with overview, URL scanner, scan history, filtering, pagination, and CSV export.
- Desktop scanner built with Python Tkinter, with persistent device-local scan history that works offline.
- SQLite history storage.
- URL normalization shared by dataset feature extraction and live prediction.

## Model improvements

The primary model is `url_char_model.joblib` (version `3.1-hostname-only`). It uses character n-gram TF-IDF and deterministic numeric features computed from the normalized hostname only. It deliberately does not use the URL path, query string, or scheme, avoiding shortcuts that can make the model mistake ordinary URL structure for phishing evidence.

- `www.example.com` and `example.com` are normalized consistently.
- A missing scheme is treated as HTTPS during canonical normalization; explicit HTTP/HTTPS is preserved for local rule features.
- The model input is the canonical hostname, so `www.example.com` and `example.com` produce the same lexical input.
- The same canonical normalization and hostname extraction are used in training and live prediction.
- The threshold is selected on a hostname-grouped validation split (`GroupShuffleSplit`) while constraining validation false-positive rate to at most 1%.
- The separate domain-held-out test split is not used for threshold selection.
- The UI risk score is normalized relative to the selected decision threshold; `phishing_probability` in the API response is the raw model probability.

The previous Random Forest model is retained as a comparison artifact, but it is no longer the primary runtime model.

## Optional live threat intelligence

The scanner works without API keys. To add live lookups, copy `.env.example` to `.env` and set one or both keys:

- `GOOGLE_SAFE_BROWSING_API_KEY` — Google Safe Browsing Lookup API.
- `URLHAUS_AUTH_KEY` — URLhaus community API Auth-Key.

A positive match from either provider marks the URL as phishing. A no-match response does **not** override an ML or local-rule warning. If the APIs are not configured or cannot be reached, the app falls back to the local model and rules. Online checks are cached in memory for 15 minutes. The dashboard starts in Offline mode; online lookups run only after the user explicitly switches to Online mode. **Privacy note:** Google Safe Browsing and URLhaus receive the full submitted URL only when their API keys are configured and Online mode is enabled. In Online mode, the app can also download the OpenPhish feed and send only the registered domain name to RDAP for its age check. Offline mode performs none of these network lookups.

## Requirements

- Windows 10/11
- Python 3.12 recommended
- The Python packages listed in `requirements.txt`

The bundled model was trained with scikit-learn 1.8.0. Keep that version when loading the bundled model.

## Installation

Open PowerShell in the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run the commands below in Command Prompt instead:

```bat
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

## Run the web dashboard

From the project root:

```powershell
python -m backend.app
```

Open:

```text
http://127.0.0.1:5000/dashboard
```

The API runs locally. The scanner does not open the target website or download its page. If online threat-intelligence keys are configured, the URL text is sent to the selected provider(s) for reputation lookup; otherwise analysis remains local.

## Deploy on Render

Create a Render **Web Service** connected to the GitHub repository and use:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --bind 0.0.0.0:$PORT backend.app:app`
- Runtime: Python 3
- Liveness check path: `/api/health`
- Readiness check path: `/api/ready` (checks that the ML model and primary database are available)

Add `GOOGLE_SAFE_BROWSING_API_KEY` and/or `URLHAUS_AUTH_KEY` under Render Environment Variables if you want online reputation checks. Keep the values private; never commit `.env` or paste API keys into source files.

**Storage note:** the default SQLite database is stored inside the project directory. On hosts with an ephemeral filesystem, history and account records can be reset when the service is redeployed or restarted. For Render, attach a persistent disk (for example mounted at `/var/data`) and set `PHISHGUARD_DATABASE_PATH=/var/data/phishguard.db` in the service environment. The application uses this same database path for accounts, subscriptions, payment records, and scan history. Back up the persistent disk regularly; a persistent disk is not itself a backup.

**Database backups:** run `python -m scripts.backup_database` from the repository root to create a timestamped, integrity-checked SQLite backup under `backups/`. You can choose an exact output path with `python -m scripts.backup_database --output "D:\\PhishGuardBackups\\phishguard.sqlite3"` on Windows or `python -m scripts.backup_database --output /secure-backups/phishguard.sqlite3` on Linux. The utility uses SQLite's online backup API, so it is safe to run while the app is open and includes committed WAL data. Keep backup copies outside the live persistent disk (for example, in a separate secure storage location); a second file on the same disk is not disaster recovery. Protect backups because they contain account, scan-history, and payment-reference data.

## Run the desktop application

Open a second terminal in the project root:

```powershell
python desktop/main.py
```

The desktop client uses the same local model and local intelligence services. It does not require the Flask server to be running. Desktop scan history is stored locally under the current Windows user profile (or the platform's application-data directory) and remains available after restarting the app. This local desktop history is separate from a signed-in web account's cloud history; cross-device account sync is a later desktop integration step.

## Run tests

```powershell
python -m pytest -q
```

## Retrain the model

Run these commands in order from the project root:

```powershell
python -m ml.features.extract_features
python -m ml.training.prepare_data
python -m ml.training.train_url_char_model
```

The primary model script trains the character n-gram model, selects a threshold on a stratified validation split under the configured false-positive-rate constraint, evaluates the untouched domain-separated test set, and writes the runtime model and metadata.

Do not change the feature extraction logic in only one place. The extractor is shared by training and prediction; changing it requires regenerating features, rebuilding splits, and retraining the model.

## Important files

```text
backend/                 Flask API and services
scripts/                 Operational utilities (database backup)
desktop/main.py          Tkinter desktop application
web/                     Dashboard HTML, CSS and JavaScript
ml/features/             URL normalization and feature extraction
ml/training/             Dataset preparation and model training
ml/dataset/              Dataset, generated features, splits and local lists
ml/models/               Trained model and metadata
ml/reports/              Evaluation reports
tests/                   Automated tests
```

## Local intelligence behavior

- A blocklist match always marks the domain as phishing.
- An allowlist match suppresses model-only false positives and local heuristic/brand warnings for that trusted host. Blocklist and positive external threat-intelligence matches always take precedence.
- Brand-impersonation rules check common brands used with login/account/security wording on unrelated domains.
- The final decision flags a URL when the model, local rules, local blocklist, or an online threat-intelligence provider identifies a threat.
- Allowlisting is intended for known trusted hosts; do not add a domain unless you are confident it is legitimate. A blocklist or positive external threat-intelligence match still overrides the allowlist.

## Model limitations

The model is a machine-learning classifier, not a guarantee that a website is safe. A low risk score does not prove that a site is legitimate. Keep the dataset and local threat lists updated, and use caution before entering passwords or payment details on unfamiliar websites.


## Accounts and monetization foundation

The web dashboard now exposes account and plan APIs:

- `GET /api/auth/csrf` returns the CSRF token required for account mutations.
- `POST /api/auth/register`, `POST /api/auth/login`, and `POST /api/auth/logout` manage browser accounts.
- `GET /api/auth/me` returns the signed-in account and its current subscription.
- `GET /api/billing/plans` returns the public plan catalog.
- `GET /api/billing/me` returns the current account plan (anonymous visitors receive the Guest plan and its 10-scan monthly allowance).
- `GET /api/billing/payments` returns the signed-in user's own recent payment history; transaction references are not exposed.
- `POST /api/billing/checkout` is intentionally unavailable until the approved UrubutoPay integration is deployed; it never falls back to PalmKash or Flutterwave.
- Legacy Flutterwave callback/webhook routes remain only to verify and audit existing historical transactions; they are not used to start new checkouts.
- The legacy PalmKash callback and payment-status routes are retained only for existing historical transactions.
- `GET /api/billing/payments/<tx_ref>/status` is retained for a signed-in customer to inspect their own historical PalmKash payment.
- Payment attempts record their provider and remain pending until verified; browser redirects and client-supplied plan IDs never grant paid access.

Legacy provider note: PalmKash and Flutterwave integrations are retained for backward-compatible verification of old payment records only. They must not be configured or used to initiate new customer checkouts.

New paid checkout remains disabled until UrubutoPay merchant approval, official API specifications, webhook requirements, and live credentials are available. Do not place unverified webhook URLs or credentials in the environment.

The historical provider implementations remain in the repository for transaction verification and audit compatibility only. Their environment credentials are not included in `.env.example`, and they cannot be selected by new checkout requests. Do not configure or use those legacy integrations for new purchases.

Plan catalog (USD):

| Plan | Price | Billing period |
| --- | ---: | --- |
| Free | $0 | No charge |
| Pro | $4.99 | Monthly |
| Business | $19.99 | Every 7 months |

Current advertised plan features are limited to capabilities already implemented: monthly scan quotas, visible history caps, CSV scan-history export, and ad-free access for paid web plans. The catalog does not currently promise API keys, team workspaces/reporting, advanced analytics, or priority support. Subscription entitlements currently apply to the web dashboard only; the standalone desktop client does not yet sync account plans or monthly usage.

A new account receives Free automatically. A browser cannot grant itself a paid plan: paid subscription activation is reserved for verified server-side payment events. New paid checkout is intentionally disabled pending the approved UrubutoPay integration. Existing Flutterwave/PalmKash callback handlers are legacy-only and must not be used to initiate new payments. Paid subscription activation remains restricted to server-verified successful payment events; recurring billing, customer self-service cancellation, and automated refunds are not enabled.

### Advertising rollout

AdSense is disabled by default and fails closed. Guest and Free accounts can receive ads only after Google publisher approval, a verified Google-certified IAB TCF consent-management platform (CMP), and valid consent signals from that CMP. Pro and Business plans never request ads. All of the following environment variables must be configured:

- `ADS_ENABLED=true`
- `ADSENSE_APPROVED=true` (set only after Google approves the publisher/site)
- `ADS_CONSENT_CONFIGURED=true` (set only after a Google-certified TCF CMP is installed, configured and tested on every page; never use this as a substitute for installing a CMP)
- `ADSENSE_CLIENT_ID=ca-pub-...`
- `ADSENSE_SLOT_ID=...`

The dashboard footer links to Advertising Preferences, an informational page; it is not itself a CMP. The browser fails closed and does not request the AdSense script unless the configured CMP exposes IAB TCF v2 signals showing the required consent for Google (vendor 755 and purposes 1, 3 and 4 where GDPR applies). If the CMP is missing, broken, or the user declines, no ad request is made. Google requires a certified CMP integrated with TCF for personalized ads to users in the EEA, UK and Switzerland; review current Google requirements and local law before launch. Paid Pro and Business plans do not load ads. The private Admin > Ads & monetization page reports AdSense readiness without exposing provider secrets. Update server environment variables and restart the service to change provider configuration.

The ad configuration endpoint is `GET /api/ads/config`. The root `/ads.txt` endpoint generates Google's authorized-seller line from the configured publisher ID; it returns 404 until a valid ID is configured. No ad script is loaded when the publisher is not approved, configuration is incomplete, the visitor is on a paid plan, or the browser is offline. In AdSense, check that the site approval status is Ready and that ads.txt is Authorized or Not applicable. Google recommends ads.txt and notes that crawl status may take time to update. Complete applicable privacy disclosures and consent requirements before enabling ads.


### Account management and server-side entitlements

The dashboard includes a My Account page for registration, sign-in, sign-out, current plan, and monthly scan usage. New accounts begin on Free, and anonymous scan history is linked to the account when the visitor registers or signs in.

Initial configurable plan limits are centralized in `backend/services/plan_service.py`:

| Plan | Scans per UTC calendar month | Visible history records |
| --- | ---: | ---: |
| Guest (no account) | 10 | 10 |
| Free | 50 | 50 |
| Pro | 2,000 | 2,000 |
| Business | 10,000 | 10,000 |

The backend enforces scan quotas on both `/api/analyze` and `/api/predict`, and applies the plan's history cap to history listing and individual scan detail retrieval. These are initial launch defaults and should be reviewed against infrastructure and threat-intelligence costs before public launch. Limits are not enforced only in the browser.

Anonymous web visitors receive a separate Guest allowance of 10 scans per UTC calendar month. Both `/api/analyze` and `/api/predict` enforce this quota on the server. When the allowance is exhausted, the API returns `GUEST_SCAN_LIMIT_REACHED` and the dashboard directs the visitor to create a Free account or sign in. Registration and login transfer the browser's existing scan history to the account; the signed-in Free plan then provides 50 scans per month. Guest identity is maintained by the signed, HttpOnly browser session, so clearing cookies or switching browsers can create a new guest identity; IP-level request throttling remains a separate abuse-control layer.

The web scanning endpoints also enforce server-side fixed-window rate limits: 30 valid scans per minute per signed-in account or anonymous browser identity, and 300 per minute per client IP. The limits are stored in SQLite and updated atomically so they are shared across application workers using the same persistent database. On Render, the app trusts the single edge proxy for the forwarded client IP and HTTPS scheme; do not expose the Gunicorn service directly to untrusted proxy headers. A blocked request receives HTTP 429 with a `Retry-After: 60` header. These request-rate limits are separate from the monthly plan quota.

### Owner management dashboard

The private owner workspace is available at `/admin`. Configure `PHISHGUARD_OWNER_EMAIL` in the server environment with the email address of an existing PhishGuard account. The owner account must have a verified email address and must sign in with its normal account password at `/admin/login`. The public website does not expose the owner dashboard.

The management workspace provides account and subscription metrics, user and payment lists, and owner-granted bonus scan credits. Owner APIs require the authenticated owner session and CSRF protection; the session is tied to the configured owner email and account session version. Do not create a public owner-registration flow or expose owner credentials in frontend code.

To set up the owner:
1. Register the intended owner account through the normal account registration flow.
2. Verify its email address.
3. Set `PHISHGUARD_OWNER_EMAIL` to that exact email in local `.env` or the production host's environment variables.
4. Restart the application and sign in at `/admin/login`.

Bonus scan grants require an active registered customer, 1–10,000 scans, and an audit reason. Grants expire at the end of the current UTC month. The shared IP safety limit remains active.



### Brevo account email security

PhishGuard supports transactional email for account verification and password reset through Brevo SMTP. Add these variables to your local `.env` file (or your production host's environment settings):

- `MAIL_SERVER=smtp-relay.brevo.com`
- `MAIL_PORT=587`
- `MAIL_USE_TLS=true`
- `MAIL_USERNAME`: your Brevo SMTP login (not your account email unless Brevo shows that as the SMTP login).
- `MAIL_PASSWORD`: your Brevo SMTP key.
- `MAIL_DEFAULT_SENDER`: the sender address you verified in Brevo.
- `MAIL_SENDER_NAME=PhishGuard Security`
- `PUBLIC_APP_URL`: trusted app origin used in email links. For local development use `http://127.0.0.1:5000`; production must use your real HTTPS domain.

Never commit `.env`, SMTP keys, or production credentials. `.env.example` contains blank placeholders only. Verification links expire after 24 hours; password-reset links expire after 30 minutes. Tokens are random, single-use, and only SHA-256 digests are stored in the database. Password reset increments the account session version to revoke existing sessions. If SMTP is not configured or delivery fails, the account flow remains available and the user can request another email after mail settings are fixed.


### Public legal and trust pages

The web app provides these public pages and links them from the dashboard footer:

- `/privacy` — account, scan-history, cookie/session, online lookup, email, payment, and advertising data practices.
- `/terms` — acceptable use, service limitations, accounts, plans, and payment terms.
- `/security-disclaimer` — detection limitations and safe-use guidance.

Set `PUBLIC_SUPPORT_EMAIL` to a monitored support address in the deployment environment. The pages display a setup notice until this is configured. These starter policies describe the current product behavior but are not a substitute for legal review. Before public launch, the owner must add the correct legal entity, operating jurisdiction, governing-law details, retention periods, and refund/cancellation process, and review applicable privacy, consumer, cookie/consent, and advertising requirements.


For a production Render deployment, configure at minimum:

- `SECRET_KEY`: a long, random secret unique to the production service.
- `PHISHGUARD_DATABASE_PATH`: path inside the mounted persistent disk, such as `/var/data/phishguard.db`.
- `PUBLIC_APP_URL`: the canonical public HTTPS origin, with no trailing slash.
- `PUBLIC_SUPPORT_EMAIL`: a monitored support address.
- `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`: verified Brevo SMTP credentials and sender.
- UrubutoPay merchant credentials and webhook settings: add only after merchant approval and after the matching integration routes have been implemented and tested.
- `SESSION_COOKIE_SECURE=true` (the app enforces Secure cookies whenever the `RENDER` environment is present; local HTTP testing may set it to `false` only outside Render).

Use the Render start command `gunicorn --bind 0.0.0.0:$PORT backend.app:app`. Do not enable AdSense until publisher approval and the required privacy/consent setup are complete.

The Flask app also adds baseline browser security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`) to responses. On Render it adds HTTP Strict Transport Security (HSTS). Do not put the public production service behind plain HTTP.


### First owner setup and expanded owner management

If no owner account exists yet, do not try to sign in with a made-up/default password. Set `PHISHGUARD_OWNER_EMAIL` in your local `.env` (or the production service environment) to the email you want to use, then run this one-time command from the repository root in a trusted terminal:

```powershell
python -m scripts.create_owner
```

The command asks you to create and confirm a password without echoing it, requires 12–128 characters, creates the account (or resets that exact account's password), marks its email verified, and never exposes an owner-registration HTTP endpoint. It uses the configured application database, so run it against the same database used by the web service. Keep the email variable configured, restart the service, and open `/admin/login`. The password is the one entered in this command. If the application is hosted, run the command in a trusted deployment shell with the production database mounted; never run it against an empty temporary database.

Expanded owner APIs are available under `/api/admin/management`: searchable/filterable/paginated users, account suspend/reactivate, plan changes, payment search/details, subscription listing/cancellation, revenue and conversion analytics, in-app user notifications, and an append-only owner audit log. Mutations require the owner session and CSRF token. Admin-granted plan changes are operational overrides and are recorded in the audit log; they do not represent a verified customer payment. Notifications are stored in-app and do not claim that an email was delivered.
