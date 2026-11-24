# AI-Based Phishing URL Detection System

An offline-first phishing URL detection project with a Flask web dashboard, a Tkinter desktop client, a character n-gram + numeric-feature ML model, local blocklist/allowlist checks, optional live threat-intelligence APIs, and SQLite scan history.

## Main features

- URL analysis using a trained character n-gram model combined with numeric URL features.
- Offline heuristic checks, brand-impersonation checks, and local blocklist/allowlist matching.
- Optional Google Safe Browsing and URLhaus lookups when API credentials are configured.
- Web dashboard with overview, URL scanner, scan history, filtering, pagination, and CSV export.
- Desktop scanner built with Python Tkinter.
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

Add `GOOGLE_SAFE_BROWSING_API_KEY` and/or `URLHAUS_AUTH_KEY` under Render Environment Variables if you want online reputation checks. Keep the values private; never commit `.env` or paste API keys into source files.

**Storage note:** the default SQLite database is stored inside the project directory. On hosts with an ephemeral filesystem, history can be reset when the service is redeployed or restarted. Configure a persistent disk and point the database path to it if durable production history is required.

## Run the desktop application

Open a second terminal in the project root:

```powershell
python desktop/main.py
```

The desktop client uses the same local model and local intelligence services. It does not require the Flask server to be running.

## Run tests

```powershell
pytest -q
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
- `GET /api/billing/me` returns the current account plan (anonymous visitors are treated as Free).
- `POST /api/billing/checkout` intentionally remains unavailable until a payment provider and verified webhook flow are configured.

Plan catalog (USD):

| Plan | Price | Billing period |
| --- | ---: | --- |
| Free | $0 | No charge |
| Pro | $4.99 | Monthly |
| Business | $19.99 | Every 7 months |

A new account receives Free automatically. A browser cannot grant itself a paid plan: paid subscription activation is reserved for verified server-side payment events. Payment collection, renewal, cancellation, refunds, and webhook verification are not enabled yet.

### Advertising rollout

AdSense is disabled by default. The website only requests an ad placement for Free accounts/visitors, and only when all of these environment variables are configured:

- `ADS_ENABLED=true`
- `ADSENSE_APPROVED=true` (set only after Google approves the publisher/site)
- `ADSENSE_CLIENT_ID=ca-pub-...`
- `ADSENSE_SLOT_ID=...`

The ad configuration endpoint is `GET /api/ads/config`. No ad script is loaded when the publisher is not approved, configuration is incomplete, the visitor is on a paid plan, or the browser is offline. Complete applicable privacy disclosures and consent requirements before enabling ads.


### Account management and server-side entitlements

The dashboard includes a My Account page for registration, sign-in, sign-out, current plan, and monthly scan usage. New accounts begin on Free, and anonymous scan history is linked to the account when the visitor registers or signs in.

Initial configurable plan limits are centralized in `backend/services/plan_service.py`:

| Plan | Scans per UTC calendar month | Visible history records |
| --- | ---: | ---: |
| Free | 50 | 50 |
| Pro | 2,000 | 2,000 |
| Business | 10,000 | 10,000 |

The backend enforces scan quotas on both `/api/analyze` and `/api/predict`, and applies the plan's history cap to history listing and individual scan detail retrieval. These are initial launch defaults and should be reviewed against infrastructure and threat-intelligence costs before public launch. Limits are not enforced only in the browser.
