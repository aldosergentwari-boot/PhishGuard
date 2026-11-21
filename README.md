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

The primary model is now `url_char_model.joblib` (version `3.1-hostname-only`). It combines character n-gram TF-IDF features from the normalized URL with the existing numeric URL features. This lets it learn suspicious spelling patterns and domain/URL character sequences that a small set of length/count features cannot represent.

- `www.example.com` and `example.com` are normalized consistently.
- A missing scheme is treated as HTTPS for feature extraction; explicit HTTP/HTTPS is preserved.
- The same canonical normalization is used in training and live prediction.
- The threshold is selected on a stratified validation split while constraining validation false-positive rate to at most 1%.
- The separate domain-held-out test split is not used for threshold selection.
- The UI risk score is normalized relative to the selected decision threshold; `phishing_probability` in the API response is the raw model probability.

The previous Random Forest model is retained as a comparison artifact, but it is no longer the primary runtime model.

## Optional live threat intelligence

The scanner works without API keys. To add live lookups, copy `.env.example` to `.env` and set one or both keys:

- `GOOGLE_SAFE_BROWSING_API_KEY` — Google Safe Browsing Lookup API.
- `URLHAUS_AUTH_KEY` — URLhaus community API Auth-Key.

A positive match from either provider marks the URL as phishing. A no-match response does **not** override an ML or local-rule warning. If the APIs are not configured or cannot be reached, the app falls back to the local model and rules. Online checks are cached in memory for 15 minutes. **Privacy note:** when you enable a provider, the URL text you submit is sent to that provider for reputation lookup; with both keys blank, scans stay local.

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

## Session and browser-history security

The web app assigns anonymous browser sessions a random owner ID so scan history is isolated between browser profiles. The session cookie is HTTP-only, uses SameSite=Lax, and lasts up to one year. Clearing browser cookies creates a new anonymous identity; anonymous history is not an account and cannot be recovered across devices.

Set these environment variables before production deployment:

- `SECRET_KEY`: a long, randomly generated secret used to sign Flask sessions. Keep it stable across restarts and never commit the real value.
- `SESSION_COOKIE_SECURE=true`: required when serving the site over HTTPS. For local development over `http://127.0.0.1`, use `false`.

The browser dashboard sends same-origin API requests so its session cookie is included with scan and history requests.

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
- An allowlist match skips local heuristic scoring, but does not override the machine-learning result or a blocklist match.
- Brand-impersonation rules check common brands used with login/account/security wording on unrelated domains.
- The final decision flags a URL when the model, local rules, local blocklist, or an online threat-intelligence provider identifies a threat.
- Allowlisting never overrides a model, brand-impersonation, or blocklist warning.

## Model limitations

The model is a machine-learning classifier, not a guarantee that a website is safe. A low risk score does not prove that a site is legitimate. Keep the dataset and local threat lists updated, and use caution before entering passwords or payment details on unfamiliar websites.
