# Project Repair Notes — 2026-11-18

## Root cause fixed

The original dataset had `www.` in 100% of legitimate URLs but only 41.5% of phishing URLs. The old Random Forest learned this dataset-specific shortcut. At inference time, the changed extractor removed `www.` from URLs, so the feature values no longer matched the values used during training. This caused root domains such as `google.com`, `wikipedia.org`, and `instagram.com` to be classified as phishing.

## Changes made

- Replaced `ml/features/extract_features.py` with one canonical URL normalizer shared by feature generation and live scanning.
- Canonicalization removes `www.` from the hostname, defaults to HTTPS only when the user omitted a scheme, and preserves an explicit HTTP/HTTPS scheme.
- Regenerated `ml/dataset/features.csv` for all 235,370 dataset rows.
- Rebuilt the existing domain-separated train/test splits. The original split membership was preserved and domain overlap remains zero.
- Retrained the Random Forest and Logistic Regression models on the canonicalized features.
- Selected the Random Forest threshold of 0.41 from 3-fold group-aware out-of-fold predictions under a maximum 1% validation false-positive-rate constraint.
- Replaced `best_model.joblib`, `random_forest.joblib`, and `logistic_regression.joblib`.
- Updated model metadata, feature columns, evaluation reports, confusion matrices, feature statistics, correlation reports, and charts.
- Updated `backend/services/model_service.py` to fail clearly if model feature order, metadata, or scikit-learn version does not match. It no longer silently removes feature columns.
- Updated `backend/config.py` fallback threshold to 0.41.
- Kept local blocklist/allowlist matching consistent for `www.` and non-`www` hostnames.
- Fixed dashboard CSV export to request history in pages of 100, matching the API's maximum page size.
- Removed unreachable code from the dashboard prediction helper.
- Implemented the previously empty `desktop/main.py` as a Tkinter offline scanner.
- Added README, `.env.example`, `.gitignore`, and model regression tests.

## Held-out test results

- Test rows: 47,074
- Accuracy: 99.22038%
- Precision: 99.86357%
- Recall: 98.30879%
- F1: 99.08009%
- PR-AUC: 99.68844%
- False-positive rate: 0.10011%
- Confusion matrix (actual rows: legitimate, phishing; predicted columns: legitimate, phishing):

```text
[[26943, 27],
 [340, 19764]]
```

## Regression checks

The bundled model returns the same result and risk score for each `www.` / non-`www` pair, and for a scheme-less domain / explicit HTTPS pair.

Known legitimate test domains:
- Google — LEGITIMATE
- Wikipedia — LEGITIMATE
- Instagram — LEGITIMATE
- YouTube — LEGITIMATE
- Microsoft — LEGITIMATE

High-risk test URLs using an IP address and suspicious login/verification paths are classified as PHISHING.

## Verification

- Automated tests: 39 passed.
- Python compile check: passed.
- JavaScript syntax check (`node --check`): passed.
- Feature extraction command: completed for all dataset rows with zero missing feature values.
- Dataset preparation command: completed with zero train/test domain overlap.
- Web API and offline analysis endpoints: covered by automated tests.

The Tkinter window was syntax-checked but not interactively launched in this environment. The full hyperparameter-search script was not rerun; the bundled model was retrained using the project's selected Random Forest parameters and a fresh group-aware out-of-fold threshold selection.

## Runtime version

The bundled model was serialized with scikit-learn 1.8.0. `requirements.txt` pins that version to avoid model persistence incompatibility. The archive excludes `.venv`; recreate it using the README installation steps.


## Follow-up phishing-detection correction — 2026-11-18

The first repaired Random Forest still missed 340 phishing URLs in the held-out test split. The alternative Logistic Regression missed 268. This showed that the original numeric-only feature representation was too weak for URLs whose lexical patterns resemble legitimate domains.

### New primary model

- Added a character n-gram TF-IDF model (2–5 character sequences) combined with the existing numeric URL features.
- Added `ml/features/url_model_features.py` so the exact numeric feature transform is serializable and reused at inference.
- Added reproducible training entry point `python -m ml.training.train_url_char_model`.
- The model is trained on a stratified validation subset of the training partition; the existing domain-separated test partition remains untouched for evaluation.
- Added a threshold-relative UI risk score and retained raw `phishing_probability` in API output, because the raw SGD probability scale is extremely small near the selected decision boundary.

### Threat intelligence and rules

- Added optional Google Safe Browsing Lookup API integration.
- Added optional URLhaus URL lookup integration. Both are disabled until the user supplies keys in `.env`; the app remains usable offline.
- Positive threat-intelligence matches are authoritative warnings; a no-match never overrides ML or local detections.
- Added local brand-impersonation checks for common brands used with login/account/security language on unrelated domains.
- `/api/predict`, `/api/analyze`, the dashboard and desktop client now use the same hybrid decision path.

### New held-out test results

- Test rows: 47,074
- Accuracy: 99.43281%
- Precision: 99.62476%
- Recall: 99.04497%
- F1: 99.33402%
- F2: 99.16038%
- PR-AUC: 99.80271%
- False-positive rate: 0.27809%
- Confusion matrix: `[[26895, 75], [192, 19912]]`

Compared with the previous Random Forest, false negatives fell from 340 to 192 on the same held-out test set. This remains a classifier, not a guarantee of safety; online reputation checks improve coverage only when configured and reachable.

### Verification

- Automated tests: 47 passed.
- Python compile check: passed.
- Positive Google Safe Browsing and URLhaus API responses tested with mocked HTTP responses.
- Live API keys were not supplied in this environment, so live provider connectivity was not tested.


## Fix v3 - hostname-only model (2026-11-19)

Problem: every legitimate URL in the dataset is a bare https root domain (0% have a path or query),
so the model learned "path / query / http => phishing". Even `https://google.com/` was PHISHING.
The reported 99.4% accuracy was inflated by this shortcut.

Changes:
- `ml/features/extract_features.py`: new `model_input(url)` -> hostname only (no scheme/path/query).
- `ml/training/train_url_char_model.py`: train on hostnames; drop shared-platform hosts
  (google.com/url, docs.google.com, s3.amazonaws.com, ipfs.io ...); group-aware validation split;
  alpha 2e-6 -> 5e-5 (threshold 0.29 instead of 1e-16).
- `backend/services/model_service.py`: feed the hostname to the model; risk score 0-50 below / 50-100 above threshold.
- `backend/services/hybrid_service.py`: allowlist now overrides ML/rules (never blocklist / threat intel / shared platforms).
- `backend/services/local_intelligence.py`: microsoftonline.com etc. are official Microsoft domains.
- `backend/config.py`: removed unused DEFAULT_THRESHOLD.
- `ml/dataset/intelligence/allowlist.txt`: seeded with well-known domains (extend it!).
- Tests: 50 passed.

Honest held-out result (domain-separated test): ROC-AUC 0.906, FPR 0.78%, recall 59.4%.
