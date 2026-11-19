"""Train the primary character n-gram phishing URL model.

Run from the project root:
    python -m ml.training.train_url_char_model
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

from ml.features.extract_features import model_input
from ml.features.url_model_features import NumericURLFeatures

BASE_DIR = Path(__file__).resolve().parents[2]
SPLIT_DIR = BASE_DIR / "ml" / "dataset" / "splits"
MODEL_DIR = BASE_DIR / "ml" / "models"
REPORT_DIR = BASE_DIR / "ml" / "reports"
MAX_VALIDATION_FPR = 0.01
RANDOM_STATE = 42


def build_model() -> Pipeline:
    features = FeatureUnion([
        (
            "char_ngrams",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(2, 5),
                min_df=2,
                max_features=250_000,
                sublinear_tf=True,
                dtype=np.float32,
            ),
        ),
        (
            "numeric",
            Pipeline([
                ("extract", NumericURLFeatures()),
                ("scale", StandardScaler(with_mean=False)),
            ]),
        ),
    ])
    classifier = SGDClassifier(
        loss="log_loss",
        alpha=5e-5,   # stronger regularization -> sane probabilities (old 2e-6 gave thresholds like 1e-16)
        max_iter=40,
        tol=1e-4,
        class_weight=None,
        random_state=RANDOM_STATE,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=4,
        n_jobs=-1,
    )
    return Pipeline([
        ("features", features),
        ("classifier", classifier),
    ])


def main() -> None:
    train_df = pd.read_csv(SPLIT_DIR / "train.csv")
    test_df = pd.read_csv(SPLIT_DIR / "test.csv")

    # Shared platforms (google.com/url, docs.google.com, sites.google.com, s3.amazonaws.com, ipfs.io ...)
    # host both good and bad pages: the hostname alone cannot tell them apart, so they
    # must NOT be used to teach a hostname-only model. Detect them from TRAIN only.
    train_hosts = train_df["url"].map(model_input)
    host_rows = train_hosts.groupby(train_hosts).size()
    host_labels = train_df.groupby(train_hosts)["label"].nunique()
    platform_hosts = set(host_rows[host_rows >= 20].index) | set(host_labels[host_labels > 1].index)
    train_df = train_df[~train_hosts.isin(platform_hosts)].reset_index(drop=True)
    print(f"Excluded {len(platform_hosts)} shared-platform hosts from training", flush=True)

    y_train = train_df["label"].to_numpy(dtype=int)
    y_test = test_df["label"].to_numpy(dtype=int)
    X_train = np.asarray([model_input(url) for url in train_df["url"]], dtype=object)
    X_test = np.asarray([model_input(url) for url in test_df["url"]], dtype=object)

    # Keep the existing domain-separated test split untouched. Use a separate
    # stratified validation subset from the training partition to select threshold.
    # Group-aware split: the same domain never appears in both fit and validation.
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=RANDOM_STATE)
    fit_idx, valid_idx = next(splitter.split(X_train, y_train, groups=X_train))
    X_fit, y_fit = X_train[fit_idx], y_train[fit_idx]
    X_valid, y_valid = X_train[valid_idx], y_train[valid_idx]

    print("Training character n-gram URL model...", flush=True)
    started = time.time()
    model = build_model()
    model.fit(X_fit.tolist(), y_fit)
    print(f"Fit completed in {time.time() - started:.1f}s", flush=True)

    validation_probabilities = model.predict_proba(X_valid.tolist())[:, 1]
    candidates = np.unique(np.quantile(validation_probabilities, np.linspace(0.001, 0.999, 400)))
    threshold_rows = []

    for threshold in candidates:
        predicted = validation_probabilities >= threshold
        tn, fp, fn, tp = confusion_matrix(y_valid, predicted, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if fp + tn else 0.0
        precision = precision_score(y_valid, predicted, zero_division=0)
        recall = recall_score(y_valid, predicted, zero_division=0)
        f2 = fbeta_score(y_valid, predicted, beta=2, zero_division=0)
        threshold_rows.append((fpr, f2, precision, recall, float(threshold), tn, fp, fn, tp))

    acceptable = [row for row in threshold_rows if row[0] <= MAX_VALIDATION_FPR]
    best = max(acceptable, key=lambda row: (row[1], row[2])) if acceptable else max(
        threshold_rows, key=lambda row: row[1]
    )
    threshold = best[4]

    probabilities = model.predict_proba(X_test.tolist())[:, 1]
    predicted = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(y_test, predicted, labels=[0, 1]).ravel()

    metrics = {
        "accuracy": float(accuracy_score(y_test, predicted)),
        "precision": float(precision_score(y_test, predicted, zero_division=0)),
        "recall": float(recall_score(y_test, predicted, zero_division=0)),
        "f1": float(f1_score(y_test, predicted, zero_division=0)),
        "f2": float(fbeta_score(y_test, predicted, beta=2, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "pr_auc": float(average_precision_score(y_test, probabilities)),
        "false_positive_rate": float(fp / (fp + tn)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "threshold": float(threshold),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "url_char_model.joblib", compress=0)

    metadata = {
        "model_name": "Character n-gram TF-IDF + numeric URL features (SGD logistic)",
        "model_version": "3.0-url-lexical-hybrid",
        "threshold": float(threshold),
        "features": "HOSTNAME-only character n-grams (2-5) plus deterministic numeric features computed on the hostname",
        "training_partition_records": int(len(train_df)),
        "model_fit_records": int(len(X_fit)),
        "validation_records": int(len(X_valid)),
        "testing_records": int(len(test_df)),
        "validation": {
            "method": "Stratified 85/15 validation split from the training partition (random_state=42)",
            "threshold": float(threshold),
            "false_positive_rate": float(best[0]),
            "f2_score": float(best[1]),
            "precision": float(best[2]),
            "recall": float(best[3]),
            "confusion_matrix": {
                "tn": int(best[5]), "fp": int(best[6]),
                "fn": int(best[7]), "tp": int(best[8]),
            },
        },
        "test": metrics,
        "scikit_learn_version": sklearn.__version__,
        "normalization": {
            "strip_www": True,
            "default_scheme_when_missing": "https",
            "preserve_explicit_http_https": True,
        },
        "risk_score_method": "piecewise: 0-50 below threshold, 50-100 above threshold",
    }
    (MODEL_DIR / "url_char_model_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    (REPORT_DIR / "url_char_model_evaluation.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )

    print("Threshold:", threshold)
    print(json.dumps(metrics, indent=2))
    print("Saved:", MODEL_DIR / "url_char_model.joblib")


if __name__ == "__main__":
    main()
