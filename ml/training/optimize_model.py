
from pathlib import Path
import json
import time

import joblib
import sklearn
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedGroupKFold,
    cross_val_predict
)

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    fbeta_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    precision_recall_curve
)


# ==================================================
# 1. PROJECT PATHS AND CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "ml" / "dataset" / "splits"
MODEL_DIR = BASE_DIR / "ml" / "models"
REPORT_DIR = BASE_DIR / "ml" / "reports"
EVALUATION_DIR = BASE_DIR / "ml" / "evaluation"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)
EVALUATION_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42
CV_SPLITS = 3

# Maximum acceptable false positive rate during
# threshold selection on out-of-fold predictions.
MAX_VALIDATION_FPR = 0.01


# ==================================================
# 2. LOAD DATA
# ==================================================

print("Loading datasets...")

train_df = pd.read_csv(DATA_DIR / "train.csv")
test_df = pd.read_csv(DATA_DIR / "test.csv")

with open(
    DATA_DIR / "feature_columns.json",
    "r",
    encoding="utf-8"
) as file:
    feature_columns = json.load(file)

X_train = train_df[feature_columns]
y_train = train_df["label"]

X_test = test_df[feature_columns]
y_test = test_df["label"]

# Groups are reconstructed from URLs.
# This must match the registered-domain grouping
# used during the original data split.
import tldextract
from urllib.parse import urlparse

extract_domain = tldextract.TLDExtract(suffix_list_urls=())


def get_domain_group(url):
    url = str(url).strip()

    try:
        parsed = urlparse(
            url if "://" in url else "//" + url
        )

        hostname = parsed.hostname

        if not hostname:
            return url.lower()

        hostname = hostname.lower().strip(".")
        extracted = extract_domain(hostname)

        domain = extracted.top_domain_under_public_suffix

        return domain.lower() if domain else hostname

    except Exception:
        return url.lower()


groups = train_df["url"].apply(get_domain_group)

print(f"Training records: {len(X_train):,}")
print(f"Testing records: {len(X_test):,}")
print(f"Features: {len(feature_columns)}")
print(f"Training domain groups: {groups.nunique():,}")


# ==================================================
# 3. DEFINE MODELS AND SEARCH PARAMETERS
# ==================================================

models = {
    "Logistic Regression": {
        "estimator": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=RANDOM_STATE
            ))
        ]),
        "parameters": {
            "classifier__C": [0.01, 0.1, 1, 10, 100]
        },
        "iterations": 5
    },

    "Random Forest": {
        "estimator": RandomForestClassifier(
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1
        ),
        "parameters": {
            "n_estimators": [200, 300, 400],
            "max_depth": [None, 20, 30],
            "min_samples_split": [2, 5, 10],
            "min_samples_leaf": [1, 2, 4],
            "max_features": ["sqrt", "log2"],
            "max_samples": [0.8, None]
        },
        "iterations": 4
    }
}


# ==================================================
# 4. HELPER: FIND OPTIMAL THRESHOLD
# ==================================================

def find_best_threshold(y_true, probabilities):

    threshold_results = []

    thresholds = np.arange(0.05, 1.00, 0.01)

    for threshold in thresholds:

        predictions = (
            probabilities >= threshold
        ).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            y_true,
            predictions,
            labels=[0, 1]
        ).ravel()

        precision = precision_score(
            y_true,
            predictions,
            zero_division=0
        )

        recall = recall_score(
            y_true,
            predictions,
            zero_division=0
        )

        f2 = fbeta_score(
            y_true,
            predictions,
            beta=2,
            zero_division=0
        )

        fpr = fp / (fp + tn) if (fp + tn) else 0

        threshold_results.append({
            "threshold": round(float(threshold), 2),
            "precision": precision,
            "recall": recall,
            "f2_score": f2,
            "false_positive_rate": fpr,
            "false_positive": int(fp),
            "false_negative": int(fn)
        })

    results_df = pd.DataFrame(threshold_results)

    # Prefer thresholds that keep false positives
    # at or below the configured limit.
    acceptable = results_df[
        results_df["false_positive_rate"]
        <= MAX_VALIDATION_FPR
    ]

    if not acceptable.empty:
        best_row = acceptable.sort_values(
            by=["f2_score", "precision"],
            ascending=False
        ).iloc[0]

        constraint_met = True

    else:
        best_row = results_df.sort_values(
            by="f2_score",
            ascending=False
        ).iloc[0]

        constraint_met = False

    return (
        float(best_row["threshold"]),
        results_df,
        constraint_met
    )


# ==================================================
# 5. HYPERPARAMETER SEARCH
# ==================================================

print("\n========== HYPERPARAMETER OPTIMIZATION ==========")

optimized_models = {}
search_results = []

for model_name, configuration in models.items():

    print("\n" + "=" * 55)
    print(f"OPTIMIZING: {model_name}")
    print("=" * 55)

    start_time = time.time()

    cv = StratifiedGroupKFold(
        n_splits=CV_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE
    )

    search = RandomizedSearchCV(
        estimator=configuration["estimator"],
        param_distributions=configuration["parameters"],
        n_iter=configuration["iterations"],
        scoring="average_precision",
        cv=cv,
        random_state=RANDOM_STATE,
        n_jobs=1,
        verbose=1,
        refit=True
    )

    search.fit(
        X_train,
        y_train,
        groups=groups
    )

    elapsed = time.time() - start_time

    optimized_models[model_name] = search.best_estimator_

    print("\nBest parameters:")
    print(search.best_params_)

    print(
        f"Best cross-validation PR-AUC: "
        f"{search.best_score_:.5f}"
    )

    print(f"Optimization time: {elapsed:.2f} seconds")

    search_results.append({
        "model": model_name,
        "best_cv_pr_auc": search.best_score_,
        "optimization_time_seconds": round(elapsed, 2),
        "best_parameters": json.dumps(search.best_params_)
    })


search_df = pd.DataFrame(search_results)

search_df.to_csv(
    REPORT_DIR / "hyperparameter_search.csv",
    index=False
)


# ==================================================
# 6. OUT-OF-FOLD VALIDATION
# ==================================================

print("\n========== OUT-OF-FOLD VALIDATION ==========")

validation_results = []
threshold_tables = {}

validation_cv = StratifiedGroupKFold(
    n_splits=CV_SPLITS,
    shuffle=True,
    random_state=99
)

for model_name, model in optimized_models.items():

    print("\nValidating:", model_name)

    start_time = time.time()

    # Every training record receives a prediction
    # from a model that did not train on that record.
    probabilities = cross_val_predict(
        model,
        X_train,
        y_train,
        groups=groups,
        cv=validation_cv,
        method="predict_proba",
        n_jobs=1
    )[:, 1]

    validation_time = time.time() - start_time

    threshold, threshold_df, constraint_met = (
        find_best_threshold(y_train, probabilities)
    )

    threshold_tables[model_name] = threshold_df

    filename = (
        model_name.lower().replace(" ", "_")
        + "_threshold_analysis.csv"
    )

    threshold_df.to_csv(
        REPORT_DIR / filename,
        index=False
    )

    predictions = (
        probabilities >= threshold
    ).astype(int)

    precision = precision_score(
        y_train,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_train,
        predictions,
        zero_division=0
    )

    f2 = fbeta_score(
        y_train,
        predictions,
        beta=2,
        zero_division=0
    )

    pr_auc = average_precision_score(
        y_train,
        probabilities
    )

    roc_auc = roc_auc_score(
        y_train,
        probabilities
    )

    tn, fp, fn, tp = confusion_matrix(
        y_train,
        predictions,
        labels=[0, 1]
    ).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0

    print(f"Selected threshold: {threshold:.2f}")
    print(f"Precision: {precision:.5f}")
    print(f"Recall: {recall:.5f}")
    print(f"F2 Score: {f2:.5f}")
    print(f"PR-AUC: {pr_auc:.5f}")
    print(f"ROC-AUC: {roc_auc:.5f}")
    print(f"False Positive Rate: {fpr:.5f}")
    print(f"Validation time: {validation_time:.2f} seconds")

    print(
        "FPR constraint met:",
        "YES" if constraint_met else "NO"
    )

    validation_results.append({
        "model": model_name,
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f2_score": f2,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "false_positive_rate": fpr,
        "false_positive": int(fp),
        "false_negative": int(fn),
        "constraint_met": constraint_met,
        "validation_time_seconds": round(validation_time, 2)
    })


validation_df = pd.DataFrame(validation_results)

validation_df.to_csv(
    REPORT_DIR / "validation_comparison.csv",
    index=False
)


# ==================================================
# 7. SELECT BEST MODEL
# ==================================================

print("\n========== MODEL SELECTION ==========")

# Prefer models meeting the false-positive constraint.
# Within that group, prioritize F2 and then PR-AUC.

validation_df = validation_df.sort_values(
    by=[
        "constraint_met",
        "f2_score",
        "pr_auc"
    ],
    ascending=False
)

selected = validation_df.iloc[0]

best_model_name = selected["model"]
best_threshold = float(selected["threshold"])

best_model = optimized_models[best_model_name]

print("Selected model:", best_model_name)
print(f"Selected threshold: {best_threshold:.2f}")
print(f"Validation F2: {selected['f2_score']:.5f}")
print(f"Validation PR-AUC: {selected['pr_auc']:.5f}")


# ==================================================
# 8. TRAIN FINAL MODEL ON ALL TRAINING DATA
# ==================================================

print("\n========== FINAL MODEL TRAINING ==========")

start_time = time.time()

best_model.fit(X_train, y_train)

final_training_time = time.time() - start_time

print(
    f"Final training completed in "
    f"{final_training_time:.2f} seconds."
)


# ==================================================
# 9. FINAL TEST EVALUATION
# ==================================================

print("\n========== FINAL TEST EVALUATION ==========")

# This is the first and only use of the test set
# for final model evaluation in this workflow.

test_probabilities = best_model.predict_proba(X_test)[:, 1]

test_predictions = (
    test_probabilities >= best_threshold
).astype(int)

accuracy = accuracy_score(y_test, test_predictions)

precision = precision_score(
    y_test,
    test_predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    test_predictions,
    zero_division=0
)

f1 = fbeta_score(
    y_test,
    test_predictions,
    beta=1,
    zero_division=0
)

f2 = fbeta_score(
    y_test,
    test_predictions,
    beta=2,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    test_probabilities
)

pr_auc = average_precision_score(
    y_test,
    test_probabilities
)

cm = confusion_matrix(
    y_test,
    test_predictions,
    labels=[0, 1]
)

tn, fp, fn, tp = cm.ravel()

fpr = fp / (fp + tn) if (fp + tn) else 0

print("\nSelected model:", best_model_name)
print(f"Threshold: {best_threshold:.2f}")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        test_predictions,
        target_names=["Legitimate", "Phishing"],
        zero_division=0
    )
)

print("Confusion Matrix:")
print(cm)

print("\nFinal Metrics:")
print(f"Accuracy:  {accuracy:.5f}")
print(f"Precision: {precision:.5f}")
print(f"Recall:    {recall:.5f}")
print(f"F1 Score:  {f1:.5f}")
print(f"F2 Score:  {f2:.5f}")
print(f"ROC-AUC:   {roc_auc:.5f}")
print(f"PR-AUC:    {pr_auc:.5f}")
print(f"False Positive Rate: {fpr:.5f}")


# ==================================================
# 10. SAVE FINAL MODEL AND METADATA
# ==================================================

model_path = MODEL_DIR / "best_model.joblib"

joblib.dump(best_model, model_path)

metadata = {
    "model_name": best_model_name,
    "model_version": "2.0-canonical-url",
    "threshold": best_threshold,
    "features": feature_columns,
    "normalization": {
        "strip_www": True,
        "default_scheme_when_missing": "https",
        "preserve_explicit_http_https": True,
        "same_normalization_for_training_and_prediction": True
    },
    "scikit_learn_version": sklearn.__version__,
    "label_mapping": {
        "0": "legitimate",
        "1": "phishing"
    },
    "validation": {
        "f2_score": float(selected["f2_score"]),
        "pr_auc": float(selected["pr_auc"]),
        "false_positive_rate": float(
            selected["false_positive_rate"]
        )
    },
    "test": {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "f2_score": float(f2),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "false_positive_rate": float(fpr),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp)
    }
}

with open(
    MODEL_DIR / "best_model_metadata.json",
    "w",
    encoding="utf-8"
) as file:
    json.dump(metadata, file, indent=4)


# ==================================================
# 11. SAVE FINAL REPORT
# ==================================================

final_report = {
    "selected_model": best_model_name,
    "model_version": "2.0-canonical-url",
    "threshold": best_threshold,
    "test_metrics": metadata["test"],
    "confusion_matrix": cm.tolist(),
    "normalization": metadata["normalization"],
    "scikit_learn_version": sklearn.__version__
}

with open(
    REPORT_DIR / "final_evaluation.json",
    "w",
    encoding="utf-8"
) as file:
    json.dump(final_report, file, indent=4)


# ==================================================
# 12. SAVE FEATURE IMPORTANCE
# ==================================================

print("\n========== FEATURE IMPORTANCE ==========")

classifier = (
    best_model.named_steps["classifier"]
    if isinstance(best_model, Pipeline)
    else best_model
)

if hasattr(classifier, "feature_importances_"):

    importance_values = classifier.feature_importances_

elif hasattr(classifier, "coef_"):

    importance_values = np.abs(
        classifier.coef_[0]
    )

else:
    importance_values = np.zeros(len(feature_columns))


importance_df = pd.DataFrame({
    "feature": feature_columns,
    "importance": importance_values
}).sort_values(
    by="importance",
    ascending=False
)

importance_df.to_csv(
    REPORT_DIR / "feature_importance.csv",
    index=False
)

print(importance_df.to_string(index=False))


# ==================================================
# 13. GENERATE EVALUATION GRAPHS
# ==================================================

print("\nGenerating evaluation graphs...")

# ROC Curve
fpr_values, tpr_values, _ = roc_curve(
    y_test,
    test_probabilities
)

plt.figure(figsize=(8, 6))
plt.plot(
    fpr_values,
    tpr_values,
    label=f"ROC-AUC = {roc_auc:.4f}"
)
plt.plot([0, 1], [0, 1], linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Final Model - ROC Curve")
plt.legend()
plt.grid()
plt.tight_layout()
plt.savefig(REPORT_DIR / "roc_curve.png", dpi=150)
plt.close()


# Precision-Recall Curve
precision_values, recall_values, _ = precision_recall_curve(
    y_test,
    test_probabilities
)

plt.figure(figsize=(8, 6))
plt.plot(
    recall_values,
    precision_values,
    label=f"PR-AUC = {pr_auc:.4f}"
)
plt.xlabel("Recall")
plt.ylabel("Precision")
plt.title("Final Model - Precision Recall Curve")
plt.legend()
plt.grid()
plt.tight_layout()
plt.savefig(REPORT_DIR / "precision_recall_curve.png", dpi=150)
plt.close()


# Confusion Matrix
plt.figure(figsize=(7, 6))
plt.imshow(cm, interpolation="nearest")
plt.title("Final Model - Confusion Matrix")
plt.colorbar()

plt.xticks(
    [0, 1],
    ["Legitimate", "Phishing"]
)

plt.yticks(
    [0, 1],
    ["Legitimate", "Phishing"]
)

for i in range(2):
    for j in range(2):
        plt.text(
            j,
            i,
            str(cm[i, j]),
            ha="center",
            va="center"
        )

plt.xlabel("Predicted Label")
plt.ylabel("Actual Label")
plt.tight_layout()
plt.savefig(REPORT_DIR / "confusion_matrix.png", dpi=150)
plt.close()


# Feature Importance Graph
top_features = importance_df.head(15).sort_values(
    by="importance"
)

plt.figure(figsize=(10, 7))
plt.barh(
    top_features["feature"],
    top_features["importance"]
)
plt.xlabel("Importance")
plt.title("Top 15 Feature Importance")
plt.tight_layout()
plt.savefig(REPORT_DIR / "feature_importance.png", dpi=150)
plt.close()


# ==================================================
# 14. COMPLETION
# ==================================================

print("\n========== PHASE 7 COMPLETED ==========")

print("\nFinal model:")
print(model_path)

print("\nModel metadata:")
print(MODEL_DIR / "best_model_metadata.json")

print("\nReports directory:")
print(REPORT_DIR)

print("\nGenerated graphs:")
print("- roc_curve.png")
print("- precision_recall_curve.png")
print("- confusion_matrix.png")
print("- feature_importance.png")

print("\nOptimization and evaluation completed successfully.")
