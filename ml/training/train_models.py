
from pathlib import Path
import json
import time

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report
)


# ==========================================
# 1. PROJECT PATHS
# ==========================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "ml" / "dataset" / "splits"
MODEL_DIR = BASE_DIR / "ml" / "models"
REPORT_DIR = BASE_DIR / "ml" / "reports"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================
# 2. LOAD FEATURE NAMES
# ==========================================

print("Loading feature columns...")

with open(DATA_DIR / "feature_columns.json", "r", encoding="utf-8") as file:
    feature_columns = json.load(file)


# ==========================================
# 3. LOAD TRAINING AND TESTING DATA
# ==========================================

print("Loading training and testing datasets...")

train_df = pd.read_csv(DATA_DIR / "train.csv")
test_df = pd.read_csv(DATA_DIR / "test.csv")

X_train = train_df[feature_columns]
y_train = train_df["label"]

X_test = test_df[feature_columns]
y_test = test_df["label"]

print("\n========== DATASET INFORMATION ==========")

print(f"Training records: {len(X_train):,}")
print(f"Testing records: {len(X_test):,}")
print(f"Number of features: {len(feature_columns)}")

print("\nTraining labels:")
print(y_train.value_counts().sort_index())

print("\nTesting labels:")
print(y_test.value_counts().sort_index())


# ==========================================
# 4. DEFINE MODELS
# ==========================================

models = {
    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        ))
    ]),

    "Random Forest": RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    )
}


# ==========================================
# 5. TRAIN AND EVALUATE MODELS
# ==========================================

results = []

for model_name, model in models.items():

    print("\n" + "=" * 55)
    print(f"TRAINING: {model_name}")
    print("=" * 55)

    start_time = time.time()

    model.fit(X_train, y_train)

    training_time = time.time() - start_time

    print(f"Training completed in {training_time:.2f} seconds.")

    # Predict class labels.
    y_pred = model.predict(X_test)

    # Predict probability of phishing (class 1).
    y_probability = model.predict_proba(X_test)[:, 1]

    # Calculate evaluation metrics.
    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred,
        pos_label=1,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        pos_label=1,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        pos_label=1,
        zero_division=0
    )

    roc_auc = roc_auc_score(y_test, y_probability)

    pr_auc = average_precision_score(y_test, y_probability)

    # Confusion matrix: rows = actual, columns = predicted.
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    tn, fp, fn, tp = cm.ravel()

    # Save model.
    model_filename = (
        model_name.lower().replace(" ", "_") + ".joblib"
    )

    model_path = MODEL_DIR / model_filename

    joblib.dump(model, model_path)

    # Save confusion matrix.
    confusion_df = pd.DataFrame(
        cm,
        index=["Actual Legitimate", "Actual Phishing"],
        columns=["Predicted Legitimate", "Predicted Phishing"]
    )

    confusion_filename = (
        model_name.lower().replace(" ", "_")
        + "_confusion_matrix.csv"
    )

    confusion_df.to_csv(
        REPORT_DIR / confusion_filename
    )

    # Save detailed classification report.
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Legitimate", "Phishing"],
            zero_division=0
        )
    )

    print("Confusion Matrix:")
    print(confusion_df)

    print("\nMain Metrics:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print(f"PR-AUC:    {pr_auc:.4f}")

    print(f"\nSaved model: {model_path}")

    results.append({
        "model": model_name,
        "accuracy": accuracy,
        "precision_phishing": precision,
        "recall_phishing": recall,
        "f1_phishing": f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
        "training_time_seconds": round(training_time, 2)
    })


# ==========================================
# 6. SAVE MODEL COMPARISON
# ==========================================

results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    by="f1_phishing",
    ascending=False
)

comparison_path = REPORT_DIR / "model_comparison.csv"

results_df.to_csv(comparison_path, index=False)

print("\n" + "=" * 55)
print("FINAL MODEL COMPARISON")
print("=" * 55)

print(results_df.to_string(index=False))

print("\nComparison saved to:")
print(comparison_path)

print("\n========== MODEL TRAINING COMPLETED ==========")
