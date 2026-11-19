
import pandas as pd
import numpy as np
from pathlib import Path

# ==========================================
# CONFIGURATION
# ==========================================

INPUT_FILE = Path("ml/dataset/features.csv")
REPORT_DIR = Path("ml/reports")

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================
# LOAD DATASET
# ==========================================

print("Loading feature dataset...")

df = pd.read_csv(INPUT_FILE)

# Separate features and target
X = df.drop(columns=["url", "label"])
y = df["label"]

print("\n========== FEATURE ANALYSIS ==========")

print("Total records:", len(df))
print("Total features:", len(X.columns))


# ==========================================
# 1. CONSTANT FEATURES
# ==========================================

print("\n--- Constant Features ---")

constant_features = [
    col for col in X.columns
    if X[col].nunique(dropna=False) <= 1
]

print("Constant features:", constant_features)

# ==========================================
# 2. FEATURE STATISTICS
# ==========================================

print("\n--- Feature Statistics ---")

statistics = X.describe().T

statistics.to_csv(
    REPORT_DIR / "feature_statistics.csv"
)

print(statistics)


# ==========================================
# 3. CLASS COMPARISON
# ==========================================

print("\n--- Class Comparison ---")

legitimate = df[df["label"] == 0][X.columns]
phishing = df[df["label"] == 1][X.columns]

comparison = pd.DataFrame({
    "legitimate_mean": legitimate.mean(),
    "phishing_mean": phishing.mean(),
    "legitimate_median": legitimate.median(),
    "phishing_median": phishing.median()
})

comparison["mean_difference"] = (
    comparison["phishing_mean"] -
    comparison["legitimate_mean"]
).abs()

comparison["correlation_with_label"] = X.corrwith(y)

comparison = comparison.sort_values(
    by="mean_difference",
    ascending=False
)

comparison.to_csv(
    REPORT_DIR / "class_comparison.csv"
)

print(comparison.to_string())


# ==========================================
# 4. FEATURE CORRELATION
# ==========================================

print("\n--- Feature Correlation ---")

correlation = X.corr()

correlation.to_csv(
    REPORT_DIR / "feature_correlation.csv"
)

# Identify highly correlated feature pairs
high_correlations = []

for i in range(len(correlation.columns)):
    for j in range(i + 1, len(correlation.columns)):

        value = correlation.iloc[i, j]

        if abs(value) >= 0.95:

            high_correlations.append({
                "feature_1": correlation.columns[i],
                "feature_2": correlation.columns[j],
                "correlation": value
            })

high_corr_df = pd.DataFrame(
    high_correlations,
    columns=[
        "feature_1",
        "feature_2",
        "correlation"
    ]
)

high_corr_df.to_csv(
    REPORT_DIR / "high_correlations.csv",
    index=False
)

print(high_corr_df.to_string(index=False))


# ==========================================
# 5. MISSING VALUES
# ==========================================

print("\n--- Missing Values ---")

missing = X.isnull().sum()

print(missing[missing > 0])

print("Total missing values:", missing.sum())


# ==========================================
# 6. LABEL CORRELATION
# ==========================================

print("\n--- Correlation With Target ---")

target_correlation = (
    comparison["correlation_with_label"]
    .sort_values(
        key=lambda values: values.abs(),
        ascending=False
    )
)

print(target_correlation)


# ==========================================
# 7. SAVE SUMMARY
# ==========================================

summary = {
    "total_records": len(df),
    "total_features": len(X.columns),
    "constant_features": len(constant_features),
    "missing_values": int(X.isnull().sum().sum()),
    "highly_correlated_pairs": len(high_corr_df)
}

pd.DataFrame(
    [summary]
).to_csv(
    REPORT_DIR / "analysis_summary.csv",
    index=False
)

print("\n========== ANALYSIS COMPLETED ==========")

print("Reports saved in:", REPORT_DIR)
print("\nGenerated files:")

for file in REPORT_DIR.iterdir():
    print("-", file.name)
