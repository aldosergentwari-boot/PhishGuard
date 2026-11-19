
from pathlib import Path
import json
from urllib.parse import urlparse

import pandas as pd
import tldextract
from sklearn.model_selection import StratifiedGroupKFold


# ==========================================
# 1. PROJECT PATHS
# ==========================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = BASE_DIR / "ml" / "dataset" / "features.csv"
OUTPUT_DIR = BASE_DIR / "ml" / "dataset" / "splits"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================
# 2. CONFIGURATION
# ==========================================

TEST_SIZE = 0.20
RANDOM_STATE = 42
N_SPLITS = 5

# Offline extraction: does not download a suffix list.
extract_domain = tldextract.TLDExtract(suffix_list_urls=())


# ==========================================
# 3. EXTRACT DOMAIN GROUPS
# ==========================================

def get_domain_group(url):
    """
    Extract the registered domain from a URL.
    URLs belonging to the same registered domain
    will remain in the same dataset split.
    """

    url = str(url).strip()

    if not url:
        return "unknown"

    try:
        parsed = urlparse(
            url if "://" in url else "//" + url
        )

        hostname = parsed.hostname

        if not hostname:
            return url.lower()

        hostname = hostname.lower().strip(".")

        # Extract registered domain.
        extracted = extract_domain(hostname)

        registered_domain = extracted.top_domain_under_public_suffix

        if registered_domain:
            return registered_domain.lower()

        # Fallback for IP addresses or unknown suffixes.
        return hostname

    except Exception:
        return url.lower()


# ==========================================
# 4. LOAD DATASET
# ==========================================

print("Loading feature dataset...")

df = pd.read_csv(DATASET_PATH)

required_columns = {"url", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError(
        f"Dataset must contain these columns: {required_columns}"
    )

if df["url"].isna().any() or df["label"].isna().any():
    raise ValueError("Dataset contains missing URLs or labels.")

df["label"] = df["label"].astype(int)

if not set(df["label"].unique()).issubset({0, 1}):
    raise ValueError("Labels must be 0 (legitimate) or 1 (phishing).")


# ==========================================
# 5. CREATE DOMAIN GROUPS
# ==========================================

print("Extracting registered domains...")

df["domain_group"] = df["url"].apply(get_domain_group)

print(f"Unique domain groups: {df['domain_group'].nunique():,}")


# ==========================================
# 6. PREPARE FEATURES AND TARGET
# ==========================================

# Remove URL, label and grouping column.
# has_http is removed because it is perfectly
# negatively correlated with has_https.

excluded_columns = [
    "url",
    "label",
    "domain_group",
    "has_http"
]

X = df.drop(columns=excluded_columns, errors="ignore")
y = df["label"]
groups = df["domain_group"]

feature_columns = X.columns.tolist()


# ==========================================
# 7. DOMAIN-AWARE STRATIFIED SPLITTING
# ==========================================

print("\nCreating domain-aware train/test split...")

splitter = StratifiedGroupKFold(
    n_splits=N_SPLITS,
    shuffle=True,
    random_state=RANDOM_STATE
)

# Choose the fold whose test size and class balance
# are closest to the full dataset.
best_split = None
best_score = float("inf")

overall_phishing_ratio = y.mean()

for train_indices, test_indices in splitter.split(X, y, groups):

    test_phishing_ratio = y.iloc[test_indices].mean()
    test_size_ratio = len(test_indices) / len(df)

    score = (
        abs(test_size_ratio - TEST_SIZE)
        + abs(test_phishing_ratio - overall_phishing_ratio)
    )

    if score < best_score:
        best_score = score
        best_split = (train_indices, test_indices)


if best_split is None:
    raise RuntimeError("Could not create a valid train/test split.")

train_indices, test_indices = best_split


# ==========================================
# 8. CREATE TRAINING AND TESTING DATA
# ==========================================

train_df = df.iloc[train_indices].copy()
test_df = df.iloc[test_indices].copy()

# Keep URL for later inspection, but it will not
# be used as a numerical model feature.
output_columns = ["url"] + feature_columns + ["label"]

train_df = train_df[output_columns]
test_df = test_df[output_columns]


# ==========================================
# 9. VERIFY DOMAIN SEPARATION
# ==========================================

train_domains = set(
    df.iloc[train_indices]["domain_group"]
)

test_domains = set(
    df.iloc[test_indices]["domain_group"]
)

overlapping_domains = train_domains.intersection(test_domains)

if overlapping_domains:
    raise RuntimeError(
        f"Domain leakage detected: {len(overlapping_domains)} domains overlap."
    )


# ==========================================
# 10. SAVE DATASETS
# ==========================================

train_path = OUTPUT_DIR / "train.csv"
test_path = OUTPUT_DIR / "test.csv"
features_path = OUTPUT_DIR / "feature_columns.json"

train_df.to_csv(train_path, index=False)
test_df.to_csv(test_path, index=False)

with open(features_path, "w", encoding="utf-8") as file:
    json.dump(feature_columns, file, indent=4)


# ==========================================
# 11. DISPLAY RESULTS
# ==========================================

print("\n========== DATA SPLIT RESULTS ==========")

print(f"Original records: {len(df):,}")

print("\nTraining dataset:")
print(f"Records: {len(train_df):,}")
print(f"Legitimate: {(train_df['label'] == 0).sum():,}")
print(f"Phishing: {(train_df['label'] == 1).sum():,}")
print(f"Unique domains: {len(train_domains):,}")

print("\nTesting dataset:")
print(f"Records: {len(test_df):,}")
print(f"Legitimate: {(test_df['label'] == 0).sum():,}")
print(f"Phishing: {(test_df['label'] == 1).sum():,}")
print(f"Unique domains: {len(test_domains):,}")

print("\nDataset proportions:")
print(f"Training: {len(train_df) / len(df) * 100:.2f}%")
print(f"Testing: {len(test_df) / len(df) * 100:.2f}%")

print("\nDomain leakage:")
print(f"Overlapping domains: {len(overlapping_domains)}")

print("\nFeature count:", len(feature_columns))

print("\nSaved files:")
print(train_path)
print(test_path)
print(features_path)

print("\n========== PREPARATION COMPLETED ==========")
