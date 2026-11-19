
import pandas as pd
from urllib.parse import urlparse
from pathlib import Path

# Load dataset
DATASET_PATH = Path("ml/dataset/urls.csv")

df = pd.read_csv(DATASET_PATH)

print("\n========== DATASET ANALYSIS ==========\n")

# 1. Basic information
print("Total records:", len(df))
print("Columns:", list(df.columns))

# 2. Missing values
print("\n--- Missing Values ---")
print(df.isnull().sum())

# 3. Duplicate records
print("\n--- Duplicate URLs ---")
print(df["url"].duplicated().sum())

# 4. Class distribution
print("\n--- Class Distribution ---")

class_counts = df["label"].value_counts().sort_index()

print("Legitimate (0):", class_counts.get(0, 0))
print("Phishing (1):", class_counts.get(1, 0))

print("\nClass percentages:")
print((class_counts / len(df) * 100).round(2))

# 5. URL length analysis
df["url_length"] = df["url"].astype(str).apply(len)

print("\n--- URL Length Statistics ---")
print(df["url_length"].describe())

# 6. URL structure analysis
def extract_domain(url):
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

df["domain"] = df["url"].apply(extract_domain)

print("\n--- Domain Analysis ---")
print("Empty domains:", (df["domain"] == "").sum())

# 7. HTTPS analysis
df["has_https"] = df["url"].str.lower().str.startswith(
    "https://"
)

print("\n--- HTTPS Distribution ---")
print(
    df.groupby("label")["has_https"]
    .mean()
    .mul(100)
    .round(2)
    .rename(index={
        0: "Legitimate",
        1: "Phishing"
    })
)

# 8. Average URL length per class
print("\n--- Average URL Length ---")
print(
    df.groupby("label")["url_length"]
    .mean()
    .rename(index={
        0: "Legitimate",
        1: "Phishing"
    })
)

# 9. Sample phishing URLs
print("\n--- Phishing URL Samples ---")
print(df[df["label"] == 1]["url"].head(5).to_string(index=False))

# 10. Sample legitimate URLs
print("\n--- Legitimate URL Samples ---")
print(df[df["label"] == 0]["url"].head(5).to_string(index=False))

print("\n========== ANALYSIS COMPLETED ==========")