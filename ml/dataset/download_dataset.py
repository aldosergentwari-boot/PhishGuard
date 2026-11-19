
import requests
import pandas as pd
import zipfile
import io
import time
from pathlib import Path

# Dataset source
URL = (
    "https://archive.ics.uci.edu/static/public/967/"
    "phiusiil%2Bphishing%2Burl%2Bdataset.zip"
)

OUTPUT = Path("ml/dataset/urls.csv")

def download_dataset():

    print("Starting dataset download...")

    # Retry if connection fails
    for attempt in range(1, 6):

        try:
            print(f"Download attempt {attempt}/5")

            response = requests.get(
                URL,
                timeout=(30, 180)
            )

            response.raise_for_status()

            zip_data = io.BytesIO(response.content)

            # Validate ZIP file
            with zipfile.ZipFile(zip_data) as archive:

                bad_file = archive.testzip()

                if bad_file:
                    raise ValueError("ZIP file is corrupted!")

                csv_files = [
                    name for name in archive.namelist()
                    if name.lower().endswith(".csv")
                ]

                if not csv_files:
                    raise ValueError("No CSV file found!")

                print("Extracting dataset...")

                with archive.open(csv_files[0]) as file:
                    df = pd.read_csv(file)

            print("Dataset downloaded successfully!")
            return df

        except Exception as error:

            print("Download failed:", error)

            if attempt < 5:
                print("Retrying in 5 seconds...")
                time.sleep(5)

    raise RuntimeError(
        "Dataset download failed after 5 attempts."
    )


def prepare_dataset():

    df = download_dataset()

    # Locate required columns
    url_column = next(
        col for col in df.columns
        if col.lower() == "url"
    )

    label_column = next(
        col for col in df.columns
        if col.lower() == "label"
    )

    # Select URL and label
    df = df[[url_column, label_column]].copy()

    df.columns = ["url", "original_label"]

    df["url"] = df["url"].astype(str).str.strip()
    df["original_label"] = pd.to_numeric(
        df["original_label"], errors="coerce"
    )

    # Remove invalid records
    df = df.dropna()
    df = df[df["url"] != ""]
    df = df[df["original_label"].isin([0, 1])]

    # Standardize labels:
    # 1 = Phishing
    # 0 = Legitimate

    df["label"] = df["original_label"].map({
        0: 1,
        1: 0
    })

    df = df[["url", "label"]]

    # Remove duplicate URLs
    df = df.drop_duplicates(subset=["url"])

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(OUTPUT, index=False)

    print("\n========== DATASET REPORT ==========")

    print("Total URLs:", len(df))
    print("Phishing:", (df["label"] == 1).sum())
    print("Legitimate:", (df["label"] == 0).sum())

    print("\nPreview:")
    print(df.head())

    print("\nSaved to:", OUTPUT)
    print("====================================")


if __name__ == "__main__":
    prepare_dataset()