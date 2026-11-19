import ipaddress
import math
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pandas as pd


# ==========================================
# CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parents[2]
INPUT_FILE = BASE_DIR / "ml" / "dataset" / "urls.csv"
OUTPUT_FILE = BASE_DIR / "ml" / "dataset" / "features.csv"

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure",
    "update", "password", "signin", "banking",
    "confirm", "wallet", "authenticate",
    "suspend", "recover", "payment"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "shorturl.at"
]


# ==========================================
# URL NORMALIZATION
# ==========================================

def normalize_url(url):
    """
    Create the canonical URL used by BOTH training and prediction.

    - Add https:// only when the user omitted a scheme.
    - Preserve an explicitly supplied http:// or https:// scheme.
    - Remove www. from the hostname only.
    - Preserve port, path, query and fragment.
    """

    value = str(url).strip()

    if not value or value.lower() == "nan":
        return ""

    if value.startswith("//"):
        value = "https:" + value
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return value

        while hostname.startswith("www."):
            hostname = hostname[4:]

        userinfo = ""
        if "@" in parsed.netloc:
            userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"

        port = ""
        try:
            if parsed.port is not None:
                port = f":{parsed.port}"
        except ValueError:
            pass

        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        netloc = userinfo + hostname + port

        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment
        ))

    except Exception:
        return value


def model_input(url):
    """
    What the ML model is allowed to see: the HOSTNAME only (no scheme, path, query).

    Why: in the training dataset every legitimate URL is a bare root domain
    (no path, no query, always https), so a model trained on full URLs learns
    "has a path / is http  =>  phishing". Using only the hostname removes that shortcut.
    """
    try:
        host = (urlsplit(normalize_url(url)).hostname or "").lower()
    except Exception:
        host = ""
    while host.startswith("www."):
        host = host[4:]
    return host


def parse_url(url):
    """Parse a URL using the same canonicalization as feature extraction."""
    try:
        return urlsplit(normalize_url(url))
    except Exception:
        return urlsplit("")


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    entropy = 0.0

    for char in set(text):
        probability = text.count(char) / len(text)
        entropy -= probability * math.log2(probability)

    return entropy


def is_ip_address(hostname):
    """Check whether hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return 1
    except ValueError:
        return 0


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def extract_features(url):
    """
    Extract features from the canonical URL.

    IMPORTANT:
    This exact function is used for dataset generation and live prediction.
    """

    normalized_url = normalize_url(url)
    parsed = parse_url(normalized_url)

    hostname = (parsed.hostname or "").lower()
    domain_parts = hostname.split(".") if hostname else []

    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = normalized_url.lower()

    subdomains = [
        part for part in domain_parts[:-2]
        if part and part != "www"
    ]

    suspicious_count = sum(
        1 for word in SUSPICIOUS_WORDS
        if word in url_lower
    )

    is_shortened = any(
        hostname == shortener
        or hostname.endswith("." + shortener)
        for shortener in URL_SHORTENERS
    )

    query_params = (
        len([part for part in query.split("&") if part])
        if query else 0
    )

    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 0

    return {
        "url_length": len(normalized_url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": normalized_url.count("."),
        "num_hyphens": normalized_url.count("-"),
        "num_underscores": normalized_url.count("_"),
        "num_digits": sum(char.isdigit() for char in normalized_url),
        "num_subdomains": len(subdomains),
        "has_ip": is_ip_address(hostname),
        "has_at_symbol": int("@" in normalized_url),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_http": int(parsed.scheme.lower() == "http"),
        "has_suspicious_words": int(suspicious_count > 0),
        "suspicious_word_count": suspicious_count,
        "num_query_params": query_params,
        "has_port": has_port,
        "num_special_chars": len(
            re.findall(r"[^a-zA-Z0-9]", normalized_url)
        ),
        "uses_shortener": int(is_shortened),
        "has_double_slash": int("//" in path),
        "has_percent_encoding": int("%" in normalized_url),
        "has_punycode": int("xn--" in hostname),
        "url_entropy": calculate_entropy(normalized_url),
        "domain_entropy": calculate_entropy(hostname)
    }


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():
    print("Starting canonical feature extraction...")

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE)

    required_columns = {"url", "label"}
    if not required_columns.issubset(df.columns):
        raise ValueError("Dataset must contain url and label columns.")

    if df["url"].isna().any() or df["label"].isna().any():
        raise ValueError("Dataset contains missing URLs or labels.")

    print("Total URLs:", len(df))

    feature_data = []

    for index, url in enumerate(df["url"]):
        feature_data.append(extract_features(url))

        if (index + 1) % 25000 == 0:
            print(f"Processed {index + 1}/{len(df)} URLs")

    features_df = pd.DataFrame(feature_data)

    result = pd.concat(
        [
            df[["url", "label"]].reset_index(drop=True),
            features_df.reset_index(drop=True)
        ],
        axis=1
    )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT_FILE, index=False)

    print("\n========== FEATURE EXTRACTION REPORT ==========")
    print("Total URLs:", len(result))
    print("Total features:", len(features_df.columns))
    print("Missing values:", int(features_df.isnull().sum().sum()))
    print("Output saved to:", OUTPUT_FILE)
    print("\nFEATURE EXTRACTION COMPLETED!")


if __name__ == "__main__":
    main()
