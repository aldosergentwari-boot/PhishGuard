from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Primary character-level lexical model
URL_MODEL_PATH = BASE_DIR / "ml" / "models" / "url_char_model.joblib"
URL_MODEL_METADATA_PATH = BASE_DIR / "ml" / "models" / "url_char_model_metadata.json"

# Legacy model paths retained for backwards compatibility and diagnostics
MODEL_PATH = BASE_DIR / "ml" / "models" / "best_model.joblib"
METADATA_PATH = BASE_DIR / "ml" / "models" / "best_model_metadata.json"
FEATURE_COLUMNS_PATH = BASE_DIR / "ml" / "dataset" / "splits" / "feature_columns.json"

MAX_URL_LENGTH = 8192

DATABASE_DIR = BASE_DIR / "backend" / "database"
DATABASE_PATH = DATABASE_DIR / "phishing_scans.db"
