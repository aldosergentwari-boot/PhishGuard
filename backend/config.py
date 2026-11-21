import os
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

# Allow production hosts with persistent disks (for example Render) to
# store SQLite outside the deploy's ephemeral application directory.
_default_database_path = BASE_DIR / "backend" / "database" / "phishing_scans.db"
DATABASE_PATH = Path(
    os.getenv("DATABASE_PATH", str(_default_database_path))
).expanduser()
DATABASE_DIR = DATABASE_PATH.parent
