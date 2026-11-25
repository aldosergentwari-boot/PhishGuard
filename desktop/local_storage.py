"""Persistent, device-local identity and history helpers for the desktop client."""
import os
import uuid
from pathlib import Path

from backend.database.history_service import get_history_service


def desktop_data_directory():
    """Return the per-user application data directory without extra dependencies."""
    if os.name == "nt":
        root = os.getenv("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
    else:
        root = os.getenv("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(root) / "PhishGuard"


def get_desktop_owner_id(identity_path=None):
    """Return a stable, non-secret owner key for this desktop installation."""
    path = Path(identity_path) if identity_path else desktop_data_directory() / "desktop_identity"
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        existing = path.read_text(encoding="utf-8").strip()
        identity = str(uuid.UUID(existing))
    except (OSError, ValueError, AttributeError):
        identity = str(uuid.uuid4())
        temporary = path.with_suffix(".tmp")
        temporary.write_text(identity, encoding="utf-8")
        try:
            temporary.replace(path)
        except OSError:
            if path.exists():
                temporary.unlink(missing_ok=True)
                identity = str(uuid.UUID(path.read_text(encoding="utf-8").strip()))
            else:
                raise
    return f"desktop:{identity}"


def save_desktop_scan(result, owner_id=None):
    """Persist an offline/online desktop result in the shared local history DB."""
    owner_id = owner_id or get_desktop_owner_id()
    return get_history_service().save_scan(result, owner_id=owner_id)


def get_desktop_history(limit=100, offset=0, owner_id=None):
    owner_id = owner_id or get_desktop_owner_id()
    return get_history_service().get_history(
        owner_id=owner_id, limit=limit, offset=offset
    )
