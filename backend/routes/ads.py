import os
import re

from flask import Blueprint, jsonify

ads_bp = Blueprint("ads", __name__)


@ads_bp.get("/api/ads/config")
def ads_config():
    """Expose only safe display configuration; ad scripts stay off by default."""
    client_id = os.getenv("ADSENSE_CLIENT_ID", "").strip()
    slot_id = os.getenv("ADSENSE_SLOT_ID", "").strip()
    approved = os.getenv("ADSENSE_APPROVED", "").strip().lower() in ("1", "true", "yes", "on")
    enabled = (
        approved
        and os.getenv("ADS_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
        and bool(re.fullmatch(r"ca-pub-[0-9]{10,30}", client_id))
        and bool(re.fullmatch(r"[0-9]{5,30}", slot_id))
    )
    return jsonify({
        "success": True,
        "enabled": enabled,
        "provider": "adsense" if enabled else None,
        "client_id": client_id if enabled else None,
        "slot_id": slot_id if enabled else None,
    }), 200
