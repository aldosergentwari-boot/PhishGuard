import os
import re

from flask import Blueprint, jsonify

ads_bp = Blueprint("ads", __name__)


def _enabled(name):
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


@ads_bp.get("/api/ads/config")
def ads_config():
    """Expose safe ad settings only after publisher and consent setup are verified.

    ADS_CONSENT_CONFIGURED is an explicit operator gate: set it only after a
    Google-certified TCF CMP is installed and tested on every public page.
    The browser independently requires a valid TCF consent signal before it
    requests the AdSense script. Missing or broken CMP integrations fail closed.
    """
    client_id = os.getenv("ADSENSE_CLIENT_ID", "").strip()
    slot_id = os.getenv("ADSENSE_SLOT_ID", "").strip()
    consent_configured = _enabled("ADS_CONSENT_CONFIGURED")
    enabled = (
        _enabled("ADS_ENABLED")
        and _enabled("ADSENSE_APPROVED")
        and consent_configured
        and bool(re.fullmatch(r"ca-pub-[0-9]{10,30}", client_id))
        and bool(re.fullmatch(r"[0-9]{5,30}", slot_id))
    )
    return jsonify({
        "success": True,
        "enabled": enabled,
        "provider": "adsense" if enabled else None,
        "client_id": client_id if enabled else None,
        "slot_id": slot_id if enabled else None,
        "consent_configured": consent_configured,
    }), 200
