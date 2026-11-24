import hashlib
import hmac

from flask import Blueprint, request, jsonify, session, current_app
from urllib.parse import urlparse
import ipaddress

import tldextract

from backend.config import MAX_URL_LENGTH
from backend.services.model_service import get_model_service
from backend.services.hybrid_service import get_hybrid_service
from backend.services.threat_intelligence import get_threat_intelligence_service
from backend.services.user_identity import get_current_user_id
from backend.database.auth_service import auth_service
from backend.database.history_service import (
    get_history_service
)


prediction_bp = Blueprint(
    "prediction",
    __name__
)


_extractor = tldextract.TLDExtract(suffix_list_urls=())  # offline copy of the public-suffix list


def looks_like_real_host(hostname):
    """True for an IP address or a name with a real ending (.com, .rw, .co.uk ...)."""
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        pass
    parts = _extractor(hostname)
    return bool(parts.domain and parts.suffix)


def validate_url(url):

    if not isinstance(url, str):

        return False, "URL must be a string."

    url = url.strip()

    if not url:

        return False, "URL cannot be empty."

    if len(url) > MAX_URL_LENGTH:

        return False, "URL is too long."

    if any(char.isspace() for char in url):

        return False, "URL must not contain whitespace."

    try:

        parsed = urlparse(url)

        # Support URLs without an explicit scheme
        if not parsed.netloc:

            parsed = urlparse("//" + url)

        if parsed.scheme and parsed.scheme.lower() not in [
            "http",
            "https"
        ]:

            return False, "Only HTTP and HTTPS URLs are supported."

        if not parsed.hostname:

            return False, "A valid hostname is required."

        # "hello", "bank", "localhost", "a.b" are not domains: do not classify them
        if not looks_like_real_host(parsed.hostname):

            return False, "Enter a real domain or URL, for example example.com"

        # Reject embedded usernames and passwords
        if parsed.username or parsed.password:

            return False, "URLs containing embedded credentials are not supported."

        # Validate port syntax
        _ = parsed.port

        return True, None

    except ValueError:

        return False, "Invalid URL format."


def parse_mode(data):
    """Read the optional "mode" field.

    Returns (online, error_message). Missing mode means "offline" so that
    no network request is ever made unless the client asks for it.
    """
    mode = data.get("mode", "offline")

    if not isinstance(mode, str) or mode.strip().lower() not in (
        "offline",
        "online"
    ):
        return False, 'The mode field must be "offline" or "online".'

    return mode.strip().lower() == "online", None




def _scan_rate_limit_exceeded(owner_id, remote_addr=None):
    """Limit both a client IP and its signed-in account/browser identity."""
    secret = str(current_app.secret_key).encode("utf-8")

    if remote_addr:
        ip_digest = hmac.new(
            secret, str(remote_addr).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not auth_service.allow_scan_attempt(
            f"scan-ip:{ip_digest}",
            limit=300,
            window_seconds=60,
        ):
            return True

    identity_digest = hmac.new(
        secret, str(owner_id).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return not auth_service.allow_scan_attempt(
        f"scan-identity:{identity_digest}",
        limit=30,
        window_seconds=60,
    )


def _rate_limit_response():
    response = jsonify({
        "success": False,
        "error": "Too many scan requests. Please wait before trying again.",
        "code": "RATE_LIMIT_EXCEEDED",
    })
    response.headers["Retry-After"] = "60"
    return response, 429

@prediction_bp.route(
    "/api/predict",
    methods=["POST"]
)
def predict_url():

    # Read JSON request
    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "error": "A valid JSON object is required."
        }), 400

    if "url" not in data:

        return jsonify({
            "success": False,
            "error": "The url field is required."
        }), 400

    url = data["url"]

    valid, error_message = validate_url(url)

    if not valid:

        return jsonify({
            "success": False,
            "error": error_message
        }), 400

    url = url.strip()

    online, mode_error = parse_mode(data)

    if mode_error:

        return jsonify({
            "success": False,
            "error": mode_error
        }), 400

    try:
        owner_id = get_current_user_id()
        if _scan_rate_limit_exceeded(owner_id, request.remote_addr):
            return _rate_limit_response()

        account_id = session.get("account_id")
        from backend.services.plan_service import can_scan, get_account_plan
        plan_id = get_account_plan(account_id)["plan_id"] if account_id else "free"
        allowed, usage = can_scan(owner_id, plan_id)
        if not allowed:
            return jsonify({
                "success": False,
                "error": "You have reached this plan's monthly scan limit. Upgrade your plan to continue.",
                "code": "SCAN_LIMIT_REACHED",
                "usage": usage,
                "plan": plan_id
            }), 429

        service = get_hybrid_service()
        analysis = service.analyze(url, online=online)
        result = dict(analysis["ml_result"])
        result.update({
            "prediction": analysis["final_prediction"],
            "risk_score": analysis["final_risk_score"],
            "final_prediction": analysis["final_prediction"],
            "decision_sources": analysis["decision_sources"],
            "threat_intelligence": analysis["threat_intelligence"],
            "detection_mode": analysis["detection_mode"],
            "indicators": analysis["indicators"],
            "message": analysis["message"],
        })

        scan_id = get_history_service().save_scan(analysis, owner_id=owner_id)
        result["scan_id"] = scan_id
        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception:

        # Avoid exposing internal errors to API users
        return jsonify({
            "success": False,
            "error": "Prediction failed. Check the server logs."
        }), 500


@prediction_bp.route(
    "/api/status",
    methods=["GET"]
)
def online_status():
    """Tell the dashboard whether the internet is reachable and which online
    sources are ready. No URL is sent or received here."""

    service = get_threat_intelligence_service()

    return jsonify({
        "success": True,
        "internet": service.is_online(),
        "providers": service.provider_overview()
    }), 200


@prediction_bp.route(
    "/api/health",
    methods=["GET"]
)
def health_check():

    try:

        service = get_model_service()
        from backend.services.threat_intelligence import get_threat_intelligence_service
        threat_service = get_threat_intelligence_service()

        return jsonify({
            "status": "healthy",
            "model_loaded": service.model is not None,
            "model": service.metadata.get("model_name", "Phishing URL Detection Model"),
            "model_version": service.metadata.get("model_version"),
            "online_threat_intelligence_configured": threat_service.configured,
        }), 200

    except Exception:

        return jsonify({
            "status": "unhealthy",
            "model_loaded": False
        }), 503
    
@prediction_bp.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze_url():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "error": "A valid JSON object is required."
        }), 400

    if "url" not in data:

        return jsonify({
            "success": False,
            "error": "The url field is required."
        }), 400

    url = data["url"]

    valid, error_message = validate_url(url)

    if not valid:

        return jsonify({
            "success": False,
            "error": error_message
        }), 400

    online, mode_error = parse_mode(data)

    if mode_error:

        return jsonify({
            "success": False,
            "error": mode_error
        }), 400

    try:

        owner_id = get_current_user_id()
        if _scan_rate_limit_exceeded(owner_id, request.remote_addr):
            return _rate_limit_response()

        account_id = session.get("account_id")
        from backend.services.plan_service import can_scan, get_account_plan
        plan_id = get_account_plan(account_id)["plan_id"] if account_id else "free"
        allowed, usage = can_scan(owner_id, plan_id)
        if not allowed:
            return jsonify({
                "success": False,
                "error": "You have reached this plan's monthly scan limit. Upgrade your plan to continue.",
                "code": "SCAN_LIMIT_REACHED",
                "usage": usage,
                "plan": plan_id
            }), 429
    
    
        service = get_hybrid_service()

        result = service.analyze(url.strip(), online=online)

        # Save scan under the current browser's identity
        history_service = get_history_service()
        owner_id = get_current_user_id()
        scan_id = history_service.save_scan(
            result,
            owner_id=owner_id
        )

        # Return the saved scan's id so the client can refer to it later.
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "data": result
        }), 200
    
    except Exception:

        return jsonify({
            "success": False,
            "error": "Offline analysis failed. Check server logs."
        }), 500