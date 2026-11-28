
from flask import Blueprint, current_app, jsonify, request, session

from backend.database.history_service import (
    get_history_service
)

from backend.services.user_identity import get_current_user_id
from backend.services.plan_service import PLAN_LIMITS, get_account_plan


history_bp = Blueprint("history", __name__)


@history_bp.route("/api/history", methods=["GET"])
def get_history():
    try:
        owner_id = get_current_user_id()

        limit = request.args.get("limit", default=20, type=int)
        offset = request.args.get("offset", default=0, type=int)
        search = request.args.get(
            "search", default="", type=str
        ).strip()
        filter_by = request.args.get(
            "filter", default="all", type=str
        )

        if limit is None or offset is None:
            return jsonify({
                "success": False,
                "error": "Limit and offset must be integers."
            }), 400

        if limit < 1 or limit > 100 or offset < 0:
            return jsonify({
                "success": False,
                "error": "Limit must be 1-100 and offset must be zero or greater."
            }), 400

        if len(search) > 300:
            return jsonify({
                "success": False,
                "error": "Search query is too long."
            }), 400

        if filter_by not in ("all", "phishing", "suspicious", "legitimate"):
            return jsonify({
                "success": False,
                "error": "Invalid history filter."
            }), 400

        account_id = session.get("account_id")
        plan_id = get_account_plan(account_id)["plan_id"] if account_id else "free"
        history_limit = PLAN_LIMITS[plan_id]["history_records"]
        service = get_history_service()
        if offset >= history_limit:
            result = service.get_history(
                owner_id=owner_id,
                limit=1,
                offset=0,
                search=search,
                filter_by=filter_by,
                max_records=history_limit
            )
            result["scans"] = []
            result["limit"] = limit
            result["offset"] = offset
        else:
            limit = min(limit, history_limit - offset)
            result = service.get_history(
                owner_id=owner_id,
                limit=limit,
                offset=offset,
                search=search,
                filter_by=filter_by,
                max_records=history_limit
            )

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception:
        current_app.logger.exception("Failed to retrieve scan history")
        return jsonify({
            "success": False,
            "error": "Could not retrieve scan history."
        }), 500


@history_bp.route("/api/history/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    try:
        owner_id = get_current_user_id()
        service = get_history_service()

        account_id = session.get("account_id")
        plan_id = get_account_plan(account_id)["plan_id"] if account_id else "free"
        history_limit = PLAN_LIMITS[plan_id]["history_records"]
        scan = service.get_scan(
            scan_id=scan_id,
            owner_id=owner_id,
            max_records=history_limit
        )

        if scan is None:
            return jsonify({
                "success": False,
                "error": "Scan not found."
            }), 404

        return jsonify({
            "success": True,
            "data": scan
        }), 200

    except Exception:
        return jsonify({
            "success": False,
            "error": "Could not retrieve scan."
        }), 500


@history_bp.route("/api/history/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    try:
        owner_id = get_current_user_id()
        service = get_history_service()

        deleted = service.delete_scan(
            scan_id=scan_id,
            owner_id=owner_id
        )

        if not deleted:
            return jsonify({
                "success": False,
                "error": "Scan not found."
            }), 404

        return jsonify({
            "success": True,
            "message": "Scan deleted successfully."
        }), 200

    except Exception:
        return jsonify({
            "success": False,
            "error": "Could not delete scan."
        }), 500


@history_bp.route("/api/history", methods=["DELETE"])
def clear_history():
    try:
        owner_id = get_current_user_id()
        service = get_history_service()

        deleted_count = service.clear_history(owner_id)

        return jsonify({
            "success": True,
            "message": "Your scan history cleared.",
            "deleted_count": deleted_count
        }), 200

    except Exception:
        return jsonify({
            "success": False,
            "error": "Could not clear scan history."
        }), 500
