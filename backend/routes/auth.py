from flask import Blueprint, jsonify, request, session
from backend.database.auth_service import auth_service
from backend.services.user_identity import get_browser_identity

auth_bp = Blueprint("auth", __name__)


def _payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@auth_bp.post("/api/auth/register")
def register():
    data = _payload()
    try:
        user = auth_service.create_user(data.get("email"), data.get("password"))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    # Move only this browser's anonymous scans into the new account.
    anonymous_id = get_browser_identity()
    account_owner = f"account:{user['id']}"
    from backend.database.history_service import get_history_service
    service = get_history_service()
    with service.get_connection() as db:
        db.execute(
            "UPDATE scan_history SET owner_id = ? WHERE owner_id = ?",
            (account_owner, anonymous_id)
        )

    session.clear()
    session["account_id"] = user["id"]
    session["account_email"] = user["email"]
    session.permanent = True
    return jsonify({"success": True, "user": user}), 201


@auth_bp.post("/api/auth/login")
def login():
    data = _payload()
    user = auth_service.authenticate(data.get("email"), data.get("password"))
    if not user:
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    anonymous_id = get_current_user_id()
    account_owner = f"account:{user['id']}"
    from backend.database.history_service import get_history_service
    service = get_history_service()
    with service.get_connection() as db:
        db.execute(
            "UPDATE scan_history SET owner_id = ? WHERE owner_id = ?",
            (account_owner, anonymous_id)
        )

    session.clear()
    session["account_id"] = user["id"]
    session["account_email"] = user["email"]
    session.permanent = True
    return jsonify({"success": True, "user": user}), 200


@auth_bp.get("/api/auth/me")
def current_user():
    user_id = session.get("account_id")
    if not user_id:
        return jsonify({"success": True, "authenticated": False, "user": None}), 200
    user = auth_service.get_user(user_id)
    if not user:
        session.clear()
        return jsonify({"success": True, "authenticated": False, "user": None}), 200
    return jsonify({"success": True, "authenticated": True, "user": user}), 200


@auth_bp.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out."}), 200
