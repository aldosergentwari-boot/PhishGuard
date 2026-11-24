
import os
import secrets
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    render_template,
    render_template_string,
    request,
    redirect,
    session,
)

from backend.routes.prediction import prediction_bp
from backend.routes.history import history_bp
from datetime import timedelta


LOCAL_SECRET_KEY_PATH = Path(__file__).resolve().parents[1] / ".phishguard_secret_key"


def _load_secret_key():
    """Use a stable local key so browser identities survive app restarts.

    Production deployments must supply SECRET_KEY through the environment.
    The local key file is ignored by Git and must never be committed.
    """
    configured_key = os.getenv("SECRET_KEY", "").strip()
    if configured_key:
        return configured_key

    if os.getenv("RENDER"):
        raise RuntimeError("SECRET_KEY must be configured on Render.")

    try:
        return LOCAL_SECRET_KEY_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        LOCAL_SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        generated_key = secrets.token_hex(32)
        try:
            with LOCAL_SECRET_KEY_PATH.open("x", encoding="utf-8") as file:
                file.write(generated_key)
            return generated_key
        except FileExistsError:
            return LOCAL_SECRET_KEY_PATH.read_text(encoding="utf-8").strip()


MAINTENANCE_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>PhishGuard | Under Maintenance</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            background: #080d18;
            color: #f5f7fb;
            font-family: Arial, sans-serif;
        }

        .maintenance-card {
            width: 100%;
            max-width: 580px;
            padding: 48px 32px;
            text-align: center;
            background: #111a2b;
            border: 1px solid #26334a;
            border-radius: 20px;
        }

        .icon {
            width: 76px;
            height: 76px;
            display: grid;
            place-items: center;
            margin: 0 auto 26px;
            border-radius: 50%;
            background: #f59e0b20;
            color: #fbbf24;
            font-size: 36px;
        }

        h1 {
            margin-bottom: 16px;
            font-size: 30px;
        }

        p {
            color: #aab6ca;
            line-height: 1.7;
            font-size: 15px;
        }

        .status {
            display: inline-block;
            margin-top: 26px;
            padding: 9px 15px;
            border: 1px solid #f59e0b55;
            border-radius: 30px;
            color: #fbbf24;
            font-size: 12px;
            letter-spacing: 1px;
        }

        footer {
            margin-top: 36px;
            color: #718096;
            font-size: 12px;
        }

        strong {
            color: #fff;
        }
    </style>
</head>
<body>
    <main class="maintenance-card">
        <div class="icon">⚙</div>

        <h1>We're Working on Something</h1>

        <p>
            <strong>PhishGuard</strong> is currently undergoing
            development and improvements.
        </p>

        <p style="margin-top: 12px;">
            We'll be back online soon. Thank you for your patience.
        </p>

        <div class="status">SYSTEM UNDER MAINTENANCE</div>

        <footer>© PhishGuard — AI-Based Phishing Detection System</footer>
    </main>
</body>
</html>
"""


def create_app():

    app = Flask(
        __name__,
        template_folder="../web/templates",
        static_folder="../web/static",
        static_url_path="/static"
    )

    app.secret_key = _load_secret_key()

    secure_cookie_default = bool(os.getenv("RENDER"))
    secure_cookie_setting = os.getenv("SESSION_COOKIE_SECURE")
    secure_cookie = (
        secure_cookie_default
        if secure_cookie_setting is None
        else secure_cookie_setting.strip().lower() in ("1", "true", "yes", "on")
    )

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=secure_cookie,
        # Browser identities are persistent, but should not live for a year.
        PERMANENT_SESSION_LIFETIME=timedelta(days=30)
    )

    app.register_blueprint(prediction_bp)
    app.register_blueprint(history_bp)

    def maintenance_enabled():
        return os.getenv("MAINTENANCE_MODE", "false").lower() in (
            "1", "true", "yes", "on"
        )

    @app.before_request
    def protect_public_website():

        if not maintenance_enabled():
            return None

        # Allow the maintenance page and its static resources.
        if request.endpoint == "static":
            return None

        # Allow the owner to leave preview mode.
        if request.args.get("exit_preview") == "1":
            session.pop("phishguard_preview", None)
            return redirect(request.path)

        # Owner already authenticated for preview.
        if session.get("phishguard_preview") is True:
            return None

        # Allow the owner to enter preview mode using a private token.
        supplied_token = request.args.get("preview", "")
        preview_token = os.getenv("PREVIEW_TOKEN", "")

        if (
            preview_token
            and supplied_token
            and secrets.compare_digest(supplied_token, preview_token)
        ):
            session["phishguard_preview"] = True
            return redirect(request.path)

        # Everyone else sees the maintenance page.
        return (
            render_template_string(MAINTENANCE_PAGE),
            503,
            {"Retry-After": "3600"}
        )

    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("index.html")

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "Resource not found."
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "success": False,
            "error": "Method not allowed."
        }), 405

    return app


app = create_app()


if __name__ == "__main__":
    # By default the app is reachable only from this computer.
    # To open it from a phone on the same Wi-Fi, set PHISHGUARD_HOST=0.0.0.0
    # (see .env.example). The debugger is switched off in that case, because
    # it would let anybody on the network run code on this computer.
    host = os.getenv("PHISHGUARD_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.getenv("PHISHGUARD_PORT", "5000"))

    app.run(
        host=host,
        port=port,
        debug=host in ("127.0.0.1", "localhost")
    )
