
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
from backend.routes.auth import auth_bp
from backend.routes.billing import billing_bp
from backend.routes.ads import ads_bp
from backend.database.auth_service import auth_service
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
    app.register_blueprint(auth_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(ads_bp)
    auth_service.initialize()

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

    def render_legal_page(page_title, page_description, sections):
        support_email = os.getenv("PUBLIC_SUPPORT_EMAIL", "").strip()
        return render_template(
            "legal.html",
            page_title=page_title,
            page_description=page_description,
            sections=sections,
            updated_date="November 24, 2026",
            support_email=support_email or "Official support email not configured yet.",
            show_setup_notice=not bool(support_email),
        )

    @app.route("/privacy")
    def privacy_policy():
        return render_legal_page(
            "Privacy Policy",
            "How PhishGuard handles account, scan, and service information.",
            [
                {
                    "heading": "Information we handle",
                    "paragraphs": [
                        "When you create an account, PhishGuard processes your email address and a securely hashed password. The web application also uses session and browser-identity information to keep you signed in and associate scan history with your account.",
                        "When you scan a URL, the submitted URL and its analysis result may be stored in the scan history database. Do not submit passwords, private access tokens, or other secrets as part of a URL.",
                    ],
                    "bullets": [
                        "Account details such as email address and password hash.",
                        "Submitted URLs, scan results, timestamps, and scan-history records.",
                        "Session and browser identifiers needed for authentication and history.",
                        "Plan, usage, and payment-transaction references needed to operate subscriptions.",
                    ],
                },
                {
                    "heading": "Offline and online scanning",
                    "paragraphs": [
                        "Offline mode processes URL analysis using the local model and local rules and does not send the submitted URL to online reputation providers. The app may still communicate with its own server to use account and scan-history features.",
                        "If you deliberately enable Online mode and configure the relevant providers, PhishGuard may send the submitted URL to Google Safe Browsing and URLhaus for reputation checks. Domain-age checks send the domain name to RDAP. The OpenPhish community feed is downloaded by the service and compared locally. Provider terms and privacy practices also apply.",
                    ],
                },
                {
                    "heading": "Email, payments, and advertising providers",
                    "paragraphs": [
                        "Brevo is used to deliver account-verification and password-reset emails. Flutterwave processes hosted checkout and payment information when paid plans are available. PhishGuard does not need to receive or store your full card number or Mobile Money PIN.",
                        "Google AdSense scripts are not loaded unless publisher approval and the required configuration are enabled. When enabled, Google may use cookies or similar technologies according to its own policies and applicable consent requirements.",
                    ],
                },
                {
                    "heading": "Cookies, storage, and security",
                    "paragraphs": [
                        "The web app uses a signed session cookie to maintain authentication and a browser identity. Session cookies are configured as HttpOnly and SameSite=Lax; production HTTPS deployments should use Secure cookies.",
                        "Passwords are stored as password hashes, not plaintext. Email verification and password-reset tokens are random, single-use tokens; the database stores their SHA-256 digests rather than the raw tokens.",
                        "We use reasonable technical safeguards, but no internet service or storage system can be guaranteed completely secure.",
                    ],
                },
                {
                    "heading": "Retention and your choices",
                    "paragraphs": [
                        "Account and scan-history information is retained as needed to provide the service, enforce plan limits, maintain security, and handle payment records. Exact retention periods depend on the deployment and operational requirements; do not assume that deleting a browser session deletes server-side records.",
                        "You can use Offline mode to avoid sending scanned URLs to external reputation providers. For questions or requests concerning personal information, contact the service using the official support address shown below.",
                    ],
                },
                {
                    "heading": "Changes and contact",
                    "paragraphs": [
                        "This policy may be updated as PhishGuard adds features or changes providers. The last-updated date above identifies the current published version. The site owner should review this policy against the laws that apply to the business and its users before public launch.",
                    ],
                },
            ],
        )

    @app.route("/terms")
    def terms_of_service():
        return render_legal_page(
            "Terms of Service",
            "Terms for using the PhishGuard phishing URL analysis service.",
            [
                {
                    "heading": "Acceptable use",
                    "paragraphs": [
                        "You may use PhishGuard to assess URLs for defensive, educational, and legitimate security purposes. You must not use the service to attack systems, distribute malware, access accounts without permission, interfere with the service, or violate applicable laws or third-party rights.",
                        "You are responsible for the URLs you submit and for ensuring that you have the right to submit them for analysis.",
                    ],
                },
                {
                    "heading": "What PhishGuard does and does not promise",
                    "paragraphs": [
                        "PhishGuard combines a machine-learning model, local security rules, and optional third-party threat-intelligence lookups. Results are estimates based on the data and checks available at the time of scanning.",
                        "A LEGITIMATE result does not prove that a website is safe, and a PHISHING result may require further investigation. Do not rely on PhishGuard as the only security control or enter credentials or payment details solely because a URL receives a low risk score.",
                    ],
                },
                {
                    "heading": "Accounts and security",
                    "paragraphs": [
                        "You must provide an email address you control, keep your sign-in credentials confidential, and notify the service if you suspect unauthorized account use. You are responsible for activity performed through your account, subject to applicable law.",
                        "Email verification and password reset links are time-limited and single-use. Anyone with access to an active reset link may be able to change the associated password; keep such links private.",
                    ],
                },
                {
                    "heading": "Plans, billing, and cancellation",
                    "paragraphs": [
                        "The Free plan is available at no charge and has usage limits displayed in the application. Paid plans and their current prices and limits are displayed on the pricing page.",
                        "Where Flutterwave checkout is enabled, payments are processed by Flutterwave. Current paid subscriptions use one-time payments and manual renewal; automatic recurring billing is not enabled. Access lasts for the period stated for the purchased plan, subject to successful payment verification.",
                        "Refunds, cancellation, and payment disputes are subject to the payment provider's rules and applicable consumer-protection laws. The site owner must publish a clear refund and cancellation process before accepting public payments.",
                    ],
                },
                {
                    "heading": "Availability and changes",
                    "paragraphs": [
                        "The service may be updated, interrupted, or discontinued for maintenance, security, or operational reasons. Plan limits, supported providers, and features may change; material changes should be communicated as required by applicable law.",
                        "To the extent permitted by law, PhishGuard is provided on an as-available basis. Nothing in these terms excludes consumer rights or liability that cannot legally be excluded.",
                    ],
                },
                {
                    "heading": "Contact and governing law",
                    "paragraphs": [
                        "Questions about these terms should be sent to the official support contact shown below. The site owner must specify the operating legal entity and governing-law details after obtaining appropriate legal advice; this template does not select a jurisdiction.",
                    ],
                },
            ],
        )

    @app.route("/security-disclaimer")
    def security_disclaimer():
        return render_legal_page(
            "Security Disclaimer",
            "Important limitations and safe-use guidance for PhishGuard scan results.",
            [
                {
                    "heading": "Detection is not a guarantee",
                    "paragraphs": [
                        "PhishGuard is a defensive URL-analysis aid, not a guarantee of website safety. Threats change rapidly, new phishing domains appear continuously, and no model, blocklist, or reputation provider detects every malicious URL.",
                        "A LEGITIMATE classification means only that the currently available checks did not identify a threat. It does not certify the website, its owner, its content, or its payment forms as trustworthy.",
                    ],
                },
                {
                    "heading": "Use multiple safeguards",
                    "bullets": [
                        "Check the domain spelling and the website address carefully.",
                        "Do not enter passwords, one-time codes, or payment details on unfamiliar pages.",
                        "Use multi-factor authentication and keep your browser and operating system updated.",
                        "Report suspected phishing to the relevant service provider or security team.",
                        "Treat unexpected links and attachments as suspicious even when a scan reports a low risk score.",
                    ],
                },
                {
                    "heading": "Third-party intelligence",
                    "paragraphs": [
                        "Online reputation checks depend on external providers and may be unavailable, delayed, incomplete, or subject to their own terms. When Online mode is enabled, submitted URL or domain information may be shared with the providers described in the Privacy Policy.",
                    ],
                },
                {
                    "heading": "No professional security guarantee",
                    "paragraphs": [
                        "PhishGuard does not replace a professional security assessment, incident-response service, legal advice, or an organization's security controls. You remain responsible for decisions made using scan results.",
                    ],
                },
            ],
        )

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
