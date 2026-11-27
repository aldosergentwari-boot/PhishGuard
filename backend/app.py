
import os
import re
import secrets
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    Response,
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
from backend.routes.admin import admin_bp
from backend.routes.admin_management import admin_management_bp
from backend.database.auth_service import auth_service
from backend.services.financial_ledger import initialize_ledger
from datetime import timedelta
from werkzeug.middleware.proxy_fix import ProxyFix


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


def _session_cookie_secure():
    """Return whether session cookies must use the Secure attribute."""
    if os.getenv("RENDER"):
        # Render terminates HTTPS at its edge; production must stay secure.
        return True

    setting = os.getenv("SESSION_COOKIE_SECURE")
    return (
        setting.strip().lower() in ("1", "true", "yes", "on")
        if setting is not None
        else False
    )


def create_app():

    app = Flask(
        __name__,
        template_folder="../web/templates",
        static_folder="../web/static",
        static_url_path="/static"
    )

    # Render sits behind one trusted edge proxy. Normalize forwarded client IP
    # and HTTPS scheme before applying IP-based request limits.
    if os.getenv("RENDER"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    app.secret_key = _load_secret_key()

    secure_cookie = _session_cookie_secure()

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=secure_cookie,
        # Keep authenticated browsers signed in for 90 days of inactivity.
        # Flask refreshes permanent cookies on each request, so active users
        # receive a rolling expiry without weakening logout or revocation.
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
        SESSION_REFRESH_EACH_REQUEST=True
    )

    app.register_blueprint(prediction_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(ads_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(admin_management_bp)
    auth_service.initialize()
    initialize_ledger()

    def maintenance_enabled():
        return os.getenv("MAINTENANCE_MODE", "false").lower() in (
            "1", "true", "yes", "on"
        )

    @app.after_request
    def add_security_headers(response):
        """Apply baseline browser security headers to every web response."""
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()"
        )

        # Render serves the public application over HTTPS at its edge.
        if os.getenv("RENDER"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000"
            )

        return response

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

    @app.route("/ads.txt")
    def ads_txt():
        """Serve Google's authorized-seller declaration from the site root."""
        client_id = os.getenv("ADSENSE_CLIENT_ID", "").strip()
        if not re.fullmatch(r"ca-pub-[0-9]{10,30}", client_id):
            return Response("AdSense publisher ID is not configured.\n", status=404, mimetype="text/plain")
        publisher_id = client_id.removeprefix("ca-")
        return Response(
            f"google.com, {publisher_id}, DIRECT, f08c47fec0942fa0\n",
            mimetype="text/plain",
        )

    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("index.html")


    def render_legal_page(page_title, page_description, sections):
        support_email = os.getenv("PUBLIC_SUPPORT_EMAIL", "").strip() or "aldosergentwari@gmail.com"
        return render_template(
            "legal.html",
            page_title=page_title,
            page_description=page_description,
            sections=sections,
            updated_date="November 25, 2026",
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
                        "When you create an account, PhishGuard processes your email address and a securely hashed password. If you choose to add profile details, the service also stores your username, full name and profile picture so they can be displayed in your account. Profile pictures are stored with the account data.",
                        "When you scan a URL, the submitted URL, its analysis result and scan timestamp may be stored in the scan-history and usage records. Do not place passwords, private access tokens, session identifiers or other secrets inside a URL submitted for analysis.",
                    ],
                    "bullets": [
                        "Account details such as email address, password hash, username, full name and optional profile picture.",
                        "Submitted URLs, scan results, timestamps, and scan-history records.",
                        "Session and browser identifiers needed for authentication and history.",
                        "Plan, monthly scan-usage, administrator-set scan-limit and bonus-credit records.",
                        "Payment transaction references and status information needed to operate paid plans; full card numbers and Mobile Money PINs are not required by PhishGuard.",
                    ],
                },
                {
                    "heading": "Offline and online scanning",
                    "paragraphs": [
                        "In Offline mode, URL analysis uses the model and local rules available to the PhishGuard application server. The submitted URL is not sent to external online reputation providers by that scan mode. The browser may still communicate with the PhishGuard server for authentication, scan processing, history, account limits and other enabled application features; Offline mode does not mean that the entire website runs without a network connection.",
                        "If you deliberately enable Online mode and the relevant providers are configured, PhishGuard may send the submitted URL to Google Safe Browsing and URLhaus for reputation checks. Domain-age checks send the domain name to RDAP. The OpenPhish community feed is downloaded by the service and compared locally. Those providers process requests under their own terms and privacy practices.",
                    ],
                },
                {
                    "heading": "Email, payments, and advertising providers",
                    "paragraphs": [
                        "Brevo is used to deliver account-verification and password-reset emails. New paid checkout is currently unavailable while PhishGuard completes merchant onboarding and its approved payment integration. Legacy Flutterwave and PalmKash handlers are retained only for verification and audit of older transactions; they are not offered for new purchases. PhishGuard does not receive or store full card numbers or Mobile Money PINs.",
                        "Google AdSense scripts are not loaded unless the publisher is approved, the required configuration is enabled, and a visitor explicitly accepts the advertising-consent prompt. Visitors can reject optional advertising and continue using PhishGuard. If accepted, Google may use cookies or similar technologies according to its own policies and applicable consent requirements.",
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
                        "Account, profile, scan-history, scan-usage and security records are retained for as long as reasonably necessary to operate the service, enforce monthly limits, investigate abuse, maintain audit trails and meet payment or legal obligations. Retention periods may vary by record type and deployment. Deleting a browser session does not delete server-side records.",
                        "You can use Offline mode to avoid sending scanned URLs to external reputation providers. You may update profile details through your account where those controls are available. For privacy questions or requests concerning personal information, contact the service using the official support address shown below. Requests may be subject to identity verification and applicable legal requirements.",
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
                        "You must not attempt to bypass account, scan, rate or security limits; disrupt the service; probe accounts or infrastructure without authorization; or use the platform to facilitate phishing, fraud, malware distribution or other harmful activity.",
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
                        "Where enabled, card payments are processed by Flutterwave and Rwanda MTN MoMo/Airtel Money collections may be processed by PalmKash. Current paid subscriptions use one-time payments and manual renewal; automatic recurring billing is not enabled. Access lasts for the period stated for the purchased plan, subject to successful server-side payment verification.",
                        "Refunds, cancellation, and payment disputes are subject to the payment provider's rules and applicable consumer-protection laws. The site owner must publish a clear refund and cancellation process before accepting public payments.",
                        "Monthly scan allowances are based on the plan shown in your account. The service owner may apply an individual account limit or grant additional bonus scans for support or operational reasons. Bonus scans are added to the applicable monthly limit and may expire at the date shown by the service. A customized account limit remains in effect until it is changed or reset. Scan counters use the UTC calendar month unless the application states otherwise.",
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
                        "A PHISHING classification is an automated warning based on available signals and may require independent review. Both false positives and false negatives are possible. Risk scores and confidence values are estimates, not probabilities or guarantees unless explicitly defined by the product.",
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
                        "An ordinary URL scan analyzes the submitted address and available reputation signals; it is not a full penetration test, malware sandbox, content review or certification of the destination website. Do not treat a successful scan as permission to open an unfamiliar link or enter sensitive information.",
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
