"""Minimal Brevo SMTP delivery for account security emails.

Credentials are read only from environment variables and are never logged.
"""
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from html import escape
from urllib.parse import urlencode, urlsplit


def _settings():
    return {
        "host": os.getenv("MAIL_SERVER", "smtp-relay.brevo.com").strip(),
        "port": int(os.getenv("MAIL_PORT") or "587"),
        "username": os.getenv("MAIL_USERNAME", "").strip(),
        "password": os.getenv("MAIL_PASSWORD", ""),
        "sender": os.getenv("MAIL_DEFAULT_SENDER", "").strip(),
        "sender_name": os.getenv("MAIL_SENDER_NAME", "PhishGuard Security").strip(),
        "base_url": os.getenv("PUBLIC_APP_URL", "").strip().rstrip("/"),
        "use_tls": os.getenv("MAIL_USE_TLS", "true").strip().lower() in ("1", "true", "yes", "on"),
    }


def is_configured():
    cfg = _settings()
    parsed = urlsplit(cfg["base_url"])
    trusted_origin = (
        parsed.scheme == "https" and bool(parsed.hostname)
        or parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")
    ) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    return bool(
        cfg["host"] and cfg["username"] and cfg["password"]
        and cfg["sender"] and trusted_origin
    )


def _send(subject, recipient, text_body, html_body):
    cfg = _settings()
    if not is_configured():
        return False
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((cfg["sender_name"], cfg["sender"]))
    message["To"] = recipient
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as smtp:
            smtp.ehlo()
            if cfg["use_tls"]:
                smtp.starttls()
                smtp.ehlo()
            smtp.login(cfg["username"], cfg["password"])
            smtp.send_message(message)
        return True
    except (OSError, smtplib.SMTPException):
        # Do not log provider responses or credentials.
        return False


def _security_email(recipient, subject, heading, intro, action_label, action_url, expiry):
    safe_heading = escape(heading)
    safe_intro = escape(intro)
    safe_label = escape(action_label)
    safe_url = escape(action_url, quote=True)
    text_body = (
        f"{heading}\n\n{intro}\n\n{action_label}: {action_url}\n\n"
        f"This link expires in {expiry}. If you did not request this, ignore this email."
    )
    html_body = f"""<!doctype html><html><body style="margin:0;background:#0b1220;color:#e8eef8;font-family:Arial,sans-serif;padding:32px">
<div style="max-width:560px;margin:auto;background:#121d30;border:1px solid #263650;border-radius:16px;padding:32px">
<div style="font-weight:700;letter-spacing:1px;color:#8fb8ff">PHISHGUARD</div>
<h1 style="font-size:24px">{safe_heading}</h1><p style="line-height:1.6;color:#c4cede">{safe_intro}</p>
<p style="margin:28px 0"><a href="{safe_url}" style="display:inline-block;background:#3678ed;color:white;text-decoration:none;padding:13px 20px;border-radius:8px;font-weight:700">{safe_label}</a></p>
<p style="font-size:13px;color:#a5b2c7">This link expires in {escape(expiry)}. If you did not request this, you can safely ignore this email.</p>
<p style="font-size:12px;color:#718096">PhishGuard Security</p></div></body></html>"""
    return _send(subject, recipient, text_body, html_body)


def send_verification_email(recipient, raw_token):
    cfg = _settings()
    url = cfg["base_url"] + "/api/auth/verify-email?" + urlencode({"token": raw_token})
    return _security_email(
        recipient, "Verify your PhishGuard email", "Verify your email address",
        "Confirm this email address to secure your PhishGuard account.",
        "Verify email", url, "24 hours"
    )


def send_password_reset_email(recipient, raw_token):
    cfg = _settings()
    # Keep the bearer token in the URL fragment so it is not sent in HTTP requests or Referer headers.
    url = cfg["base_url"] + "/#reset_token=" + raw_token
    return _security_email(
        recipient, "Reset your PhishGuard password", "Reset your password",
        "A password reset was requested for your PhishGuard account.",
        "Choose a new password", url, "30 minutes"
    )


def send_admin_password_reset_email(recipient, raw_token):
    cfg = _settings()
    url = cfg["base_url"] + "/admin/reset-password#token=" + raw_token
    return _security_email(recipient, "Reset your PhishGuard admin password",
        "Reset your admin password",
        "A password reset was requested for the PhishGuard owner account.",
        "Reset admin password", url, "30 minutes")


def send_subscription_request_email(recipient, details):
    """Notify the configured owner about a customer-initiated subscription request."""
    from html import escape
    from urllib.parse import quote
    plan = str(details.get("plan_id", "")).upper()
    fields = [
        ("Request ID", details.get("request_id")),
        ("Customer", details.get("customer_name")),
        ("Account email", details.get("customer_email")),
        ("Account ID", details.get("user_id")),
        ("Requested plan", plan),
        ("Phone", details.get("phone_number")),
        ("Preferred payment", details.get("payment_method")),
        ("Message", details.get("message") or "(none)"),
        ("Submitted at", details.get("created_at")),
    ]
    text_body = "A new PhishGuard subscription request was submitted.\n\n" + "\n".join(f"{k}: {v}" for k,v in fields)
    rows = "".join(f"<tr><th style='text-align:left;padding:8px;color:#9fb1ca'>{escape(str(k))}</th><td style='padding:8px;color:#edf3fb'>{escape(str(v))}</td></tr>" for k,v in fields)
    html_body = f"""<!doctype html><html><body style="background:#0b1220;color:#edf3fb;font-family:Arial;padding:24px"><div style="max-width:620px;margin:auto;background:#121d30;border:1px solid #263650;border-radius:14px;padding:24px"><h2>New subscription request</h2><p>A customer wants to purchase a PhishGuard subscription. Verify payment independently before activating access.</p><table style="width:100%;border-collapse:collapse">{rows}</table><p>Open the owner dashboard to review and process this request.</p></div></body></html>"""
    return _send(f"PhishGuard {plan} subscription request #{details.get('request_id')}", recipient, text_body, html_body)


def send_subscription_request_received_email(recipient, plan_id, request_id):
    subject = f"PhishGuard {str(plan_id).title()} request received"
    text_body = (
        f"We received your request #{request_id} for the {str(plan_id).title()} plan. "
        "The PhishGuard owner will contact you with payment instructions. "
        "Your plan will not change until payment is verified and the owner approves it."
    )
    html_body = f"""<!doctype html><html><body style="background:#0b1220;color:#edf3fb;font-family:Arial;padding:24px"><div style="max-width:560px;margin:auto;background:#121d30;border:1px solid #263650;border-radius:14px;padding:24px"><div style="color:#8fb8ff;font-weight:700">PHISHGUARD</div><h2>Subscription request received</h2><p>We received request <strong>#{int(request_id)}</strong> for the <strong>{escape(str(plan_id).title())}</strong> plan.</p><p>The owner will contact you with payment instructions. Your account remains on its current plan until payment is verified and your request is approved.</p></div></body></html>"""
    return _send(subject, recipient, text_body, html_body)


def send_subscription_activated_email(recipient, plan_id, period_end):
    title = str(plan_id).title()
    end_date = str(period_end)[:10]
    subject = f"Your PhishGuard {title} subscription is active"
    text_body = f"Your {title} subscription has been activated after payment verification. Your current access period ends on {end_date}. Thank you for choosing PhishGuard."
    html_body = f"""<!doctype html><html><body style="background:#0b1220;color:#edf3fb;font-family:Arial;padding:24px"><div style="max-width:560px;margin:auto;background:#121d30;border:1px solid #263650;border-radius:14px;padding:24px"><div style="color:#8fb8ff;font-weight:700">PHISHGUARD</div><h2>Your {escape(title)} plan is active</h2><p>Your payment was verified by the PhishGuard owner and your subscription is now active.</p><p>Current period ends: <strong>{escape(end_date)}</strong></p><p>You can sign in and review your plan in My Account.</p></div></body></html>"""
    return _send(subject, recipient, text_body, html_body)


def send_subscription_request_status_email(recipient, plan_id, status, note=""):
    title = str(plan_id).title()
    state = str(status).title()
    subject = f"PhishGuard {title} subscription request update"
    text_body = f"Your request for the {title} plan was {state.lower()}. Owner note: {note or 'Please contact support if you need more information.'}"
    html_body = f"""<!doctype html><html><body style="background:#0b1220;color:#edf3fb;font-family:Arial;padding:24px"><div style="max-width:560px;margin:auto;background:#121d30;border:1px solid #263650;border-radius:14px;padding:24px"><div style="color:#8fb8ff;font-weight:700">PHISHGUARD</div><h2>Subscription request {escape(state.lower())}</h2><p>Your request for the <strong>{escape(title)}</strong> plan was {escape(state.lower())}.</p><p>{escape(note or 'Please contact support if you need more information.')}</p></div></body></html>"""
    return _send(subject, recipient, text_body, html_body)
