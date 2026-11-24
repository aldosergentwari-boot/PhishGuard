"""Minimal Brevo SMTP delivery for account security emails.

Credentials are read only from environment variables and are never logged.
"""
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from html import escape


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
    trusted_origin = (
        cfg["base_url"].startswith("https://")
        or cfg["base_url"].startswith("http://127.0.0.1")
        or cfg["base_url"].startswith("http://localhost")
    )
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
