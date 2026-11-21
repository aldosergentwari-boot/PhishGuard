import os
import smtplib
from email.message import EmailMessage


def send_password_reset_email(recipient, reset_url):
    """Send a reset link using configured SMTP; never log or return the token."""
    host = os.getenv("SMTP_HOST")
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM")
    if not all((host, username, password, sender)):
        raise RuntimeError("Password-reset email is not configured.")

    message = EmailMessage()
    message["Subject"] = "Reset your PhishGuard password"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "A password reset was requested for your PhishGuard account.\n\n"
        f"Use this one-time link within 30 minutes: {reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )
    port = int(os.getenv("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(message)
