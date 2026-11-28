from pathlib import Path

from backend.services import email_service


def test_subscription_request_email_is_formal_and_replyable(monkeypatch):
    captured = {}

    def fake_send(subject, recipient, text_body, html_body, reply_to=None):
        captured.update(
            subject=subject,
            recipient=recipient,
            text_body=text_body,
            html_body=html_body,
            reply_to=reply_to,
        )
        return True

    monkeypatch.setattr(email_service, "_send", fake_send)
    sent = email_service.send_subscription_request_email(
        "owner@example.com",
        {
            "request_id": 42,
            "plan_id": "business",
            "customer_name": "Example Customer",
            "customer_email": "customer@example.com",
            "user_id": 7,
            "phone_number": "+250700000000",
            "payment_method": "mtn_momo",
            "message": "Please share payment instructions.",
        },
    )

    assert sent is True
    assert captured["recipient"] == "owner@example.com"
    assert captured["reply_to"] == "customer@example.com"
    assert "Formal subscription request" in captured["html_body"]
    assert "Dear PhishGuard Owner" in captured["text_body"]
    assert "Business" in captured["subject"]
    assert "Request reference: #42" in captured["text_body"]


def test_subscription_request_preview_requires_confirmation_and_owner_address():
    template = Path("web/templates/subscription_request.html").read_text(encoding="utf-8")
    script = Path("web/static/js/subscription_request.js").read_text(encoding="utf-8")

    assert 'id="requestEmailPreview"' in template
    assert 'id="confirmRequestEmail"' in template
    assert "window.confirm(" in script
    assert "form.requestSubmit()" in script
    assert 'data-owner-email="{{ owner_email|e }}"' in template


def test_subscription_reply_modal_script_loads_after_modal_markup():
    template = Path("web/templates/admin_dashboard.html").read_text(encoding="utf-8")

    assert template.index('id="customerEmailModal"') < template.index("subscription_requests_admin.js")
    assert 'id="closeCustomerEmail"' in template
