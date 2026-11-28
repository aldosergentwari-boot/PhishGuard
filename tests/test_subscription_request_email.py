from pathlib import Path


def test_subscription_request_is_primary_and_email_is_optional():
    route = Path("backend/routes/billing.py").read_text(encoding="utf-8")
    request_page = Path("web/templates/subscription_request.html").read_text(encoding="utf-8")
    request_script = Path("web/static/js/subscription_request.js").read_text(encoding="utf-8")

    create_route = route.split("def create_subscription_request", 1)[1].split(
        '@billing_bp.get("/subscription/request/<int:request_id>/email")', 1
    )[0]
    assert "admin_inbox_notifications" in create_route
    assert "send_subscription_request_email(" not in create_route
    assert "send_subscription_request_received_email" in create_route
    assert "Submit subscription request" in request_page
    assert "prepare-email-button" in request_page
    assert "Prepare Email (Optional)" in request_page
    assert "requestSuccess" in request_script
    assert '"/subscription/request/" + encodeURIComponent(data.request_id) + "/email"' in request_script


def test_optional_email_has_its_own_page_and_is_user_owned():
    route = Path("backend/routes/billing.py").read_text(encoding="utf-8")
    email_page = Path("web/templates/subscription_request_email.html").read_text(encoding="utf-8")

    assert '@billing_bp.get("/subscription/request/<int:request_id>/email")' in route
    assert "WHERE id=? AND user_id=?" in route
    assert "Open email application" in email_page
    assert "No email is sent automatically" in email_page
    assert 'id="sendEmailNow"' in email_page
    assert "Send Email Now" in email_page
    assert 'id="copyEmail"' in email_page


def test_subscription_request_page_keeps_phishguard_brand_artwork():
    page = Path("web/templates/subscription_request.html").read_text(encoding="utf-8")
    assert "request-hero" in page
    assert "data:image/svg+xml" in page


def test_customer_can_explicitly_send_subscription_email_to_owner():
    route = Path("backend/routes/billing.py").read_text(encoding="utf-8")
    auth_routes = Path("backend/routes/auth.py").read_text(encoding="utf-8")
    email_page = Path("web/templates/subscription_request_email.html").read_text(encoding="utf-8")

    assert '@billing_bp.post("/api/billing/requests/<int:request_id>/send-email")' in route
    assert "WHERE id=? AND user_id=?" in route
    assert "send_subscription_request_email(owner_email" in route
    assert 'request.path.endswith("/send-email")' in auth_routes
    assert 'fetch("/api/billing/requests/{{ details.id }}/send-email"' in email_page
    assert "Email Sent" in email_page
