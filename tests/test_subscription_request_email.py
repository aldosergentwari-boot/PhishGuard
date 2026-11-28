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
    assert "Prepare email (optional)" in request_page
    assert "requestSuccess" in request_script
    assert '"/subscription/request/" + encodeURIComponent(data.request_id) + "/email"' in request_script


def test_optional_email_has_its_own_page_and_is_user_owned():
    route = Path("backend/routes/billing.py").read_text(encoding="utf-8")
    email_page = Path("web/templates/subscription_request_email.html").read_text(encoding="utf-8")

    assert '@billing_bp.get("/subscription/request/<int:request_id>/email")' in route
    assert "WHERE id=? AND user_id=?" in route
    assert "Open email application" in email_page
    assert "No email will be sent automatically" in email_page
    assert 'id="copyEmail"' in email_page


def test_subscription_request_page_keeps_phishguard_brand_artwork():
    page = Path("web/templates/subscription_request.html").read_text(encoding="utf-8")
    assert "request-hero" in page
    assert "data:image/svg+xml" in page
