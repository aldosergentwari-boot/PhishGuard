def test_payment_callback_redirects_with_success_after_server_verification(client, monkeypatch):
    import backend.routes.billing as billing

    verified = []
    monkeypatch.setattr(
        billing, "verify_and_activate",
        lambda tx_ref, transaction_id: verified.append((tx_ref, transaction_id)),
    )
    response = client.get(
        "/api/billing/callback?status=successful&tx_ref=ref-123&transaction_id=456"
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/?payment=success")
    assert verified == [("ref-123", "456")]


def test_payment_callback_never_claims_success_when_provider_verification_fails(client, monkeypatch):
    import backend.routes.billing as billing

    def fail_verification(*args):
        raise billing.FlutterwaveError("provider unavailable")

    monkeypatch.setattr(billing, "verify_and_activate", fail_verification)
    response = client.get(
        "/api/billing/callback?status=successful&tx_ref=ref-123&transaction_id=456"
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/?payment=verification_failed")
