import hashlib
import hmac
import json
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from controlplane import billing, create_app  # noqa: E402

KEY = "test-admin-key-0123456789"
H = {"X-API-Key": KEY}
WH = "whsec_test"


class FakeStripe:
    def __init__(self):
        self.calls, self.status = [], 200

    def __call__(self, req):
        self.calls.append(req)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"message": "nope"}})
        return httpx.Response(200, json={"id": "cs_1", "url": "https://checkout.stripe.test/cs_1"})


@pytest.fixture
def stripe(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WH)
    monkeypatch.setenv("STRIPE_PRICE_MSP15", "price_15")
    monkeypatch.setenv("STRIPE_PRICE_MSP50", "price_50")
    monkeypatch.setenv("STRIPE_PRICE_UNLIMITED", "price_unl")
    fake = FakeStripe()
    billing.set_transport(httpx.MockTransport(fake))
    yield fake
    billing.set_transport(None)


@pytest.fixture
def client():
    return TestClient(create_app("sqlite://", api_key=KEY))


def add_tenant(client, i):
    return client.post("/api/v1/tenants", headers=H, json={
        "name": f"T{i}", "entra_tenant_id": "e", "client_id": "c"})


def signed(evt, ts=None, secret=WH):
    body = json.dumps(evt).encode()
    ts = ts or int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return body, {"Stripe-Signature": f"t={ts},v1={sig}"}


def test_billing_off_means_no_limits(client, monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    for i in range(5):
        assert add_tenant(client, i).status_code == 201
    assert client.get("/api/v1/billing", headers=H).json() == {
        "billing": "off", "tenants_used": 5, "tenant_limit": None}
    assert client.post("/api/v1/billing/checkout", headers=H, json={"plan": "msp15"}).status_code == 404
    assert client.post("/api/v1/billing/webhook", content=b"{}").status_code == 404


def test_free_plan_allows_three_tenants(client, stripe):
    for i in range(3):
        assert add_tenant(client, i).status_code == 201
    r = add_tenant(client, 3)
    assert r.status_code == 402 and "3/3" in r.text
    b = client.get("/api/v1/billing", headers=H).json()
    assert b["plan"] == "free" and b["tenant_limit"] == 3 and b["tenants_used"] == 3


def test_billing_requires_admin(client, stripe):
    assert client.get("/api/v1/billing").status_code == 401
    assert client.post("/api/v1/billing/checkout", json={"plan": "msp15"}).status_code == 401


def test_checkout_session(client, stripe):
    r = client.post("/api/v1/billing/checkout", headers=H, json={"plan": "msp50", "email": "it@msp.test"})
    assert r.status_code == 200 and r.json()["checkout_url"].endswith("cs_1")
    form = dict(httpx.QueryParams(stripe.calls[0].content.decode()))
    assert form["mode"] == "subscription" and form["line_items[0][price]"] == "price_50"
    assert form["metadata[plan]"] == "msp50" and form["customer_email"] == "it@msp.test"
    assert stripe.calls[0].headers["authorization"].startswith("Basic ")


@pytest.mark.parametrize("plan,code", [("free", 422), ("gold", 422)])
def test_checkout_rejects_bad_plan(client, stripe, plan, code):
    assert client.post("/api/v1/billing/checkout", headers=H, json={"plan": plan}).status_code == code


def test_checkout_missing_price_503(client, stripe, monkeypatch):
    monkeypatch.delenv("STRIPE_PRICE_MSP15")
    assert client.post("/api/v1/billing/checkout", headers=H, json={"plan": "msp15"}).status_code == 503


def test_checkout_stripe_error_502(client, stripe):
    stripe.status = 400
    assert client.post("/api/v1/billing/checkout", headers=H, json={"plan": "msp15"}).status_code == 502


def test_webhook_signature_required(client, stripe):
    body, hdr = signed({"type": "x"}, secret="wrong")
    assert client.post("/api/v1/billing/webhook", content=body, headers=hdr).status_code == 400
    body, hdr = signed({"type": "x"}, ts=int(time.time()) - 3600)
    assert client.post("/api/v1/billing/webhook", content=body, headers=hdr).status_code == 400


def test_upgrade_lifts_limit_then_cancel_restores_free(client, stripe):
    for i in range(3):
        add_tenant(client, i)
    body, hdr = signed({"type": "checkout.session.completed", "data": {"object": {
        "mode": "subscription", "payment_status": "paid", "metadata": {"plan": "msp15"},
        "customer": "cus_1", "subscription": "sub_1"}}})
    assert client.post("/api/v1/billing/webhook", content=body, headers=hdr).status_code == 200
    b = client.get("/api/v1/billing", headers=H).json()
    assert b["plan"] == "msp15" and b["tenant_limit"] == 15
    assert add_tenant(client, 3).status_code == 201
    # plan change in the Stripe portal: price id maps back to a plan
    body, hdr = signed({"type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_1", "status": "active", "current_period_end": 1800000000,
        "items": {"data": [{"price": {"id": "price_unl"}}]}}}})
    client.post("/api/v1/billing/webhook", content=body, headers=hdr)
    b = client.get("/api/v1/billing", headers=H).json()
    assert b["plan"] == "unlimited" and b["tenant_limit"] is None and b["current_period_end"] == 1800000000
    body, hdr = signed({"type": "customer.subscription.deleted", "data": {"object": {"id": "sub_1"}}})
    client.post("/api/v1/billing/webhook", content=body, headers=hdr)
    b = client.get("/api/v1/billing", headers=H).json()
    assert b["plan"] == "free" and b["status"] == "canceled"
    # existing tenants keep working; only new ones are blocked
    assert add_tenant(client, 9).status_code == 402
    assert client.get("/api/v1/tenants", headers=H).status_code == 200


def test_unpaid_checkout_does_not_upgrade(client, stripe):
    body, hdr = signed({"type": "checkout.session.completed", "data": {"object": {
        "mode": "subscription", "payment_status": "unpaid", "metadata": {"plan": "msp50"}}}})
    client.post("/api/v1/billing/webhook", content=body, headers=hdr)
    assert client.get("/api/v1/billing", headers=H).json()["plan"] == "free"


def test_other_subscription_ignored(client, stripe):
    body, hdr = signed({"type": "checkout.session.completed", "data": {"object": {
        "mode": "subscription", "payment_status": "paid", "metadata": {"plan": "msp15"},
        "subscription": "sub_1"}}})
    client.post("/api/v1/billing/webhook", content=body, headers=hdr)
    body, hdr = signed({"type": "customer.subscription.deleted", "data": {"object": {"id": "sub_other"}}})
    client.post("/api/v1/billing/webhook", content=body, headers=hdr)
    assert client.get("/api/v1/billing", headers=H).json()["plan"] == "msp15"


def test_past_due_keeps_service(client, stripe):
    body, hdr = signed({"type": "checkout.session.completed", "data": {"object": {
        "mode": "subscription", "payment_status": "paid", "metadata": {"plan": "msp15"},
        "subscription": "sub_1"}}})
    client.post("/api/v1/billing/webhook", content=body, headers=hdr)
    body, hdr = signed({"type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_1", "status": "past_due", "items": {"data": [{"price": {"id": "price_15"}}]}}}})
    client.post("/api/v1/billing/webhook", content=body, headers=hdr)
    assert client.get("/api/v1/billing", headers=H).json()["tenant_limit"] == 15
