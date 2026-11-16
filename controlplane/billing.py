"""MSP plans and Stripe billing for the hosted control plane.

Plans (per MSP, flat monthly):
  free       first 3 client tenants free, forever ("pay once you roll it out")
  msp15      up to 15 tenants   $49/mo
  msp50      up to 50 tenants   $99/mo
  unlimited  no tenant limit    $199/mo

Billing is OFF unless STRIPE_SECRET_KEY is set. Self-hosted installs never set it,
so they have no limits and never call Stripe. When it is on:
  GET  /api/v1/billing            plan, status, tenant usage and limit (admin)
  POST /api/v1/billing/checkout   {"plan": "msp15"} -> Stripe Checkout URL (admin)
  POST /api/v1/billing/webhook    Stripe-Signature verified; keeps the plan in sync
and creating a tenant beyond the plan's limit returns 402.

Stripe price ids come from STRIPE_PRICE_MSP15 / _MSP50 / _UNLIMITED. No Stripe SDK:
two REST calls through httpx with an injectable transport (tests).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Subscription, Tenant, utcnow

PLANS: dict[str, dict] = {
    "free": {"tenants": 3, "usd": 0, "label": "Free (3 tenants)"},
    "msp15": {"tenants": 15, "usd": 49, "label": "MSP 15"},
    "msp50": {"tenants": 50, "usd": 99, "label": "MSP 50"},
    "unlimited": {"tenants": None, "usd": 199, "label": "MSP Unlimited"},
}
PAID = ("msp15", "msp50", "unlimited")
ACTIVE = ("active", "trialing", "past_due")   # past_due keeps service while Stripe retries
STRIPE_API = "https://api.stripe.com/v1"
SIG_TOLERANCE_S = 300

_transport: httpx.BaseTransport | None = None


def set_transport(t: httpx.BaseTransport | None) -> None:
    global _transport
    _transport = t


def enabled() -> bool:
    return bool(os.environ.get("STRIPE_SECRET_KEY"))


def price_for(plan: str) -> str:
    return os.environ.get(f"STRIPE_PRICE_{plan.upper()}", "")


def plan_for_price(price_id: str) -> str | None:
    return next((p for p in PAID if price_id and price_for(p) == price_id), None)


def current(s: Session) -> Subscription:
    sub = s.get(Subscription, 1)
    if sub is None:
        sub = Subscription(id=1, plan="free", status="active")
        s.add(sub)
        s.commit()
    return sub


def effective_plan(sub: Subscription) -> str:
    return sub.plan if sub.plan in PAID and sub.status in ACTIVE else "free"


def tenant_limit(s: Session) -> int | None:
    """Max tenants allowed now. None = unlimited (billing off, or unlimited plan)."""
    if not enabled():
        return None
    return PLANS[effective_plan(current(s))]["tenants"]


def check_can_add_tenant(s: Session) -> None:
    limit = tenant_limit(s)
    if limit is None:
        return
    used = s.scalar(select(func.count()).select_from(Tenant)) or 0
    if used >= limit:
        raise HTTPException(402, f"plan limit reached ({used}/{limit} tenants); upgrade via /api/v1/billing/checkout")


def verify_signature(payload: bytes, header: str, secret: str, now: float | None = None) -> bool:
    if not secret or not header:
        return False
    parts: dict[str, list[str]] = {}
    for item in header.split(","):
        k, _, v = item.strip().partition("=")
        parts.setdefault(k, []).append(v)
    try:
        ts = int(parts.get("t", [""])[0])
    except ValueError:
        return False
    if abs((now if now is not None else time.time()) - ts) > SIG_TOLERANCE_S:
        return False
    want = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(want, v) for v in parts.get("v1", []))


class CheckoutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan: str
    email: str | None = None


def _stripe_post(path: str, form: list[tuple[str, str]], idem: str) -> dict:
    with httpx.Client(transport=_transport, timeout=20) as c:
        r = c.post(f"{STRIPE_API}/{path}", content=urlencode(form).encode(),
                   auth=(os.environ["STRIPE_SECRET_KEY"], ""),
                   headers={"Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": idem})
    if r.status_code >= 400:
        msg = (r.json().get("error") or {}).get("message", "") if r.content else ""
        raise HTTPException(502, f"Stripe error: {msg}"[:200])
    return r.json()


def register(app: FastAPI, db, admin) -> None:
    @app.get("/api/v1/billing", dependencies=[Depends(admin)])
    def billing_status(s: Session = Depends(db)):
        used = s.scalar(select(func.count()).select_from(Tenant)) or 0
        if not enabled():
            return {"billing": "off", "tenants_used": used, "tenant_limit": None}
        sub = current(s)
        plan = effective_plan(sub)
        return {"billing": "on", "plan": plan, "subscribed_plan": sub.plan, "status": sub.status,
                "tenants_used": used, "tenant_limit": PLANS[plan]["tenants"],
                "current_period_end": sub.current_period_end,
                "plans": {k: {"tenants": v["tenants"], "usd_per_month": v["usd"]} for k, v in PLANS.items()}}

    @app.post("/api/v1/billing/checkout", dependencies=[Depends(admin)])
    def billing_checkout(body: CheckoutIn, s: Session = Depends(db)):
        if not enabled():
            raise HTTPException(404, "billing is off")
        if body.plan not in PAID:
            raise HTTPException(422, f"plan must be one of {', '.join(PAID)}")
        price = price_for(body.plan)
        if not price:
            raise HTTPException(503, f"no Stripe price configured for {body.plan}")
        base = os.environ.get("CONTROLPLANE_PUBLIC_URL", "https://scanrelay.infinihash.com").rstrip("/")
        form = [("mode", "subscription"), ("line_items[0][price]", price), ("line_items[0][quantity]", "1"),
                ("success_url", f"{base}/?billing=ok"), ("cancel_url", f"{base}/?billing=cancelled"),
                ("client_reference_id", "controlplane"), ("metadata[plan]", body.plan),
                ("subscription_data[metadata][plan]", body.plan), ("allow_promotion_codes", "true")]
        sub = current(s)
        if sub.stripe_customer:
            form.append(("customer", sub.stripe_customer))
        elif body.email:
            form.append(("customer_email", body.email))
        sess = _stripe_post("checkout/sessions", form, f"cp-{body.plan}-{int(time.time() // 600)}")
        return {"checkout_url": sess.get("url")}

    @app.post("/api/v1/billing/webhook")
    async def billing_webhook(request: Request, s: Session = Depends(db)):
        if not enabled():
            raise HTTPException(404, "billing is off")
        body = await request.body()
        if not verify_signature(body, request.headers.get("stripe-signature", ""),
                                os.environ.get("STRIPE_WEBHOOK_SECRET", "")):
            raise HTTPException(400, "bad signature")
        try:
            evt = json.loads(body)
        except ValueError:
            raise HTTPException(400, "bad JSON")
        typ, obj = evt.get("type", ""), (evt.get("data") or {}).get("object") or {}
        sub = current(s)
        if typ == "checkout.session.completed" and obj.get("mode") == "subscription":
            plan = (obj.get("metadata") or {}).get("plan")
            if plan in PAID and obj.get("payment_status") in ("paid", "no_payment_required"):
                sub.plan, sub.status = plan, "active"
                sub.stripe_customer = obj.get("customer") or sub.stripe_customer
                sub.stripe_subscription = obj.get("subscription") or sub.stripe_subscription
        elif typ in ("customer.subscription.updated", "customer.subscription.created"):
            if not sub.stripe_subscription or obj.get("id") == sub.stripe_subscription:
                items = ((obj.get("items") or {}).get("data") or [])
                plan = plan_for_price(((items[0].get("price") or {}).get("id")) if items else "") \
                    or (obj.get("metadata") or {}).get("plan")
                if plan in PAID:
                    sub.plan = plan
                sub.status = obj.get("status") or sub.status
                sub.stripe_subscription = obj.get("id") or sub.stripe_subscription
                sub.stripe_customer = obj.get("customer") or sub.stripe_customer
                if obj.get("current_period_end"):
                    sub.current_period_end = int(obj["current_period_end"])
        elif typ == "customer.subscription.deleted" and obj.get("id") == sub.stripe_subscription:
            sub.status = "canceled"
        sub.updated_at = utcnow()
        s.commit()
        return {"received": True}
