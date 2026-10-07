"""ScanRelay MSP control plane (preview): tenants, devices, send metadata, alerts, fleet dashboard.

Two kinds of key:
- Admin API key (CONTROLPLANE_API_KEY): X-API-Key header, or the dashboard login cookie.
- Per-tenant relay ingest key: issued once when a tenant is created, stored only as a hash,
  sent by relays in the X-ScanRelay-Key header to POST /api/v1/ingest.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import html
import os
import secrets
from typing import Literal

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import alerts as alerts_mod
from .db import make_engine, make_sessionmaker
from .models import Device, SendLog, Tenant, utcnow

COOKIE = "scanrelay_cp"


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# ---- schemas (extra="forbid": a stray client_secret / subject / body is rejected, not stored) ----
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TenantIn(Strict):
    name: str = Field(min_length=1, max_length=200)
    entra_tenant_id: str = Field(min_length=1, max_length=64)
    client_id: str = Field(min_length=1, max_length=64)
    secret_ref: str = Field("", max_length=300, description="Where the secret lives, never the secret")
    secret_expires: dt.date | None = None


class TenantPatch(Strict):
    secret_ref: str | None = Field(None, max_length=300)
    secret_expires: dt.date | None = None


class DeviceIn(Strict):
    name: str = Field(min_length=1, max_length=200)
    auth_mode: Literal["login", "ip", "both", "unknown"] = "unknown"
    allowed_ips: list[str] = []


class IngestEvent(Strict):
    device: str = Field(min_length=1, max_length=200)
    ts: float | None = None                       # epoch seconds; default now
    recipients: int = Field(0, ge=0)
    size: int = Field(0, ge=0)
    status: Literal["sent", "failed", "retry"]
    graph_request_id: str = Field("", max_length=64)
    auth_mode: Literal["login", "ip", "both", "unknown"] | None = None


class IngestBatch(Strict):
    events: list[IngestEvent] = Field(max_length=500)


def tenant_out(t: Tenant) -> dict:
    return {"id": t.id, "name": t.name, "entra_tenant_id": t.entra_tenant_id, "client_id": t.client_id,
            "secret_ref": t.secret_ref, "secret_expires": t.secret_expires.isoformat() if t.secret_expires else None,
            "devices": len(t.devices)}


def device_out(d: Device) -> dict:
    return {"id": d.id, "tenant_id": d.tenant_id, "name": d.name, "auth_mode": d.auth_mode,
            "allowed_ips": d.allowed_ips}


def fleet(db: Session, now: dt.datetime | None = None) -> list[dict]:
    """One row per device (or per tenant with no devices) for the dashboard."""
    now = now or utcnow()
    by_key: dict[tuple, list] = {}
    for a in alerts_mod.evaluate(db, now):
        by_key.setdefault((a.tenant, a.device), []).append(a)
    rows = []
    for t in db.scalars(select(Tenant).order_by(Tenant.name)).all():
        days = (t.secret_expires - now.date()).days if t.secret_expires else None
        tenant_alerts = by_key.get((t.name, None), [])
        for d in sorted(t.devices, key=lambda d: d.name) or [None]:
            total = failed = 0
            seen = None
            if d is not None:
                total, failed = alerts_mod.device_stats(db, d, now - dt.timedelta(hours=24))
                seen = alerts_mod.last_seen(db, d)
            al = tenant_alerts + (by_key.get((t.name, d.name), []) if d else [])
            sev = "critical" if any(a.severity == "critical" for a in al) else \
                  "warning" if any(a.severity == "warning" for a in al) else "info" if al else "ok"
            rows.append({"tenant": t.name, "device": d.name if d else None, "auth_mode": d.auth_mode if d else "",
                         "sends_24h": total, "failed_24h": failed,
                         "failure_pct": round(100 * failed / total, 1) if total else 0.0,
                         "last_seen": seen.isoformat(timespec="minutes") if seen else None,
                         "secret_days_left": days, "health": sev, "alerts": [a.message for a in al]})
    return rows


def create_app(db_url: str | None = None, api_key: str | None = None) -> FastAPI:
    api_key = api_key if api_key is not None else os.environ.get("CONTROLPLANE_API_KEY", "")
    if len(api_key) < 16:
        raise RuntimeError("Set CONTROLPLANE_API_KEY to a random value of at least 16 characters.")
    Sessions = make_sessionmaker(make_engine(db_url))
    app = FastAPI(title="ScanRelay control plane (preview)", version="0.1.0")
    app.state.sessions = Sessions

    def db():
        with Sessions() as s:
            yield s

    def admin(request: Request, x_api_key: str | None = Header(None)) -> None:
        given = x_api_key or request.cookies.get(COOKIE, "")
        if not given or not hmac.compare_digest(given, api_key):
            raise HTTPException(401, "invalid or missing API key")

    def relay_tenant(x_scanrelay_key: str | None = Header(None), s: Session = Depends(db)) -> Tenant:
        t = s.scalar(select(Tenant).where(Tenant.ingest_key_hash == _hash(x_scanrelay_key))) \
            if x_scanrelay_key else None
        if t is None:
            raise HTTPException(401, "invalid or missing relay key")
        return t

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # ---- tenants ----
    @app.post("/api/v1/tenants", status_code=201, dependencies=[Depends(admin)])
    def create_tenant(body: TenantIn, s: Session = Depends(db)):
        if s.scalar(select(Tenant).where(Tenant.name == body.name)):
            raise HTTPException(409, "tenant exists")
        key = "srk_" + secrets.token_urlsafe(32)
        t = Tenant(**body.model_dump(), ingest_key_hash=_hash(key))
        s.add(t)
        s.commit()
        return {**tenant_out(t), "ingest_key": key}   # shown once; only the hash is stored

    @app.get("/api/v1/tenants", dependencies=[Depends(admin)])
    def list_tenants(s: Session = Depends(db)):
        return [tenant_out(t) for t in s.scalars(select(Tenant).order_by(Tenant.name))]

    def get_tenant(s: Session, tid: int) -> Tenant:
        t = s.get(Tenant, tid)
        if t is None:
            raise HTTPException(404, "no such tenant")
        return t

    @app.patch("/api/v1/tenants/{tid}", dependencies=[Depends(admin)])
    def patch_tenant(tid: int, body: TenantPatch, s: Session = Depends(db)):
        t = get_tenant(s, tid)
        for k, v in body.model_dump(exclude_unset=True).items():
            setattr(t, k, v)
        s.commit()
        return tenant_out(t)

    @app.post("/api/v1/tenants/{tid}/rotate-ingest-key", dependencies=[Depends(admin)])
    def rotate_key(tid: int, s: Session = Depends(db)):
        t = get_tenant(s, tid)
        key = "srk_" + secrets.token_urlsafe(32)
        t.ingest_key_hash = _hash(key)
        s.commit()
        return {"ingest_key": key}

    # ---- devices ----
    @app.post("/api/v1/tenants/{tid}/devices", status_code=201, dependencies=[Depends(admin)])
    def create_device(tid: int, body: DeviceIn, s: Session = Depends(db)):
        t = get_tenant(s, tid)
        if any(d.name == body.name for d in t.devices):
            raise HTTPException(409, "device exists")
        d = Device(tenant=t, **body.model_dump())
        s.add(d)
        s.commit()
        return device_out(d)

    @app.get("/api/v1/tenants/{tid}/devices", dependencies=[Depends(admin)])
    def list_devices(tid: int, s: Session = Depends(db)):
        return [device_out(d) for d in get_tenant(s, tid).devices]

    @app.get("/api/v1/tenants/{tid}/sends", dependencies=[Depends(admin)])
    def list_sends(tid: int, limit: int = 100, s: Session = Depends(db)):
        get_tenant(s, tid)
        q = (select(SendLog, Device.name).join(Device).where(Device.tenant_id == tid)
             .order_by(SendLog.ts.desc()).limit(min(max(limit, 1), 1000)))
        return [{"ts": l.ts.isoformat(), "device": name, "recipients": l.recipients, "size": l.size,
                 "status": l.status, "graph_request_id": l.graph_request_id} for l, name in s.execute(q)]

    # ---- alerts / fleet ----
    @app.get("/api/v1/alerts", dependencies=[Depends(admin)])
    def get_alerts(s: Session = Depends(db)):
        return [a.dict() for a in alerts_mod.evaluate(s)]

    @app.get("/api/v1/fleet", dependencies=[Depends(admin)])
    def get_fleet(s: Session = Depends(db)):
        return fleet(s)

    # ---- relay -> control plane metrics push ----
    @app.post("/api/v1/ingest", status_code=202)
    def ingest(body: IngestBatch, t: Tenant = Depends(relay_tenant), s: Session = Depends(db)):
        t = s.merge(t)
        devices = {d.name: d for d in t.devices}
        for ev in body.events:
            d = devices.get(ev.device)
            if d is None:
                d = devices[ev.device] = Device(tenant=t, name=ev.device, auth_mode=ev.auth_mode or "unknown")
                s.add(d)
            elif ev.auth_mode and d.auth_mode == "unknown":
                d.auth_mode = ev.auth_mode
            ts = dt.datetime.fromtimestamp(ev.ts, dt.timezone.utc).replace(tzinfo=None) if ev.ts else utcnow()
            s.add(SendLog(device=d, ts=ts, recipients=ev.recipients, size=ev.size, status=ev.status,
                          graph_request_id=ev.graph_request_id))
        s.commit()
        return {"accepted": len(body.events)}

    # ---- dashboard ----
    @app.get("/login", response_class=HTMLResponse)
    def login_form():
        return _page("Sign in", '<form method="post" action="/login"><label>Admin API key '
                     '<input type="password" name="key" autofocus></label> <button>Sign in</button></form>')

    @app.post("/login")
    def login(key: str = Form(...)):
        if not hmac.compare_digest(key, api_key):
            raise HTTPException(401, "invalid API key")
        r = RedirectResponse("/", status_code=303)
        r.set_cookie(COOKIE, key, httponly=True, samesite="strict", secure=os.environ.get(
            "CONTROLPLANE_INSECURE_COOKIE", "0") != "1")
        return r

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, s: Session = Depends(db)):
        try:
            admin(request, request.headers.get("x-api-key"))
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        return _page("Fleet health", render_fleet(fleet(s)))

    return app


def render_fleet(rows: list[dict]) -> str:
    e = html.escape
    if not rows:
        return "<p>No tenants yet. Create one with <code>POST /api/v1/tenants</code>.</p>"
    counts = {k: sum(r["health"] == k for r in rows) for k in ("ok", "info", "warning", "critical")}
    head = "".join(f'<span class="pill {k}">{v} {k}</span> ' for k, v in counts.items())
    body = []
    for r in rows:
        days = r["secret_days_left"]
        body.append(
            f'<tr><td><span class="pill {r["health"]}">{r["health"]}</span></td><td>{e(r["tenant"])}</td>'
            f'<td>{e(r["device"] or "(no devices)")}</td><td>{e(r["auth_mode"])}</td>'
            f'<td class="n">{r["sends_24h"]}</td><td class="n">{r["failure_pct"]}%</td>'
            f'<td>{e(r["last_seen"] or "never")}</td><td class="n">{"-" if days is None else days}</td>'
            f'<td>{"<br>".join(e(a) for a in r["alerts"])}</td></tr>')
    return (f"<p>{head}</p><table><thead><tr><th>Health</th><th>Tenant</th><th>Device</th><th>Auth</th>"
            "<th>Sends 24h</th><th>Fail 24h</th><th>Last seen (UTC)</th><th>Secret days left</th>"
            f"<th>Alerts</th></tr></thead><tbody>{''.join(body)}</tbody></table>")


def _page(title: str, content: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ScanRelay - {html.escape(title)}</title>
<style>
body{{font:14px/1.4 system-ui,sans-serif;margin:24px;color:#1b1f24;background:#fff}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:6px 10px;border-bottom:1px solid #e3e6ea;text-align:left;vertical-align:top}}
th{{background:#f5f7f9}}td.n{{text-align:right;font-variant-numeric:tabular-nums}}
.pill{{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;background:#e3e6ea}}
.ok{{background:#d7f5dd}}.info{{background:#dbe9ff}}.warning{{background:#ffecc2}}.critical{{background:#ffd3d0}}
@media (prefers-color-scheme:dark){{body{{background:#15181c;color:#e6e8eb}}th{{background:#20252b}}
th,td{{border-color:#2c3239}}.pill{{color:#15181c}}}}
</style></head><body><h1>ScanRelay control plane <small>(preview)</small></h1><h2>{html.escape(title)}</h2>
{content}</body></html>"""


def main() -> None:
    import uvicorn
    uvicorn.run(create_app(), host=os.environ.get("CONTROLPLANE_HOST", "127.0.0.1"),
                port=int(os.environ.get("CONTROLPLANE_PORT", "8080")))


if __name__ == "__main__":
    main()
