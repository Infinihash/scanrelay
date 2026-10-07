import datetime as dt

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from controlplane import create_app  # noqa: E402
from controlplane.alerts import evaluate, secret_expiry_alert  # noqa: E402
from controlplane.models import AlertRule, Device, SendLog, Tenant, utcnow  # noqa: E402

KEY = "test-admin-key-0123456789"
H = {"X-API-Key": KEY}


@pytest.fixture
def app():
    return create_app("sqlite://", api_key=KEY)


@pytest.fixture
def client(app):
    return TestClient(app)


def new_tenant(client, name="Acme", expires=None):
    r = client.post("/api/v1/tenants", headers=H, json={
        "name": name, "entra_tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "cid",
        "secret_ref": "vault:msp/acme/scanrelay", "secret_expires": expires})
    assert r.status_code == 201, r.text
    return r.json()


# ---- models ---------------------------------------------------------------
def test_models_roundtrip_and_cascade(app):
    with app.state.sessions() as s:
        t = Tenant(name="T", entra_tenant_id="e", client_id="c", secret_ref="kv:scanrelay",
                   secret_expires=dt.date(2027, 1, 1))
        d = Device(tenant=t, name="copier1", auth_mode="login", allowed_ips=["10.0.0.0/24"])
        s.add_all([t, d, SendLog(device=d, recipients=2, size=1234, status="sent", graph_request_id="rid")])
        s.commit()
        assert s.get(Device, d.id).allowed_ips == ["10.0.0.0/24"]
        assert t.devices[0].sends[0].graph_request_id == "rid"
        s.delete(t)
        s.commit()
        assert s.query(SendLog).count() == 0


def test_schema_has_no_secret_or_content_columns(app):
    cols = {c.name for m in (Tenant, SendLog) for c in m.__table__.columns}
    assert not cols & {"client_secret", "secret", "subject", "body", "recipients_list"}


# ---- auth -----------------------------------------------------------------
def test_admin_key_required(client):
    assert client.get("/api/v1/tenants").status_code == 401
    assert client.get("/api/v1/tenants", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/tenants", headers=H).status_code == 200
    assert client.get("/healthz").status_code == 200


def test_short_api_key_refused():
    with pytest.raises(RuntimeError):
        create_app("sqlite://", api_key="short")


def test_tenant_rejects_secret_value_and_hashes_ingest_key(client, app):
    r = client.post("/api/v1/tenants", headers=H, json={
        "name": "X", "entra_tenant_id": "e", "client_id": "c", "client_secret": "hunter2"})
    assert r.status_code == 422
    t = new_tenant(client)
    assert t["ingest_key"].startswith("srk_")
    with app.state.sessions() as s:
        assert s.get(Tenant, t["id"]).ingest_key_hash != t["ingest_key"]
    assert "ingest_key" not in client.get("/api/v1/tenants", headers=H).json()[0]


def test_ingest_requires_relay_key_and_rejects_content(client):
    t = new_tenant(client)
    ev = {"device": "copier1", "recipients": 1, "size": 10, "status": "sent"}
    assert client.post("/api/v1/ingest", json={"events": [ev]}).status_code == 401
    assert client.post("/api/v1/ingest", json={"events": [ev]}, headers=H).status_code == 401  # admin key != relay key
    rk = {"X-ScanRelay-Key": t["ingest_key"]}
    bad = dict(ev, subject="Payroll")
    assert client.post("/api/v1/ingest", json={"events": [bad]}, headers=rk).status_code == 422
    r = client.post("/api/v1/ingest", json={"events": [ev, dict(ev, status="failed", graph_request_id="abc")]},
                    headers=rk)
    assert r.status_code == 202 and r.json() == {"accepted": 2}
    devs = client.get(f"/api/v1/tenants/{t['id']}/devices", headers=H).json()
    assert [d["name"] for d in devs] == ["copier1"]
    sends = client.get(f"/api/v1/tenants/{t['id']}/sends", headers=H).json()
    assert {s["status"] for s in sends} == {"sent", "failed"}
    new = client.post(f"/api/v1/tenants/{t['id']}/rotate-ingest-key", headers=H).json()["ingest_key"]
    assert client.post("/api/v1/ingest", json={"events": [ev]}, headers=rk).status_code == 401
    assert client.post("/api/v1/ingest", json={"events": [ev]},
                       headers={"X-ScanRelay-Key": new}).status_code == 202


def test_device_crud(client):
    t = new_tenant(client)
    r = client.post(f"/api/v1/tenants/{t['id']}/devices", headers=H,
                    json={"name": "ricoh-2f", "auth_mode": "ip", "allowed_ips": ["192.168.10.20/32"]})
    assert r.status_code == 201
    assert client.post(f"/api/v1/tenants/{t['id']}/devices", headers=H,
                       json={"name": "ricoh-2f"}).status_code == 409
    assert client.post(f"/api/v1/tenants/{t['id']}/devices", headers=H,
                       json={"name": "x", "auth_mode": "magic"}).status_code == 422


# ---- alerts ---------------------------------------------------------------
@pytest.mark.parametrize("days,sev", [(45, None), (30, "info"), (15, "info"), (14, "warning"),
                                      (8, "warning"), (7, "critical"), (0, "critical"), (-3, "critical")])
def test_secret_expiry_thresholds(days, sev):
    today = dt.date(2026, 9, 28)
    t = Tenant(name="T", entra_tenant_id="e", client_id="c", secret_expires=today + dt.timedelta(days=days))
    a = secret_expiry_alert(t, today)
    assert (a.severity if a else None) == sev


def _seed(app, statuses, age_hours=1, created_hours=1):
    now = utcnow()
    with app.state.sessions() as s:
        t = Tenant(name="T", entra_tenant_id="e", client_id="c")
        d = Device(tenant=t, name="copier", created_at=now - dt.timedelta(hours=created_hours))
        s.add_all([t, d])
        for st in statuses:
            s.add(SendLog(device=d, status=st, ts=now - dt.timedelta(hours=age_hours)))
        s.commit()
        return t.id


def test_failure_rate_alert(app):
    _seed(app, ["sent"] * 3 + ["failed"] * 3 + ["retry"] * 10)
    with app.state.sessions() as s:
        a = [x for x in evaluate(s) if x.kind == "failure_rate"]
    assert len(a) == 1 and a[0].severity == "critical" and "3/6" in a[0].message


def test_failure_rate_needs_min_sends_and_tenant_override(app):
    tid = _seed(app, ["sent"] * 2 + ["failed"])
    with app.state.sessions() as s:
        assert not [x for x in evaluate(s) if x.kind == "failure_rate"]
        s.add(AlertRule(tenant_id=tid, kind="failure_rate", threshold=0.3, window_hours=24, min_sends=2))
        s.commit()
        assert [x for x in evaluate(s) if x.kind == "failure_rate"][0].severity == "warning"


def test_no_traffic_alert_and_disable(app):
    _seed(app, ["sent"], age_hours=100, created_hours=200)
    with app.state.sessions() as s:
        assert [x.kind for x in evaluate(s)] == ["no_traffic"]
        s.add(AlertRule(tenant_id=None, kind="no_traffic", enabled=False))
        s.commit()
        assert evaluate(s) == []


def test_new_device_without_traffic_gets_grace_period(app):
    _seed(app, [], created_hours=1)
    with app.state.sessions() as s:
        assert evaluate(s) == []


# ---- dashboard ------------------------------------------------------------
def test_dashboard_login_and_fleet_table(client):
    soon = (dt.date.today() + dt.timedelta(days=5)).isoformat()
    t = new_tenant(client, name="Acme <Dental>", expires=soon)
    client.post("/api/v1/ingest", headers={"X-ScanRelay-Key": t["ingest_key"]},
                json={"events": [{"device": "copier1", "status": "sent", "recipients": 1, "size": 5}]})
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.post("/login", data={"key": "nope"}, follow_redirects=False).status_code == 401
    page = client.get("/", headers=H).text
    assert "Fleet health" in page and "copier1" in page
    assert "Acme &lt;Dental&gt;" in page and "<Dental>" not in page   # escaped
    assert "critical" in page and "expires in 5 day" in page
    fleet = client.get("/api/v1/fleet", headers=H).json()
    assert fleet[0]["sends_24h"] == 1 and fleet[0]["secret_days_left"] == 5
