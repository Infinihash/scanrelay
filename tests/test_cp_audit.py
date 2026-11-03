import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy import text

from controlplane import audit
from controlplane.app import create_app
from controlplane.db import make_engine, make_sessionmaker
from controlplane.models import Device, SendLog, Tenant
from controlplane.retention import purge_send_log

KEY = "k" * 20


@pytest.fixture()
def client(tmp_path):
    app = create_app(f"sqlite:///{tmp_path}/cp.db", KEY)
    return TestClient(app), app, tmp_path


def _mk(c):
    h = {"x-api-key": KEY}
    t = c.post("/api/v1/tenants", headers=h, json={"name": "Acme Corp", "entra_tenant_id": "e", "client_id": "c"}).json()
    c.post(f"/api/v1/tenants/{t['id']}/devices", headers=h, json={"name": "printer1"})
    c.patch(f"/api/v1/tenants/{t['id']}", headers=h, json={"secret_ref": "vault:x"})
    c.post(f"/api/v1/tenants/{t['id']}/rotate-ingest-key", headers=h)
    return t, h


def test_admin_actions_are_chained_and_verifiable(client):
    c, app, _ = client
    t, h = _mk(c)
    v = c.get("/api/v1/audit/verify", headers=h).json()
    assert v["ok"] and v["length"] == 4
    assert c.get("/api/v1/audit/verify").status_code == 401   # admin only
    with app.state.sessions() as s:
        kinds = [e["kind"] for e in audit.entries(s)]
        blob = str(audit.entries(s))
    assert kinds == ["tenant_created", "device_created", "tenant_patched", "ingest_key_rotated"]
    assert "Acme Corp" not in blob and "vault:x" not in blob


def test_ingest_is_audited(client):
    c, app, _ = client
    t, h = _mk(c)
    key = c.post(f"/api/v1/tenants/{t['id']}/rotate-ingest-key", headers=h).json()["ingest_key"]
    r = c.post("/api/v1/ingest", headers={"x-scanrelay-key": key},
               json={"events": [{"device": "printer1", "recipients": 1, "size": 10, "status": "sent"}]})
    assert r.status_code == 202
    assert c.get("/api/v1/audit/verify", headers=h).json()["ok"]
    with app.state.sessions() as s:
        assert audit.entries(s)[-1]["kind"] == "ingest_batch"


def test_append_only_triggers_and_tamper_detection(client):
    c, app, _ = client
    t, h = _mk(c)
    with app.state.sessions() as s:
        with pytest.raises(Exception, match="append-only"):
            s.execute(text("update audit_log set kind='x' where seq=2")); s.commit()
        s.rollback()
        with pytest.raises(Exception, match="append-only"):
            s.execute(text("delete from audit_log where seq=2")); s.commit()
        s.rollback()
        # an attacker with the DB file drops the trigger and edits an entry
        s.execute(text("drop trigger audit_log_no_update"))
        s.execute(text("update audit_log set data='tampered' where seq=2")); s.commit()
        v = audit.verify(s)
    assert not v["ok"] and v["broken_at"] == 2 and v["reason"] == "data altered"
    assert c.get("/api/v1/audit/verify", headers=h).json()["broken_at"] == 2


def test_send_log_purge_is_audited():
    SM = make_sessionmaker(make_engine("sqlite://"))
    with SM() as s:
        t = Tenant(name="t", entra_tenant_id="e", client_id="c"); d = Device(tenant=t, name="d")
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        s.add_all([t, d, SendLog(device=d, ts=now - dt.timedelta(days=200), status="sent"),
                   SendLog(device=d, ts=now, status="sent")]); s.commit()
        assert purge_send_log(s, 90, dry_run=True) == 1
        assert audit.entries(s) == []                       # dry run audits nothing
        assert purge_send_log(s, 90) == 1
        es = audit.entries(s)
        assert [e["kind"] for e in es] == ["send_log_purged"] and es[0]["data"]["rows"] == 1
        assert audit.verify(s)["ok"]


def test_export_has_records_and_audit(client):
    c, app, _ = client
    t, h = _mk(c)
    b = c.get("/api/v1/export", headers=h).json()
    assert len(b["tenants"]) == 1 and len(b["devices"]) == 1 and len(b["audit"]["entries"]) == 4
    assert b["audit"]["verify"]["ok"]
    assert "ingest_key_hash" not in str(b) and "vault:x" not in str(b)
    assert c.get("/api/v1/export").status_code == 401
