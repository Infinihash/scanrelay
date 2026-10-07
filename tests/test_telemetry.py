import json
import smtplib

import httpx
import pytest

from scanrelay.server import Config, build
from scanrelay.telemetry import ControlPlaneReporter
from tests.test_relay import FakeGraph, free_port, scan_msg


class RidGraph(FakeGraph):
    def handler(self, req):
        r = super().handler(req)
        if req.url.path.endswith("/sendMail") and r.status_code == 202:
            return httpx.Response(202, headers={"request-id": "req-123"})
        return r


def run_one(tmp_path, reporter, **kw):
    fake = RidGraph(**kw)
    from scanrelay.graph import GraphSender
    cfg = Config(tenant_id="t", client_id="c", client_secret="s", sender="scans@contoso.com",
                 listen_host="127.0.0.1", listen_port=free_port(), spool=str(tmp_path / "spool"),
                 log_path=str(tmp_path / "sends.jsonl"), users={"copier1": "pw"})
    sender = GraphSender("t", "c", "s", cfg.sender, client=httpx.Client(transport=httpx.MockTransport(fake.handler)))
    ctl, spool = build(cfg, sender, reporter)
    ctl.start()
    try:
        with smtplib.SMTP("127.0.0.1", cfg.listen_port) as s:
            s.login("copier1", "pw")
            s.send_message(scan_msg(), to_addrs=["alice@external.com", "bob@contoso.com"])
    finally:
        ctl.stop()
    return cfg, spool


def test_hook_off_by_default(tmp_path):
    assert ControlPlaneReporter.from_env({}) is None
    cfg = Config(tenant_id="t", client_id="c", client_secret="s", sender="x@y", spool=str(tmp_path / "s"),
                 log_path=str(tmp_path / "l.jsonl"), listen_port=free_port())
    _, spool = build(cfg, sender=object())
    assert spool.reporter is None


def test_hook_enabled_by_env(tmp_path, monkeypatch):
    for k in ("SCANRELAY_TENANT_ID", "SCANRELAY_CLIENT_ID", "SCANRELAY_CLIENT_SECRET", "SCANRELAY_SENDER"):
        monkeypatch.setenv(k, "x")
    monkeypatch.setenv("CONTROLPLANE_URL", "https://cp.example/")
    monkeypatch.setenv("CONTROLPLANE_KEY", "k")
    monkeypatch.setenv("SCANRELAY_SPOOL", str(tmp_path / "s"))
    monkeypatch.setenv("SCANRELAY_LOG", str(tmp_path / "l.jsonl"))
    cfg = Config.from_env()
    _, spool = build(cfg, sender=object())
    assert spool.reporter.url == "https://cp.example/api/v1/ingest"


def test_hook_posts_metadata_only(tmp_path):
    seen = []

    def cp(req):
        seen.append(req)
        return httpx.Response(202, json={"accepted": 1})
    rep = ControlPlaneReporter("https://cp.example", "srk_x", client=httpx.Client(transport=httpx.MockTransport(cp)))
    cfg, spool = run_one(tmp_path, rep)
    assert spool.process_once() == 1
    assert len(seen) == 1 and seen[0].headers["X-ScanRelay-Key"] == "srk_x"
    ev = json.loads(seen[0].content)["events"][0]
    assert set(ev) == {"device", "ts", "recipients", "size", "status", "graph_request_id", "auth_mode"}
    assert ev["device"] == "copier1" and ev["recipients"] == 2 and ev["status"] == "sent"
    assert ev["graph_request_id"] == "req-123" and ev["auth_mode"] == "login"
    body = seen[0].content.decode()
    assert "Scan" not in body and "alice@" not in body and "PDF" not in body
    assert json.loads(open(cfg.log_path).readlines()[-1])["graph_request_id"] == "req-123"


def test_control_plane_outage_does_not_break_delivery(tmp_path):
    def down(req):
        raise httpx.ConnectError("refused")
    rep = ControlPlaneReporter("https://cp.example", "k", client=httpx.Client(transport=httpx.MockTransport(down)))
    _, spool = run_one(tmp_path, rep)
    assert spool.process_once() == 1
    assert not list((tmp_path / "spool").glob("*.eml"))


def test_hook_end_to_end_into_control_plane(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from controlplane import create_app
    key = "admin-key-0123456789"
    cp = TestClient(create_app("sqlite://", api_key=key))
    t = cp.post("/api/v1/tenants", headers={"X-API-Key": key},
                json={"name": "Acme", "entra_tenant_id": "e", "client_id": "c"}).json()
    rep = ControlPlaneReporter("http://testserver", t["ingest_key"], client=cp)
    _, spool = run_one(tmp_path, rep, fail_first=1)          # one 503 retry, then sent
    assert spool.process_once() == 0
    for m in (tmp_path / "spool").glob("*.json"):
        meta = json.loads(m.read_text()); meta["next_try"] = 0; m.write_text(json.dumps(meta))
    assert spool.process_once() == 1
    sends = cp.get(f"/api/v1/tenants/{t['id']}/sends", headers={"X-API-Key": key}).json()
    assert sorted(s["status"] for s in sends) == ["retry", "sent"]
    fleet = cp.get("/api/v1/fleet", headers={"X-API-Key": key}).json()
    assert fleet[0]["device"] == "copier1" and fleet[0]["sends_24h"] == 1 and fleet[0]["health"] == "ok"
