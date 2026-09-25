import base64
import email
import email.policy
import json
import smtplib
import socket
from email.message import EmailMessage

import httpx
import pytest

from scanrelay.graph import GraphSender, prepare
from scanrelay.server import Config, build


class FakeGraph:
    def __init__(self, fail_first=0, status=503):
        self.calls, self.fail_first, self.status = [], fail_first, status

    def handler(self, req: httpx.Request):
        self.calls.append(req)
        if req.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "T", "expires_in": 3600})
        if self.fail_first:
            self.fail_first -= 1
            return httpx.Response(self.status, text="busy")
        if req.url.path.endswith("/messages") and req.method == "POST":
            return httpx.Response(201, json={"id": "M1"})
        if req.url.path.endswith("createUploadSession"):
            return httpx.Response(201, json={"uploadUrl": "https://upload.example/session1"})
        if req.url.host == "upload.example":
            return httpx.Response(200, json={})
        return httpx.Response(202)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def make(tmp_path, fake, **kw):
    cfg = Config(tenant_id="t", client_id="c", client_secret="s", sender="scans@contoso.com",
                 listen_host="127.0.0.1", listen_port=free_port(), spool=str(tmp_path / "spool"),
                 log_path=str(tmp_path / "sends.jsonl"), **kw)
    sender = GraphSender("t", "c", "s", cfg.sender, client=httpx.Client(transport=httpx.MockTransport(fake.handler)))
    return cfg, *build(cfg, sender)


def scan_msg(size=1000):
    m = EmailMessage()
    m["From"] = "Ricoh MFP <copier@local>"
    m["To"] = "alice@external.com"
    m["Subject"] = "Scan"
    m.set_content("Scanned document attached.")
    m.add_attachment(b"%PDF" + b"x" * size, maintype="application", subtype="pdf", filename="scan.pdf")
    return m


def test_prepare_rewrites_from_and_adds_bcc():
    raw = scan_msg().as_bytes()
    msg = prepare(raw, "scans@contoso.com", ["alice@external.com", "hidden@contoso.com"])
    assert "scans@contoso.com" in msg["From"]
    assert msg["Reply-To"] == "copier@local"
    assert "hidden@contoso.com" in msg["Bcc"]


def test_auth_and_mime_send(tmp_path):
    fake = FakeGraph()
    cfg, ctl, spool = make(tmp_path, fake, users={"scanner1": "pw1"})
    ctl.start()
    try:
        with smtplib.SMTP("127.0.0.1", cfg.listen_port) as s:
            s.login("scanner1", "pw1")
            s.send_message(scan_msg(), to_addrs=["alice@external.com", "bob@contoso.com"])
    finally:
        ctl.stop()
    assert spool.process_once() == 1
    send = [c for c in fake.calls if c.url.path.endswith("/sendMail")][0]
    assert send.url.path == "/v1.0/users/scans@contoso.com/sendMail"
    mime = email.message_from_bytes(base64.b64decode(send.content), policy=email.policy.default)
    assert "bob@contoso.com" in str(mime["Bcc"])
    log = [json.loads(l) for l in open(cfg.log_path)]
    assert log[-1]["status"] == "sent" and log[-1]["user"] == "scanner1"
    assert not list((tmp_path / "spool").glob("*.eml"))   # content not retained


def test_rejects_unauthenticated_outside_allowlist(tmp_path):
    fake = FakeGraph()
    cfg, ctl, _ = make(tmp_path, fake, users={"u": "p"})
    ctl.start()
    try:
        with smtplib.SMTP("127.0.0.1", cfg.listen_port) as s, pytest.raises(smtplib.SMTPSenderRefused):
            s.send_message(scan_msg(), to_addrs=["x@external.com"])
        with smtplib.SMTP("127.0.0.1", cfg.listen_port) as s, pytest.raises(smtplib.SMTPAuthenticationError):
            s.login("u", "wrong")
    finally:
        ctl.stop()


def test_ip_allowlist_and_retry_then_send(tmp_path):
    fake = FakeGraph(fail_first=1)
    cfg, ctl, spool = make(tmp_path, fake, allow_ips=["127.0.0.0/8"])
    ctl.start()
    try:
        with smtplib.SMTP("127.0.0.1", cfg.listen_port) as s:
            s.send_message(scan_msg(), to_addrs=["alice@external.com"])
    finally:
        ctl.stop()
    assert spool.process_once() == 0            # 503 -> retry scheduled
    meta = json.loads(next((tmp_path / "spool").glob("*.json")).read_text())
    meta["next_try"] = 0
    next((tmp_path / "spool").glob("*.json")).write_text(json.dumps(meta))
    assert spool.process_once() == 1


def test_large_attachment_uses_upload_session(tmp_path):
    fake = FakeGraph()
    cfg, ctl, spool = make(tmp_path, fake, allow_ips=["127.0.0.0/8"])
    ctl.start()
    try:
        with smtplib.SMTP("127.0.0.1", cfg.listen_port) as s:
            s.send_message(scan_msg(size=6 * 1024 * 1024), to_addrs=["alice@external.com"])
    finally:
        ctl.stop()
    assert spool.process_once() == 1
    paths = [c.url.path for c in fake.calls]
    assert any(p.endswith("createUploadSession") for p in paths)
    assert paths[-1].endswith("/messages/M1/send")
    puts = [c for c in fake.calls if c.url.host == "upload.example"]
    assert len(puts) == 2 and "Authorization" not in puts[0].headers


def test_permanent_error_moves_to_failed(tmp_path):
    fake = FakeGraph(fail_first=5, status=403)
    cfg, ctl, spool = make(tmp_path, fake, allow_ips=["127.0.0.0/8"])
    ctl.start()
    try:
        with smtplib.SMTP("127.0.0.1", cfg.listen_port) as s:
            s.send_message(scan_msg(), to_addrs=["alice@external.com"])
    finally:
        ctl.stop()
    spool.process_once()
    assert list((tmp_path / "spool" / "failed").glob("*.eml"))
