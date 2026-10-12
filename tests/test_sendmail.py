import base64
import email
import email.policy

import httpx
import pytest

from scanrelay.graph import GraphSender
from scanrelay.sendmail import (EX_DATAERR, EX_NOPERM, EX_OK, EX_TEMPFAIL, EX_UNAVAILABLE, EX_USAGE,
                                load_settings, main)


class Fake:
    def __init__(self, status=202, token_status=200):
        self.calls, self.status, self.token_status = [], status, token_status

    def __call__(self, req: httpx.Request):
        self.calls.append(req)
        if req.url.path.endswith("/token"):
            if self.token_status != 200:
                return httpx.Response(self.token_status, text='{"error":"invalid_client","error_description":"AADSTS7000215"}')
            return httpx.Response(200, json={"access_token": "T", "expires_in": 3600})
        return httpx.Response(self.status, text="nope" if self.status >= 400 else "")


def sender(fake):
    return GraphSender("tid", "cid", "s3cret", "scans@example.com",
                       client=httpx.Client(transport=httpx.MockTransport(fake)))


def sent_mime(fake):
    req = [c for c in fake.calls if c.url.path.endswith("/sendMail")][-1]
    return email.message_from_bytes(base64.b64decode(req.content), policy=email.policy.default)


def test_quick_mode_body_from_stdin():
    fake = Fake()
    rc = main(["--to", "ops@example.com", "--subject", "disk full"], stdin=b"/var is at 97%\n", sender=sender(fake))
    assert rc == EX_OK
    m = sent_mime(fake)
    assert m["Subject"] == "disk full" and m["To"] == "ops@example.com"
    assert m["From"].addresses[0].addr_spec == "scans@example.com"
    assert "/var is at 97%" in m.get_content()


def test_t_flag_reads_header_recipients_and_drops_bcc_header():
    fake = Fake()
    raw = b"From: app@legacy.local\r\nTo: a@example.com\r\nCc: b@example.com\r\nBcc: hidden@example.com\r\nSubject: x\r\n\r\nhi\r\n"
    assert main(["-t", "-i"], stdin=raw, sender=sender(fake)) == EX_OK
    m = sent_mime(fake)
    # Graph needs Bcc on the MIME to deliver; prepare() re-adds envelope-only rcpts there.
    assert "hidden@example.com" in str(m["Bcc"])
    assert m["Reply-To"] == "app@legacy.local"


def test_sendmail_flags_are_ignored():
    fake = Fake()
    raw = b"To: a@example.com\r\nSubject: x\r\n\r\nhi\r\n"
    assert main(["-oi", "-f", "root@host", "-F", "Cron", "a@example.com"], stdin=raw, sender=sender(fake)) == EX_OK


def test_no_recipients_is_usage_error():
    assert main([], stdin=b"To: a@example.com\r\n\r\nhi\r\n", sender=sender(Fake())) == EX_USAGE


def test_empty_stdin_is_data_error():
    assert main(["a@example.com"], stdin=b"  \n", sender=sender(Fake())) == EX_DATAERR


def test_transient_graph_error_returns_tempfail():
    assert main(["--to", "a@example.com", "--subject", "s"], stdin=b"x", sender=sender(Fake(status=503))) == EX_TEMPFAIL


def test_bad_secret_returns_noperm_and_never_prints_secret(capsys):
    rc = main(["--to", "a@example.com", "--subject", "s"], stdin=b"x", sender=sender(Fake(token_status=401)))
    assert rc == EX_NOPERM
    assert "s3cret" not in capsys.readouterr().err


def test_permanent_error_returns_unavailable():
    assert main(["--to", "a@example.com", "--subject", "s"], stdin=b"x", sender=sender(Fake(status=400))) == EX_UNAVAILABLE


def test_dry_run_makes_no_calls():
    fake = Fake()
    assert main(["--dry-run", "--to", "a@example.com", "--subject", "s"], stdin=b"x", sender=sender(fake)) == EX_OK
    assert fake.calls == []


def test_env_file_loading_and_env_override(tmp_path):
    f = tmp_path / "scanrelay.env"
    f.write_text('# from Setup-ScanRelay.ps1\nSCANRELAY_TENANT_ID=t\nexport SCANRELAY_CLIENT_ID="c"\n'
                 "SCANRELAY_CLIENT_SECRET='s'\nSCANRELAY_SENDER=scans@example.com\n")
    cfg = load_settings(str(f), environ={"SCANRELAY_SENDER": "other@example.com"})
    assert cfg["SCANRELAY_CLIENT_ID"] == "c" and cfg["SCANRELAY_CLIENT_SECRET"] == "s"
    assert cfg["SCANRELAY_SENDER"] == "other@example.com"


def test_missing_settings_is_usage_error(tmp_path, monkeypatch):
    for k in ("SCANRELAY_TENANT_ID", "SCANRELAY_CLIENT_ID", "SCANRELAY_CLIENT_SECRET", "SCANRELAY_SENDER", "SCANRELAY_ENV_FILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)
    assert main(["--to", "a@example.com", "--subject", "s"], stdin=b"x") == EX_USAGE
    with pytest.raises(FileNotFoundError):
        load_settings(str(tmp_path / "nope.env"), environ={})
