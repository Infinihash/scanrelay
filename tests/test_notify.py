import datetime as dt
import json

import pytest

from controlplane.alerts import Alert
from controlplane import notify

T0 = dt.datetime(2026, 11, 1, 9, 0)


def A(sev="info", kind="secret_expiry", tenant="Acme", device=None, msg="expires in 20 day(s)"):
    return Alert(kind, sev, tenant, device, msg)


class Sink:
    def __init__(self, fail=False):
        self.posts, self.fail = [], fail

    def __call__(self, url, body):
        if self.fail:
            raise RuntimeError("boom")
        self.posts.append((url, body))


def run(tmp_path, alerts, now, sink, **kw):
    return notify.run(alerts, state_path=tmp_path / "s.json", url="https://hooks.example/x",
                      now=now, send=sink, **kw)


def test_new_alert_posted_once(tmp_path):
    s = Sink()
    assert [e for e, _ in run(tmp_path, [A()], T0, s)] == ["new"]
    assert run(tmp_path, [A()], T0 + dt.timedelta(hours=1), s) == []
    assert len(s.posts) == 1


def test_severity_change_reposts(tmp_path):
    s = Sink()
    run(tmp_path, [A("info")], T0, s)
    ev = run(tmp_path, [A("warning", msg="expires in 14 day(s)")], T0 + dt.timedelta(hours=1), s)
    assert [e for e, _ in ev] == ["changed"]
    assert "WARNING (severity changed)" in s.posts[-1][1]["text"]


def test_reminder_after_repeat_window(tmp_path):
    s = Sink()
    run(tmp_path, [A()], T0, s)
    assert run(tmp_path, [A()], T0 + dt.timedelta(hours=23), s) == []
    assert [e for e, _ in run(tmp_path, [A()], T0 + dt.timedelta(hours=24), s)] == ["reminder"]
    assert run(tmp_path, [A()], T0 + dt.timedelta(hours=30), s) == []


def test_resolved_posted_once(tmp_path):
    s = Sink()
    run(tmp_path, [A(), A("warning", "no_traffic", device="copier1", msg="No traffic for 80h")], T0, s)
    ev = run(tmp_path, [A()], T0 + dt.timedelta(hours=1), s)
    assert [e for e, _ in ev] == ["resolved"]
    assert "Resolved: Acme / copier1: no traffic" in s.posts[-1][1]["text"]
    assert run(tmp_path, [A()], T0 + dt.timedelta(hours=2), s) == []


def test_failed_post_keeps_state_for_retry(tmp_path):
    with pytest.raises(RuntimeError):
        run(tmp_path, [A()], T0, Sink(fail=True))
    assert not (tmp_path / "s.json").exists()
    s = Sink()
    assert [e for e, _ in run(tmp_path, [A()], T0, s)] == ["new"]


def test_dry_run_changes_nothing(tmp_path):
    s = Sink()
    ev = run(tmp_path, [A()], T0, s, dry_run=True)
    assert [e for e, _ in ev] == ["new"] and s.posts == []
    assert not (tmp_path / "s.json").exists()


def test_no_events_no_post(tmp_path):
    s = Sink()
    run(tmp_path, [], T0, s)
    assert s.posts == []


def test_duplicate_alerts_collapse(tmp_path):
    s = Sink()
    assert len(run(tmp_path, [A(), A()], T0, s)) == 1


def test_formats():
    ev = [("new", A("critical", msg="Client secret expired 2 day(s) ago"))]
    assert "CRITICAL" in notify.payload(ev, "slack")["text"]
    card = notify.payload(ev, "teams")["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and "Acme" in json.dumps(card)
    j = notify.payload(ev + [("resolved", {"kind": "no_traffic", "tenant": "B", "device": "d",
                                            "severity": "warning", "message": "m", "first": "x"})], "json")
    assert j["events"][0]["event"] == "new" and j["events"][1]["event"] == "resolved"
    assert "first" not in j["events"][1]


def test_bad_format_and_http_url(tmp_path):
    with pytest.raises(ValueError):
        notify.run([], state_path=tmp_path / "s", url="https://x", fmt="email", send=Sink())
    with pytest.raises(ValueError):
        notify.post_json("http://hooks.example/x", {})


def test_corrupt_state_treated_as_empty(tmp_path):
    (tmp_path / "s.json").write_text("{not json")
    assert [e for e, _ in run(tmp_path, [A()], T0, Sink())] == ["new"]


def test_cli_requires_webhook_and_hides_url(monkeypatch, capsys, tmp_path):
    pytest.importorskip("sqlalchemy")
    monkeypatch.delenv("SCANRELAY_ALERT_WEBHOOK", raising=False)
    assert notify.main([]) == 2
    monkeypatch.setenv("CONTROLPLANE_DB_URL", f"sqlite:///{tmp_path}/cp.db")
    monkeypatch.setenv("SCANRELAY_ALERT_STATE", str(tmp_path / "st.json"))
    assert notify.main(["--dry-run"]) == 0
    assert "0 event(s) (dry run)" in capsys.readouterr().out
    secret = "https://hooks.slack.com/services/SECRET123"
    monkeypatch.setenv("SCANRELAY_ALERT_WEBHOOK", secret)
    from controlplane import alerts
    monkeypatch.setattr(alerts, "evaluate", lambda s: [A()])
    monkeypatch.setattr(notify, "post_json", lambda u, b: (_ for _ in ()).throw(OSError(u)))
    assert notify.main([]) == 1
    out = capsys.readouterr()
    assert "SECRET123" not in out.out + out.err
