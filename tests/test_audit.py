"""Tamper-evident audit trail (launch-readiness #6) for the relay and the control plane."""
import json
import os
import time

import pytest

from scanrelay import audit, retention
from scanrelay.server import Config, Spool

DAY = 86400


def _chain(path, n=4):
    for i in range(n):
        audit.append(path, "send_recorded", f"m{i}", {"status": "sent", "size": i})


def test_chain_verifies(tmp_path):
    p = tmp_path / "audit.jsonl"
    _chain(p)
    v = audit.verify(p)
    assert v["ok"] and v["length"] == 4 and v["head"] != audit.GENESIS


def _rewrite(p, fn):
    lines = p.read_text().splitlines()
    fn(lines)
    p.write_text("".join(l + "\n" for l in lines))


@pytest.mark.parametrize("name,edit,reason,at", [
    ("data edit", lambda L: L.__setitem__(1, L[1].replace('"size": 1', '"size": 999')), "entry hash mismatch", 2),
    ("delete middle", lambda L: L.pop(1), "sequence gap", 2),
    ("swap order", lambda L: L.insert(1, L.pop(2)), "sequence gap", 2),
    ("garbage", lambda L: L.__setitem__(2, "not json"), "unparseable line", 3),
])
def test_tampering_is_detected_at_the_exact_line(tmp_path, name, edit, reason, at):
    p = tmp_path / "audit.jsonl"
    _chain(p)
    _rewrite(p, edit)
    v = audit.verify(p)
    assert not v["ok"] and v["broken_at"] == at and v["reason"] == reason, name


def test_recomputed_forgery_breaks_the_next_link(tmp_path):
    p = tmp_path / "audit.jsonl"
    _chain(p)

    def forge(L):
        e = json.loads(L[1]); e["data"] = {"status": "sent", "size": 777}
        e["hash"] = audit._entry_hash(e["prev"], e["seq"], e["ts"], e["kind"], e["ref"],
                                      audit.sha256_bytes(audit._canon(e["data"]).encode()))
        L[1] = json.dumps(e, sort_keys=True)
    _rewrite(p, forge)
    v = audit.verify(p)
    assert not v["ok"] and v["broken_at"] == 3 and v["reason"] == "prev hash mismatch"


def test_truncating_the_tail_is_visible_against_an_exported_head(tmp_path):
    p = tmp_path / "audit.jsonl"
    _chain(p)
    head = audit.verify(p)["head"]
    _rewrite(p, lambda L: L.pop())
    v = audit.verify(p)
    assert v["ok"] and v["head"] != head   # chain is valid but the head no longer matches the one we recorded


def test_retention_purges_are_themselves_audited(tmp_path):
    spool, logp, ap = tmp_path / "spool", tmp_path / "sends.jsonl", str(tmp_path / "audit.jsonl")
    (spool / "failed").mkdir(parents=True)
    for ext in (".eml", ".json"):
        f = spool / "failed" / f"old{ext}"; f.write_text("x")
        os.utime(f, (time.time() - 30 * DAY,) * 2)
    old = {"ts": time.time() - 200 * DAY, "id": "o"}; new = {"ts": time.time(), "id": "n"}
    logp.write_text(json.dumps(old) + "\n" + json.dumps(new) + "\n")
    res = retention.sweep(spool, str(logp), audit_path=ap)
    assert res["failed_purged"] == 1 and res["log_lines_dropped"] == 1 and res["audit"]["ok"]
    es = [json.loads(l) for l in open(ap)]
    kinds = [e["kind"] for e in es]
    assert kinds == ["failed_purged", "log_rotated", "retention_sweep"]
    assert es[0]["ref"] == "old" and es[1]["data"]["dropped"] == 1 and len(es[1]["data"]["dropped_sha256"]) == 64
    assert audit.verify(ap)["ok"]
    assert json.loads((tmp_path / "audit-status.json").read_text())["ok"] is True


def test_dry_run_and_manual_delete(tmp_path):
    spool, ap = tmp_path / "spool", str(tmp_path / "audit.jsonl")
    (spool / "failed").mkdir(parents=True)
    (spool / "failed" / "m1.eml").write_text("x")
    retention.delete_message(spool, "m1", dry_run=True, audit_path=ap)
    assert not os.path.exists(ap)
    assert retention.delete_message(spool, "m1", audit_path=ap) == 1
    assert [json.loads(l)["kind"] for l in open(ap)] == ["message_deleted"]


def test_sweep_flags_a_broken_chain(tmp_path, caplog):
    spool, logp, ap = tmp_path / "spool", tmp_path / "sends.jsonl", tmp_path / "audit.jsonl"
    spool.mkdir()
    _chain(ap)
    _rewrite(ap, lambda L: L.pop(1))
    with caplog.at_level("ERROR"):
        res = retention.sweep(spool, str(logp), audit_path=str(ap))
    assert res["audit"]["ok"] is False and res["audit"]["broken_at"] == 2
    assert "AUDIT CHAIN BROKEN" in caplog.text
    assert json.loads((tmp_path / "audit-status.json").read_text())["ok"] is False


def test_relay_records_receipt_and_outcome_without_addresses(tmp_path):
    cfg = Config(tenant_id="t", client_id="c", client_secret="s", sender="a@b.c",
                 spool=str(tmp_path / "spool"), log_path=str(tmp_path / "sends.jsonl"))

    class OK:
        last_request_id = "rid-1"
        def send(self, raw, rcpts): return "sendMail"
    sp = Spool(cfg, OK())
    sp.put(b"Subject: secret thing\r\n\r\nbody", ["bob@example.com"], "10.0.0.5", None)
    assert sp.process_once() == 1
    text = (tmp_path / "audit.jsonl").read_text()
    es = [json.loads(l) for l in text.splitlines()]
    assert [e["kind"] for e in es] == ["message_received", "send_recorded"]
    assert es[1]["data"]["status"] == "sent" and es[1]["data"]["graph_request_id"] == "rid-1"
    for leak in ("bob@example.com", "secret thing", "10.0.0.5"):
        assert leak not in text
    assert audit.verify(tmp_path / "audit.jsonl")["ok"]


def test_export_bundles_records_audit_and_verification(tmp_path):
    ap, lp = tmp_path / "audit.jsonl", tmp_path / "sends.jsonl"
    _chain(ap, 2)
    lp.write_text(json.dumps({"id": "m0", "status": "sent"}) + "\n")
    b = audit.export(ap, lp, tmp_path / "out.json")
    assert b["audit"]["verify"]["ok"] and len(b["audit"]["entries"]) == 2 and len(b["send_log"]) == 1
    assert json.loads((tmp_path / "out.json").read_text())["audit"]["verify"]["head"] == b["audit"]["verify"]["head"]


def test_cli_verify_exit_codes(tmp_path, monkeypatch, capsys):
    ap = tmp_path / "audit.jsonl"
    monkeypatch.setenv("SCANRELAY_AUDIT", str(ap))
    _chain(ap)
    assert audit.main(["verify"]) == 0
    _rewrite(ap, lambda L: L.pop(0))
    assert audit.main(["verify"]) == 1
