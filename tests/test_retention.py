import json
import os
import time

import pytest

from scanrelay import retention
from scanrelay.server import Config, Spool

DAY = 86400


def _mk(spool, mid, age_days, failed=True):
    d = spool / "failed" if failed else spool
    d.mkdir(parents=True, exist_ok=True)
    for ext in (".eml", ".json"):
        p = d / f"{mid}{ext}"
        p.write_text("x")
        t = time.time() - age_days * DAY
        os.utime(p, (t, t))


def test_failed_older_than_retention_purged_recent_kept(tmp_path):
    _mk(tmp_path, "old", 30)
    _mk(tmp_path, "new", 2)
    gone = retention.purge_failed(tmp_path, 14)
    assert gone == ["old"]
    assert not (tmp_path / "failed" / "old.eml").exists()
    assert (tmp_path / "failed" / "new.eml").exists()


def test_dry_run_deletes_nothing(tmp_path):
    _mk(tmp_path, "old", 30)
    assert retention.purge_failed(tmp_path, 14, dry_run=True) == ["old"]
    assert (tmp_path / "failed" / "old.eml").exists()


def test_inflight_spool_never_touched_by_purge(tmp_path):
    _mk(tmp_path, "queued", 99, failed=False)
    retention.purge_failed(tmp_path, 14)
    assert (tmp_path / "queued.eml").exists()


def test_log_rotation_drops_old_keeps_new_and_garbage(tmp_path):
    lp = tmp_path / "sends.jsonl"
    lp.write_text(json.dumps({"ts": time.time() - 200 * DAY, "id": "a"}) + "\n"
                  + json.dumps({"ts": time.time() - 1 * DAY, "id": "b"}) + "\n"
                  + "not json\n")
    assert retention.rotate_log(str(lp), 90) == 1
    left = lp.read_text().splitlines()
    assert len(left) == 2 and '"b"' in left[0] and left[1] == "not json"


def test_delete_message_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError):
        retention.delete_message(tmp_path, "../etc/passwd")


def test_delete_message_removes_both_files(tmp_path):
    _mk(tmp_path, "m1", 1)
    assert retention.delete_message(tmp_path, "m1") == 2
    assert not list((tmp_path / "failed").iterdir())


def test_running_relay_enforces_retention(tmp_path, monkeypatch):
    """The Spool worker must actually call the sweep (not just ship the module)."""
    _mk(tmp_path / "spool", "old", 30)
    cfg = Config(tenant_id="t", client_id="c", client_secret="s", sender="a@b.c",
                 spool=str(tmp_path / "spool"), log_path=str(tmp_path / "sends.jsonl"))
    sp = Spool(cfg, sender=None)
    sp.maybe_sweep(force=True)
    assert not (tmp_path / "spool" / "failed" / "old.eml").exists()


def test_worker_loop_runs_the_sweep(tmp_path):
    cfg = Config(tenant_id="t", client_id="c", client_secret="s", sender="a@b.c",
                 spool=str(tmp_path / "spool"), log_path=str(tmp_path / "sends.jsonl"))
    sp = Spool(cfg, sender=None)
    calls = []
    sp.maybe_sweep = lambda force=False: calls.append(1)
    import threading
    t = threading.Thread(target=sp.run, daemon=True)
    t.start()
    time.sleep(0.3)
    sp.stop()
    t.join(5)
    assert calls
