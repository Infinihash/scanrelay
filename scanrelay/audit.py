"""Tamper-evident audit trail for the relay (launch-readiness #6).

An append-only, hash-chained JSON-lines file (`audit.jsonl`, next to the send log). Each line commits to
the one before it:

    hash = sha256(prev | seq | ts | kind | ref | sha256(canonical data))

so editing, reordering, truncating the middle or deleting any line is detected by `verify()` at the exact
line. Entries carry ids, counts, sizes and hashes only: no addresses, subjects, bodies or attachment names.
It is NOT trimmed by the send-log retention - a log rotation, a failed-mail purge and a manual delete are
themselves entries - so the purge of evidence is evidenced.

Events: message_received (sha256 of the raw message), send_recorded (sent|failed outcome),
failed_purged, message_deleted, log_rotated (count + sha256 of the dropped lines), retention_sweep.

    scanrelay-audit verify      exit 0 intact, 1 broken (JSON on stdout)
    scanrelay-audit export OUT  bundle: audit chain + verify result + send log (metadata) as one JSON file

Honest limits: a file can be appended to by anyone with write access to it, so the chain proves that history
was not edited, not that entries were not added; keep copies of `head` off the host (the export prints it)
and run the relay's audit file on append-only storage (`chattr +a`) if the threat model needs it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover  (Windows)
    fcntl = None

GENESIS = "0" * 64
_LOCK = threading.Lock()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _canon(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _entry_hash(prev: str, seq: int, ts: float, kind: str, ref: str, data_sha: str) -> str:
    return sha256_bytes("|".join([prev, str(seq), repr(float(ts)), kind, ref, data_sha]).encode())


def _last(path: Path) -> tuple[int, str]:
    if not path.exists() or path.stat().st_size == 0:
        return 0, GENESIS
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        chunk = min(size, 65536)
        f.seek(size - chunk)
        lines = f.read().splitlines()
    last = json.loads(lines[-1])
    return last["seq"], last["hash"]


def append(path: str | Path, kind: str, ref: str, data: dict | None = None, ts: float | None = None) -> str:
    """Append one entry (fsynced). Returns its hash."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    canon = _canon(data or {})
    with _LOCK:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:   # the relay and `scanrelay-retention` are separate processes
                fcntl.flock(fd, fcntl.LOCK_EX)
            seq0, prev = _last(path)
            seq, ts = seq0 + 1, time.time() if ts is None else ts
            h = _entry_hash(prev, seq, ts, kind, ref, sha256_bytes(canon.encode()))
            line = json.dumps({"seq": seq, "ts": ts, "kind": kind, "ref": ref, "data": json.loads(canon),
                               "prev": prev, "hash": h}, sort_keys=True)
            os.write(fd, (line + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)   # also releases the flock
    return h


def verify(path: str | Path) -> dict[str, Any]:
    """Walk the whole chain. {ok, length, head, broken_at, reason}."""
    path, prev, n = Path(path), GENESIS, 0
    if not path.exists():
        return {"ok": True, "length": 0, "head": GENESIS, "broken_at": None, "reason": None}
    for raw in path.read_text().splitlines():
        n += 1
        try:
            e = json.loads(raw)
            seq, ts, kind, ref, data, eprev, h = (e[k] for k in ("seq", "ts", "kind", "ref", "data", "prev", "hash"))
        except Exception:  # noqa: BLE001
            return {"ok": False, "length": n - 1, "head": prev, "broken_at": n, "reason": "unparseable line"}
        if seq != n:
            return {"ok": False, "length": n - 1, "head": prev, "broken_at": n, "reason": "sequence gap"}
        if eprev != prev:
            return {"ok": False, "length": n - 1, "head": prev, "broken_at": n, "reason": "prev hash mismatch"}
        if _entry_hash(prev, seq, ts, kind, ref, sha256_bytes(_canon(data).encode())) != h:
            return {"ok": False, "length": n - 1, "head": prev, "broken_at": n, "reason": "entry hash mismatch"}
        prev = h
    return {"ok": True, "length": n, "head": prev, "broken_at": None, "reason": None}


def export(audit_path: str | Path, log_path: str | Path | None = None, out: str | Path | None = None) -> dict:
    """Records plus audit as one self-describing evidence bundle."""
    audit_path = Path(audit_path)
    entries = [json.loads(l) for l in audit_path.read_text().splitlines()] if audit_path.exists() else []
    sends = []
    if log_path and Path(log_path).exists():
        for l in Path(log_path).read_text().splitlines():
            try:
                sends.append(json.loads(l))
            except ValueError:
                pass
    bundle = {"exported_at": int(time.time()), "audit": {"entries": entries, "verify": verify(audit_path)},
              "send_log": sends, "note": "metadata only; no message content, addresses or subjects"}
    if out:
        Path(out).write_text(json.dumps(bundle, indent=2, sort_keys=True))
    return bundle


def write_status(audit_path: str | Path) -> dict:
    """Verify and leave `audit-status.json` beside the chain for monitoring; returns the result."""
    res = verify(audit_path)
    res["checked_at"] = int(time.time())
    p = Path(audit_path).with_name("audit-status.json")
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(res))
    os.replace(tmp, p)
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scanrelay-audit", description="Verify / export the relay's audit chain")
    ap.add_argument("cmd", choices=["verify", "export"])
    ap.add_argument("out", nargs="?", help="export: output file")
    a = ap.parse_args(argv)
    ap_ = os.environ.get("SCANRELAY_AUDIT", "/var/log/scanrelay/audit.jsonl")
    lp = os.environ.get("SCANRELAY_LOG", "/var/log/scanrelay/sends.jsonl")
    if a.cmd == "verify":
        res = verify(ap_)
        print(json.dumps(res))
        return 0 if res["ok"] else 1
    if not a.out:
        print("export needs an output file", file=sys.stderr)
        return 2
    b = export(ap_, lp, a.out)
    print(f"wrote {a.out}: {len(b['audit']['entries'])} audit entries, {len(b['send_log'])} send-log lines, "
          f"chain ok={b['audit']['verify']['ok']} head={b['audit']['verify']['head']}")
    return 0 if b["audit"]["verify"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
