"""Retention for what ScanRelay keeps on disk. See DATA.md.

  spool/*.eml + *.json   in-flight mail; removed on delivery (server.py)
  spool/failed/*         mail that exhausted retries; content kept for a
                         human to recover, then purged after failed_days
  sends.jsonl            metadata-only send log; lines older than log_days dropped

Enforced by the running relay (daily) and by `python -m scanrelay.retention`
(dry-run unless --apply). `--delete ID` removes one failed message at once.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path

from . import audit as auditlog

log = logging.getLogger("scanrelay.retention")
DAY = 86400


def failed_days() -> int:
    return int(os.environ.get("SCANRELAY_FAILED_RETENTION_DAYS", "14"))


def log_days() -> int:
    return int(os.environ.get("SCANRELAY_LOG_RETENTION_DAYS", "90"))


def purge_failed(spool: Path, days: int, *, dry_run: bool = False, now: float | None = None,
                 audit_path: str | None = None) -> list[str]:
    """Delete failed/ messages older than ``days`` (by file mtime = time of failure).
    days <= 0 disables. Returns the message ids affected."""
    fdir = Path(spool) / "failed"
    if days <= 0 or not fdir.is_dir():
        return []
    cutoff = (now or time.time()) - days * DAY
    ids = sorted({p.stem for p in fdir.iterdir()
                  if p.suffix in (".eml", ".json") and p.stat().st_mtime < cutoff})
    for mid in ids:
        if dry_run:
            log.info("retention would delete failed message %s", mid)
            continue
        if audit_path:   # audit first: if the unlink then fails, the entry is a conservative over-statement
            auditlog.append(audit_path, "failed_purged", mid, {"via": "retention", "days": days}, ts=now)
        for ext in (".eml", ".json"):
            (fdir / f"{mid}{ext}").unlink(missing_ok=True)
    return ids


def delete_message(spool: Path, mid: str, *, dry_run: bool = False, audit_path: str | None = None) -> int:
    """Remove one message (failed or still queued) by id. Returns files removed."""
    if not mid or "/" in mid or "\\" in mid or mid.startswith("."):
        raise ValueError("bad message id")
    n = 0
    for d in (Path(spool), Path(spool) / "failed"):
        for ext in (".eml", ".json"):
            p = d / f"{mid}{ext}"
            if p.exists():
                n += 1
                if not dry_run:
                    p.unlink()
    if n and not dry_run and audit_path:
        auditlog.append(audit_path, "message_deleted", mid, {"via": "manual", "files": n})
    return n


def rotate_log(log_path: str, days: int, *, dry_run: bool = False, now: float | None = None,
               audit_path: str | None = None) -> int:
    """Drop send-log lines older than ``days``. Returns lines dropped."""
    p = Path(log_path)
    if days <= 0 or not p.exists():
        return 0
    cutoff = (now or time.time()) - days * DAY
    keep, gone, dropped = [], [], 0
    for line in p.read_text().splitlines():
        try:
            old = json.loads(line).get("ts", cutoff + 1) < cutoff
        except Exception:  # noqa: BLE001  unparseable lines are kept, not guessed at
            old = False
        if old:
            dropped += 1
            gone.append(line)
        else:
            keep.append(line)
    if dropped and not dry_run:
        if audit_path:   # evidence of what was dropped (count + digest of the dropped lines), not the lines
            auditlog.append(audit_path, "log_rotated", "sends.jsonl",
                            {"dropped": dropped, "days": days,
                             "dropped_sha256": auditlog.sha256_bytes("\n".join(gone).encode())}, ts=now)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text("".join(l + "\n" for l in keep))
        os.replace(tmp, p)
    return dropped


def sweep(spool: Path, log_path: str, *, dry_run: bool = False, now: float | None = None,
          audit_path: str | None = None) -> dict:
    res = {"dry_run": dry_run,
           "failed_purged": len(purge_failed(spool, failed_days(), dry_run=dry_run, now=now, audit_path=audit_path)),
           "log_lines_dropped": rotate_log(log_path, log_days(), dry_run=dry_run, now=now, audit_path=audit_path)}
    if audit_path and not dry_run:
        if res["failed_purged"] or res["log_lines_dropped"]:
            auditlog.append(audit_path, "retention_sweep", "sweep",
                            {"failed_purged": res["failed_purged"], "log_lines_dropped": res["log_lines_dropped"]}, ts=now)
        chain = auditlog.write_status(audit_path)   # verify on every sweep (6 h)
        res["audit"] = {"ok": chain["ok"], "length": chain["length"], "broken_at": chain["broken_at"]}
        if not chain["ok"]:
            log.error("AUDIT CHAIN BROKEN at entry %s (%s)", chain["broken_at"], chain["reason"])
    log.info("retention sweep %s", res)
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description="ScanRelay data retention (dry-run unless --apply)")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--delete", metavar="ID", help="delete one message by id")
    a = ap.parse_args()
    spool = Path(os.environ.get("SCANRELAY_SPOOL", "/var/lib/scanrelay/spool"))
    logp = os.environ.get("SCANRELAY_LOG", "/var/log/scanrelay/sends.jsonl")
    audp = os.environ.get("SCANRELAY_AUDIT", str(Path(logp).with_name("audit.jsonl")))
    if a.delete:
        print(json.dumps({"deleted_files": delete_message(spool, a.delete, dry_run=not a.apply, audit_path=audp)}))
    else:
        print(json.dumps(sweep(spool, logp, dry_run=not a.apply, audit_path=audp)))


if __name__ == "__main__":
    main()
