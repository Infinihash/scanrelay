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

log = logging.getLogger("scanrelay.retention")
DAY = 86400


def failed_days() -> int:
    return int(os.environ.get("SCANRELAY_FAILED_RETENTION_DAYS", "14"))


def log_days() -> int:
    return int(os.environ.get("SCANRELAY_LOG_RETENTION_DAYS", "90"))


def purge_failed(spool: Path, days: int, *, dry_run: bool = False, now: float | None = None) -> list[str]:
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
        for ext in (".eml", ".json"):
            (fdir / f"{mid}{ext}").unlink(missing_ok=True)
    return ids


def delete_message(spool: Path, mid: str, *, dry_run: bool = False) -> int:
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
    return n


def rotate_log(log_path: str, days: int, *, dry_run: bool = False, now: float | None = None) -> int:
    """Drop send-log lines older than ``days``. Returns lines dropped."""
    p = Path(log_path)
    if days <= 0 or not p.exists():
        return 0
    cutoff = (now or time.time()) - days * DAY
    keep, dropped = [], 0
    for line in p.read_text().splitlines():
        try:
            old = json.loads(line).get("ts", cutoff + 1) < cutoff
        except Exception:  # noqa: BLE001  unparseable lines are kept, not guessed at
            old = False
        if old:
            dropped += 1
        else:
            keep.append(line)
    if dropped and not dry_run:
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text("".join(l + "\n" for l in keep))
        os.replace(tmp, p)
    return dropped


def sweep(spool: Path, log_path: str, *, dry_run: bool = False, now: float | None = None) -> dict:
    res = {"dry_run": dry_run,
           "failed_purged": len(purge_failed(spool, failed_days(), dry_run=dry_run, now=now)),
           "log_lines_dropped": rotate_log(log_path, log_days(), dry_run=dry_run, now=now)}
    log.info("retention sweep %s", res)
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description="ScanRelay data retention (dry-run unless --apply)")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--delete", metavar="ID", help="delete one message by id")
    a = ap.parse_args()
    spool = Path(os.environ.get("SCANRELAY_SPOOL", "/var/lib/scanrelay/spool"))
    logp = os.environ.get("SCANRELAY_LOG", "/var/log/scanrelay/sends.jsonl")
    if a.delete:
        print(json.dumps({"deleted_files": delete_message(spool, a.delete, dry_run=not a.apply)}))
    else:
        print(json.dumps(sweep(spool, logp, dry_run=not a.apply)))


if __name__ == "__main__":
    main()
