"""Control plane retention: send_log rows (metadata only) older than N days."""
from __future__ import annotations

import datetime as dt
import os

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import audit
from .models import SendLog

DEFAULT_DAYS = 90


def days() -> int:
    return int(os.environ.get("CONTROLPLANE_SENDLOG_RETENTION_DAYS", str(DEFAULT_DAYS)))


def purge_send_log(s: Session, n_days: int | None = None, *, dry_run: bool = False,
                   now: dt.datetime | None = None) -> int:
    n_days = days() if n_days is None else n_days
    if n_days <= 0:
        return 0
    cutoff = (now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)) - dt.timedelta(days=n_days)
    count = s.scalar(select(func.count()).select_from(SendLog).where(SendLog.ts < cutoff)) or 0
    if count and not dry_run:
        # the purge is itself audited, in the same transaction as the delete
        audit.append(s, "send_log_purged", "send_log", {"rows": count, "days": n_days, "cutoff": cutoff.isoformat()})
        s.execute(delete(SendLog).where(SendLog.ts < cutoff))
        s.commit()
    return count


def main() -> int:
    """Cron entry point (`python -m controlplane.retention`): purge old send_log rows, then verify the audit
    chain. Exit 0 ok, 1 if the chain is broken (so cron/monitoring alarms)."""
    import json

    from .db import make_engine, make_sessionmaker
    with make_sessionmaker(make_engine())() as s:
        purged = purge_send_log(s)
        chain = audit.verify(s)
    print(json.dumps({"send_log_purged": purged, "audit": chain}))
    return 0 if chain["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
