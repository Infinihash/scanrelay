"""Control plane retention: send_log rows (metadata only) older than N days."""
from __future__ import annotations

import datetime as dt
import os

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

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
        s.execute(delete(SendLog).where(SendLog.ts < cutoff))
        s.commit()
    return count
