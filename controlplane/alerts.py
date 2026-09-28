"""Alert evaluation: expiring client secrets, device failure rate, devices gone quiet."""
from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AlertRule, Device, SendLog, Tenant, utcnow

EXPIRY_STEPS = {7: "critical", 14: "warning", 30: "info"}   # days left -> severity

DEFAULTS: dict[str, dict] = {
    "secret_expiry": {"threshold": 30, "enabled": True},                       # horizon in days
    "failure_rate": {"threshold": 0.2, "window_hours": 24, "min_sends": 5, "enabled": True},
    "no_traffic": {"window_hours": 72, "enabled": True},
}


@dataclass
class Alert:
    kind: str
    severity: str          # info | warning | critical
    tenant: str
    device: str | None
    message: str

    def dict(self) -> dict:
        return asdict(self)


def rules_for(db: Session, tenant_id: int) -> dict[str, dict]:
    """Defaults, overridden by global rules, overridden by tenant rules."""
    rules = {k: dict(v) for k, v in DEFAULTS.items()}
    rows = db.scalars(select(AlertRule).where(
        (AlertRule.tenant_id.is_(None)) | (AlertRule.tenant_id == tenant_id))).all()
    for r in sorted(rows, key=lambda r: r.tenant_id is not None):   # global first, tenant wins
        if r.kind in rules:
            rules[r.kind].update(threshold=r.threshold, window_hours=r.window_hours,
                                 min_sends=r.min_sends, enabled=r.enabled)
    return rules


def secret_expiry_alert(tenant: Tenant, today: dt.date, horizon: float = 30) -> Alert | None:
    if tenant.secret_expires is None:
        return None
    days = (tenant.secret_expires - today).days
    if days > horizon:
        return None
    if days < 0:
        return Alert("secret_expiry", "critical", tenant.name, None,
                     f"Client secret expired {-days} day(s) ago; sending is failing")
    step = next((s for s in sorted(EXPIRY_STEPS) if days <= s), int(horizon))
    return Alert("secret_expiry", EXPIRY_STEPS.get(step, "info"), tenant.name, None,
                 f"Client secret expires in {days} day(s) (within {step}d)")


def device_stats(db: Session, device: Device, since: dt.datetime) -> tuple[int, int]:
    """(final outcomes, failures) since a time. Retries are attempts, not outcomes."""
    rows = db.execute(select(SendLog.status, func.count()).where(
        SendLog.device_id == device.id, SendLog.ts >= since,
        SendLog.status.in_(("sent", "failed"))).group_by(SendLog.status)).all()
    counts = dict(rows)
    return counts.get("sent", 0) + counts.get("failed", 0), counts.get("failed", 0)


def last_seen(db: Session, device: Device) -> dt.datetime | None:
    return db.scalar(select(func.max(SendLog.ts)).where(SendLog.device_id == device.id))


def evaluate(db: Session, now: dt.datetime | None = None) -> list[Alert]:
    now = now or utcnow()
    out: list[Alert] = []
    for t in db.scalars(select(Tenant).order_by(Tenant.name)).all():
        rules = rules_for(db, t.id)
        r = rules["secret_expiry"]
        if r["enabled"] and (a := secret_expiry_alert(t, now.date(), r["threshold"])):
            out.append(a)
        for d in sorted(t.devices, key=lambda d: d.name):
            r = rules["failure_rate"]
            if r["enabled"]:
                total, failed = device_stats(db, d, now - dt.timedelta(hours=r["window_hours"]))
                if total >= r["min_sends"] and total and failed / total >= r["threshold"]:
                    rate = failed / total
                    out.append(Alert("failure_rate", "critical" if rate >= 0.5 else "warning", t.name, d.name,
                                     f"{failed}/{total} sends failed ({rate:.0%}) in {r['window_hours']}h"))
            r = rules["no_traffic"]
            if r["enabled"]:
                ref = last_seen(db, d) or d.created_at
                if now - ref > dt.timedelta(hours=r["window_hours"]):
                    hours = int((now - ref).total_seconds() // 3600)
                    out.append(Alert("no_traffic", "warning", t.name, d.name,
                                     f"No traffic for {hours}h (limit {r['window_hours']}h)"))
    return out
