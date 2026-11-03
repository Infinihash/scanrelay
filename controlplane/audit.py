"""Tamper-evident audit trail for the control plane (launch-readiness #6).

Append-only, hash-chained `audit_log` table: hash = sha256(prev | seq | ts | kind | ref | sha256(data)).
Ids, counts and field names only - no tenant names, secrets refs, addresses. Appends run in the caller's
session, so the change and its audit entry commit together. SQLite gets triggers that refuse
UPDATE/DELETE; every backend gets ORM guards, and `verify()` catches edits made behind both.

    python -m controlplane.audit verify      exit 0 intact, 1 broken
    python -m controlplane.audit export OUT  tenants + devices + send_log + audit chain, one JSON file
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from typing import Any

from sqlalchemy import DDL, Float, Integer, String, Text, event, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Base

GENESIS = "0" * 64


class AuditEntry(Base):
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[float] = mapped_column(Float)
    kind: Mapped[str] = mapped_column(String(48))
    ref: Mapped[str] = mapped_column(String(128), index=True)
    data_sha256: Mapped[str] = mapped_column(String(64))
    data: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


for _ev in ("update", "delete"):
    event.listen(AuditEntry.__table__, "after_create", DDL(
        f"CREATE TRIGGER IF NOT EXISTS audit_log_no_{_ev} BEFORE {_ev.upper()} ON audit_log "
        f"BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END").execute_if(dialect="sqlite"))


@event.listens_for(AuditEntry, "before_update")
@event.listens_for(AuditEntry, "before_delete")
def _refuse(mapper, connection, target):   # noqa: ARG001
    raise RuntimeError("audit_log is append-only")


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _canon(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _entry_hash(prev: str, seq: int, ts: float, kind: str, ref: str, data_sha: str) -> str:
    return sha256_text("|".join([prev, str(seq), repr(float(ts)), kind, ref, data_sha]))


def append(s: Session, kind: str, ref: str, data: dict | None = None, ts: float | None = None) -> str:
    """Add one entry to the session (flushed, not committed). Returns its hash."""
    s.flush()
    last = s.execute(select(AuditEntry.seq, AuditEntry.hash).order_by(AuditEntry.seq.desc()).limit(1)).first()
    seq0, prev = (last[0], last[1]) if last else (0, GENESIS)
    canon = _canon(data or {})
    ts = time.time() if ts is None else ts
    h = _entry_hash(prev, seq0 + 1, ts, kind, ref, sha256_text(canon))
    s.add(AuditEntry(seq=seq0 + 1, ts=ts, kind=kind, ref=ref, data_sha256=sha256_text(canon), data=canon,
                     prev_hash=prev, hash=h))
    s.flush()
    return h


def verify(s: Session) -> dict[str, Any]:
    prev, n = GENESIS, 0
    for e in s.execute(select(AuditEntry).order_by(AuditEntry.seq)).scalars():
        n += 1
        bad = None
        if e.seq != n:
            bad = "sequence gap"
        elif e.prev_hash != prev:
            bad = "prev hash mismatch"
        elif sha256_text(e.data) != e.data_sha256:
            bad = "data altered"
        elif _entry_hash(prev, e.seq, e.ts, e.kind, e.ref, e.data_sha256) != e.hash:
            bad = "entry hash mismatch"
        if bad:
            return {"ok": False, "length": n - 1, "head": prev, "broken_at": n, "reason": bad}
        prev = e.hash
    return {"ok": True, "length": n, "head": prev, "broken_at": None, "reason": None}


def entries(s: Session) -> list[dict]:
    return [{"seq": e.seq, "ts": e.ts, "kind": e.kind, "ref": e.ref, "data": json.loads(e.data),
             "prev_hash": e.prev_hash, "hash": e.hash}
            for e in s.execute(select(AuditEntry).order_by(AuditEntry.seq)).scalars()]


def export(s: Session) -> dict:
    """Records + audit chain as one evidence bundle (ingest-key hashes and secret refs are NOT included)."""
    from .models import Device, SendLog, Tenant
    return {
        "exported_at": int(time.time()),
        "tenants": [{"id": t.id, "name": t.name, "entra_tenant_id": t.entra_tenant_id, "client_id": t.client_id,
                     "secret_expires": t.secret_expires.isoformat() if t.secret_expires else None,
                     "created_at": t.created_at.isoformat()} for t in s.scalars(select(Tenant))],
        "devices": [{"id": d.id, "tenant_id": d.tenant_id, "name": d.name, "auth_mode": d.auth_mode,
                     "created_at": d.created_at.isoformat()} for d in s.scalars(select(Device))],
        "send_log": [{"id": r.id, "ts": r.ts.isoformat(), "device_id": r.device_id, "recipients": r.recipients,
                      "size": r.size, "status": r.status, "graph_request_id": r.graph_request_id}
                     for r in s.scalars(select(SendLog))],
        "audit": {"entries": entries(s), "verify": verify(s)},
    }


def main(argv: list[str] | None = None) -> int:
    from .db import make_engine, make_sessionmaker
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("verify", "export"):
        print(__doc__)
        return 2
    SM = make_sessionmaker(make_engine())
    with SM() as s:
        if argv[0] == "verify":
            res = verify(s)
            print(json.dumps(res))
            return 0 if res["ok"] else 1
        if len(argv) < 2:
            print("export needs an output file", file=sys.stderr)
            return 2
        b = export(s)
        open(argv[1], "w").write(json.dumps(b, indent=2, sort_keys=True))
        print(f"wrote {argv[1]}: chain ok={b['audit']['verify']['ok']} entries={len(b['audit']['entries'])}")
        return 0 if b["audit"]["verify"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
