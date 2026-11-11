import pytest

pytest.importorskip("sqlalchemy")

import datetime as dt

from controlplane.db import make_engine, make_sessionmaker
from controlplane.models import Device, SendLog, Tenant
from controlplane.retention import purge_send_log


def test_old_send_rows_purged_recent_kept():
    SM = make_sessionmaker(make_engine("sqlite://"))
    with SM() as s:
        t = Tenant(name="t", entra_tenant_id="e", client_id="c")
        d = Device(tenant=t, name="d")
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        s.add_all([t, d,
                   SendLog(device=d, ts=now - dt.timedelta(days=200), status="sent"),
                   SendLog(device=d, ts=now - dt.timedelta(days=1), status="sent")])
        s.commit()
        assert purge_send_log(s, 90, dry_run=True) == 1
        assert purge_send_log(s, 90) == 1
        assert [r.status for r in s.query(SendLog)] == ["sent"] and s.query(SendLog).count() == 1
