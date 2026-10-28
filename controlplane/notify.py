"""Push control-plane alerts to Slack, Teams or any JSON webhook.

Run it from cron or a systemd timer (every 15 minutes is plenty):

    SCANRELAY_ALERT_WEBHOOK=https://hooks.slack.com/services/... \\
    SCANRELAY_ALERT_FORMAT=slack scanrelay-notify

It evaluates the same alerts as GET /api/v1/alerts and only posts changes:

* a new alert is posted once;
* an alert whose severity changes (e.g. secret expiry info -> warning ->
  critical) is posted again;
* an alert still open after SCANRELAY_ALERT_REPEAT_HOURS (default 24) is
  posted again as a reminder;
* an alert that has cleared is posted once as resolved.

State is a small JSON file (SCANRELAY_ALERT_STATE, default
./alert-state.json) holding alert keys, severities and timestamps only. It is
written only after the webhook accepts the post, so a failed post is retried
on the next run. The webhook URL is a secret: it is never logged or printed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Callable

from .alerts import Alert

FORMATS = ("slack", "teams", "json")
_ICON = {"critical": "\U0001F534", "warning": "\U0001F7E0", "info": "\U0001F535", "resolved": "✅"}


def alert_key(a: Alert) -> str:
    return f"{a.kind}|{a.tenant}|{a.device or ''}"


def diff(alerts: list[Alert], state: dict, now: dt.datetime, repeat_hours: float = 24
         ) -> tuple[list[tuple[str, Alert | dict]], dict]:
    """Return ([(event, alert_or_old_state)], new_state). event: new|changed|reminder|resolved."""
    events: list[tuple[str, Alert | dict]] = []
    new_state: dict = {}
    seen = set()
    for a in alerts:
        k = alert_key(a)
        if k in seen:
            continue
        seen.add(k)
        old = state.get(k)
        rec = {"kind": a.kind, "tenant": a.tenant, "device": a.device,
               "severity": a.severity, "message": a.message,
               "first": old["first"] if old else now.isoformat(), "notified": now.isoformat()}
        if old is None:
            events.append(("new", a))
        elif old.get("severity") != a.severity:
            events.append(("changed", a))
        elif now - dt.datetime.fromisoformat(old["notified"]) >= dt.timedelta(hours=repeat_hours):
            events.append(("reminder", a))
        else:
            rec["notified"] = old["notified"]
        new_state[k] = rec
    for k, old in state.items():
        if k not in seen:
            events.append(("resolved", old))
    return events, new_state


def _line(event: str, item: Alert | dict) -> str:
    d = item.dict() if isinstance(item, Alert) else item
    where = d["tenant"] + (f" / {d['device']}" if d.get("device") else "")
    if event == "resolved":
        return f"{_ICON['resolved']} Resolved: {where}: {d['kind'].replace('_', ' ')}"
    tag = {"new": "", "changed": " (severity changed)", "reminder": " (still open)"}[event]
    return f"{_ICON.get(d['severity'], '')} {d['severity'].upper()}{tag}: {where}: {d['message']}"


def payload(events: list[tuple[str, Alert | dict]], fmt: str) -> dict:
    lines = [_line(e, i) for e, i in events]
    text = "ScanRelay alerts\n" + "\n".join(lines)
    if fmt == "slack":
        return {"text": text}
    if fmt == "teams":
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4",
                        "body": [{"type": "TextBlock", "text": "ScanRelay alerts", "weight": "Bolder"}]
                        + [{"type": "TextBlock", "text": ln, "wrap": True} for ln in lines]}}]}
    return {"source": "scanrelay", "events": [
        {"event": e, **(i.dict() if isinstance(i, Alert) else
                        {k: i.get(k) for k in ("kind", "tenant", "device", "severity", "message")})}
        for e, i in events]}


def post_json(url: str, body: dict, timeout: float = 10) -> None:
    if not url.startswith("https://"):
        raise ValueError("webhook URL must be https")
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (https enforced above)
        if r.status >= 300:
            raise RuntimeError(f"webhook returned HTTP {r.status}")


def load_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(path)


def run(alerts: list[Alert], *, state_path: Path, url: str, fmt: str = "slack",
        repeat_hours: float = 24, now: dt.datetime | None = None, dry_run: bool = False,
        send: Callable[[str, dict], None] | None = None) -> list[tuple[str, Alert | dict]]:
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {FORMATS}")
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    events, new_state = diff(alerts, load_state(state_path), now, repeat_hours)
    if dry_run:
        return events
    if events:
        (send or post_json)(url, payload(events, fmt))      # raises -> state untouched -> retried next run
    save_state(state_path, new_state)
    return events


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scanrelay-notify", description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="print what would be posted; change nothing")
    args = ap.parse_args(argv)
    url = os.environ.get("SCANRELAY_ALERT_WEBHOOK", "")
    if not url and not args.dry_run:
        print("SCANRELAY_ALERT_WEBHOOK is not set", file=sys.stderr)
        return 2
    from .db import make_engine, make_sessionmaker
    from .alerts import evaluate
    with make_sessionmaker(make_engine())() as s:
        alerts = evaluate(s)
    try:
        events = run(alerts, state_path=Path(os.environ.get("SCANRELAY_ALERT_STATE", "alert-state.json")),
                     url=url, fmt=os.environ.get("SCANRELAY_ALERT_FORMAT", "slack"),
                     repeat_hours=float(os.environ.get("SCANRELAY_ALERT_REPEAT_HOURS", "24")),
                     dry_run=args.dry_run)
    except Exception as e:  # never echo the URL
        print(f"notify failed: {type(e).__name__}", file=sys.stderr)
        return 1
    for e, i in events:
        print(_line(e, i))
    print(f"{len(events)} event(s){' (dry run)' if args.dry_run else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
