"""Optional control plane hook. Off unless CONTROLPLANE_URL is set.

Sends send *metadata only* (device, recipient count, size, status, Graph request-id) to the
ScanRelay control plane. Never subjects, bodies, attachment names or addresses. A control
plane outage never affects mail delivery: errors are logged and dropped.
"""
from __future__ import annotations

import logging
import os
import time

import httpx

log = logging.getLogger("scanrelay.telemetry")


class ControlPlaneReporter:
    def __init__(self, url: str, key: str, client: httpx.Client | None = None, timeout: float = 5.0):
        self.url = url.rstrip("/") + "/api/v1/ingest"
        self.key = key
        self.http = client or httpx.Client(timeout=timeout)

    @classmethod
    def from_env(cls, env: dict | None = None) -> "ControlPlaneReporter | None":
        e = os.environ if env is None else env
        url = e.get("CONTROLPLANE_URL", "").strip()
        if not url:
            return None
        return cls(url, e.get("CONTROLPLANE_KEY", ""))

    @staticmethod
    def event(meta: dict, status: str, request_id: str = "") -> dict:
        user = meta.get("user")
        return {"device": user or meta.get("peer") or "unknown", "ts": time.time(),
                "recipients": len(meta.get("rcpts", [])), "size": int(meta.get("size", 0)),
                "status": status, "graph_request_id": (request_id or "")[:64],
                "auth_mode": "login" if user else "ip"}

    def report(self, meta: dict, status: str, request_id: str = "") -> bool:
        try:
            r = self.http.post(self.url, json={"events": [self.event(meta, status, request_id)]},
                               headers={"X-ScanRelay-Key": self.key})
            if r.status_code >= 300:
                log.warning("control plane push rejected: HTTP %s", r.status_code)
                return False
            return True
        except Exception as e:  # noqa: BLE001  (never break delivery)
            log.warning("control plane push failed: %s", e)
            return False
