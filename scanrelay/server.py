"""ScanRelay SMTP front end: accepts mail from LAN devices (per-device login and/or IP
allowlist), spools it to disk, and a worker delivers it through Microsoft Graph with retries.
Never an open relay: every session must match the allowlist or authenticate."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, Envelope, LoginPassword, Session, SMTP

from .graph import GraphError, GraphSender

log = logging.getLogger("scanrelay")


@dataclass
class Config:
    tenant_id: str
    client_id: str
    client_secret: str
    sender: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 2525
    users: dict[str, str] = field(default_factory=dict)       # username -> password (or sha256:<hex>)
    allow_ips: list[str] = field(default_factory=list)        # CIDRs allowed without AUTH
    allowed_rcpt_domains: list[str] = field(default_factory=list)  # empty = any
    max_size: int = 35 * 1024 * 1024
    spool: str = "/var/lib/scanrelay/spool"
    log_path: str = "/var/log/scanrelay/sends.jsonl"
    tls_cert: str = ""
    tls_key: str = ""
    require_tls_for_auth: bool = False   # many old copiers can't do STARTTLS; LAN-only default
    max_attempts: int = 12

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ
        users = {}
        for pair in filter(None, (e.get("SCANRELAY_USERS", "")).split(",")):
            u, _, p = pair.strip().partition(":")
            users[u] = p
        return cls(
            tenant_id=e["SCANRELAY_TENANT_ID"], client_id=e["SCANRELAY_CLIENT_ID"],
            client_secret=e["SCANRELAY_CLIENT_SECRET"], sender=e["SCANRELAY_SENDER"],
            listen_host=e.get("SCANRELAY_HOST", "0.0.0.0"), listen_port=int(e.get("SCANRELAY_PORT", "2525")),
            users=users,
            allow_ips=[c.strip() for c in e.get("SCANRELAY_ALLOW_IPS", "").split(",") if c.strip()],
            allowed_rcpt_domains=[d.strip().lower() for d in e.get("SCANRELAY_RCPT_DOMAINS", "").split(",") if d.strip()],
            max_size=int(e.get("SCANRELAY_MAX_SIZE", str(35 * 1024 * 1024))),
            spool=e.get("SCANRELAY_SPOOL", "/var/lib/scanrelay/spool"),
            log_path=e.get("SCANRELAY_LOG", "/var/log/scanrelay/sends.jsonl"),
            tls_cert=e.get("SCANRELAY_TLS_CERT", ""), tls_key=e.get("SCANRELAY_TLS_KEY", ""),
            require_tls_for_auth=e.get("SCANRELAY_REQUIRE_TLS", "0") in ("1", "true", "yes"),
        )


def check_password(stored: str, given: str) -> bool:
    if stored.startswith("sha256:"):
        return hmac.compare_digest(stored[7:], hashlib.sha256(given.encode()).hexdigest())
    return hmac.compare_digest(stored, given)


class Authenticator:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def __call__(self, server, session, envelope, mechanism, auth_data):
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)
        user, pw = auth_data.login.decode(), auth_data.password.decode()
        ok = user in self.cfg.users and check_password(self.cfg.users[user], pw)
        log.info("auth %s user=%s peer=%s", "ok" if ok else "FAILED", user, session.peer[0])
        if ok:
            session.scanrelay_user = user
        return AuthResult(success=ok, handled=False)


class Handler:
    def __init__(self, cfg: Config, spool: "Spool"):
        self.cfg, self.spool = cfg, spool
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cfg.allow_ips]

    def _allowed_ip(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets)

    async def handle_MAIL(self, server, session: Session, envelope: Envelope, address, mail_options):
        if not (session.authenticated or self._allowed_ip(session.peer[0])):
            log.warning("rejected unauthenticated sender peer=%s", session.peer[0])
            return "530 5.7.0 Authentication required"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope: Envelope, address: str, rcpt_options):
        dom = address.rsplit("@", 1)[-1].lower()
        if self.cfg.allowed_rcpt_domains and dom not in self.cfg.allowed_rcpt_domains:
            return "550 5.7.1 Recipient domain not allowed by relay policy"
        if len(envelope.rcpt_tos) >= 100:
            return "452 4.5.3 Too many recipients"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope: Envelope):
        data = envelope.original_content or envelope.content
        if isinstance(data, str):
            data = data.encode()
        if len(data) > self.cfg.max_size:
            return "552 5.3.4 Message too large"
        user = getattr(session, "scanrelay_user", None)
        mid = self.spool.put(data, list(envelope.rcpt_tos), session.peer[0], user)
        return f"250 2.0.0 Queued as {mid}"


class Spool:
    """Durable on-disk queue: <id>.eml + <id>.json (metadata, attempts, next_try)."""

    def __init__(self, cfg: Config, sender: GraphSender):
        self.cfg, self.sender = cfg, sender
        self.dir = Path(cfg.spool)
        (self.dir / "failed").mkdir(parents=True, exist_ok=True)
        Path(cfg.log_path).parent.mkdir(parents=True, exist_ok=True)
        self._wake = threading.Event()
        self._stop = threading.Event()

    def put(self, raw: bytes, rcpts: list[str], peer: str, user: str | None) -> str:
        mid = time.strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
        (self.dir / f"{mid}.eml").write_bytes(raw)
        meta = {"id": mid, "rcpts": rcpts, "peer": peer, "user": user, "size": len(raw),
                "received": time.time(), "attempts": 0, "next_try": 0}
        tmp = self.dir / f"{mid}.json.tmp"
        tmp.write_text(json.dumps(meta))
        tmp.rename(self.dir / f"{mid}.json")   # atomic: worker only sees complete items
        self._wake.set()
        return mid

    def _record(self, meta: dict, status: str, detail: str = "", path: str = "") -> None:
        line = {"ts": time.time(), "id": meta["id"], "status": status, "peer": meta["peer"],
                "user": meta["user"], "rcpt_count": len(meta["rcpts"]), "size": meta["size"],
                "attempts": meta["attempts"], "path": path, "detail": detail[:300]}
        with open(self.cfg.log_path, "a") as f:
            f.write(json.dumps(line) + "\n")

    def process_once(self) -> int:
        done = 0
        for mpath in sorted(self.dir.glob("*.json")):
            meta = json.loads(mpath.read_text())
            if meta["next_try"] > time.time():
                continue
            epath = self.dir / f"{meta['id']}.eml"
            meta["attempts"] += 1
            try:
                how = self.sender.send(epath.read_bytes(), meta["rcpts"])
            except Exception as e:  # noqa: BLE001
                transient = isinstance(e, GraphError) and e.transient or not isinstance(e, GraphError)
                if transient and meta["attempts"] < self.cfg.max_attempts:
                    meta["next_try"] = time.time() + min(3600, 30 * 2 ** (meta["attempts"] - 1))
                    mpath.write_text(json.dumps(meta))
                    self._record(meta, "retry", str(e))
                    log.warning("retry %s attempt=%s: %s", meta["id"], meta["attempts"], e)
                else:
                    epath.rename(self.dir / "failed" / epath.name)
                    mpath.rename(self.dir / "failed" / mpath.name)
                    self._record(meta, "failed", str(e))
                    log.error("FAILED %s: %s", meta["id"], e)
                continue
            epath.unlink(missing_ok=True)   # never keep message content after delivery
            mpath.unlink(missing_ok=True)
            self._record(meta, "sent", path=how)
            log.info("sent %s via %s rcpts=%d size=%d", meta["id"], how, len(meta["rcpts"]), meta["size"])
            done += 1
        return done

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.process_once()
            except Exception:  # noqa: BLE001
                log.exception("spool worker error")
            self._wake.wait(15)
            self._wake.clear()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()


def build(cfg: Config, sender: GraphSender | None = None):
    sender = sender or GraphSender(cfg.tenant_id, cfg.client_id, cfg.client_secret, cfg.sender)
    spool = Spool(cfg, sender)
    tls = None
    if cfg.tls_cert and cfg.tls_key:
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    handler = Handler(cfg, spool)
    controller = Controller(
        handler, hostname=cfg.listen_host, port=cfg.listen_port, tls_context=tls,
        authenticator=Authenticator(cfg) if cfg.users else None,
        auth_require_tls=cfg.require_tls_for_auth and tls is not None,
        data_size_limit=cfg.max_size, ident="ScanRelay")
    return controller, spool


def main() -> None:
    logging.basicConfig(level=os.environ.get("SCANRELAY_LOGLEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        cfg = Config.from_env()
    except KeyError as e:
        raise SystemExit(f"Missing required setting {e.args[0]} (see README).")
    if not cfg.users and not cfg.allow_ips:
        raise SystemExit("Refusing to start: set SCANRELAY_USERS and/or SCANRELAY_ALLOW_IPS (never an open relay).")
    controller, spool = build(cfg)
    worker = threading.Thread(target=spool.run, daemon=True)
    worker.start()
    controller.start()
    log.info("ScanRelay listening on %s:%s, sending as %s", cfg.listen_host, cfg.listen_port, cfg.sender)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        spool.stop()


if __name__ == "__main__":
    main()
