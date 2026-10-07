"""Microsoft Graph sender: app-only (client credentials) OAuth, MIME send for small
messages, draft + upload sessions for large attachments."""
from __future__ import annotations

import base64
import email
import email.policy
import time
from email.message import EmailMessage

import httpx

GRAPH = "https://graph.microsoft.com/v1.0"
MIME_LIMIT = 3_500_000          # raw bytes; base64 inflates ~4/3 -> under Graph's 4 MB request cap
SMALL_ATTACH = 3 * 1024 * 1024   # attachments >= 3 MB must use an upload session
CHUNK = 4 * 1024 * 1024 - (4 * 1024 * 1024 % 327_680)  # upload chunks must be multiples of 320 KiB


class GraphError(Exception):
    def __init__(self, status: int, detail: str, request_id: str = ""):
        super().__init__(f"Graph {status}: {detail[:300]}")
        self.status, self.request_id = status, request_id

    @property
    def transient(self) -> bool:
        return self.status in (408, 429) or self.status >= 500


class GraphSender:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, sender: str,
                 save_to_sent: bool = True, client: httpx.Client | None = None,
                 authority: str = "https://login.microsoftonline.com"):
        self.tenant_id, self.client_id, self.client_secret = tenant_id, client_id, client_secret
        self.sender, self.save_to_sent, self.authority = sender, save_to_sent, authority
        self.http = client or httpx.Client(timeout=60)
        self._token, self._exp = "", 0.0
        self.last_request_id = ""   # Graph "request-id" of the last call, for support tickets

    # ---- auth -------------------------------------------------------------
    def token(self) -> str:
        if self._token and time.time() < self._exp - 120:
            return self._token
        r = self.http.post(f"{self.authority}/{self.tenant_id}/oauth2/v2.0/token", data={
            "grant_type": "client_credentials", "client_id": self.client_id,
            "client_secret": self.client_secret, "scope": "https://graph.microsoft.com/.default"})
        if r.status_code != 200:
            raise GraphError(r.status_code, r.text)
        j = r.json()
        self._token, self._exp = j["access_token"], time.time() + int(j.get("expires_in", 3600))
        return self._token

    def _req(self, method: str, url: str, **kw) -> httpx.Response:
        h = kw.pop("headers", {})
        h["Authorization"] = "Bearer " + self.token()
        r = self.http.request(method, url if url.startswith("http") else GRAPH + url, headers=h, **kw)
        self.last_request_id = r.headers.get("request-id", "")
        if r.status_code >= 400:
            raise GraphError(r.status_code, r.text, self.last_request_id)
        return r

    # ---- send -------------------------------------------------------------
    def send(self, raw: bytes, envelope_rcpts: list[str]) -> str:
        """Send a message. Returns 'mime' or 'draft' (path used)."""
        self.last_request_id = ""
        msg = prepare(raw, self.sender, envelope_rcpts)
        data = msg.as_bytes(policy=email.policy.SMTP)
        if len(data) <= MIME_LIMIT:
            self._req("POST", f"/users/{self.sender}/sendMail", content=base64.b64encode(data),
                      headers={"Content-Type": "text/plain"})
            return "mime"
        self._send_large(msg)
        return "draft"

    def _send_large(self, msg: EmailMessage) -> None:
        body_part = msg.get_body(preferencelist=("html", "plain"))
        body = body_part.get_content() if body_part else ""
        ctype = "HTML" if body_part is not None and body_part.get_content_subtype() == "html" else "Text"

        def addrs(hdr):
            return [{"emailAddress": {"address": a}} for _, a in email.utils.getaddresses(msg.get_all(hdr, []))]

        draft = {"subject": str(msg.get("Subject", "")), "body": {"contentType": ctype, "content": body},
                 "toRecipients": addrs("To"), "ccRecipients": addrs("Cc"), "bccRecipients": addrs("Bcc"),
                 "replyTo": addrs("Reply-To")}
        mid = self._req("POST", f"/users/{self.sender}/messages", json=draft).json()["id"]
        for part in msg.iter_attachments():
            name = part.get_filename() or "attachment"
            blob = part.get_payload(decode=True) or b""
            ctype_a = part.get_content_type()
            if len(blob) < SMALL_ATTACH:
                self._req("POST", f"/users/{self.sender}/messages/{mid}/attachments", json={
                    "@odata.type": "#microsoft.graph.fileAttachment", "name": name,
                    "contentType": ctype_a, "contentBytes": base64.b64encode(blob).decode()})
                continue
            up = self._req("POST", f"/users/{self.sender}/messages/{mid}/attachments/createUploadSession", json={
                "AttachmentItem": {"attachmentType": "file", "name": name, "size": len(blob),
                                   "contentType": ctype_a}}).json()["uploadUrl"]
            for start in range(0, len(blob), CHUNK):
                chunk = blob[start:start + CHUNK]
                r = self.http.put(up, content=chunk, headers={  # pre-authenticated URL: no bearer
                    "Content-Length": str(len(chunk)), "Content-Type": "application/octet-stream",
                    "Content-Range": f"bytes {start}-{start + len(chunk) - 1}/{len(blob)}"})
                if r.status_code >= 400:
                    raise GraphError(r.status_code, r.text)
        self._req("POST", f"/users/{self.sender}/messages/{mid}/send")


def prepare(raw: bytes, sender: str, envelope_rcpts: list[str]) -> EmailMessage:
    """Rewrite From to the licensed sending mailbox (keeping the device's From as Reply-To),
    and add envelope-only recipients as Bcc so Graph delivers to everyone the device asked for."""
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]
    orig_from = email.utils.getaddresses(msg.get_all("From", []))
    display = orig_from[0][0] if orig_from and orig_from[0][0] else ""
    if orig_from and orig_from[0][1].lower() != sender.lower() and "Reply-To" not in msg:
        msg["Reply-To"] = orig_from[0][1]
    del msg["From"]
    msg["From"] = email.utils.formataddr((display, sender))
    del msg["Sender"]
    headed = {a.lower() for h in ("To", "Cc", "Bcc") for _, a in email.utils.getaddresses(msg.get_all(h, []))}
    extra = [r for r in envelope_rcpts if r.lower() not in headed]
    if extra:
        existing = msg.get("Bcc")
        del msg["Bcc"]
        msg["Bcc"] = ", ".join(([str(existing)] if existing else []) + extra)
    if not msg.get("Subject"):
        msg["Subject"] = "Scanned document"
    return msg
