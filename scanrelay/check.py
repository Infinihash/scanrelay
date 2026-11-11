"""Preflight check: can this app registration send as SCANRELAY_SENDER?

    scanrelay-check                    # token only (no mail sent)
    scanrelay-check --send-to me@x.com # also sends one test message

Turns the common Entra / Exchange errors into a plain next step, so a tech
setting up a copier doesn't have to decode AADSTS codes. Never prints the
secret or the access token.
"""
from __future__ import annotations

import argparse
import os
import sys
from email.message import EmailMessage

import httpx

from .graph import GraphError, GraphSender

HINTS = [
    ("AADSTS7000215", "The client secret is wrong. Copy the secret VALUE (not the Secret ID)."),
    ("AADSTS7000222", "The client secret has expired. Create a new one and update SCANRELAY_CLIENT_SECRET."),
    ("AADSTS700016", "No app with that client ID in this tenant. Check SCANRELAY_CLIENT_ID and SCANRELAY_TENANT_ID."),
    ("AADSTS90002", "Tenant not found. Check SCANRELAY_TENANT_ID (Directory ID or domain)."),
    ("ErrorAccessDenied", "The app is not allowed to send as this mailbox. Check the RBAC management scope "
                          "includes the sender (Test-ServicePrincipalAuthorization). New assignments can take "
                          "30 minutes to 2 hours to apply."),
    ("MailboxNotEnabledForRESTAPI", "The sender has no Exchange Online mailbox. Use a licensed or shared mailbox."),
    ("ErrorInvalidUser", "The sender address does not exist in this tenant."),
    ("ResourceNotFound", "The sender address does not exist in this tenant."),
]


def explain(err: str) -> str:
    for code, hint in HINTS:
        if code in err:
            return f"{code}: {hint}"
    return "Unrecognised error; see the Graph response above."


def run(env: dict, send_to: str = "", client: httpx.Client | None = None, out=print) -> int:
    missing = [k for k in ("SCANRELAY_TENANT_ID", "SCANRELAY_CLIENT_ID", "SCANRELAY_CLIENT_SECRET",
                           "SCANRELAY_SENDER") if not env.get(k)]
    if missing:
        out("FAIL missing settings: " + ", ".join(missing))
        return 2
    g = GraphSender(env["SCANRELAY_TENANT_ID"], env["SCANRELAY_CLIENT_ID"], env["SCANRELAY_CLIENT_SECRET"],
                    env["SCANRELAY_SENDER"], client=client)
    try:
        g.token()
        out("OK   token acquired for app " + env["SCANRELAY_CLIENT_ID"])
    except GraphError as e:
        out(f"FAIL token: {str(e)[:200]}")
        out("     " + explain(str(e)))
        return 1
    if not send_to:
        out("SKIP test send (pass --send-to to send one message)")
        return 0
    m = EmailMessage()
    m["From"] = env["SCANRELAY_SENDER"]
    m["To"] = send_to
    m["Subject"] = "ScanRelay test message"
    m.set_content("This is a test from scanrelay-check. If you received it, Graph sending works.")
    try:
        g.send(m.as_bytes(), [send_to])
        out(f"OK   test message accepted by Graph for {send_to} (check Sent Items of {env['SCANRELAY_SENDER']})")
        return 0
    except GraphError as e:
        out(f"FAIL send: {str(e)[:200]}")
        out("     " + explain(str(e)))
        return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ScanRelay preflight check")
    ap.add_argument("--send-to", default="", help="send one test message to this address")
    a = ap.parse_args(argv)
    return run(dict(os.environ), a.send_to)


if __name__ == "__main__":
    sys.exit(main())
