"""scanrelay-send: a sendmail-compatible command that sends straight through Microsoft Graph.

For cron jobs, alert scripts and apps that shell out to `sendmail` (or used smtplib against
smtp.office365.com with a password). No SMTP listener, no spool: one message, one Graph call.

    echo "disk full" | scanrelay-send --to ops@example.com --subject "alert"
    scanrelay-send -t < message.eml                 # recipients from To/Cc/Bcc
    scanrelay-send -i -f ignored ops@example.com < message.eml

Credentials come from the environment (SCANRELAY_TENANT_ID, SCANRELAY_CLIENT_ID,
SCANRELAY_CLIENT_SECRET, SCANRELAY_SENDER) or an env file (--env-file, $SCANRELAY_ENV_FILE,
/etc/scanrelay/scanrelay.env, ./scanrelay.env), the same file Setup-ScanRelay.ps1 writes.
Exit codes follow sysexits: 0 sent, 64 usage, 65 bad message, 75 temporary failure (retry),
77 permission/auth problem, 69 other permanent failure. The secret is never printed.
"""
from __future__ import annotations

import argparse
import email
import email.policy
import email.utils
import os
import sys
from email.message import EmailMessage

from .graph import GraphError, GraphSender

EX_OK, EX_USAGE, EX_DATAERR, EX_UNAVAILABLE, EX_TEMPFAIL, EX_NOPERM = 0, 64, 65, 69, 75, 77
REQUIRED = ("SCANRELAY_TENANT_ID", "SCANRELAY_CLIENT_ID", "SCANRELAY_CLIENT_SECRET", "SCANRELAY_SENDER")
DEFAULT_ENV_FILES = ("/etc/scanrelay/scanrelay.env", "scanrelay.env")


def read_env_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip().removeprefix("export ").strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            out[k] = v
    return out


def load_settings(env_file: str | None, environ: dict[str, str] | None = None) -> dict[str, str]:
    """Environment wins over the file, so a single value can be overridden per call."""
    environ = dict(os.environ if environ is None else environ)
    candidates = [env_file] if env_file else [environ.get("SCANRELAY_ENV_FILE", ""), *DEFAULT_ENV_FILES]
    file_vals: dict[str, str] = {}
    for c in filter(None, candidates):
        if os.path.isfile(c):
            file_vals = read_env_file(c)
            break
        if env_file:  # an explicitly named file must exist
            raise FileNotFoundError(c)
    merged = {**file_vals, **{k: v for k, v in environ.items() if k.startswith("SCANRELAY_") and v}}
    missing = [k for k in REQUIRED if not merged.get(k)]
    if missing:
        raise KeyError(", ".join(missing))
    return merged


def header_rcpts(msg: EmailMessage) -> list[str]:
    seen, out = set(), []
    for _, a in email.utils.getaddresses([str(v) for h in ("To", "Cc", "Bcc") for v in msg.get_all(h, [])]):
        if a and a.lower() not in seen:
            seen.add(a.lower())
            out.append(a)
    return out


def build_message(raw: bytes, args: argparse.Namespace) -> tuple[bytes, list[str]]:
    """Return (raw RFC 5322 bytes, envelope recipients)."""
    if args.subject is not None or args.to:
        # Quick mode: stdin is the plain-text body.
        msg = EmailMessage(policy=email.policy.SMTP)
        msg["To"] = ", ".join(args.to)
        if args.cc:
            msg["Cc"] = ", ".join(args.cc)
        msg["Subject"] = args.subject or "(no subject)"
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg.set_content(raw.decode("utf-8", errors="replace"))
        rcpts = [*args.to, *args.cc, *args.rcpt]
        return msg.as_bytes(), rcpts
    if not raw.strip():
        raise ValueError("empty message on stdin")
    msg = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]
    if not msg.keys():
        raise ValueError("stdin has no headers; use --to/--subject to send a plain body")
    rcpts = list(args.rcpt)
    if args.t:
        rcpts += [a for a in header_rcpts(msg) if a.lower() not in {r.lower() for r in rcpts}]
    if "Bcc" in msg and args.t:
        del msg["Bcc"]  # sendmail -t semantics: Bcc recipients get it, the header doesn't travel
    return msg.as_bytes(policy=email.policy.SMTP), rcpts


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="scanrelay-send", description="Send one message through Microsoft Graph.")
    p.add_argument("rcpt", nargs="*", help="envelope recipients")
    p.add_argument("-t", action="store_true", help="also read recipients from To/Cc/Bcc")
    p.add_argument("--to", action="append", default=[], help="quick mode: recipient (repeatable)")
    p.add_argument("--cc", action="append", default=[], help="quick mode: Cc (repeatable)")
    p.add_argument("--subject", help="quick mode: subject; stdin becomes the text body")
    p.add_argument("--env-file", help="path to scanrelay.env")
    p.add_argument("--dry-run", action="store_true", help="build and validate, but don't call Graph")
    # Accepted for sendmail compatibility and ignored: the sender is always the scoped mailbox.
    p.add_argument("-f", "-r", dest="_from", help=argparse.SUPPRESS)
    p.add_argument("-F", dest="_fullname", help=argparse.SUPPRESS)
    p.add_argument("-i", "-oi", "-odi", "-odb", "-Am", "-Ac", dest="_ign", action="store_true", help=argparse.SUPPRESS)
    return p.parse_args(argv)


def main(argv: list[str] | None = None, stdin: bytes | None = None, sender: GraphSender | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as e:
        return EX_OK if e.code == 0 else EX_USAGE
    raw = sys.stdin.buffer.read() if stdin is None else stdin
    try:
        data, rcpts = build_message(raw, args)
    except ValueError as e:
        print(f"scanrelay-send: {e}", file=sys.stderr)
        return EX_DATAERR
    if not rcpts:
        print("scanrelay-send: no recipients (pass addresses, --to, or -t)", file=sys.stderr)
        return EX_USAGE
    if sender is None:
        try:
            cfg = load_settings(args.env_file)
        except FileNotFoundError as e:
            print(f"scanrelay-send: env file not found: {e}", file=sys.stderr)
            return EX_USAGE
        except KeyError as e:
            print(f"scanrelay-send: missing settings: {e.args[0]}", file=sys.stderr)
            return EX_USAGE
        sender = GraphSender(cfg["SCANRELAY_TENANT_ID"], cfg["SCANRELAY_CLIENT_ID"],
                             cfg["SCANRELAY_CLIENT_SECRET"], cfg["SCANRELAY_SENDER"])
    if args.dry_run:
        print(f"scanrelay-send: dry run OK ({len(data)} bytes, {len(rcpts)} recipient(s))", file=sys.stderr)
        return EX_OK
    try:
        path = sender.send(data, rcpts)
    except GraphError as e:
        rid = f" request-id={e.request_id}" if e.request_id else ""
        print(f"scanrelay-send: Graph refused the message (HTTP {e.status}){rid}", file=sys.stderr)
        if e.transient:
            return EX_TEMPFAIL
        auth_problem = e.status in (401, 403) or "AADSTS" in str(e) or "invalid_client" in str(e)
        return EX_NOPERM if auth_problem else EX_UNAVAILABLE
    except Exception as e:  # network trouble: let cron/scripts retry
        print(f"scanrelay-send: temporary failure: {type(e).__name__}", file=sys.stderr)
        return EX_TEMPFAIL
    print(f"scanrelay-send: sent via Graph ({path}) to {len(rcpts)} recipient(s)", file=sys.stderr)
    return EX_OK


if __name__ == "__main__":
    sys.exit(main())
