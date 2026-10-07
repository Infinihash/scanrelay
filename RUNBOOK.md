# ScanRelay runbook

On-call: Jason (jlvardon@gmail.com). Customer-run product; no hosted production instance yet (hosted edition is PR #3, unmerged).

## What / where
- SMTP-to-Microsoft-Graph relay (Python, aiosmtpd) for scanners/printers after Exchange Online ends SMTP Basic auth (end of Dec 2026). Repo github.com/Infinihash/scanrelay (public, Apache-2.0, v0.1.0). Optional `controlplane/` (FastAPI + SQLite/Postgres) for MSP fleets (preview).
- Landing/guides: https://scanrelay.infinihash.com, served by `oradar-web` on CT760 (10.0.0.52, `systemctl status oradar-web`; source `/opt/scanrelay-src`). The relay itself is not run by us in production.
- Data handling: see DATA.md.

## Deploy
- Relay: `docker build -t scanrelay .` then `docker run ... -v scanrelay-spool:/var/lib/scanrelay scanrelay` (README section 2). Control plane: `scanrelay-controlplane`.
- Landing page change: edit oradar-web on CT760 (backup the `app.py` first), `systemctl restart oradar-web`.
- Releases: merge to main (CI = pytest on py3.10/3.12), tag.

## Rollback
Relay: `docker run` the previous image tag (spool volume is compatible; queued mail resumes). Landing: restore `app.py.bak-*` on CT760 and restart.

## Health
- Relay has no HTTP port: `nc -z <relay> 25` (or mapped port) and SMTP banner `ScanRelay`; `docker logs scanrelay`; `sends.jsonl` last line status `sent`.
- Control plane: `GET /healthz`.
- Landing: `curl -sI https://scanrelay.infinihash.com/`.

## Common failures
- **Graph 401 / AADSTS7000222**: client secret expired. Create a new secret in the Entra app, update `SCANRELAY_CLIENT_SECRET`, restart.
- **Graph 403 ErrorAccessDenied**: RBAC for Applications scope missing; `Test-ServicePrincipalAuthorization` must show InScope True (PR #2 `scripts/Setup-ScanRelay.ps1` automates, pending Jason).
- **Device gets 5xx / auth refused**: IP not in `SCANRELAY_ALLOW_IPS` and no `SCANRELAY_USERS` login.
- **Mail stuck**: `spool/*.eml` backlog and `retry` lines in log means Graph throttling or outage; it retries up to 12 times with backoff, then moves to `spool/failed/` (purged after 14 days; recover before then).
- **Too large (552)**: raise `SCANRELAY_MAX_SIZE`.

## First commands
```
docker logs --tail 80 scanrelay
tail -n 5 /var/lib/scanrelay/sends.jsonl
ls /var/lib/scanrelay/spool /var/lib/scanrelay/spool/failed
```

## Restore
No database to restore for the relay (spool is transient). Control plane: restore its SQLite/Postgres backup; ingest keys are stored hashed, so rotate keys if the DB was lost. Config is env vars; secrets live in the operator's secret store.
