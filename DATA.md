# ScanRelay data handling and retention

ScanRelay relays mail from printers and legacy apps to Microsoft Graph. It runs in the customer's own network and tenant. We (Infinihash) do not receive message content.

| What | Where | How long | Enforced by |
|---|---|---|---|
| Message content (`<id>.eml`) and its queue metadata (`<id>.json`) | relay spool dir | Until delivered, then deleted immediately | `Spool.process_once` |
| Messages that failed after all retries (`spool/failed/`) | relay spool dir | `SCANRELAY_FAILED_RETENTION_DAYS`, default **14** days, then deleted | `scanrelay.retention` (every 6 h in the running relay) |
| Send log `sends.jsonl` (time, id, status, peer IP, SMTP user, recipient count, size, Graph request-id; no subject, body, addresses or attachment names) | relay host | `SCANRELAY_LOG_RETENTION_DAYS`, default **90** days | `scanrelay.retention` |
| Optional control-plane `send_log` rows (device, recipient count, size, status, request-id) | control-plane database | `CONTROLPLANE_SENDLOG_RETENTION_DAYS`, default 90 | `controlplane.retention.purge_send_log` (preview: call it from a cron or the admin shell) |
| Audit chain `audit.jsonl` (hash-chained: message-received/outcome ids, sizes, counts, sha256 of the raw message; never addresses, subjects or content) | relay host, beside the send log | Not trimmed: log rotations, failed-mail purges and manual deletes are themselves entries, so removing evidence is evidenced | `scanrelay.audit` (verified on every 6-hourly sweep; status in `audit-status.json`) |
| Control-plane `audit_log` (hash-chained, append-only: tenant/device create/patch, key rotation, ingest batches, send_log purges; ids and counts only) | control-plane database | Not trimmed | `controlplane.audit` |
| Entra client secret | relay environment | Until rotated; never logged | operator |

At Microsoft: each relayed message is saved to the sender mailbox's Sent Items and follows that tenant's own retention, journaling and DLP policy. We do not control or delete that.

## Manual controls
- Dry-run: `scanrelay-retention` (or `python -m scanrelay.retention`). Add `--apply` to delete.
- Remove one message now: `scanrelay-retention --delete <id> --apply`.
- Set a retention variable to `0` to disable that purge (not recommended: it contradicts the published promise).

## Audit trail and evidence export
- Verify: `scanrelay-audit verify` (exit 1 if the chain is broken; the sweep also logs `AUDIT CHAIN BROKEN` and writes `audit-status.json`). Control plane: `GET /api/v1/audit/verify` (admin) or `python -m controlplane.audit verify`; `python -m controlplane.retention` (cron) purges old rows and exits 1 on a broken chain.
- Export: `scanrelay-audit export out.json` (audit chain + verification + metadata send log); control plane `GET /api/v1/export` (admin) or `python -m controlplane.audit export out.json` (tenants, devices, send_log, audit; ingest-key hashes and secret refs are excluded).
- Limit: a plain file can be appended to by anyone who can write it. The chain proves history was not edited or removed; keep the `head` it prints off-host, or put the file on append-only storage (`chattr +a`).
