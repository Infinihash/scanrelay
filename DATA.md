# ScanRelay data handling and retention

ScanRelay relays mail from printers and legacy apps to Microsoft Graph. It runs in the customer's own network and tenant. We (Infinihash) do not receive message content.

| What | Where | How long | Enforced by |
|---|---|---|---|
| Message content (`<id>.eml`) and its queue metadata (`<id>.json`) | relay spool dir | Until delivered, then deleted immediately | `Spool.process_once` |
| Messages that failed after all retries (`spool/failed/`) | relay spool dir | `SCANRELAY_FAILED_RETENTION_DAYS`, default **14** days, then deleted | `scanrelay.retention` (every 6 h in the running relay) |
| Send log `sends.jsonl` (time, id, status, peer IP, SMTP user, recipient count, size, Graph request-id; no subject, body, addresses or attachment names) | relay host | `SCANRELAY_LOG_RETENTION_DAYS`, default **90** days | `scanrelay.retention` |
| Optional control-plane `send_log` rows (device, recipient count, size, status, request-id) | control-plane database | `CONTROLPLANE_SENDLOG_RETENTION_DAYS`, default 90 | `controlplane.retention.purge_send_log` (preview: call it from a cron or the admin shell) |
| Entra client secret | relay environment | Until rotated; never logged | operator |

At Microsoft: each relayed message is saved to the sender mailbox's Sent Items and follows that tenant's own retention, journaling and DLP policy. We do not control or delete that.

## Manual controls
- Dry-run: `scanrelay-retention` (or `python -m scanrelay.retention`). Add `--apply` to delete.
- Remove one message now: `scanrelay-retention --delete <id> --apply`.
- Set a retention variable to `0` to disable that purge (not recommended: it contradicts the published promise).
