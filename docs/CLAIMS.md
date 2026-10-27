# Public claims -> the test that proves each one

Every claim in the README and DATA.md is listed with the test that fails if it stops being true.
`tests/test_claims_map.py` fails CI if a mapped test disappears or is renamed. These tests run against a fake Microsoft Graph
and a real SMTP listener; none of them has run against a real Microsoft 365 tenant yet (the end-to-end test is waiting on the
Entra app registration), which is why the README's "works for internal and external recipients" is not mapped here.

Format: `- CLAIM | tests/<file>.py::<function>[, tests/<file>.py::<function>]`

## Relay behaviour
- Each message is sent from the configured mailbox through Graph with OAuth, and arrives as the device sent it | tests/test_relay.py::test_auth_and_mime_send, tests/test_relay.py::test_prepare_rewrites_from_and_adds_bcc
- It is not an open relay: a session must be from an allowlisted IP or log in | tests/test_relay.py::test_rejects_unauthenticated_outside_allowlist, tests/test_relay.py::test_ip_allowlist_and_retry_then_send
- Throttling and 5xx errors are retried; permanent errors move the message to failed instead of looping | tests/test_relay.py::test_ip_allowlist_and_retry_then_send, tests/test_relay.py::test_permanent_error_moves_to_failed
- Large attachments are sent through a Graph upload session | tests/test_relay.py::test_large_attachment_uses_upload_session

## Data (DATA.md, README)
- Message content is deleted once delivered or after the retention period; failed messages are purged at 14 days; the send log keeps 90 days | tests/test_retention.py::test_failed_older_than_retention_purged_recent_kept, tests/test_cp_retention.py::test_old_send_rows_purged_recent_kept
- A message still being delivered is never purged | tests/test_retention.py::test_inflight_spool_never_touched_by_purge
- A dry run deletes nothing | tests/test_retention.py::test_dry_run_deletes_nothing
- The running relay enforces retention on its own | tests/test_retention.py::test_running_relay_enforces_retention, tests/test_retention.py::test_worker_loop_runs_the_sweep
- Deleting a message cannot be steered outside the spool | tests/test_retention.py::test_delete_message_rejects_path_traversal

## Control plane
- The control plane never stores a client secret or message content | tests/test_controlplane.py::test_schema_has_no_secret_or_content_columns, tests/test_controlplane.py::test_tenant_rejects_secret_value_and_hashes_ingest_key
- Reporting accepts only a relay's own key and rejects any content | tests/test_controlplane.py::test_ingest_requires_relay_key_and_rejects_content
- The admin API needs its key | tests/test_controlplane.py::test_admin_key_required
- The relay reports metadata only, is off by default, and an outage of the control plane never breaks delivery | tests/test_telemetry.py::test_hook_off_by_default, tests/test_telemetry.py::test_hook_posts_metadata_only, tests/test_telemetry.py::test_control_plane_outage_does_not_break_delivery
- Alerts: expiring secrets, failure rate, silent devices | tests/test_controlplane.py::test_secret_expiry_thresholds, tests/test_controlplane.py::test_failure_rate_alert, tests/test_controlplane.py::test_no_traffic_alert_and_disable
