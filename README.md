# ScanRelay

Keep scan-to-email and legacy SMTP apps working after Microsoft 365 turns off **Basic auth for SMTP AUTH** (off by default from the end of December 2026).

Devices keep speaking plain SMTP on your LAN. ScanRelay sends each message **from your own tenant** through Microsoft Graph with OAuth 2.0 (client credentials):

- Works for **internal and external** recipients
- Saved to the mailbox's **Sent Items**; retention, journaling and DLP still apply
- **No DNS/SPF changes**, and no third-party sending service
- Least privilege: the app can send as **one mailbox only** (Exchange RBAC for Applications)
- Not an open relay: every session must come from an allowlisted IP or log in
- Message content is spooled only until it's delivered, then deleted. The log keeps metadata only.

```
copier / app ──SMTP──▶ ScanRelay ──OAuth 2.0──▶ Microsoft Graph /sendMail ──▶ recipient
```

## 1. Create the app registration (once per tenant)

1. In Entra ID, go to **App registrations → New registration** (single tenant). Copy the *Application (client) ID* and the *Directory (tenant) ID*.
2. Under **Certificates & secrets**, create a new client secret and copy its value. Note the expiry date.
3. **Don't** grant tenant-wide `Mail.Send`. Scope it to one mailbox with RBAC for Applications instead:

```powershell
Connect-ExchangeOnline
$appId  = "<client-id>"
$sp     = Get-MgServicePrincipal -Filter "appId eq '$appId'"   # or copy the Enterprise App object ID
New-ServicePrincipal -AppId $appId -ObjectId $sp.Id -DisplayName "ScanRelay"
New-ManagementScope -Name "ScanRelay-Sender" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'scans@contoso.com'"
New-ManagementRoleAssignment -App $appId -Role "Application Mail.Send" -CustomResourceScope "ScanRelay-Sender"
Test-ServicePrincipalAuthorization -Identity $appId -Resource scans@contoso.com   # should show InScope = True
```

`scans@contoso.com` can be a shared mailbox, which needs no license.

## 2. Run it

```bash
docker run -d --name scanrelay --restart unless-stopped -p 25:2525 \
  -e SCANRELAY_TENANT_ID=... -e SCANRELAY_CLIENT_ID=... -e SCANRELAY_CLIENT_SECRET=... \
  -e SCANRELAY_SENDER=scans@contoso.com \
  -e SCANRELAY_ALLOW_IPS=192.168.10.0/24 \
  -e SCANRELAY_USERS=copier1:changeme \
  -v scanrelay-spool:/var/lib/scanrelay scanrelay:latest   # build first: docker build -t scanrelay .
```

| Variable | Meaning |
|---|---|
| `SCANRELAY_ALLOW_IPS` | CIDRs that may send without logging in (for example the printer VLAN) |
| `SCANRELAY_USERS` | `user:pass,user2:sha256:<hex>`: per-device SMTP logins |
| `SCANRELAY_RCPT_DOMAINS` | Optional: only allow these recipient domains |
| `SCANRELAY_TLS_CERT` / `_KEY` | Enable STARTTLS; `SCANRELAY_REQUIRE_TLS=1` requires TLS before AUTH |
| `SCANRELAY_MAX_SIZE` | Max message size in bytes (default 35 MB). Large scans use Graph upload sessions. |

## 3. Point the device at it

On the copier, set **SMTP server** to the relay's IP, **port** 25 (or whatever port you mapped), and either no authentication (allowlisted IP) or the per-device login. The *From* address is rewritten to the sending mailbox, and the device's original From address is kept as Reply-To.

## Delivery and retries

Messages are written to a disk spool and accepted immediately. A worker delivers them through Graph and retries throttling and 5xx errors with exponential backoff (up to about 12 attempts). Permanent errors, such as a 403 when the mailbox is out of scope, go to `spool/failed/`. Each attempt is logged to `sends.jsonl`, metadata only.

## Control plane (preview)

For MSPs running ScanRelay across many client tenants, `controlplane/` is a small FastAPI + SQLAlchemy service (SQLite by default, Postgres via `CONTROLPLANE_DB_URL`) that tracks:

- **Tenants**: name, Entra tenant ID, client ID, and the client secret's **expiry date** plus a *reference* to where it's stored (for example `vault:msp/acme/scanrelay`). The secret itself is never stored, and the API rejects it.
- **Devices**: name, auth mode (login / IP), allowed IPs. Devices also register themselves on first send.
- **Send log**: metadata only (time, device, recipient count, size, status, Graph `request-id`). No subjects, bodies, attachment names or addresses.
- **Alerts**: client secret expiring within 30/14/7 days (info/warning/critical) or already expired, device failure rate (default: 20% or more of at least 5 sends in 24h), and no traffic from a device (default: 72h). Thresholds can be overridden globally or per tenant with `AlertRule` rows.

```bash
pip install '.[controlplane]'
CONTROLPLANE_API_KEY=$(openssl rand -hex 24) scanrelay-controlplane   # listens on 127.0.0.1:8080
```

Admin API calls use the `X-API-Key` header (`/api/v1/tenants`, `/devices`, `/sends`, `/alerts`, `/fleet`). The dashboard at `/` (sign in at `/login`) shows a fleet health table: health, tenant, device, auth mode, sends and failure rate over 24h, last seen, days until the secret expires, and active alerts. Put it behind HTTPS; set `CONTROLPLANE_INSECURE_COOKIE=1` only for local HTTP testing.

Creating a tenant returns a one-time **relay ingest key** (only its hash is stored). To have a relay report to the control plane, set these on the relay. The hook is off by default, and a control plane outage never affects mail delivery:

| Variable | Meaning |
|---|---|
| `CONTROLPLANE_URL` | Control plane base URL, for example `https://cp.example.com` |
| `CONTROLPLANE_KEY` | That tenant's relay ingest key |

## License

Apache-2.0. The hosted relay and the multi-tenant MSP dashboard are commercial add-ons: https://scanrelay.infinihash.com

*Not affiliated with Microsoft. Microsoft 365 and Exchange Online are trademarks of Microsoft Corporation.*
