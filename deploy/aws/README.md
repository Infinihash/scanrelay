# ScanRelay hosted edition on AWS

One small, locked-down relay per customer tenant. Copiers on the customer's network
send to `relay-host:587` (STARTTLS + SMTP AUTH); the relay delivers through Microsoft
Graph from the customer's own mailbox, exactly like the self-hosted edition.

**Cost:** about $16/month per node in us-east-2 (t4g.small ~$12, Elastic IP ~$3.60,
Secrets Manager $0.40). Bigger fleets should move to a shared multi-tenant node later.

## Security model
- **Never an open relay.** The security group only opens 587 to `allowed_cidrs` (the
  office's public egress IPs; `/0` is rejected by validation), the relay requires
  STARTTLS before AUTH (`SCANRELAY_REQUIRE_TLS=1`), and per-device SMTP logins are
  still required.
- **No secrets in Terraform state or user-data.** You create the Secrets Manager
  secret yourself; the instance role can read only that one ARN.
- **No SSH.** Admin via SSM Session Manager. IMDSv2 only, encrypted root volume,
  container runs read-only as uid 10001 with all capabilities dropped.
- Message bodies are deleted after delivery; the send log is metadata only.

## Deploy
1. Run `scripts/Setup-ScanRelay.ps1` in the customer tenant (app registration,
   shared mailbox, RBAC scope). It writes `scanrelay.env`.
2. Store those values plus per-device logins as one JSON secret:
   ```bash
   aws secretsmanager create-secret --region us-east-2 --name scanrelay/acme-dental \
     --secret-string file://acme-dental.json
   # {"SCANRELAY_TENANT_ID":"...","SCANRELAY_CLIENT_ID":"...","SCANRELAY_CLIENT_SECRET":"...",
   #  "SCANRELAY_SENDER":"scans@acme.example","SCANRELAY_USERS":"copier1:sha256:<hex>"}
   ```
   Use `sha256:` hashed device passwords (`printf '%s' 'pw' | sha256sum`).
3. Apply:
   ```bash
   cd deploy/aws
   cp example.tfvars acme-dental.tfvars   # edit name, allowed_cidrs, secret_arn
   terraform init && terraform apply -var-file=acme-dental.tfvars
   ```
4. Optional: create `relay.acme.example` → `public_ip` and re-apply with
   `tls_hostname`/`acme_email` for a Let's Encrypt cert (port 80 opens for ACME).
   Without it the node uses a self-signed cert, which most copiers accept.
5. Point the copier at `public_ip` (or the hostname), port 587, STARTTLS on, with its
   device login. Run `scanrelay-check` from the customer side to confirm.

## Rotate the Graph secret
Update the Secrets Manager value, then on the node (SSM shell):
`/usr/local/sbin/scanrelay-env us-east-2 <secret-arn> && docker restart scanrelay`.

## Tear down
`terraform destroy -var-file=acme-dental.tfvars` (the secret is left in place on purpose).
