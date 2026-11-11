<#
.SYNOPSIS
  One-shot Microsoft 365 setup for ScanRelay: app registration + secret, optional
  shared mailbox, and Exchange RBAC for Applications scoped to ONE sender mailbox.

.DESCRIPTION
  Does not grant tenant-wide Mail.Send. The app can send only as -Sender.
  Run as a Global Admin (or Application Admin + Exchange Admin).
  Requires: Install-Module Microsoft.Graph.Applications, ExchangeOnlineManagement

  Writes scanrelay.env (tenant, client id, secret, sender) next to this script.
  Treat that file like a password. Supports -WhatIf.

.EXAMPLE
  ./Setup-ScanRelay.ps1 -Sender scans@contoso.com -CreateSharedMailbox
  ./Setup-ScanRelay.ps1 -Sender scans@contoso.com -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][string]$Sender,
  [string]$AppName = "ScanRelay",
  [int]$SecretMonths = 12,
  [switch]$CreateSharedMailbox,
  [string]$EnvFile = (Join-Path $PSScriptRoot "scanrelay.env")
)
$ErrorActionPreference = "Stop"
$scopeName = "$AppName-Sender"

Write-Host "== Microsoft Graph: app registration" -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome
$tenantId = (Get-MgContext).TenantId
$app = Get-MgApplication -Filter "displayName eq '$AppName'" | Select-Object -First 1
if (-not $app -and $PSCmdlet.ShouldProcess($AppName, "Create app registration")) {
  $app = New-MgApplication -DisplayName $AppName -SignInAudience AzureADMyOrg
}
if ($app) {
  $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" | Select-Object -First 1
  if (-not $sp -and $PSCmdlet.ShouldProcess($AppName, "Create enterprise app (service principal)")) {
    $sp = New-MgServicePrincipal -AppId $app.AppId
  }
}
$secretText = ""
if ($app -and $PSCmdlet.ShouldProcess($AppName, "Add client secret ($SecretMonths months)")) {
  $pw = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    displayName = "scanrelay $(Get-Date -Format yyyy-MM-dd)"; endDateTime = (Get-Date).AddMonths($SecretMonths) }
  $secretText = $pw.SecretText
}

Write-Host "== Exchange Online: sender mailbox + RBAC for Applications" -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false
$mbx = Get-EXOMailbox -Identity $Sender -ErrorAction SilentlyContinue
if (-not $mbx) {
  if (-not $CreateSharedMailbox) { throw "$Sender has no mailbox. Re-run with -CreateSharedMailbox or create it first." }
  if ($PSCmdlet.ShouldProcess($Sender, "Create shared mailbox (no license needed)")) {
    $alias = ($Sender -split "@")[0]
    New-Mailbox -Shared -Name "$AppName $alias" -DisplayName "Scans" -Alias $alias -PrimarySmtpAddress $Sender | Out-Null
  }
}
if ($app -and $sp) {
  if (-not (Get-ServicePrincipal -Identity $app.AppId -ErrorAction SilentlyContinue) -and
      $PSCmdlet.ShouldProcess($AppName, "Register service principal in Exchange")) {
    New-ServicePrincipal -AppId $app.AppId -ObjectId $sp.Id -DisplayName $AppName | Out-Null
  }
  if (-not (Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue) -and
      $PSCmdlet.ShouldProcess($scopeName, "Create management scope limited to $Sender")) {
    New-ManagementScope -Name $scopeName -RecipientRestrictionFilter "PrimarySmtpAddress -eq '$Sender'" | Out-Null
  }
  $existing = Get-ManagementRoleAssignment -RoleAssignee $app.AppId -Role "Application Mail.Send" -ErrorAction SilentlyContinue
  if (-not $existing -and $PSCmdlet.ShouldProcess($AppName, "Assign 'Application Mail.Send' in scope $scopeName")) {
    New-ManagementRoleAssignment -App $app.AppId -Role "Application Mail.Send" -CustomResourceScope $scopeName | Out-Null
  }
  Write-Host "== Check (may show InScope=False for up to ~2 hours while it propagates)" -ForegroundColor Cyan
  Test-ServicePrincipalAuthorization -Identity $app.AppId -Resource $Sender | Format-Table RoleName, InScope -AutoSize
}

if ($secretText) {
  @(
    "SCANRELAY_TENANT_ID=$tenantId"
    "SCANRELAY_CLIENT_ID=$($app.AppId)"
    "SCANRELAY_CLIENT_SECRET=$secretText"
    "SCANRELAY_SENDER=$Sender"
  ) | Set-Content -Path $EnvFile -Encoding ascii
  Write-Host "Wrote $EnvFile (contains the client secret; move it to the relay host and delete this copy)." -ForegroundColor Yellow
  Write-Host "Secret expires $((Get-Date).AddMonths($SecretMonths).ToString('yyyy-MM-dd')). Next: docker run --env-file scanrelay.env ... then: scanrelay-check --send-to you@yourdomain"
}
