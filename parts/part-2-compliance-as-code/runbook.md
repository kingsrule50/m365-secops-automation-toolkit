# Part 2 runbook: compliance-as-code for Exchange Online and Purview

Commands in the order I ran them. Placeholders are in `<angle brackets>`. Every tenant change is
recorded in [docs/change-log.md](../../docs/change-log.md) before it is made.

## Prerequisites

- [ ] Part 1 complete: certificate in `Cert:\CurrentUser\My`, app registered, `settings.json` filled in
- [ ] `Organization` in `settings.json` set to the tenant's `<name>.onmicrosoft.com` domain
- [ ] ExchangeOnlineManagement 3.5 or later (`setup/01-Install-Prerequisites.ps1`)
- [ ] Tenant owner approval for: `Exchange.ManageAsApp`, Exchange and Purview role groups, tagging pilot mailboxes

## 1. Check the certificate's key provider (read-only)

```powershell
$cfg  = Get-Content ./src/KRSSecOps/Config/settings.json -Raw | ConvertFrom-Json
$cert = Get-Item "Cert:\CurrentUser\My\$($cfg.CertificateThumbprint)"
$key  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($key -is [System.Security.Cryptography.RSACng]) { $key.Key.Provider.Provider } else { $key.CspKeyContainerInfo.ProviderName }
```

A CSP provider name (for example *Microsoft Base Cryptographic Provider v1.0*) works for Exchange.
*Microsoft Software Key Storage Provider* (CNG) does not: create a CSP certificate first.

## 2. Add Exchange.ManageAsApp

```powershell
./setup/03-New-KRSAppRegistration.ps1 -TenantId $cfg.TenantId -CertificatePath "$HOME\KRSSecOps\certs\KRSSecOps-Automation.cer" -Part 2 -WhatIf
./setup/03-New-KRSAppRegistration.ps1 -TenantId $cfg.TenantId -CertificatePath "$HOME\KRSSecOps\certs\KRSSecOps-Automation.cer" -Part 2
```

Screenshot `01-exchange-permission.png`: Entra admin center > App registrations > the app > API permissions.

## 3. Exchange RBAC (admin session)

If the Exchange module fails with "cloud file provider is not running", load PowerShellGet from `$PSHOME` first:

```powershell
Import-Module "$PSHOME\Modules\PackageManagement", "$PSHOME\Modules\PowerShellGet"
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -ShowBanner:$false

# Confirm the tag attribute is unused
@(Get-Mailbox -ResultSize Unlimited -Filter "CustomAttribute15 -ne `$null").Count   # expect 0

./setup/05-Set-KRSExchangePilotRbac.ps1 -PilotMailbox <upn1>, <upn2>, <upn3> -ServicePrincipalId <sp-object-id> -WhatIf
./setup/05-Set-KRSExchangePilotRbac.ps1 -PilotMailbox <upn1>, <upn2>, <upn3> -ServicePrincipalId <sp-object-id>
```

Screenshot `02-exchange-rbac.png`: role assignments, member, in-scope mailboxes, trimmed `Set-*` entries.

## 4. Boundary test (as the app)

```powershell
$org = (Get-AcceptedDomain | Where-Object InitialDomain).DomainName
Disconnect-ExchangeOnline -Confirm:$false
Connect-ExchangeOnline -AppId $cfg.ClientId -CertificateThumbprint $cfg.CertificateThumbprint -Organization $org -ShowBanner:$false
```

Run one allowed write on a pilot mailbox, the same write on an untagged mailbox, and a parameter outside the role,
each with `-ErrorAction Stop` and a value equal to the current one. Expected: Allowed, Blocked (write scope), Blocked (parameter not found).
Screenshot `03-boundary-test.png`.

## 5. Purview read-only role group (admin session)

```powershell
Connect-IPPSSession -ShowBanner:$false
./setup/06-Set-KRSPurviewReadRbac.ps1 -ServicePrincipalId <sp-object-id> -WhatIf
./setup/06-Set-KRSPurviewReadRbac.ps1 -ServicePrincipalId <sp-object-id>
```

Then connect as the app (`Connect-IPPSSession -AppId ... -CertificateThumbprint ... -Organization $org`), confirm every
`Get-*` returns objects and that `Get-Command New-Label, Set-Label, ...` finds nothing. Screenshot `04-purview-readonly.png`.

## 6. Toolkit run (as the app)

```powershell
Import-Module ExchangeOnlineManagement
Import-Module ./src/KRSSecOps/KRSSecOps.psd1 -Force
Connect-KRSCompliance                                   # screenshot 05
Export-KRSComplianceBaseline
@(Compare-KRSComplianceBaseline).Count                  # expect 0 straight after export
```

## 7. Seed scenarios (admin session)

```powershell
Set-Mailbox <upn2> -ForwardingSmtpAddress 'smtp:marcus.home@example.com' -DeliverToMailboxAndForward $true
New-InboxRule -Mailbox <upn1> -Name 'Forward invoices' -SubjectContainsWords 'invoice' -ForwardTo 'collector@example.net'
Set-DlpCompliancePolicy -Identity '<your DLP policy>' -Mode TestWithoutNotifications
```

## 8. Audit, enforce, re-audit (as the app)

```powershell
$summary = Invoke-KRSComplianceAudit -Redact             # screenshots 06, 07
Set-KRSMailboxBaseline -WhatIf                           # screenshot 08
Set-KRSMailboxBaseline                                   # screenshot 09
$after = Invoke-KRSComplianceAudit -Redact               # screenshot 10
```

## 9. Restore (admin session)

```powershell
Set-DlpCompliancePolicy -Identity '<your DLP policy>' -Mode Enable
```

The inbox rule on `<upn1>` is kept on purpose: Part 3 starts from it.
