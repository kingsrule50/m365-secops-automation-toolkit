# Part 1 runbook: identity posture audit

Run everything on the Precision 7760 (Windows 11) in **PowerShell 7.4+**, from the repo root.
Allow about 90 minutes the first time, plus one overnight wait so the test activity shows up in the reports.

## 0. Before you start

- [ ] Purview lab finished, and its policies left in place (Part 2 exports them)
- [ ] Tenant owner approval recorded in [change-log.md](change-log.md) for: the app registration, admin consent for the Part 1 read permissions, and creating pilot users and a pilot group
- [ ] PowerShell 7.4+: `winget install --id Microsoft.PowerShell` then open **PowerShell 7** (not Windows PowerShell 5.1)
- [ ] Git and VS Code with the PowerShell extension

```powershell
$PSVersionTable.PSVersion          # must be 7.4 or later
Set-Location <path-to>\m365-secops-automation-toolkit
```

## 1. Install the modules

```powershell
./setup/01-Install-Prerequisites.ps1 -WhatIf
./setup/01-Install-Prerequisites.ps1
```

## 2. Create the authentication certificate

```powershell
./setup/02-New-KRSAuthCertificate.ps1
```

Note the **Thumbprint**. The private key is non-exportable and stays in `Cert:\CurrentUser\My`.
Only the public `.cer` file is written, to `%USERPROFILE%\KRSSecOps\certs`, outside the repo.

## 3. Register the app and grant Part 1 permissions

Preview first, then run it. Sign in with your tenant admin account when prompted.
Answer **A** (Yes to All) once you have reviewed the `-WhatIf` output.

```powershell
$cer = "$env:USERPROFILE\KRSSecOps\certs\KRSSecOps-Automation.cer"
./setup/03-New-KRSAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -CertificatePath $cer -WhatIf
./setup/03-New-KRSAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -CertificatePath $cer
Disconnect-MgGraph
```

Note the **TenantId** and **ClientId**. Check in the Entra admin center: App registrations > app-krs-secops-automation >
API permissions shows six Microsoft Graph application permissions, all with "Granted for <your tenant>".

> **Screenshot `01-app-certificate.png`:** App registrations > app-krs-secops-automation > Certificates & secrets.
> Show the certificate (thumbprint, expiry) and the **empty Client secrets tab** count. Crop out your browser bar.
>
> **Screenshot `02-api-permissions.png`:** API permissions blade. Show all six permissions with type *Application*
> and the green *Granted for <your tenant>* status.

## 4. Create the pilot users and group

Check which licence to use first (only needed if you want mailboxes for Part 2):

```powershell
Connect-MgGraph -TenantId contoso.onmicrosoft.com -Scopes Organization.Read.All -NoWelcome
(Invoke-MgGraphRequest GET 'v1.0/subscribedSkus').value | ForEach-Object { '{0}  free: {1}' -f $_.skuPartNumber, ($_.prepaidUnits.enabled - $_.consumedUnits) }
Disconnect-MgGraph
```

Then create the pilot:

```powershell
./setup/04-New-KRSPilotUsers.ps1 -TenantId contoso.onmicrosoft.com -IncludeExistingDomainUsers -WhatIf
./setup/04-New-KRSPilotUsers.ps1 -TenantId contoso.onmicrosoft.com -IncludeExistingDomainUsers -LicenseSkuPartNumber <SKU>
Disconnect-MgGraph
```

The temporary passwords are shown once. Use them in a private browser window in step 6, then forget them.
Note the **PilotGroupId**.

## 5. Create settings.json

```powershell
Copy-Item ./src/KRSSecOps/Config/settings.example.json ./src/KRSSecOps/Config/settings.json
code ./src/KRSSecOps/Config/settings.json
```

Fill in TenantId, ClientId, CertificateThumbprint, PilotGroupId and Organization (the tenant's
`*.onmicrosoft.com` domain, used in Part 2). `settings.json` is in `.gitignore`. Confirm with `git status`
that it does not show up.

## 6. Seed realistic findings in the pilot

So the audit has something to find. Every item below stays inside the pilot domain.

| Do this | Expected finding |
| --- | --- |
| Sign in as **Amara Okafor**, change her password, skip MFA registration | High: no MFA registered |
| Sign in as **Sofia Laurent**, register Microsoft Authenticator | No finding (compliant) |
| Entra admin center > Roles > **User Administrator** > add **Daniel Reyes** as an *active, permanent* assignment | High: standing privileged access (MFA gap is Critical if he is not registered) |
| PIM > Entra roles > **Security Reader** > add **Priya Shah** as *eligible* | Info: eligible through PIM |
| App registrations > New: `app-krs-demo-legacy` > add a client secret that expires in **7 days** | High: secret expires in 7 days |
| Leave **Marcus Bennett** and **Daniel Reyes** never signed in | Next day, with `-InactiveDays 1`: never signed in |

Wait until the next day. Sign-in data and the registration report can take several hours to update.

## 7. Run the audit

```powershell
Import-Module ./src/KRSSecOps/KRSSecOps.psd1 -Force
Connect-KRSTenant

Get-KRSMfaGap | Format-Table UserPrincipalName, IsAdmin, MethodsRegistered, Finding, Severity
Get-KRSStaleAccount -InactiveDays 1 | Format-Table UserPrincipalName, DaysInactive, Finding
Get-KRSPrivilegedRoleReport -Redact -IncludeCompliant | Format-Table RoleName, PrincipalName, AssignmentState, Severity
Get-KRSGuestAccessReport -Scope Tenant -Redact | Format-Table DisplayName, InvitationState, Finding
Get-KRSAppCredentialRisk | Sort-Object SeverityRank | Format-Table AppDisplayName, Detail, Finding, Severity
Get-KRSConditionalAccessInventory -IncludeCompliant -Redact | Format-Table PolicyName, State, GrantControls, Finding

$summary = Invoke-KRSIdentityAudit -Scope Tenant -Redact
$summary.Checks | Format-Table
Invoke-Item $summary.OutputFolder

Disconnect-KRSTenant
```

> **Screenshot `03-connect-session.png`:** the `Connect-KRSTenant` output. `AuthType` must read **AppOnly** and the
> Permissions line must list the six permissions.
>
> **Screenshot `04-identity-audit-summary.png`:** the `Invoke-KRSIdentityAudit -Scope Tenant -Redact` summary plus the
> `$summary.Checks` table, in one frame.
>
> **Screenshot `05-findings-csv.png`:** `findings.csv` from the evidence folder, opened in Excel or VS Code. Check that
> every identity outside the pilot is masked before you capture it.

**Always use `-Redact` with `-Scope Tenant`** for anything you screenshot or record. The tenant is shared.

The toolkit's own audit trail is in `%USERPROFILE%\KRSSecOps\logs\KRSSecOps-<date>.jsonl`:

```powershell
Get-Content "$env:USERPROFILE\KRSSecOps\logs\KRSSecOps-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd')).jsonl" | ConvertFrom-Json | Format-Table timestamp, action, target, result
```

## 8. Build, test and push

Create an empty public repo named `m365-secops-automation-toolkit` on GitHub first (no README, no .gitignore).

```powershell
./build/build.ps1 -Task Analyze, Test, Package
git init -b main
git remote add origin https://github.com/kingsrule50/m365-secops-automation-toolkit.git
git add .
git status            # settings.json, .cer and reports must NOT be listed
git commit -m "Part 1: module foundation and identity posture audit"
git push -u origin main
```

Then open the Actions tab and confirm both CI jobs (Windows and Ubuntu) are green.

> **Screenshot `06-ci-green.png`:** the Actions run summary with both jobs green and the job summary table
> (tests, passed, coverage) visible.

## 9. Screenshot checklist (essential only)

The callouts in steps 3, 7 and 8 say when to take each one. Save them to `screenshots/`:

1. `01-app-certificate.png`: app registration > Certificates & secrets, certificate listed, **no client secrets**
2. `02-api-permissions.png`: the six granted application permissions
3. `03-connect-session.png`: `Connect-KRSTenant` output showing `AuthType AppOnly`
4. `04-identity-audit-summary.png`: `Invoke-KRSIdentityAudit` summary and `$summary.Checks` table
5. `05-findings-csv.png`: `findings.csv` open, redacted
6. `06-ci-green.png`: GitHub Actions run with both jobs passing

## 10. Clean up after recording

- Delete `app-krs-demo-legacy`
- Remove Daniel's permanent User Administrator assignment
- Keep the pilot users, the pilot group and the automation app: Parts 2 and 3 use them
