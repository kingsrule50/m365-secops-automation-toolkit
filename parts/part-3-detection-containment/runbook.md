# Part 3 runbook: detection, safe containment and incident reporting

Commands in the order I ran them. Placeholders are in `<angle brackets>`. Every tenant change is
recorded in [docs/change-log.md](../../docs/change-log.md) before it is made.

## Prerequisites

- [ ] Parts 1 and 2 complete: certificate, app registration, `settings.json`, Exchange role group for the app
- [ ] The pilot users are licensed and in the pilot domain; the Part 2 inbox rule `Forward invoices` is still on `<upn1>`
- [ ] Tenant owner approval for: `IdentityRiskyUser.Read.All`, the administrative unit and scoped role, the Exchange role changes, and the containment run
- [ ] A ticket ID (for example `INC-1042`) and an approver who is not you

## 1. Add the Part 3 Graph permission

```powershell
$cfg = Get-Content ./src/KRSSecOps/Config/settings.json -Raw | ConvertFrom-Json
./setup/03-New-KRSAppRegistration.ps1 -TenantId $cfg.TenantId -CertificatePath "$HOME\KRSSecOps\certs\KRSSecOps-Automation.cer" -Part 3 -WhatIf
./setup/03-New-KRSAppRegistration.ps1 -TenantId $cfg.TenantId -CertificatePath "$HOME\KRSSecOps\certs\KRSSecOps-Automation.cer" -Part 3
```

Screenshot `11-app-api-permissions.png`: Entra admin center > App registrations > the app > API permissions.

## 2. Containment boundary in Entra (admin Graph session)

```powershell
Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All, RoleManagement.ReadWrite.Directory, User.Read.All
./setup/07-Set-KRSContainmentRbac.ps1 -Component Entra -PilotUser <upn1>, <upn2>, <upn3> -ServicePrincipalId <sp-object-id> -WhatIf
./setup/07-Set-KRSContainmentRbac.ps1 -Component Entra -PilotUser <upn1>, <upn2>, <upn3> -ServicePrincipalId <sp-object-id>
```

Screenshot `09-entra-au-members.png`: Entra admin center > Roles & admins > Admin units > KRS-SecOps Pilot Containment > Users.

## 3. Containment additions in Exchange (admin Exchange session)

```powershell
Import-Module "$PSHOME\Modules\PackageManagement", "$PSHOME\Modules\PowerShellGet"
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -ShowBanner:$false
./setup/07-Set-KRSContainmentRbac.ps1 -Component Exchange -WhatIf
./setup/07-Set-KRSContainmentRbac.ps1 -Component Exchange
```

Adds `Disable-InboxRule` and `Enable-InboxRule` to the custom role and `View-Only Audit Logs` to the role group.

## 4. Connect as the app: Graph and Exchange in one session

Load Exchange before the module, so both connections coexist:

```powershell
Import-Module "$PSHOME\Modules\PackageManagement", "$PSHOME\Modules\PowerShellGet"
Import-Module ExchangeOnlineManagement
Import-Module ./src/KRSSecOps/KRSSecOps.psd1 -Force
Connect-KRSTenant | Format-List AppName, AuthType, Permissions          # 7 Graph permissions
Connect-KRSCompliance -Service Exchange | Format-List CommandsLoaded    # 16
```

## 5. Prove the Entra boundary (as the app)

Make a real, reversible change on a user inside the unit and on a pilot-domain user outside it.
Writing back a value the user already has proves nothing.

```powershell
& (Get-Module KRSSecOps) {
    foreach ($u in '<upn-in-unit>', '<pilot-upn-outside-unit>') {
        $original = (Invoke-KRSGraphRequest -Uri "users/$u`?`$select=officeLocation").officeLocation
        try {
            $null = Invoke-KRSGraphRequest -Method PATCH -Uri "users/$u" -Body @{ officeLocation = 'KRS-boundary-test' } -MaxRetries 1
            $result = 'Allowed'
            $null = Invoke-KRSGraphRequest -Method PATCH -Uri "users/$u" -Body @{ officeLocation = $original } -MaxRetries 1
        }
        catch { $result = "Denied (HTTP $(Get-KRSHttpStatus -ErrorRecord $_))" }
        [pscustomobject]@{ User = $u; Result = $result }
    }
} | Format-Table -AutoSize
```

Expected: Allowed, then Denied (HTTP 403). Screenshot `01-entra-au-boundary.png`.

## 6. Detect, contain, re-detect (as the app)

```powershell
$upn = '<upn1>'
Find-KRSCompromiseIndicator -UserPrincipalName $upn -Days 7 -Redact -IncludeCompliant |
    Sort-Object SeverityRank | Format-Table Signal, Severity, Source, Detail -Wrap                   # screenshot 02

Invoke-KRSContainment -UserPrincipalName $upn -TicketId INC-1042 -ApprovedBy '<approver>' -WhatIf  # screenshot 03

$contain = Invoke-KRSContainment -UserPrincipalName $upn -TicketId INC-1042 -ApprovedBy '<approver>'
$contain | Format-Table Action, Target, Result, @{ n = 'Record'; e = { Split-Path $_.RecordPath -Leaf } }   # screenshot 04

Find-KRSCompromiseIndicator -UserPrincipalName $upn -Days 7 -Redact -IncludeCompliant |
    Sort-Object SeverityRank | Format-Table Signal, Severity, Source, Detail -Wrap                   # screenshot 05
```

Answer `Y` to each of the three confirmation prompts.

## 7. Recover (as the app)

Only after the cause is fixed (password reset, MFA re-registration):

```powershell
$undo = Undo-KRSContainment -RecordPath $contain[0].RecordPath -ApprovedBy '<approver>'
$undo | Format-Table Action, Target, Result, @{ n = 'Record'; e = { Split-Path $_.RecordPath -Leaf } }      # screenshot 07
```

The rule stays disabled. Add `-IncludeInboxRules` only if a reviewed rule must be switched back on.

## 8. Incident report (as the app)

```powershell
$report = Export-KRSIncidentReport -UserPrincipalName $upn -TicketId INC-1042 -Days 7 -Redact
$report | Format-List TicketId, HighestSeverity, Findings, ContainmentActions, RecoveryActions, CurrentState   # screenshot 06
Invoke-Item $report.ReportPath                                                                                # screenshot 08, address bar cropped
```

## 9. Verify the scoped role from the directory (admin Graph session)

The portal's PIM view may not list an app's administrative-unit-scoped role. Read it from the directory:

```powershell
Connect-MgGraph -Scopes AdministrativeUnit.Read.All, RoleManagement.Read.Directory, Application.Read.All -NoWelcome
$sp = (Invoke-MgGraphRequest -Uri "v1.0/servicePrincipals?`$filter=displayName eq 'app-krs-secops-automation'&`$select=id,displayName").value[0]
(Invoke-MgGraphRequest -Uri "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($sp.id)'&`$expand=roleDefinition").value | ForEach-Object {
    $scope = if ($_.directoryScopeId -eq '/') { 'TENANT-WIDE' }
             else { 'Admin unit: ' + (Invoke-MgGraphRequest -Uri "v1.0/directory$($_.directoryScopeId)?`$select=displayName").displayName }
    [pscustomobject]@{ App = $sp.displayName; Role = $_.roleDefinition.displayName; Scope = $scope }
} | Format-Table -AutoSize
```

Expected: one row, scoped to the administrative unit. Screenshot `10-app-role-au-scope.png`.

## 10. Clean up after the series (admin session)

```powershell
Remove-InboxRule -Mailbox <upn1> -Identity 'Forward invoices' -Confirm:$false      # the planted rule, after review
```

The administrative unit, scoped role and Exchange role changes can stay for repeat demos; their rollback is in the change log.
