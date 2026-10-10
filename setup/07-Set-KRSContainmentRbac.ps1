#Requires -Version 7.4
<#
.SYNOPSIS
    Gives the automation app containment rights that the platform limits to the pilot users.

.DESCRIPTION
    Idempotent. Two components, run separately (Entra and Exchange modules are kept in separate sessions):

    Entra (needs an admin Microsoft Graph session: Connect-MgGraph with the scopes below)
      1. Creates administrative unit 'KRS-SecOps Pilot Containment' and adds the pilot users.
         Every user must be in the pilot domain.
      2. Assigns the app's service principal the User Administrator role SCOPED TO THAT UNIT.
         The app can block sign-in and revoke sessions for those users only. Graph refuses the same
         call for anyone else, and User Administrator cannot act on administrators at all.
         No tenant-wide write permission (User.EnableDisableAccount.All, User.RevokeSessions.All) is used.

    Exchange (needs an admin Exchange Online session: Connect-ExchangeOnline)
      3. Adds Disable-InboxRule and Enable-InboxRule to the custom role 'KRS-SecOps Mailbox Hardening',
         so containment can switch off a malicious rule. The role's pilot scope still applies.
      4. Adds the read-only 'View-Only Audit Logs' role to the app's role group, so detection can read
         who created or changed inbox rules and forwarding.

    Get the tenant owner's approval before running this in a shared tenant.

.PARAMETER Component
    Entra, Exchange, or both (default). Run each in its own PowerShell session.

.PARAMETER PilotUser
    UPNs to place in the administrative unit (Entra component). Each must be in PilotDomain.

.PARAMETER ServicePrincipalId
    Object ID of the app's service principal (Enterprise application).

.PARAMETER ConfigPath
    settings.json with PilotDomain. Default src/KRSSecOps/Config/settings.json.

.EXAMPLE
    Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All, RoleManagement.ReadWrite.Directory, User.Read.All
    ./setup/07-Set-KRSContainmentRbac.ps1 -Component Entra -PilotUser amara@contoso.com, marcus@contoso.com -ServicePrincipalId <sp-id> -WhatIf

.EXAMPLE
    Connect-ExchangeOnline
    ./setup/07-Set-KRSContainmentRbac.ps1 -Component Exchange -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('Entra', 'Exchange')]
    [string[]]$Component = @('Entra', 'Exchange'),

    [Parameter()]
    [string[]]$PilotUser,

    [Parameter()]
    [guid]$ServicePrincipalId,

    [Parameter()]
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'src', 'KRSSecOps', 'Config', 'settings.json')
)

$ErrorActionPreference = 'Stop'
$unitName = 'KRS-SecOps Pilot Containment'
$userAdministratorTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
$roleName = 'KRS-SecOps Mailbox Hardening'
$roleGroupName = 'KRS-SecOps Pilot Mailbox Automation'

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$pilotDomain = ([string]$config.PilotDomain).Trim().TrimStart('@').ToLowerInvariant()

if ('Entra' -in $Component) {
    if (-not $PilotUser -or -not $ServicePrincipalId) { throw 'The Entra component needs -PilotUser and -ServicePrincipalId.' }
    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue) -or -not (Get-MgContext)) {
        throw 'Connect to Microsoft Graph as an admin first: Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All, RoleManagement.ReadWrite.Directory, User.Read.All'
    }
    function Invoke-Graph {
        param([string]$Method = 'GET', [string]$Uri, [object]$Body)
        $request = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri"; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($PSBoundParameters.ContainsKey('Body')) { $request.Body = ($Body | ConvertTo-Json -Depth 10); $request.ContentType = 'application/json' }
        Invoke-MgGraphRequest @request
    }

    # Resolve pilot users first: refuse anything outside the pilot domain before changing anything
    $users = foreach ($upn in $PilotUser) {
        $upn = $upn.Trim().ToLowerInvariant()
        if (-not $upn.EndsWith("@$pilotDomain")) { throw "Refusing '$upn': not in the pilot domain $pilotDomain." }
        Invoke-Graph -Uri "users/$upn`?`$select=id,userPrincipalName,displayName"
    }

    # 1. Administrative unit and members
    $unit = (Invoke-Graph -Uri "directory/administrativeUnits?`$filter=displayName eq '$unitName'").value | Select-Object -First 1
    if (-not $unit -and $PSCmdlet.ShouldProcess($unitName, 'Create administrative unit')) {
        $unit = Invoke-Graph -Method POST -Uri 'directory/administrativeUnits' -Body @{
            displayName = $unitName
            description = 'KRSSecOps Part 3: the only users the automation app can contain (block sign-in, revoke sessions).'
        }
        Start-Sleep -Seconds 5
    }
    if ($unit) {
        $members = @((Invoke-Graph -Uri "directory/administrativeUnits/$($unit.id)/members?`$select=id").value | ForEach-Object { $_.id })
        foreach ($user in $users) {
            if ($user.id -in $members) { Write-Verbose "$($user.userPrincipalName) already a member."; continue }
            if ($PSCmdlet.ShouldProcess($user.userPrincipalName, "Add to administrative unit '$unitName'")) {
                Invoke-Graph -Method POST -Uri "directory/administrativeUnits/$($unit.id)/members/`$ref" -Body @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($user.id)"
                } | Out-Null
            }
        }
    }

    # 2. User Administrator for the app, scoped to the unit
    if ($unit) {
        $scope = "/administrativeUnits/$($unit.id)"
        $existing = (Invoke-Graph -Uri "roleManagement/directory/roleAssignments?`$filter=principalId eq '$ServicePrincipalId'").value |
            Where-Object { $_.roleDefinitionId -eq $userAdministratorTemplateId -and $_.directoryScopeId -eq $scope }
        if (-not $existing -and $PSCmdlet.ShouldProcess("service principal $ServicePrincipalId", "Assign User Administrator scoped to '$unitName'")) {
            Invoke-Graph -Method POST -Uri 'roleManagement/directory/roleAssignments' -Body @{
                principalId      = $ServicePrincipalId.ToString()
                roleDefinitionId = $userAdministratorTemplateId
                directoryScopeId = $scope
            } | Out-Null
        }
        $assignments = @((Invoke-Graph -Uri "roleManagement/directory/roleAssignments?`$filter=principalId eq '$ServicePrincipalId'").value)
        [pscustomobject]@{
            AdministrativeUnit = $unitName
            Members            = ($users.userPrincipalName -join ', ')
            AppRoleAssignments = ($assignments | ForEach-Object { "$(if ($_.roleDefinitionId -eq $userAdministratorTemplateId) { 'User Administrator' } else { $_.roleDefinitionId }) @ $(if ($_.directoryScopeId -eq $scope) { $unitName } else { $_.directoryScopeId })" }) -join '; '
        } | Format-List | Out-Host
    }
}

if ('Exchange' -in $Component) {
    if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) -or
        -not (Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession })) {
        throw 'Connect to Exchange Online PowerShell as an Exchange admin first: Connect-ExchangeOnline'
    }

    # 3. Inbox rule containment commands in the trimmed custom role
    foreach ($cmdlet in 'Disable-InboxRule', 'Enable-InboxRule') {
        if (Get-ManagementRoleEntry -Identity "$roleName\$cmdlet" -ErrorAction SilentlyContinue) { Write-Verbose "$cmdlet already in $roleName."; continue }
        if (-not (Get-ManagementRoleEntry -Identity "Mail Recipients\$cmdlet" -ErrorAction SilentlyContinue)) {
            throw "'$cmdlet' is not in the parent role 'Mail Recipients', so it cannot be added to '$roleName'."
        }
        if ($PSCmdlet.ShouldProcess("$roleName\$cmdlet", 'Add role entry')) {
            Add-ManagementRoleEntry -Identity "$roleName\$cmdlet"
        }
    }

    # 4. Read-only audit log access for detection
    $assigned = @(Get-ManagementRoleAssignment -RoleAssignee $roleGroupName | ForEach-Object { [string]$_.Role })
    if ('View-Only Audit Logs' -notin $assigned -and $PSCmdlet.ShouldProcess($roleGroupName, "Add read-only role 'View-Only Audit Logs'")) {
        $null = New-ManagementRoleAssignment -SecurityGroup $roleGroupName -Role 'View-Only Audit Logs'
    }

    Get-ManagementRoleAssignment -RoleAssignee $roleGroupName | Select-Object Role, CustomRecipientWriteScope, RecipientWriteScope |
        Format-Table -AutoSize | Out-Host
    Get-ManagementRoleEntry -Identity "$roleName\*" | Select-Object Name | Sort-Object Name | Format-Wide -Column 4 | Out-Host
}
