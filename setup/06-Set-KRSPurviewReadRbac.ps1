#Requires -Version 7.4
<#
.SYNOPSIS
    Gives the automation app read-only access to Purview configuration in Security & Compliance PowerShell.

.DESCRIPTION
    Idempotent. Run it signed in to Security & Compliance PowerShell as a compliance admin
    (Connect-IPPSSession). It creates one custom role group holding only these view roles:

      Sensitivity Label Reader              Get-Label, Get-LabelPolicy
      View-Only DLP Compliance Management   Get-DlpCompliancePolicy, Get-DlpComplianceRule
      View-Only Retention Management        Get-RetentionCompliancePolicy, Get-RetentionComplianceRule

    and makes the app's service principal its only member. The app gets no Microsoft Entra role,
    so it can read the Purview baseline but cannot create, change or delete any policy.
    Get the tenant owner's approval before running this in a shared tenant.

.PARAMETER ServicePrincipalId
    Object ID of the app's service principal (Enterprise application), from 03-New-KRSAppRegistration.ps1.

.PARAMETER ConfigPath
    settings.json with ClientId. Default src/KRSSecOps/Config/settings.json.

.EXAMPLE
    ./setup/06-Set-KRSPurviewReadRbac.ps1 -ServicePrincipalId <sp-object-id> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [guid]$ServicePrincipalId,

    [Parameter()]
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'src', 'KRSSecOps', 'Config', 'settings.json')
)

$ErrorActionPreference = 'Stop'

$roleGroupName = 'KRS-SecOps Purview Baseline Reader'
$roles = 'Sensitivity Label Reader', 'View-Only DLP Compliance Management', 'View-Only Retention Management'
$spDisplayName = 'KRS-SecOps automation (app-only)'

# 0. Preconditions: an admin Security & Compliance session
if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) -or
    -not (Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' -and $_.IsEopSession })) {
    throw 'Connect to Security & Compliance PowerShell as a compliance admin first: Connect-IPPSSession'
}
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$clientId = [string]$config.ClientId
if (-not $clientId -or $clientId -like '<*>') { throw "ClientId must be set in $ConfigPath." }

foreach ($role in $roles) {
    if (-not (Get-ManagementRole -Identity $role -ErrorAction SilentlyContinue)) { throw "Role '$role' was not found in this tenant." }
}

# 1. Role group with view-only roles
$group = Get-RoleGroup -Identity $roleGroupName -ErrorAction SilentlyContinue
if (-not $group -and $PSCmdlet.ShouldProcess($roleGroupName, "Create role group with roles: $($roles -join ', ')")) {
    # Security & Compliance needs DisplayName set explicitly, or the group cannot take members.
    $group = New-RoleGroup -Name $roleGroupName -DisplayName $roleGroupName -Roles $roles `
        -Description 'KRSSecOps automation app. Read-only Purview baseline export. Owner: Chinedu. See docs/permission-matrix.md.'
}
elseif ($group) {
    if (-not $group.DisplayName -and $PSCmdlet.ShouldProcess($roleGroupName, 'Set missing DisplayName')) {
        Set-RoleGroup -Identity $roleGroupName -DisplayName $roleGroupName
    }
    $missing = @($roles | Where-Object { $_ -notin @($group.Roles | ForEach-Object { ([string]$_ -split '[\\/]')[-1] }) })
    if ($missing) { Write-Warning "Role group exists but lacks: $($missing -join ', '). Add them in the Purview portal or with New-ManagementRoleAssignment." }
}

# 2. Service principal as the only member
$sp = Get-ServicePrincipal -Identity $ServicePrincipalId.ToString() -ErrorAction SilentlyContinue
if (-not $sp -and $PSCmdlet.ShouldProcess($spDisplayName, "Register service principal for app $clientId in Security & Compliance")) {
    $sp = New-ServicePrincipal -AppId $clientId -ObjectId $ServicePrincipalId.ToString() -DisplayName $spDisplayName
}
if ($sp -and $group) {
    $members = @(Get-RoleGroupMember -Identity $roleGroupName | ForEach-Object { "$($_.Name) $($_.ExternalDirectoryObjectId)" })
    if (-not ($members -match [regex]::Escape($ServicePrincipalId.ToString())) -and
        $PSCmdlet.ShouldProcess($roleGroupName, "Add member $spDisplayName")) {
        Add-RoleGroupMember -Identity $roleGroupName -Member $sp.Identity
    }
}

# Result
if ($group) {
    Get-RoleGroup -Identity $roleGroupName | Select-Object Name, DisplayName, @{ n = 'Roles'; e = { ($_.Roles | ForEach-Object { ([string]$_ -split '[\\/]')[-1] }) -join ', ' } } |
        Format-List | Out-Host
    Get-RoleGroupMember -Identity $roleGroupName | Format-Table Name, RecipientType -AutoSize | Out-Host
}
[pscustomobject]@{
    RoleGroup = $roleGroupName
    Roles     = $roles -join ', '
    Member    = $spDisplayName
    NextStep  = 'Connect-IPPSSession as the app (certificate) and confirm only Get-* Purview commands are available.'
}
