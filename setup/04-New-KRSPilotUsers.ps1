#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.20.0' }
<#
.SYNOPSIS
    Creates the pilot security group and pilot test users in the pilot domain.

.DESCRIPTION
    Idempotent. Creates five persona users in the pilot domain (skipping any that exist),
    creates the pilot security group, and adds the users to it. Optionally assigns a licence
    so the users get mailboxes for Part 2.
    Refuses to run unless the pilot domain is verified in the tenant.

    Passwords are random, shown once, and must be changed at first sign-in. They are not
    written to disk. Use them only to sign in and create test activity.

.PARAMETER TenantId
    Tenant ID (GUID) or primary domain.

.PARAMETER PilotDomain
    Verified domain the pilot users live in. Default m365.kingsruleusa.com.

.PARAMETER GroupName
    Pilot security group name. Default SG-KRS-SecOps-Pilot.

.PARAMETER LicenseSkuPartNumber
    Optional licence to assign, for example DEVELOPERPACK_E5 or SPE_E5.
    List the tenant's SKUs with: Invoke-MgGraphRequest GET v1.0/subscribedSkus

.PARAMETER LicenseUser
    Only these users get the licence, given as the part of the UPN before the @ (for example amara.okafor).
    Without it, every user in the run is licensed.

.PARAMETER IncludeExistingDomainUsers
    Also add every existing user in the pilot domain (for example from the Purview lab) to the group.

.EXAMPLE
    ./setup/04-New-KRSPilotUsers.ps1 -TenantId contoso.onmicrosoft.com -WhatIf

.EXAMPLE
    ./setup/04-New-KRSPilotUsers.ps1 -TenantId contoso.onmicrosoft.com -LicenseSkuPartNumber SPE_E5 -LicenseUser amara.okafor, marcus.bennett, sofia.laurent
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter()]
    [string]$PilotDomain = 'm365.kingsruleusa.com',

    [Parameter()]
    [string]$GroupName = 'SG-KRS-SecOps-Pilot',

    [Parameter()]
    [string]$LicenseSkuPartNumber,

    [Parameter()]
    [ValidatePattern('^[a-z]+\.[a-z]+$')]
    [string[]]$LicenseUser,

    [Parameter()]
    [ValidatePattern('^[A-Z]{2}$')]
    [string]$UsageLocation = 'US',

    [Parameter()]
    [switch]$IncludeExistingDomainUsers
)

$ErrorActionPreference = 'Stop'

$personas = @(
    @{ Given = 'Amara'; Surname = 'Okafor'; Department = 'Finance'; JobTitle = 'Financial Analyst' }
    @{ Given = 'Daniel'; Surname = 'Reyes'; Department = 'Human Resources'; JobTitle = 'HR Generalist' }
    @{ Given = 'Priya'; Surname = 'Shah'; Department = 'IT Operations'; JobTitle = 'Systems Administrator' }
    @{ Given = 'Marcus'; Surname = 'Bennett'; Department = 'Sales'; JobTitle = 'Account Executive' }
    @{ Given = 'Sofia'; Surname = 'Laurent'; Department = 'Legal'; JobTitle = 'Paralegal' }
)

function Invoke-Graph {
    param([string]$Method = 'GET', [string]$Uri, [object]$Body, [hashtable]$Headers = @{})
    $request = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri"; OutputType = 'PSObject'; Headers = $Headers; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body')) { $request.Body = ($Body | ConvertTo-Json -Depth 10); $request.ContentType = 'application/json' }
    Invoke-MgGraphRequest @request
}

function Get-RandomPassword {
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_'.ToCharArray()
    $chars = for ($i = 0; $i -lt 20; $i++) { $alphabet[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($alphabet.Length)] }
    # guarantee each character class
    (-join $chars) + 'Aa1!'
}

Connect-MgGraph -TenantId $TenantId -Scopes 'User.ReadWrite.All', 'Group.ReadWrite.All', 'Domain.Read.All', 'Organization.Read.All' -NoWelcome

# Guard: the pilot domain must exist and be verified in this tenant
$domain = Invoke-Graph -Uri "domains/$PilotDomain"
if (-not $domain.isVerified) { throw "Domain '$PilotDomain' is not verified in this tenant." }

$skuId = $null
if ($LicenseSkuPartNumber) {
    $sku = (Invoke-Graph -Uri 'subscribedSkus').value | Where-Object skuPartNumber -eq $LicenseSkuPartNumber
    if (-not $sku) { throw "Licence '$LicenseSkuPartNumber' not found. Available: $(((Invoke-Graph -Uri 'subscribedSkus').value.skuPartNumber) -join ', ')" }
    $free = $sku.prepaidUnits.enabled - $sku.consumedUnits
    Write-Verbose "$LicenseSkuPartNumber has $free free licences"
    $skuId = $sku.skuId
}

# Group
$group = (Invoke-Graph -Uri "groups?`$filter=displayName eq '$GroupName'&`$select=id,displayName").value | Select-Object -First 1
if (-not $group -and $PSCmdlet.ShouldProcess($GroupName, 'Create pilot security group')) {
    $group = Invoke-Graph -Method POST -Uri 'groups' -Body @{
        displayName     = $GroupName
        description     = "KRSSecOps pilot population. Automation may only change members in @$PilotDomain."
        mailEnabled     = $false
        mailNickname    = ($GroupName -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
        securityEnabled = $true
    }
}

$results = [System.Collections.Generic.List[object]]::new()
$memberIds = [System.Collections.Generic.List[string]]::new()
$upnById = @{}

foreach ($persona in $personas) {
    $upn = ('{0}.{1}@{2}' -f $persona.Given, $persona.Surname, $PilotDomain).ToLowerInvariant()
    $user = $null
    try { $user = Invoke-Graph -Uri "users/$upn`?`$select=id,userPrincipalName" } catch { $user = $null }

    if ($user) {
        $results.Add([pscustomobject]@{ UserPrincipalName = $upn; Status = 'Exists'; TemporaryPassword = $null })
        $memberIds.Add($user.id)
        $upnById[$user.id] = $upn
        continue
    }

    if ($PSCmdlet.ShouldProcess($upn, 'Create pilot user')) {
        $password = Get-RandomPassword
        $user = Invoke-Graph -Method POST -Uri 'users' -Body @{
            accountEnabled    = $true
            displayName       = "$($persona.Given) $($persona.Surname)"
            givenName         = $persona.Given
            surname           = $persona.Surname
            mailNickname      = ('{0}.{1}' -f $persona.Given, $persona.Surname).ToLowerInvariant()
            userPrincipalName = $upn
            department        = $persona.Department
            jobTitle          = $persona.JobTitle
            usageLocation     = $UsageLocation
            passwordProfile   = @{ password = $password; forceChangePasswordNextSignIn = $true }
        }
        $memberIds.Add($user.id)
        $upnById[$user.id] = $upn
        $results.Add([pscustomobject]@{ UserPrincipalName = $upn; Status = 'Created'; TemporaryPassword = $password })
    }
}

if ($IncludeExistingDomainUsers) {
    $domainUsers = Invoke-Graph -Uri "users?`$filter=endswith(userPrincipalName,'@$PilotDomain')&`$count=true&`$select=id,userPrincipalName&`$top=999" -Headers @{ ConsistencyLevel = 'eventual' }
    foreach ($u in $domainUsers.value) {
        if ($u.id -notin $memberIds) {
            $memberIds.Add($u.id)
            $upnById[$u.id] = $u.userPrincipalName
            $results.Add([pscustomobject]@{ UserPrincipalName = $u.userPrincipalName; Status = 'Existing domain user'; TemporaryPassword = $null })
        }
    }
}

# Licence pre-check: assign all or nothing, never a partial run that leaves some users unlicensed.
$licenseTargets = @()
if ($skuId) {
    $licenseTargets = @(foreach ($id in $memberIds) {
            try { $assigned = (Invoke-Graph -Uri "users/$id`?`$select=assignedLicenses").assignedLicenses } catch { $assigned = @() }
            $localPart = ([string]$upnById[$id] -split '@')[0]
            if ($LicenseUser -and $localPart -notin $LicenseUser) { continue }
            if ($skuId -notin @($assigned | Where-Object { $_ } | ForEach-Object { $_.skuId })) { $id }
        })
    $sku = (Invoke-Graph -Uri 'subscribedSkus').value | Where-Object skuId -eq $skuId
    $free = $sku.prepaidUnits.enabled - $sku.consumedUnits
    if ($licenseTargets.Count -gt $free) {
        Write-Warning "$LicenseSkuPartNumber has $free free seat(s) but $($licenseTargets.Count) user(s) need one. No licences assigned; users and group are still set up. Free seats or pass fewer users, then rerun."
        $skuId = $null
    }
    else {
        Write-Verbose "${LicenseSkuPartNumber}: $($licenseTargets.Count) to assign, $free free"
    }
}

# Licences and group membership
if ($group) {
    $current = @((Invoke-Graph -Uri "groups/$($group.id)/members?`$select=id&`$top=999").value | Where-Object { $_ } | ForEach-Object { $_.id })
    foreach ($id in $memberIds) {
        if ($skuId -and $id -in $licenseTargets -and $PSCmdlet.ShouldProcess($id, "Assign licence $LicenseSkuPartNumber")) {
            try {
                Invoke-Graph -Method PATCH -Uri "users/$id" -Body @{ usageLocation = $UsageLocation } | Out-Null
                Invoke-Graph -Method POST -Uri "users/$id/assignLicense" -Body @{ addLicenses = @(@{ skuId = $skuId; disabledPlans = @() }); removeLicenses = @() } | Out-Null
            }
            catch { Write-Warning "Licence for $id not assigned: $($_.Exception.Message)" }
        }
        if ($id -notin $current -and $PSCmdlet.ShouldProcess($GroupName, "Add member $id")) {
            Invoke-Graph -Method POST -Uri "groups/$($group.id)/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$id" } | Out-Null
        }
    }
}

$results | Format-Table -AutoSize | Out-Host
Write-Warning 'Temporary passwords are shown once and are not saved. Each user must change it at first sign-in.'

[pscustomobject]@{
    PilotDomain  = $PilotDomain
    PilotGroup   = $GroupName
    PilotGroupId = if ($group) { $group.id } else { $null }
    Members      = $memberIds.Count
    NextStep     = 'Copy PilotGroupId into settings.json, then Disconnect-MgGraph.'
}
