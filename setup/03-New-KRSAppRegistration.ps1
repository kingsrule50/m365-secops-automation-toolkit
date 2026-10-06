#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.20.0' }
<#
.SYNOPSIS
    Creates (or updates) the automation app registration with least-privilege Graph permissions.

.DESCRIPTION
    Idempotent. Run it once per lab part to add only the permissions that part needs.
      1. Signs you in interactively as an admin (delegated, this run only).
      2. Creates app 'app-krs-secops-automation' (single tenant) with your certificate's public key.
         No client secret is ever created.
      3. Creates its service principal.
      4. Grants admin consent for the Microsoft Graph application permissions of the chosen part(s).
      5. Prints the values for settings.json.
    Permission names are resolved to IDs from the tenant's Microsoft Graph service principal,
    so no GUIDs are hard-coded.

    Get the tenant owner's approval before running this in a shared tenant.

.PARAMETER TenantId
    Tenant ID (GUID) or primary domain of the tenant.

.PARAMETER CertificatePath
    Path to the public key (.cer) from 02-New-KRSAuthCertificate.ps1.

.PARAMETER Part
    Lab part(s) whose permissions to grant. Default 1.

.PARAMETER IncludeWritePermissions
    Part 3 only: also grant the containment permissions (disable user, revoke sessions).
    Leave this off until the tenant owner approves write access.

.PARAMETER DisplayName
    App registration name. Default app-krs-secops-automation.

.EXAMPLE
    ./setup/03-New-KRSAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -CertificatePath "$HOME\KRSSecOps\certs\KRSSecOps-Automation.cer" -WhatIf

    Shows every change without making it.

.EXAMPLE
    ./setup/03-New-KRSAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -CertificatePath "$HOME\KRSSecOps\certs\KRSSecOps-Automation.cer"
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CertificatePath,

    [Parameter()]
    [ValidateSet(1, 2, 3)]
    [int[]]$Part = 1,

    [Parameter()]
    [switch]$IncludeWritePermissions,

    [Parameter()]
    [string]$DisplayName = 'app-krs-secops-automation'
)

$ErrorActionPreference = 'Stop'
$graphAppId = '00000003-0000-0000-c000-000000000000'
$exchangeAppId = '00000002-0000-0ff1-ce00-000000000000'

# Least-privilege permission sets per lab part (see docs/permission-matrix.md)
$permissionSets = @{
    1 = @(
        @{ Resource = $graphAppId; Name = 'User.Read.All' }
        @{ Resource = $graphAppId; Name = 'AuditLog.Read.All' }
        @{ Resource = $graphAppId; Name = 'RoleManagement.Read.Directory' }
        @{ Resource = $graphAppId; Name = 'Application.Read.All' }
        @{ Resource = $graphAppId; Name = 'Policy.Read.All' }
        @{ Resource = $graphAppId; Name = 'GroupMember.Read.All' }
    )
    2 = @(
        @{ Resource = $exchangeAppId; Name = 'Exchange.ManageAsApp' }
    )
    3 = @(
        @{ Resource = $graphAppId; Name = 'IdentityRiskyUser.Read.All' }
        @{ Resource = $graphAppId; Name = 'IdentityRiskEvent.Read.All' }
    )
}
$writePermissions = @(
    @{ Resource = $graphAppId; Name = 'User.EnableDisableAccount.All' }
    @{ Resource = $graphAppId; Name = 'User.RevokeSessions.All' }
)

$wanted = foreach ($p in ($Part | Sort-Object -Unique)) { $permissionSets[$p] }
if ($IncludeWritePermissions) {
    if (3 -notin $Part) { throw '-IncludeWritePermissions applies to Part 3 only.' }
    $wanted += $writePermissions
}

function Invoke-Graph {
    param([string]$Method = 'GET', [string]$Uri, [object]$Body)
    $request = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri"; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body')) { $request.Body = ($Body | ConvertTo-Json -Depth 10); $request.ContentType = 'application/json' }
    Invoke-MgGraphRequest @request
}

# 1. Delegated admin sign-in, scoped to exactly what this script does
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome
$context = Get-MgContext
Write-Verbose "Signed in as $($context.Account) to tenant $($context.TenantId)"

# Certificate public key
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path -LiteralPath $CertificatePath).Path)
$keyCredential = @{
    type          = 'AsymmetricX509Cert'
    usage         = 'Verify'
    key           = [Convert]::ToBase64String($certificate.GetRawCertData())
    displayName   = $certificate.Subject
    startDateTime = $certificate.NotBefore.ToUniversalTime().ToString('o')
    endDateTime   = $certificate.NotAfter.ToUniversalTime().ToString('o')
}

# Resolve permission names to app role IDs per resource
$resources = @{}
foreach ($resourceAppId in ($wanted.Resource | Sort-Object -Unique)) {
    $sp = Invoke-Graph -Uri "servicePrincipals(appId='$resourceAppId')?`$select=id,appId,displayName,appRoles"
    $resources[$resourceAppId] = $sp
}
$resolved = foreach ($permission in $wanted) {
    $sp = $resources[$permission.Resource]
    $role = $sp.appRoles | Where-Object { $_.value -eq $permission.Name -and 'Application' -in $_.allowedMemberTypes }
    if (-not $role) { throw "Permission '$($permission.Name)' not found on $($sp.displayName)." }
    [pscustomobject]@{ ResourceAppId = $sp.appId; ResourceSpId = $sp.id; ResourceName = $sp.displayName; Name = $permission.Name; RoleId = $role.id }
}

# 2. App registration
$app = (Invoke-Graph -Uri "applications?`$filter=displayName eq '$DisplayName'&`$select=id,appId,displayName,keyCredentials,requiredResourceAccess").value | Select-Object -First 1

$requiredResourceAccess = foreach ($group in ($resolved | Group-Object ResourceAppId)) {
    @{ resourceAppId = $group.Name; resourceAccess = @($group.Group | ForEach-Object { @{ id = $_.RoleId; type = 'Role' } }) }
}

if (-not $app) {
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create app registration with certificate credential')) {
        $app = Invoke-Graph -Method POST -Uri 'applications' -Body @{
            displayName            = $DisplayName
            signInAudience         = 'AzureADMyOrg'
            notes                  = 'KRSSecOps automation. Certificate auth only. Owner: Chinedu. Scope guard: pilot domain.'
            keyCredentials         = @($keyCredential)
            requiredResourceAccess = @($requiredResourceAccess)
        }
        Write-Verbose "Created app $($app.appId)"
    }
}
else {
    Write-Verbose "App '$DisplayName' already exists ($($app.appId)); merging permissions."
    # Merge requested permissions with what the app already lists, so earlier parts are kept.
    $merged = @{}
    foreach ($entry in @($app.requiredResourceAccess)) {
        if (-not $entry) { continue }
        $merged[$entry.resourceAppId] = [System.Collections.Generic.List[object]]::new()
        foreach ($access in $entry.resourceAccess) { $merged[$entry.resourceAppId].Add(@{ id = $access.id; type = $access.type }) }
    }
    foreach ($permission in $resolved) {
        if (-not $merged.ContainsKey($permission.ResourceAppId)) { $merged[$permission.ResourceAppId] = [System.Collections.Generic.List[object]]::new() }
        if (-not ($merged[$permission.ResourceAppId] | Where-Object { $_.id -eq $permission.RoleId })) {
            $merged[$permission.ResourceAppId].Add(@{ id = $permission.RoleId; type = 'Role' })
        }
    }
    $body = @{ requiredResourceAccess = @($merged.Keys | ForEach-Object { @{ resourceAppId = $_; resourceAccess = @($merged[$_]) } }) }

    # customKeyIdentifier can come back as the hex thumbprint itself or as base64 of its bytes.
    # A 40-character hex string is also valid base64, so test for hex first.
    $thumbprints = @($app.keyCredentials | Where-Object { $_ } | ForEach-Object {
            $id = [string]$_.customKeyIdentifier
            if ($id -match '^[0-9A-Fa-f]{40}$') { $id.ToUpperInvariant() }
            elseif ($id) { [Convert]::ToHexString([Convert]::FromBase64String($id)) }
        })
    if ($certificate.Thumbprint -notin $thumbprints) {
        if (@($app.keyCredentials | Where-Object { $_ }).Count -eq 0) {
            $body.keyCredentials = @($keyCredential)
        }
        else {
            Write-Warning 'The app already has a different certificate. Add this one in Entra admin center > App registrations > Certificates & secrets, then rerun. (Graph cannot append a key without proof of possession of an existing one.)'
        }
    }
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Update permissions list' + $(if ($body.ContainsKey('keyCredentials')) { ' and add certificate' } else { '' }))) {
        Invoke-Graph -Method PATCH -Uri "applications/$($app.id)" -Body $body | Out-Null
    }
}

if (-not $app) { return }  # -WhatIf on first run: nothing more to show

# 3. Service principal
$sp = (Invoke-Graph -Uri "servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id,appId,displayName").value | Select-Object -First 1
if (-not $sp -and $PSCmdlet.ShouldProcess($DisplayName, 'Create service principal')) {
    $sp = Invoke-Graph -Method POST -Uri 'servicePrincipals' -Body @{ appId = $app.appId; tags = @('KRSSecOps', 'HideApp') }
    Start-Sleep -Seconds 10   # let the new service principal replicate before assigning roles
}

# 4. Admin consent: app role assignments
$granted = @()
if ($sp) {
    $existing = @((Invoke-Graph -Uri "servicePrincipals/$($sp.id)/appRoleAssignments").value | Where-Object { $_ } | ForEach-Object { $_.appRoleId })
    foreach ($permission in $resolved) {
        if ($permission.RoleId -in $existing) {
            $granted += [pscustomobject]@{ Permission = $permission.Name; Resource = $permission.ResourceName; Status = 'Already granted' }
            continue
        }
        if ($PSCmdlet.ShouldProcess("$($permission.ResourceName): $($permission.Name)", 'Grant admin consent (application permission)')) {
            for ($attempt = 1; $attempt -le 4; $attempt++) {
                try {
                    Invoke-Graph -Method POST -Uri "servicePrincipals/$($sp.id)/appRoleAssignments" -Body @{
                        principalId = $sp.id
                        resourceId  = $permission.ResourceSpId
                        appRoleId   = $permission.RoleId
                    } | Out-Null
                    break
                }
                catch {
                    if ($attempt -eq 4) { throw }
                    Start-Sleep -Seconds (5 * $attempt)
                }
            }
            $granted += [pscustomobject]@{ Permission = $permission.Name; Resource = $permission.ResourceName; Status = 'Granted' }
        }
    }
}

$granted | Format-Table -AutoSize | Out-Host

# 5. Values for settings.json
[pscustomobject]@{
    TenantId              = $context.TenantId
    ClientId              = $app.appId
    CertificateThumbprint = $certificate.Thumbprint
    AppObjectId           = $app.id
    ServicePrincipalId    = if ($sp) { $sp.id } else { $null }
    NextStep              = 'Copy TenantId, ClientId and CertificateThumbprint into src/KRSSecOps/Config/settings.json, then Disconnect-MgGraph.'
}
