function Get-KRSPilotMemberSet {
    # Object IDs of the pilot security group's transitive user members, cached for the session.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param()

    if ($null -ne $script:KRSPilotMemberIds) {
        Write-Output -InputObject $script:KRSPilotMemberIds -NoEnumerate
        return
    }

    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $groupId = Get-KRSValue -InputObject $script:KRSConfig -Name 'PilotGroupId'
    if ($groupId) {
        try {
            # No OData type cast here: casts on membership need advanced-query headers. Filter users client-side.
            Invoke-KRSGraphRequest -Uri "groups/$groupId/transitiveMembers?`$select=id&`$top=999" -All |
                Where-Object { (Get-KRSValue -InputObject $_ -Name '@odata.type') -eq '#microsoft.graph.user' } |
                ForEach-Object { $null = $ids.Add($_.id) }
        }
        catch {
            Write-Warning "Could not read pilot group '$groupId'; pilot scope falls back to the pilot domain only. $($_.Exception.Message)"
        }
    }
    $script:KRSPilotMemberIds = $ids
    Write-Output -InputObject $ids -NoEnumerate
}

function Test-KRSInPilot {
    # Read-side pilot test: a pilot-domain UPN, or a member of the pilot group.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$UserPrincipalName,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Id
    )

    $domain = (Get-KRSActiveConfig).PilotDomain
    if ($UserPrincipalName -and (Test-KRSPilotScope -UserPrincipalName $UserPrincipalName -PilotDomain $domain)) { return $true }
    if ($Id) { return (Get-KRSPilotMemberSet).Contains($Id) }
    $false
}

function Assert-KRSPilotScope {
    <#
    .SYNOPSIS
        Write-side guard. Throws unless every target UPN is in the pilot domain.
    .DESCRIPTION
        Every function that changes the tenant calls this before ShouldProcess.
        It is deliberately stricter than the read-side test: group membership alone is not enough
        to let automation change an account, because group membership can be changed by others.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string[]]$UserPrincipalName
    )

    $domain = (Get-KRSActiveConfig).PilotDomain
    foreach ($upn in $UserPrincipalName) {
        if (-not (Test-KRSPilotScope -UserPrincipalName $upn -PilotDomain $domain)) {
            Write-KRSLog -Level Error -Action 'ScopeViolation' -Target $upn -Result Failure -Message "Blocked: outside pilot domain $domain"
            throw [System.UnauthorizedAccessException]::new("Scope guard blocked '$upn': changes are limited to @$domain.")
        }
    }
}

function ConvertTo-KRSMaskedUpn {
    # a.user@contoso.com -> a***@contoso.com ; guest UPNs -> guest-<8 hex of SHA-256>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$UserPrincipalName
    )

    if ([string]::IsNullOrEmpty($UserPrincipalName)) { return $UserPrincipalName }
    if ($UserPrincipalName -match '#EXT#' -or $UserPrincipalName -notmatch '@') {
        $bytes = [Text.Encoding]::UTF8.GetBytes($UserPrincipalName.ToLowerInvariant())
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).Substring(0, 8).ToLowerInvariant()
        return "guest-$hash"
    }
    $local, $domain = $UserPrincipalName -split '@', 2
    '{0}***@{1}' -f $local.Substring(0, 1), $domain
}

function Format-KRSIdentity {
    # Applies pilot membership and optional redaction to one identity for report output.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$UserPrincipalName,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DisplayName,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Id,

        [Parameter()]
        [switch]$Redact
    )

    $inPilot = Test-KRSInPilot -UserPrincipalName $UserPrincipalName -Id $Id
    if ($Redact -and -not $inPilot) {
        $UserPrincipalName = ConvertTo-KRSMaskedUpn -UserPrincipalName $UserPrincipalName
        $DisplayName = 'Redacted (outside pilot)'
    }
    [pscustomobject]@{
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $DisplayName
        InPilot           = $inPilot
    }
}

function Resolve-KRSPrincipal {
    <#
    .SYNOPSIS
        Resolves a directory object ID to a user, group or service principal, with a session cache.
    .DESCRIPTION
        Uses the typed endpoints so the app needs only User.Read.All, GroupMember.Read.All and
        Application.Read.All, instead of the broader Directory.Read.All that /directoryObjects requires.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Id
    )

    if ($script:KRSPrincipalCache.ContainsKey($Id)) { return $script:KRSPrincipalCache[$Id] }

    $lookups = @(
        @{ Type = 'User'; Uri = "users/$Id`?`$select=id,displayName,userPrincipalName,userType" }
        @{ Type = 'Group'; Uri = "groups/$Id`?`$select=id,displayName" }
        @{ Type = 'ServicePrincipal'; Uri = "servicePrincipals/$Id`?`$select=id,displayName,appId" }
    )

    $resolved = [pscustomobject]@{ Id = $Id; Type = 'Unknown'; DisplayName = $null; UserPrincipalName = $null }
    foreach ($lookup in $lookups) {
        try {
            $object = Invoke-KRSGraphRequest -Uri $lookup.Uri -MaxRetries 2
            if ($object) {
                $resolved = [pscustomobject]@{
                    Id                = $Id
                    Type              = $lookup.Type
                    DisplayName       = Get-KRSValue -InputObject $object -Name 'displayName'
                    UserPrincipalName = Get-KRSValue -InputObject $object -Name 'userPrincipalName'
                }
                break
            }
        }
        catch {
            Write-Verbose "Principal $Id is not a $($lookup.Type): $($_.Exception.Message)"
        }
    }
    $script:KRSPrincipalCache[$Id] = $resolved
    $resolved
}

function Initialize-KRSPrincipalCache {
    <#
    .SYNOPSIS
        Bulk-loads users and service principals into the principal cache.
    .DESCRIPTION
        Resolving thousands of IDs one by one costs up to three Graph calls each. Reading every user and
        service principal in pages of 999 costs a handful of calls, after which Resolve-KRSPrincipal answers
        from memory. Anything still missing (for example role-assignable groups) falls back to single lookups.
    #>
    [CmdletBinding()]
    param()

    $sources = @(
        @{ Type = 'User'; Uri = 'users?$select=id,displayName,userPrincipalName&$top=999' }
        @{ Type = 'ServicePrincipal'; Uri = 'servicePrincipals?$select=id,displayName&$top=999' }
    )
    foreach ($source in $sources) {
        $count = 0
        foreach ($object in (Invoke-KRSGraphRequest -Uri $source.Uri -All)) {
            $id = [string](Get-KRSValue -InputObject $object -Name 'id')
            if (-not $id) { continue }
            $script:KRSPrincipalCache[$id] = [pscustomobject]@{
                Id                = $id
                Type              = $source.Type
                DisplayName       = Get-KRSValue -InputObject $object -Name 'displayName'
                UserPrincipalName = Get-KRSValue -InputObject $object -Name 'userPrincipalName'
            }
            $count++
        }
        Write-Verbose "Principal cache: loaded $count $($source.Type) objects"
    }
}
