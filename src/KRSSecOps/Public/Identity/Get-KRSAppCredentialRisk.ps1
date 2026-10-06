function Get-KRSAppCredentialRisk {
    <#
    .SYNOPSIS
        Finds app registration credentials about to expire and apps holding high-risk Graph permissions.

    .DESCRIPTION
        Two checks in one report:

        Credentials on app registrations (one row per secret or certificate):
          High    expires within -ExpiryDays (outage risk)
          Medium  client secret valid for more than a year
          Low     expired credential still attached, or any client secret (prefer certificates)

        Microsoft Graph application permissions granted to any service principal:
          Critical  permissions that allow privilege escalation (for example RoleManagement.ReadWrite.Directory)
          High      tenant-wide write or send access to mail, files, users or groups
          Medium    tenant-wide read of mail or files

        Apps are tenant objects with no personal data, so there is no pilot filter.

    .PARAMETER ExpiryDays
        Days ahead to warn about expiry. Defaults to CredentialExpiryDays in settings (30).

    .PARAMETER IncludeCompliant
        Also return certificates with no finding (Severity Info).

    .EXAMPLE
        Get-KRSAppCredentialRisk | Sort-Object SeverityRank | Format-Table AppDisplayName, FindingType, Detail, Severity

    .EXAMPLE
        Get-KRSAppCredentialRisk -ExpiryDays 60 | Where-Object FindingType -eq 'CredentialExpiry'

        Credential expiries over the next 60 days only.

    .OUTPUTS
        PSCustomObject (KRSSecOps.AppRisk)

    .NOTES
        Graph: GET /applications, /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo
        Permission: Application.Read.All (application).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$ExpiryDays,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $config = Get-KRSActiveConfig
    if (-not $PSBoundParameters.ContainsKey('ExpiryDays')) { $ExpiryDays = [int]$config.CredentialExpiryDays }
    $now = [datetime]::UtcNow

    $permissionTiers = @{
        Critical = @('RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All',
            'Directory.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess')
        High     = @('Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite', 'Files.ReadWrite.All', 'Sites.FullControl.All',
            'Sites.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Domain.ReadWrite.All')
        Medium   = @('Mail.Read', 'Files.Read.All', 'Sites.Read.All')
    }

    $newRow = {
        param($AppName, $ObjectId, $Type, $Detail, $End, $Days, $Finding, $Severity)
        [pscustomobject]@{
            PSTypeName     = 'KRSSecOps.AppRisk'
            AppDisplayName = $AppName
            ObjectId       = $ObjectId
            FindingType    = $Type
            Detail         = $Detail
            EndDateTime    = $End
            DaysToExpiry   = $Days
            Finding        = $Finding
            Severity       = $Severity
            SeverityRank   = Get-KRSSeverityRank -Severity $Severity
        }
    }

    # Check 1: credentials on app registrations
    Write-KRSLog -Action 'Read' -Target 'applications/credentials' -Message "ExpiryDays=$ExpiryDays"
    $apps = Invoke-KRSGraphRequest -Uri 'applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999' -All
    foreach ($app in $apps) {
        $credentials = @(
            @(Get-KRSValue -InputObject $app -Name 'passwordCredentials') | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Kind = 'Secret'; Credential = $_ } }
            @(Get-KRSValue -InputObject $app -Name 'keyCredentials') | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Kind = 'Certificate'; Credential = $_ } }
        )
        foreach ($entry in $credentials) {
            $credential = $entry.Credential
            $start = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $credential -Name 'startDateTime')
            $end = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $credential -Name 'endDateTime')
            $label = Get-KRSValue -InputObject $credential -Name 'displayName'
            if (-not $label) { $label = Get-KRSValue -InputObject $credential -Name 'keyId' }
            $daysLeft = if ($end) { [int][math]::Floor(($end - $now).TotalDays) } else { $null }
            $lifetime = if ($start -and $end) { ($end - $start).TotalDays } else { 0 }

            $finding, $severity = switch ($true) {
                ($null -ne $daysLeft -and $daysLeft -ge 0 -and $daysLeft -le $ExpiryDays) { "$($entry.Kind) expires in $(Format-KRSDayCount -Days $daysLeft)"; 'High'; break }
                ($null -ne $daysLeft -and $daysLeft -lt 0) { "Expired $($entry.Kind.ToLower()) still attached ($(Format-KRSDayCount -Days (-$daysLeft)) ago)"; 'Low'; break }
                ($entry.Kind -eq 'Secret' -and $lifetime -gt 366) { "Client secret valid for $([int]($lifetime / 365.25 * 12)) months (keep under 12)"; 'Medium'; break }
                ($entry.Kind -eq 'Secret') { 'Client secret in use: prefer a certificate or managed identity'; 'Low'; break }
                default { 'OK'; 'Info' }
            }
            if ($severity -eq 'Info' -and -not $IncludeCompliant) { continue }
            & $newRow (Get-KRSValue -InputObject $app -Name 'displayName') $app.id 'CredentialExpiry' "$($entry.Kind): $label" $end $daysLeft $finding $severity
        }
    }

    # Check 2: high-risk Microsoft Graph application permissions actually granted
    Write-KRSLog -Action 'Read' -Target 'servicePrincipals/MicrosoftGraph/appRoleAssignedTo'
    $graphSp = Invoke-KRSGraphRequest -Uri "servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles"
    $roleNames = @{}
    foreach ($appRole in @(Get-KRSValue -InputObject $graphSp -Name 'appRoles')) {
        if ($appRole) { $roleNames[[string]$appRole.id] = [string]$appRole.value }
    }

    $grants = Invoke-KRSGraphRequest -Uri "servicePrincipals/$($graphSp.id)/appRoleAssignedTo?`$top=999" -All
    foreach ($grant in $grants) {
        $permission = $roleNames[[string](Get-KRSValue -InputObject $grant -Name 'appRoleId')]
        if (-not $permission) { continue }
        $tier = foreach ($level in 'Critical', 'High', 'Medium') { if ($permission -in $permissionTiers[$level]) { $level; break } }
        if (-not $tier) { continue }
        $finding = switch ($tier) {
            'Critical' { "Can escalate privilege: $permission" }
            'High' { "Tenant-wide write access: $permission" }
            'Medium' { "Tenant-wide read of sensitive data: $permission" }
        }
        & $newRow (Get-KRSValue -InputObject $grant -Name 'principalDisplayName') (Get-KRSValue -InputObject $grant -Name 'principalId') 'HighPrivilegePermission' "Microsoft Graph: $permission" $null $null $finding $tier
    }
}
