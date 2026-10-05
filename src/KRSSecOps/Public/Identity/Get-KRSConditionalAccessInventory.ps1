function Get-KRSConditionalAccessInventory {
    <#
    .SYNOPSIS
        Inventories Conditional Access policies and checks the tenant for baseline gaps.

    .DESCRIPTION
        Returns one row per policy with its state, targets, exclusions and grant controls, plus
        tenant baseline rows. Flags:
          High    no enabled policy requires MFA for all users on all apps
          High    no enabled policy blocks legacy authentication for all users
          Medium  enabled policy with more than -MaxDirectExclusions users excluded directly
          Low     policy disabled, or in report-only mode
        If security defaults are enabled, the two baseline gaps are reported as covered.
        This is a tenant-wide configuration report: use -Redact to mask excluded users outside the pilot.

    .PARAMETER MaxDirectExclusions
        Direct user exclusions allowed per policy before it is flagged. Default 2 (two break-glass accounts).

    .PARAMETER Redact
        Masks excluded or included users outside the pilot.

    .PARAMETER IncludeCompliant
        Also return policies and baseline checks with no finding (Severity Info).

    .EXAMPLE
        Get-KRSConditionalAccessInventory -IncludeCompliant -Redact | Format-Table PolicyName, State, GrantControls, Finding

        Full policy inventory, masked for screenshots.

    .EXAMPLE
        Get-KRSConditionalAccessInventory | Where-Object PolicyName -eq '(tenant baseline)'

        Only the tenant-level gaps.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ConditionalAccess)

    .NOTES
        Graph: GET /identity/conditionalAccess/policies, /policies/identitySecurityDefaultsEnforcementPolicy
        Permission: Policy.Read.All (application). Licence: Entra ID P1 or P2.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(0, 100)]
        [int]$MaxDirectExclusions = 2,

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $null = Get-KRSActiveConfig
    $guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    $describe = {
        param([object[]]$Ids, [bool]$Mask)
        foreach ($id in @($Ids | Where-Object { $_ })) {
            if ($id -notmatch $guid) { $id; continue }
            $principal = Resolve-KRSPrincipal -Id $id
            if ($principal.Type -eq 'User') {
                (Format-KRSIdentity -UserPrincipalName $principal.UserPrincipalName -DisplayName $principal.DisplayName -Id $id -Redact:$Mask).UserPrincipalName
            }
            elseif ($principal.DisplayName) { $principal.DisplayName }
            else { $id }
        }
    }

    $newRow = {
        param($Name, $State, $Include, $Exclude, $ExcludeGroups, $Grant, $Modified, $Finding, $Severity)
        [pscustomobject]@{
            PSTypeName       = 'KRSSecOps.ConditionalAccess'
            PolicyName       = $Name
            State            = $State
            IncludeUsers     = $Include
            ExcludedUsers    = $Exclude
            ExcludedGroups   = $ExcludeGroups
            GrantControls    = $Grant
            ModifiedDateTime = $Modified
            Finding          = $Finding
            Severity         = $Severity
            SeverityRank     = Get-KRSSeverityRank -Severity $Severity
        }
    }

    Write-KRSLog -Action 'Read' -Target 'identity/conditionalAccess/policies'
    $policies = @(Invoke-KRSGraphRequest -Uri 'identity/conditionalAccess/policies' -All)

    $mfaForAll = $false
    $legacyBlocked = $false
    foreach ($policy in $policies) {
        $state = [string](Get-KRSValue -InputObject $policy -Name 'state')
        $conditions = Get-KRSValue -InputObject $policy -Name 'conditions'
        $users = Get-KRSValue -InputObject $conditions -Name 'users'
        $apps = Get-KRSValue -InputObject $conditions -Name 'applications'
        $grant = Get-KRSValue -InputObject $policy -Name 'grantControls'

        $includeUsers = @(Get-KRSValue -InputObject $users -Name 'includeUsers') | Where-Object { $_ }
        $excludeUsers = @(Get-KRSValue -InputObject $users -Name 'excludeUsers') | Where-Object { $_ }
        $excludeGroups = @(Get-KRSValue -InputObject $users -Name 'excludeGroups') | Where-Object { $_ }
        $includeApps = @(Get-KRSValue -InputObject $apps -Name 'includeApplications') | Where-Object { $_ }
        $clientApps = @(Get-KRSValue -InputObject $conditions -Name 'clientAppTypes') | Where-Object { $_ }
        $controls = @(Get-KRSValue -InputObject $grant -Name 'builtInControls') | Where-Object { $_ }
        $strength = Get-KRSValue -InputObject (Get-KRSValue -InputObject $grant -Name 'authenticationStrength') -Name 'displayName'

        $grantText = @($controls) + @(if ($strength) { "authStrength: $strength" }) | Where-Object { $_ }
        $allUsers = 'All' -in $includeUsers
        if ($state -eq 'enabled' -and $allUsers -and 'All' -in $includeApps -and ('mfa' -in $controls -or $strength)) { $mfaForAll = $true }
        if ($state -eq 'enabled' -and $allUsers -and 'block' -in $controls -and ($clientApps -contains 'exchangeActiveSync' -or $clientApps -contains 'other')) { $legacyBlocked = $true }

        $excludeCount = @($excludeUsers).Count
        $finding, $severity = switch ($true) {
            ($state -eq 'disabled') { 'Policy is disabled'; 'Low'; break }
            ($state -eq 'enabledForReportingButNotEnforced') { 'Report-only: not enforced'; 'Low'; break }
            ($excludeCount -gt $MaxDirectExclusions) { "$excludeCount users excluded directly: keep exclusions to break-glass accounts"; 'Medium'; break }
            default { 'OK'; 'Info' }
        }
        if ($severity -eq 'Info' -and -not $IncludeCompliant) { continue }

        & $newRow (Get-KRSValue -InputObject $policy -Name 'displayName') $state `
        ((& $describe $includeUsers $Redact.IsPresent) -join '; ') ((& $describe $excludeUsers $Redact.IsPresent) -join '; ') ((& $describe $excludeGroups $Redact.IsPresent) -join '; ') `
        ($grantText -join ', ') (ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $policy -Name 'modifiedDateTime')) $finding $severity
    }

    $securityDefaults = $false
    try {
        $defaults = Invoke-KRSGraphRequest -Uri 'policies/identitySecurityDefaultsEnforcementPolicy' -MaxRetries 2
        $securityDefaults = [bool](Get-KRSValue -InputObject $defaults -Name 'isEnabled')
    }
    catch {
        Write-Verbose "Could not read security defaults: $($_.Exception.Message)"
    }

    $baseline = @(
        @{ Met = $mfaForAll; Gap = 'No enabled policy requires MFA for all users on all apps'; Ok = 'MFA required for all users on all apps' }
        @{ Met = $legacyBlocked; Gap = 'Legacy authentication is not blocked for all users'; Ok = 'Legacy authentication blocked' }
    )
    foreach ($check in $baseline) {
        $finding, $severity = if ($check.Met) { "OK: $($check.Ok)"; 'Info' }
        elseif ($securityDefaults) { "OK: covered by security defaults ($($check.Ok))"; 'Info' }
        else { $check.Gap; 'High' }
        if ($severity -eq 'Info' -and -not $IncludeCompliant) { continue }
        & $newRow '(tenant baseline)' $(if ($securityDefaults) { 'securityDefaults' } else { 'n/a' }) $null $null $null $null $null $finding $severity
    }
}
