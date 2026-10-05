function Get-KRSMfaGap {
    <#
    .SYNOPSIS
        Finds users who are not registered for MFA or have no phishing-resistant method.

    .DESCRIPTION
        Reads the Entra ID authentication methods registration report and rates each user:
          Critical  admin with no MFA registered
          High      member with no MFA registered
          Medium    admin with MFA but no phishing-resistant method (FIDO2, Windows Hello, passkey)
        Guests are skipped unless -IncludeGuests is used, because their MFA lives in their home tenant.

    .PARAMETER Scope
        Pilot (default) returns pilot users only. Tenant returns everyone.

    .PARAMETER Redact
        Masks names and UPNs of users outside the pilot. Use it for any output you will screenshot or share.

    .PARAMETER IncludeGuests
        Also rate guest accounts.

    .PARAMETER IncludeCompliant
        Also return users with no finding (Severity Info), for a full inventory.

    .EXAMPLE
        Get-KRSMfaGap

        MFA gaps for pilot users.

    .EXAMPLE
        Get-KRSMfaGap -Scope Tenant -Redact | Sort-Object SeverityRank | Format-Table UserPrincipalName, IsAdmin, Finding, Severity

        Tenant-wide gaps, with users outside the pilot masked.

    .OUTPUTS
        PSCustomObject (KRSSecOps.MfaGap)

    .NOTES
        Graph: GET /reports/authenticationMethods/userRegistrationDetails
        Permission: AuditLog.Read.All (application). Licence: Entra ID P1 or P2.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateSet('Pilot', 'Tenant')]
        [string]$Scope = 'Pilot',

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [switch]$IncludeGuests,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $null = Get-KRSActiveConfig
    $phishingResistant = '^(fido2|windowsHelloForBusiness|passKey)'

    Write-KRSLog -Action 'Read' -Target 'userRegistrationDetails' -Message "Scope=$Scope"
    $records = Invoke-KRSGraphRequest -Uri 'reports/authenticationMethods/userRegistrationDetails?$top=999' -All

    foreach ($record in $records) {
        $upn = Get-KRSValue -InputObject $record -Name 'userPrincipalName'
        $id = Get-KRSValue -InputObject $record -Name 'id'
        $userType = [string](Get-KRSValue -InputObject $record -Name 'userType')
        if ($userType -eq 'guest' -and -not $IncludeGuests) { continue }

        $identity = Format-KRSIdentity -UserPrincipalName $upn -DisplayName (Get-KRSValue -InputObject $record -Name 'userDisplayName') -Id $id -Redact:$Redact
        if ($Scope -eq 'Pilot' -and -not $identity.InPilot) { continue }

        $isAdmin = [bool](Get-KRSValue -InputObject $record -Name 'isAdmin')
        $isRegistered = [bool](Get-KRSValue -InputObject $record -Name 'isMfaRegistered')
        $methods = @(Get-KRSValue -InputObject $record -Name 'methodsRegistered') | Where-Object { $_ }
        $hasStrong = [bool]($methods | Where-Object { $_ -match $phishingResistant })

        $finding, $severity = switch ($true) {
            (-not $isRegistered -and $isAdmin) { 'Admin has no MFA method registered'; 'Critical'; break }
            (-not $isRegistered) { 'No MFA method registered'; 'High'; break }
            ($isAdmin -and -not $hasStrong) { 'Admin has no phishing-resistant method'; 'Medium'; break }
            default { 'OK'; 'Info' }
        }
        if ($severity -eq 'Info' -and -not $IncludeCompliant) { continue }

        [pscustomobject]@{
            PSTypeName           = 'KRSSecOps.MfaGap'
            UserPrincipalName    = $identity.UserPrincipalName
            DisplayName          = $identity.DisplayName
            UserType             = $userType
            IsAdmin              = $isAdmin
            IsMfaRegistered      = $isRegistered
            IsMfaCapable         = [bool](Get-KRSValue -InputObject $record -Name 'isMfaCapable')
            HasPhishingResistant = $hasStrong
            MethodsRegistered    = $methods -join ', '
            InPilot              = $identity.InPilot
            Finding              = $finding
            Severity             = $severity
            SeverityRank         = Get-KRSSeverityRank -Severity $severity
        }
    }
}
