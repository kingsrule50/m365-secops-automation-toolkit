function Get-KRSGuestAccessReport {
    <#
    .SYNOPSIS
        Reviews guest accounts for unredeemed invitations and inactivity.

    .DESCRIPTION
        Flags enabled guests that are a standing external access risk:
          Medium  invitation not redeemed for more than -PendingDays
          Medium  accepted guest with no sign-in for more than -InactiveDays, or never signed in
        Guest UPNs never fall in the pilot domain, so with -Scope Pilot a guest is in scope only
        when it is a member of the pilot security group (PilotGroupId in settings).

    .PARAMETER InactiveDays
        Inactivity threshold in days. Defaults to StaleAccountDays in settings (90).

    .PARAMETER PendingDays
        Days an invitation may stay unredeemed before it is flagged. Default 30.

    .PARAMETER Scope
        Pilot (default) or Tenant.

    .PARAMETER Redact
        Masks guests outside the pilot.

    .PARAMETER IncludeCompliant
        Also return active guests with no finding (Severity Info).

    .EXAMPLE
        Get-KRSGuestAccessReport -Scope Tenant -Redact

        Guest findings across the tenant with identities masked.

    .EXAMPLE
        Get-KRSGuestAccessReport -Scope Tenant -IncludeCompliant -Redact | Group-Object InvitationState

        Guest inventory by invitation state.

    .OUTPUTS
        PSCustomObject (KRSSecOps.GuestAccess)

    .NOTES
        Graph: GET /users?$filter=userType eq 'Guest' with signInActivity
        Permissions: User.Read.All, AuditLog.Read.All (application).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$InactiveDays,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$PendingDays = 30,

        [Parameter()]
        [ValidateSet('Pilot', 'Tenant')]
        [string]$Scope = 'Pilot',

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $config = Get-KRSActiveConfig
    if (-not $PSBoundParameters.ContainsKey('InactiveDays')) { $InactiveDays = [int]$config.StaleAccountDays }
    $now = [datetime]::UtcNow

    Write-KRSLog -Action 'Read' -Target 'users/guests' -Message "Scope=$Scope"
    $select = 'id,displayName,mail,userPrincipalName,accountEnabled,createdDateTime,externalUserState,externalUserStateChangeDateTime,signInActivity'
    $guests = Invoke-KRSGraphRequest -Uri "users?`$filter=userType eq 'Guest'&`$select=$select&`$top=500" -All

    foreach ($guest in $guests) {
        $identity = Format-KRSIdentity -UserPrincipalName (Get-KRSValue -InputObject $guest -Name 'userPrincipalName') -DisplayName (Get-KRSValue -InputObject $guest -Name 'displayName') -Id (Get-KRSValue -InputObject $guest -Name 'id') -Redact:$Redact
        if ($Scope -eq 'Pilot' -and -not $identity.InPilot) { continue }

        $enabled = [bool](Get-KRSValue -InputObject $guest -Name 'accountEnabled')
        $state = [string](Get-KRSValue -InputObject $guest -Name 'externalUserState')
        $stateChanged = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $guest -Name 'externalUserStateChangeDateTime')
        $created = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $guest -Name 'createdDateTime')
        $activity = Get-KRSValue -InputObject $guest -Name 'signInActivity'
        $lastSignIn = @(
            'lastSignInDateTime', 'lastNonInteractiveSignInDateTime', 'lastSuccessfulSignInDateTime' |
                ForEach-Object { ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $activity -Name $_) } |
                Where-Object { $_ }
            ) | Sort-Object -Descending | Select-Object -First 1

            $pendingSince = if ($stateChanged) { $stateChanged } else { $created }
            $daysInactive = if ($lastSignIn) { [int]($now - $lastSignIn).TotalDays } elseif ($created) { [int]($now - $created).TotalDays } else { $null }

            $finding, $severity = switch ($true) {
            (-not $enabled) { 'Disabled guest'; 'Info'; break }
            ($state -eq 'PendingAcceptance' -and $pendingSince -and ($now - $pendingSince).TotalDays -gt $PendingDays) { "Invitation not redeemed for $(Format-KRSDayCount -Days ([int]($now - $pendingSince).TotalDays))"; 'Medium'; break }
            (-not $lastSignIn -and $state -ne 'PendingAcceptance' -and $null -ne $daysInactive -and $daysInactive -gt $InactiveDays) { 'Guest has never signed in'; 'Medium'; break }
            ($lastSignIn -and $daysInactive -gt $InactiveDays) { "No sign-in for $(Format-KRSDayCount -Days $daysInactive)"; 'Medium'; break }
                default { 'OK'; 'Info' }
            }
            if ($severity -eq 'Info' -and -not $IncludeCompliant) { continue }

            $mail = Get-KRSValue -InputObject $guest -Name 'mail'
            [pscustomobject]@{
                PSTypeName        = 'KRSSecOps.GuestAccess'
                UserPrincipalName = $identity.UserPrincipalName
                DisplayName       = $identity.DisplayName
                Mail              = if ($Redact -and -not $identity.InPilot) { ConvertTo-KRSMaskedUpn -UserPrincipalName $mail } else { $mail }
                AccountEnabled    = $enabled
                InvitationState   = $state
                CreatedDateTime   = $created
                LastSignIn        = $lastSignIn
                DaysInactive      = $daysInactive
                InPilot           = $identity.InPilot
                Finding           = $finding
                Severity          = $severity
                SeverityRank      = Get-KRSSeverityRank -Severity $severity
            }
        }
    }
