function Get-KRSStaleAccount {
    <#
    .SYNOPSIS
        Finds enabled accounts with no sign-in for longer than a threshold.

    .DESCRIPTION
        Uses the most recent of the interactive, non-interactive and successful sign-in timestamps.
        An account is stale when it is enabled and either:
          - its last sign-in is older than -InactiveDays, or
          - it has never signed in and was created more than -InactiveDays ago.
        Stale enabled accounts are a common foothold: nobody notices when they are used.

    .PARAMETER InactiveDays
        Threshold in days. Defaults to StaleAccountDays in settings (90).

    .PARAMETER Scope
        Pilot (default) or Tenant.

    .PARAMETER Redact
        Masks names and UPNs of users outside the pilot.

    .EXAMPLE
        Get-KRSStaleAccount

        Pilot accounts inactive for 90 days or more.

    .EXAMPLE
        Get-KRSStaleAccount -Scope Tenant -InactiveDays 45 -Redact | Format-Table UserPrincipalName, UserType, DaysInactive, Finding

        Tenant-wide, with a tighter 45-day threshold.

    .OUTPUTS
        PSCustomObject (KRSSecOps.StaleAccount)

    .NOTES
        Graph: GET /users with signInActivity
        Permissions: User.Read.All, AuditLog.Read.All (application). Licence: Entra ID P1 or P2.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$InactiveDays,

        [Parameter()]
        [ValidateSet('Pilot', 'Tenant')]
        [string]$Scope = 'Pilot',

        [Parameter()]
        [switch]$Redact
    )

    $config = Get-KRSActiveConfig
    if (-not $PSBoundParameters.ContainsKey('InactiveDays')) { $InactiveDays = [int]$config.StaleAccountDays }
    $now = [datetime]::UtcNow
    $cutoff = $now.AddDays(-$InactiveDays)

    Write-KRSLog -Action 'Read' -Target 'users/signInActivity' -Message "Scope=$Scope InactiveDays=$InactiveDays"
    $select = 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity'
    $users = Invoke-KRSGraphRequest -Uri "users?`$select=$select&`$top=500" -All

    foreach ($user in $users) {
        if (-not [bool](Get-KRSValue -InputObject $user -Name 'accountEnabled')) { continue }

        $identity = Format-KRSIdentity -UserPrincipalName (Get-KRSValue -InputObject $user -Name 'userPrincipalName') -DisplayName (Get-KRSValue -InputObject $user -Name 'displayName') -Id (Get-KRSValue -InputObject $user -Name 'id') -Redact:$Redact
        if ($Scope -eq 'Pilot' -and -not $identity.InPilot) { continue }

        $activity = Get-KRSValue -InputObject $user -Name 'signInActivity'
        $lastSignIn = @(
            'lastSignInDateTime', 'lastNonInteractiveSignInDateTime', 'lastSuccessfulSignInDateTime' |
                ForEach-Object { ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $activity -Name $_) } |
                Where-Object { $_ }
            ) | Sort-Object -Descending | Select-Object -First 1
            $created = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $user -Name 'createdDateTime')

            if ($lastSignIn) {
                if ($lastSignIn -ge $cutoff) { continue }
                $daysInactive = [int]($now - $lastSignIn).TotalDays
                $finding = "No sign-in for $daysInactive days"
            }
            else {
                if ($created -and $created -ge $cutoff) { continue }
                $daysInactive = if ($created) { [int]($now - $created).TotalDays } else { $null }
                $finding = 'Enabled but never signed in'
            }

            $userType = [string](Get-KRSValue -InputObject $user -Name 'userType')
            [pscustomobject]@{
                PSTypeName        = 'KRSSecOps.StaleAccount'
                UserPrincipalName = $identity.UserPrincipalName
                DisplayName       = $identity.DisplayName
                UserType          = $userType
                CreatedDateTime   = $created
                LastSignIn        = $lastSignIn
                DaysInactive      = $daysInactive
                InPilot           = $identity.InPilot
                Finding           = $finding
                Severity          = 'Medium'
                SeverityRank      = Get-KRSSeverityRank -Severity 'Medium'
            }
        }
    }
