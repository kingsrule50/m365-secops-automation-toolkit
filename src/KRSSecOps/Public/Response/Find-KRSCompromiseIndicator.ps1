function Find-KRSCompromiseIndicator {
    <#
    .SYNOPSIS
        Looks for signs that a pilot account has been compromised, across mailbox, audit, sign-in and risk data.

    .DESCRIPTION
        One row per signal and user:

          ExternalInboxRule   High      an enabled inbox rule forwards or redirects outside the organisation
                              Low       the same, but the rule is disabled (contained, awaiting review)
          ExternalForwarding  High      mailbox-level forwarding to an outside address
          RuleChangeAudit     Medium    rules or forwarding were created or changed in the window (who, when, from where)
          FailedSignIns       Medium    3 or more failed sign-ins in the window (High at 10 or more)
          LegacySignIn        Medium    a successful sign-in over a legacy protocol
          MultipleCountries   Medium    successful sign-ins from more than one country
          UserRisk            Critical/High/Medium   Entra ID Protection risk level high/medium/low
          AccountState        Info      sign-in already blocked

        Each source is read independently. A source that cannot be read becomes an Info row
        '(not checked)' with the reason, so a permission gap is visible rather than read as "clean".
        Only pilot-domain users can be investigated.

    .PARAMETER UserPrincipalName
        Users to investigate. Default: every user mailbox in the pilot domain.

    .PARAMETER Days
        Look-back window for audit and sign-in data. Default 7.

    .PARAMETER Redact
        Masks actors outside the pilot (for example the admin who created a rule), domain included,
        and shortens IP addresses.

    .PARAMETER IncludeCompliant
        Also return the Info rows for sources that found nothing.

    .EXAMPLE
        Find-KRSCompromiseIndicator | Sort-Object SeverityRank | Format-Table UserPrincipalName, Signal, Severity, Detail

    .EXAMPLE
        Find-KRSCompromiseIndicator -UserPrincipalName amara.okafor@contoso.com -Days 14 -Redact

        Two weeks of evidence for one user, shareable.

    .OUTPUTS
        PSCustomObject (KRSSecOps.CompromiseIndicator)

    .NOTES
        Graph: users, auditLogs/signIns (AuditLog.Read.All), identityProtection/riskyUsers (IdentityRiskyUser.Read.All).
        Exchange: mailbox and inbox rules, and the unified audit log (View-Only Audit Logs role).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string[]]$UserPrincipalName,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7,

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $config = Get-KRSActiveConfig
    if ($UserPrincipalName) {
        foreach ($upn in $UserPrincipalName) {
            if (-not (Test-KRSPilotScope -UserPrincipalName $upn -PilotDomain $config.PilotDomain)) {
                throw "Investigations are limited to the pilot domain @$($config.PilotDomain): '$upn' is outside it."
            }
        }
        $targets = $UserPrincipalName
    }
    else {
        $targets = @(Invoke-KRSExoCommand -Name 'Get-Mailbox' -Parameters @{ RecipientTypeDetails = 'UserMailbox'; ResultSize = 'Unlimited' }) |
            ForEach-Object { [string](Get-KRSValue -InputObject $_ -Name 'UserPrincipalName') } |
            Where-Object { Test-KRSPilotScope -UserPrincipalName $_ -PilotDomain $config.PilotDomain }
    }
    Write-KRSLog -Action 'Investigate' -Target ($targets -join ',') -Message "Days=$Days"

    $accepted = Get-KRSAcceptedDomainSet
    $maskActors = [bool]$Redact

    foreach ($upn in @($targets)) {
        $rows = [System.Collections.Generic.List[object]]::new()
        $add = {
            param($Signal, $Detail, $Severity, $Source, $Observed)
            $rows.Add([pscustomobject]@{
                    PSTypeName        = 'KRSSecOps.CompromiseIndicator'
                    UserPrincipalName = $upn
                    Signal            = $Signal
                    Detail            = $Detail
                    Severity          = $Severity
                    SeverityRank      = Get-KRSSeverityRank -Severity $Severity
                    Source            = $Source
                    ObservedUtc       = $Observed
                })
        }
        $notChecked = { param($Signal, $Source, $ErrorRecord) & $add $Signal "(not checked) $($ErrorRecord.Exception.Message)" 'Info' $Source $null }

        # Mailbox: rules and forwarding
        try {
            $allRules = @(Get-KRSExternalInboxRule -UserPrincipalName $upn -AcceptedDomain $accepted)
            $rules = @($allRules | Where-Object Enabled)
            foreach ($rule in $rules) { & $add 'ExternalInboxRule' "Rule '$($rule.Name)' forwards to $($rule.Targets)" 'High' 'Exchange' $null }
            # A disabled rule is contained but is still evidence: keep it visible until a person deletes it
            foreach ($rule in @($allRules | Where-Object { -not $_.Enabled })) {
                & $add 'ExternalInboxRule' "Rule '$($rule.Name)' forwards to $($rule.Targets) (disabled: contained, awaiting review)" 'Low' 'Exchange' $null
            }
            if (-not $allRules) { & $add 'ExternalInboxRule' 'No rule forwards outside' 'Info' 'Exchange' $null }

            $mailbox = Invoke-KRSExoCommand -Name 'Get-Mailbox' -Parameters @{ Identity = $upn }
            $forward = @(Get-KRSSmtpAddress -Value (Get-KRSValue -InputObject $mailbox -Name 'ForwardingSmtpAddress') |
                    Where-Object { Test-KRSExternalAddress -Address $_ -AcceptedDomain $accepted })
            if ($forward) { & $add 'ExternalForwarding' "Mailbox forwards to $($forward -join ', ')" 'High' 'Exchange' $null }
            else { & $add 'ExternalForwarding' 'No external mailbox forwarding' 'Info' 'Exchange' $null }
        }
        catch { & $notChecked 'ExternalInboxRule' 'Exchange' $_ }

        # Unified audit log: who created or changed rules and forwarding
        try {
            $events = @(Search-KRSMailboxAudit -UserPrincipalName $upn -Days $Days | Sort-Object TimeUtc -Descending)
            if ($events) {
                $latest = $events[0]
                $actor = if ($maskActors) { ConvertTo-KRSMaskedActor -Actor $latest.Actor -PilotDomain $config.PilotDomain } else { $latest.Actor }
                $from = if ($maskActors) { ConvertTo-KRSMaskedIp -IpAddress $latest.ClientIp } else { $latest.ClientIp }
                $what = if ($latest.Detail) { " ($($latest.Detail))" } else { '' }
                & $add 'RuleChangeAudit' "$($events.Count) rule/forwarding change(s); latest $($latest.Operation) by $actor from $from$what" 'Medium' 'AuditLog' $latest.TimeUtc
            }
            else { & $add 'RuleChangeAudit' "No rule or forwarding changes in $(Format-KRSDayCount -Days $Days)" 'Info' 'AuditLog' $null }
        }
        catch { & $notChecked 'RuleChangeAudit' 'AuditLog' $_ }

        # Directory account, sign-ins and risk
        try {
            $user = Get-KRSDirectoryUser -UserPrincipalName $upn
            $userId = [string](Get-KRSValue -InputObject $user -Name 'id')
            if ((Get-KRSValue -InputObject $user -Name 'accountEnabled') -eq $false) { & $add 'AccountState' 'Sign-in is blocked' 'Info' 'Directory' $null }

            try {
                $signIns = @(Get-KRSSignInEvent -UserId $userId -Days $Days)
                $failed = @($signIns | Where-Object Result -eq 'Failure')
                $good = @($signIns | Where-Object Result -eq 'Success')
                if ($failed.Count -ge 3) {
                    $severity = if ($failed.Count -ge 10) { 'High' } else { 'Medium' }
                    $reasons = ($failed | Group-Object FailureReason | Sort-Object Count -Descending | Select-Object -First 2 | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join '; '
                    & $add 'FailedSignIns' "$($failed.Count) failed sign-ins in $(Format-KRSDayCount -Days $Days) ($reasons)" $severity 'SignInLogs' ($failed | Sort-Object TimeUtc -Descending | Select-Object -First 1).TimeUtc
                }
                $legacy = @($good | Where-Object IsLegacy)
                if ($legacy) { & $add 'LegacySignIn' "Successful sign-in over $(($legacy.ClientApp | Sort-Object -Unique) -join ', ')" 'Medium' 'SignInLogs' $legacy[0].TimeUtc }
                $countries = @($good | Where-Object Country | Select-Object -ExpandProperty Country -Unique)
                if ($countries.Count -gt 1) { & $add 'MultipleCountries' "Successful sign-ins from $($countries -join ', ')" 'Medium' 'SignInLogs' $null }
                if ($failed.Count -lt 3 -and -not $legacy -and $countries.Count -le 1) {
                    & $add 'SignIns' "$($signIns.Count) sign-ins ($($failed.Count) failed) in $(Format-KRSDayCount -Days $Days), no pattern found" 'Info' 'SignInLogs' $null
                }
            }
            catch { & $notChecked 'SignIns' 'SignInLogs' $_ }

            try {
                $risk = Get-KRSUserRisk -UserId $userId
                $level = if ($risk -and $risk.RiskState -in 'atRisk', 'confirmedCompromised') { $risk.RiskLevel } else { 'none' }
                $severity = switch ($level) { 'high' { 'Critical' } 'medium' { 'High' } 'low' { 'Medium' } default { 'Info' } }
                $text = if ($severity -eq 'Info') { 'No active Entra ID Protection risk' } else { "Entra ID Protection: $level risk ($($risk.RiskState), $($risk.RiskDetail))" }
                & $add 'UserRisk' $text $severity 'IdentityProtection' $(if ($risk) { $risk.UpdatedUtc } else { $null })
            }
            catch { & $notChecked 'UserRisk' 'IdentityProtection' $_ }
        }
        catch { & $notChecked 'SignIns' 'Directory' $_ }

        $rows | Where-Object { $IncludeCompliant -or $_.Severity -ne 'Info' -or $_.Detail -like '(not checked)*' }
    }
}
