function Get-KRSMailboxSecurityState {
    <#
    .SYNOPSIS
        Checks mailboxes against the toolkit's mailbox security baseline.

    .DESCRIPTION
        One row per mailbox and setting:

          Forwarding        High    forwards to an external address (mailbox-level forwarding)
                            Medium  forwards to an internal recipient
          InboxRule         High    an enabled inbox rule forwards or redirects outside the organisation
          SmtpAuth          High    SMTP AUTH explicitly enabled on the mailbox
                            Medium  not set on the mailbox, and enabled for the organisation
          Pop / Imap        Medium  legacy protocol enabled
          Audit             Medium  mailbox auditing disabled

        Remediable = True marks settings Set-KRSMailboxBaseline can fix. Inbox rules and auditing are
        report-only: the app is deliberately not allowed to delete rules or change audit settings.

    .PARAMETER Scope
        Pilot (default): user mailboxes in the pilot domain. Tenant: every user mailbox (read-only).

    .PARAMETER Identity
        Check only these mailboxes (UPN or primary SMTP address). Overrides Scope.

    .PARAMETER Redact
        Masks mailboxes outside the pilot. Use it for anything you will share.

    .PARAMETER IncludeCompliant
        Also return settings that meet the baseline (Severity Info).

    .EXAMPLE
        Get-KRSMailboxSecurityState | Format-Table UserPrincipalName, Setting, Current, Severity, Remediable

    .EXAMPLE
        Get-KRSMailboxSecurityState -Scope Tenant -Redact | Where-Object Severity -eq 'High'

        External forwarding and risky inbox rules anywhere in the tenant, with non-pilot mailboxes masked.

    .OUTPUTS
        PSCustomObject (KRSSecOps.MailboxSecurityState)

    .NOTES
        Commands: Get-Mailbox, Get-CASMailbox, Get-InboxRule, Get-AcceptedDomain, Get-TransportConfig.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateSet('Pilot', 'Tenant')]
        [string]$Scope = 'Pilot',

        [Parameter()]
        [string[]]$Identity,

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $config = Get-KRSActiveConfig
    Write-KRSLog -Action 'Read' -Target 'mailboxes' -Message "Scope=$Scope"

    $mailboxes = if ($Identity) {
        foreach ($id in $Identity) { Invoke-KRSExoCommand -Name 'Get-Mailbox' -Parameters @{ Identity = $id } }
    }
    else {
        @(Invoke-KRSExoCommand -Name 'Get-Mailbox' -Parameters @{ RecipientTypeDetails = 'UserMailbox'; ResultSize = 'Unlimited' }) |
            Where-Object { $Scope -eq 'Tenant' -or (Test-KRSPilotScope -UserPrincipalName ([string](Get-KRSValue -InputObject $_ -Name 'UserPrincipalName')) -PilotDomain $config.PilotDomain) }
    }

    $accepted = Get-KRSAcceptedDomainSet
    $orgSmtpAuthDisabled = $null
    try {
        $orgSmtpAuthDisabled = Get-KRSValue -InputObject (Invoke-KRSExoCommand -Name 'Get-TransportConfig') -Name 'SmtpClientAuthenticationDisabled'
    }
    catch {
        Write-Verbose "Organisation SMTP AUTH setting unavailable: $($_.Exception.Message)"
    }

    foreach ($mailbox in @($mailboxes)) {
        if ($null -eq $mailbox) { continue }
        $upn = [string](Get-KRSValue -InputObject $mailbox -Name 'UserPrincipalName')
        $identityInfo = Format-KRSIdentity -UserPrincipalName $upn -DisplayName (Get-KRSValue -InputObject $mailbox -Name 'DisplayName') -Redact:$Redact
        $rows = [System.Collections.Generic.List[object]]::new()
        $add = {
            param($Setting, $Current, $Desired, $Severity, $Finding, $Remediable)
            $rows.Add([pscustomobject]@{
                    PSTypeName        = 'KRSSecOps.MailboxSecurityState'
                    UserPrincipalName = $identityInfo.UserPrincipalName
                    DisplayName       = $identityInfo.DisplayName
                    InPilot           = $identityInfo.InPilot
                    Setting           = $Setting
                    Current           = $Current
                    Desired           = $Desired
                    Finding           = $Finding
                    Severity          = $Severity
                    SeverityRank      = Get-KRSSeverityRank -Severity $Severity
                    Remediable        = [bool]$Remediable
                })
        }

        # Mailbox-level forwarding
        $smtpTargets = @(Get-KRSSmtpAddress -Value (Get-KRSValue -InputObject $mailbox -Name 'ForwardingSmtpAddress'))
        $recipientTarget = [string](Get-KRSValue -InputObject $mailbox -Name 'ForwardingAddress')
        $external = @($smtpTargets | Where-Object { Test-KRSExternalAddress -Address $_ -AcceptedDomain $accepted })
        if ($external) {
            & $add 'Forwarding' ($external -join ', ') 'None' 'High' "Forwards mail outside the organisation to $($external -join ', ')" $true
        }
        elseif ($smtpTargets -or $recipientTarget) {
            $target = (@($smtpTargets) + @($recipientTarget) | Where-Object { $_ }) -join ', '
            & $add 'Forwarding' $target 'None' 'Medium' "Forwards mail to $target" $true
        }
        else { & $add 'Forwarding' 'None' 'None' 'Info' 'OK' $true }

        # Auditing (report only)
        $audit = Get-KRSValue -InputObject $mailbox -Name 'AuditEnabled'
        if ($audit -eq $false) { & $add 'Audit' 'Disabled' 'Enabled' 'Medium' 'Mailbox auditing is disabled' $false }
        else { & $add 'Audit' 'Enabled' 'Enabled' 'Info' 'OK' $false }

        # Client access protocols
        $cas = Invoke-KRSExoCommand -Name 'Get-CASMailbox' -Parameters @{ Identity = $upn }
        foreach ($protocol in @(@{ Setting = 'Pop'; Property = 'PopEnabled' }, @{ Setting = 'Imap'; Property = 'ImapEnabled' })) {
            if ([bool](Get-KRSValue -InputObject $cas -Name $protocol.Property)) {
                & $add $protocol.Setting 'Enabled' 'Disabled' 'Medium' "$($protocol.Setting.ToUpperInvariant()) is enabled (legacy protocol)" $true
            }
            else { & $add $protocol.Setting 'Disabled' 'Disabled' 'Info' 'OK' $true }
        }

        $smtpAuth = Get-KRSValue -InputObject $cas -Name 'SmtpClientAuthenticationDisabled'
        if ($smtpAuth -eq $false) {
            & $add 'SmtpAuth' 'Enabled (mailbox)' 'Disabled' 'High' 'SMTP AUTH explicitly enabled on this mailbox' $true
        }
        elseif ($null -eq $smtpAuth -and $orgSmtpAuthDisabled -ne $true) {
            $orgText = if ($null -eq $orgSmtpAuthDisabled) { 'unknown' } else { 'enabled' }
            & $add 'SmtpAuth' "Inherited (organisation: $orgText)" 'Disabled' 'Medium' "SMTP AUTH not disabled on the mailbox; organisation setting is $orgText" $true
        }
        else { & $add 'SmtpAuth' 'Disabled' 'Disabled' 'Info' 'OK' $true }

        # Inbox rules that forward or redirect outside the organisation (report only)
        $riskyRules = @()
        foreach ($rule in @(Invoke-KRSExoCommand -Name 'Get-InboxRule' -Parameters @{ Mailbox = $upn })) {
            if ($null -eq $rule -or -not [bool](Get-KRSValue -InputObject $rule -Name 'Enabled')) { continue }
            $targets = foreach ($property in 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo') {
                Get-KRSSmtpAddress -Value (Get-KRSValue -InputObject $rule -Name $property)
            }
            $outside = @($targets | Where-Object { $_ -and (Test-KRSExternalAddress -Address $_ -AcceptedDomain $accepted) } | Sort-Object -Unique)
            if ($outside) {
                $riskyRules += $true
                $ruleName = [string](Get-KRSValue -InputObject $rule -Name 'Name')
                & $add 'InboxRule' "$ruleName -> $($outside -join ', ')" 'No external forwarding rules' 'High' "Inbox rule '$ruleName' forwards outside the organisation" $false
            }
        }
        if (-not $riskyRules) { & $add 'InboxRule' 'None' 'No external forwarding rules' 'Info' 'OK' $false }

        $rows | Where-Object { $IncludeCompliant -or $_.Severity -ne 'Info' }
    }
}
