function Get-KRSExchangeTenantRisk {
    <#
    .SYNOPSIS
        Checks organisation-wide Exchange Online settings that enable data exfiltration or weak authentication.

    .DESCRIPTION
        Read-only (View-Only Configuration role). One row per finding:

          AutoForwarding   High    an outbound spam policy allows automatic external forwarding (On)
          RemoteDomain     Medium  a remote domain allows automatic forwarding
          TransportRule    Medium  an enabled transport rule redirects, copies or BCCs mail
          SmtpAuth         Medium  SMTP AUTH is enabled for the organisation
          Dkim             Medium  DKIM signing is not enabled for a custom domain
          MailboxAudit     High    mailbox auditing is turned off for the organisation

        A setting that cannot be read (for example a command missing from the app's role) is reported as
        an Info row with the reason, so a permission gap is visible instead of silently passing.

    .PARAMETER IncludeCompliant
        Also return the settings that passed (Severity Info).

    .PARAMETER Redact
        Masks domain, rule and policy names that are not the pilot's, such as other tenants' domains in a
        shared tenant. Generic values like '*', 'Default' and '(organisation)' stay readable.

    .EXAMPLE
        Get-KRSExchangeTenantRisk | Format-Table Area, Subject, Finding, Severity

    .EXAMPLE
        Get-KRSExchangeTenantRisk -Redact | Format-Table Area, Subject, Finding, Severity

        Shareable output: anything not belonging to the pilot domain appears as a stable masked name.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ExchangeTenantRisk)

    .NOTES
        Read-only. Commands used: Get-HostedOutboundSpamFilterPolicy, Get-RemoteDomain, Get-TransportRule,
        and for SMTP AUTH, DKIM and auditing: Get-TransportConfig, Get-DkimSigningConfig, Get-OrganizationConfig.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [switch]$IncludeCompliant,

        [Parameter()]
        [switch]$Redact
    )

    $config = Get-KRSActiveConfig
    $maskNames = [bool]$Redact
    Write-KRSLog -Action 'Read' -Target 'exchange/organisation settings'

    $rows = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($Area, $Subject, $Finding, $Severity)
        if ($maskNames) { $Subject = ConvertTo-KRSMaskedName -Value $Subject -Kind $Area -PilotDomain $config.PilotDomain }
        $rows.Add([pscustomobject]@{
                PSTypeName   = 'KRSSecOps.ExchangeTenantRisk'
                Area         = $Area
                Subject      = $Subject
                Finding      = $Finding
                Severity     = $Severity
                SeverityRank = Get-KRSSeverityRank -Severity $Severity
            })
    }
    $read = {
        param($Area, $Command)
        try { @(Invoke-KRSExoCommand -Name $Command) }
        catch {
            & $add $Area '(not checked)' "Could not run $($Command): $($_.Exception.Message)" 'Info'
            $null
        }
    }

    foreach ($policy in @(& $read 'AutoForwarding' 'Get-HostedOutboundSpamFilterPolicy')) {
        if ($null -eq $policy) { continue }
        $name = [string](Get-KRSValue -InputObject $policy -Name 'Name')
        $mode = [string](Get-KRSValue -InputObject $policy -Name 'AutoForwardingMode')
        if ($mode -eq 'On') { & $add 'AutoForwarding' $name 'Outbound policy allows automatic forwarding to external recipients' 'High' }
        else { & $add 'AutoForwarding' $name "Automatic external forwarding: $mode" 'Info' }
    }

    foreach ($domain in @(& $read 'RemoteDomain' 'Get-RemoteDomain')) {
        if ($null -eq $domain) { continue }
        $name = [string](Get-KRSValue -InputObject $domain -Name 'DomainName')
        if ([bool](Get-KRSValue -InputObject $domain -Name 'AutoForwardEnabled')) {
            & $add 'RemoteDomain' $name 'Remote domain allows automatic forwarding' 'Medium'
        }
        else { & $add 'RemoteDomain' $name 'Automatic forwarding blocked' 'Info' }
    }

    foreach ($rule in @(& $read 'TransportRule' 'Get-TransportRule')) {
        if ($null -eq $rule) { continue }
        if ([string](Get-KRSValue -InputObject $rule -Name 'State') -ne 'Enabled') { continue }
        $actions = foreach ($property in 'RedirectMessageTo', 'BlindCopyTo', 'CopyTo', 'AddToRecipients') {
            if (@(Get-KRSValue -InputObject $rule -Name $property) | Where-Object { $_ }) { $property }
        }
        $name = [string](Get-KRSValue -InputObject $rule -Name 'Name')
        if ($actions) { & $add 'TransportRule' $name "Enabled rule sends mail to extra recipients ($($actions -join ', ')): confirm it is approved" 'Medium' }
        else { & $add 'TransportRule' $name 'No redirect or copy actions' 'Info' }
    }

    foreach ($transport in @(& $read 'SmtpAuth' 'Get-TransportConfig')) {
        if ($null -eq $transport) { continue }
        if ((Get-KRSValue -InputObject $transport -Name 'SmtpClientAuthenticationDisabled') -eq $true) {
            & $add 'SmtpAuth' '(organisation)' 'SMTP AUTH disabled for the organisation' 'Info'
        }
        else { & $add 'SmtpAuth' '(organisation)' 'SMTP AUTH enabled for the organisation; allow it only per mailbox where needed' 'Medium' }
    }

    foreach ($dkim in @(& $read 'Dkim' 'Get-DkimSigningConfig')) {
        if ($null -eq $dkim) { continue }
        $name = [string](Get-KRSValue -InputObject $dkim -Name 'Domain')
        if ($name -like '*.onmicrosoft.com') { continue }
        if ([bool](Get-KRSValue -InputObject $dkim -Name 'Enabled')) { & $add 'Dkim' $name 'DKIM signing enabled' 'Info' }
        else { & $add 'Dkim' $name 'DKIM signing not enabled: receivers cannot verify mail from this domain' 'Medium' }
    }

    foreach ($organisation in @(& $read 'MailboxAudit' 'Get-OrganizationConfig')) {
        if ($null -eq $organisation) { continue }
        if ([bool](Get-KRSValue -InputObject $organisation -Name 'AuditDisabled')) {
            & $add 'MailboxAudit' '(organisation)' 'Mailbox auditing is turned off for the whole organisation' 'High'
        }
        else { & $add 'MailboxAudit' '(organisation)' 'Mailbox auditing on by default' 'Info' }
    }

    $rows | Where-Object { $IncludeCompliant -or $_.Severity -ne 'Info' -or $_.Subject -eq '(not checked)' }
}
