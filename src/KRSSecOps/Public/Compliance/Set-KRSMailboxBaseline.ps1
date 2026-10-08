function Set-KRSMailboxBaseline {
    <#
    .SYNOPSIS
        Brings pilot mailboxes to the mailbox security baseline: no forwarding, no POP or IMAP, SMTP AUTH off.

    .DESCRIPTION
        Idempotent desired-state enforcement. For each target mailbox it reads the current settings,
        changes only what differs from the baseline, and returns one row per setting with the before
        and after values:

          Forwarding  ForwardingSmtpAddress and ForwardingAddress cleared, DeliverToMailboxAndForward off
          Pop, Imap   disabled
          SmtpAuth    SmtpClientAuthenticationDisabled = True on the mailbox

        Two independent boundaries protect the tenant:
          1. In code: every target must be in the pilot domain (Assert-KRSPilotScope), checked before any change.
          2. In Exchange: the app's role group can only write to mailboxes tagged for the pilot, and only
             these parameters. A bug here still cannot reach any other mailbox or setting.

        Supports -WhatIf and -Confirm. Inbox rules and auditing are reported by Get-KRSMailboxSecurityState
        but never changed here.

    .PARAMETER Identity
        Mailboxes to enforce (UPN). Default: every user mailbox in the pilot domain.

    .PARAMETER Setting
        Limit enforcement to these settings. Default: all four.

    .EXAMPLE
        Set-KRSMailboxBaseline -WhatIf

        Shows every change the baseline would make to pilot mailboxes, without making it.

    .EXAMPLE
        Set-KRSMailboxBaseline -Identity marcus.bennett@contoso.com -Setting Forwarding -Confirm:$false

        Clears forwarding on one pilot mailbox without prompting.

    .OUTPUTS
        PSCustomObject (KRSSecOps.MailboxBaselineChange)

    .NOTES
        Commands: Get-Mailbox, Get-CASMailbox, Set-Mailbox, Set-CASMailbox.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string[]]$Identity,

        [Parameter()]
        [ValidateSet('Forwarding', 'Pop', 'Imap', 'SmtpAuth')]
        [string[]]$Setting = @('Forwarding', 'Pop', 'Imap', 'SmtpAuth')
    )

    $config = Get-KRSActiveConfig

    if ($Identity) {
        Assert-KRSPilotScope -UserPrincipalName $Identity
        $mailboxes = foreach ($id in $Identity) { Invoke-KRSExoCommand -Name 'Get-Mailbox' -Parameters @{ Identity = $id } }
    }
    else {
        $mailboxes = @(Invoke-KRSExoCommand -Name 'Get-Mailbox' -Parameters @{ RecipientTypeDetails = 'UserMailbox'; ResultSize = 'Unlimited' }) |
            Where-Object { Test-KRSPilotScope -UserPrincipalName ([string](Get-KRSValue -InputObject $_ -Name 'UserPrincipalName')) -PilotDomain $config.PilotDomain }
    }

    foreach ($mailbox in @($mailboxes)) {
        if ($null -eq $mailbox) { continue }
        $upn = [string](Get-KRSValue -InputObject $mailbox -Name 'UserPrincipalName')
        Assert-KRSPilotScope -UserPrincipalName $upn

        $cas = Invoke-KRSExoCommand -Name 'Get-CASMailbox' -Parameters @{ Identity = $upn }
        $plan = [System.Collections.Generic.List[object]]::new()

        if ('Forwarding' -in $Setting) {
            $smtp = [string](Get-KRSValue -InputObject $mailbox -Name 'ForwardingSmtpAddress')
            $address = [string](Get-KRSValue -InputObject $mailbox -Name 'ForwardingAddress')
            $deliver = [bool](Get-KRSValue -InputObject $mailbox -Name 'DeliverToMailboxAndForward')
            $before = (@(Get-KRSSmtpAddress -Value $smtp) + @($address) | Where-Object { $_ }) -join ', '
            if ($smtp -or $address -or $deliver) {
                $parameters = @{ Identity = $upn; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false }
                $was = if ($before) { $before } else { 'DeliverToMailboxAndForward only' }
                $plan.Add(@{ Setting = 'Forwarding'; Before = $was; After = 'None'; Command = 'Set-Mailbox'; Parameters = $parameters })
            }
            else { $plan.Add(@{ Setting = 'Forwarding'; Before = 'None'; After = 'None'; Command = $null }) }
        }
        foreach ($protocol in @(@{ Setting = 'Pop'; Property = 'PopEnabled' }, @{ Setting = 'Imap'; Property = 'ImapEnabled' })) {
            if ($protocol.Setting -notin $Setting) { continue }
            if ([bool](Get-KRSValue -InputObject $cas -Name $protocol.Property)) {
                $parameters = @{ Identity = $upn }
                $parameters[$protocol.Property] = $false
                $plan.Add(@{ Setting = $protocol.Setting; Before = 'Enabled'; After = 'Disabled'; Command = 'Set-CASMailbox'; Parameters = $parameters })
            }
            else { $plan.Add(@{ Setting = $protocol.Setting; Before = 'Disabled'; After = 'Disabled'; Command = $null }) }
        }
        if ('SmtpAuth' -in $Setting) {
            $smtpAuth = Get-KRSValue -InputObject $cas -Name 'SmtpClientAuthenticationDisabled'
            if ($smtpAuth -ne $true) {
                $was = if ($null -eq $smtpAuth) { 'Inherited' } else { 'Enabled' }
                $parameters = @{ Identity = $upn; SmtpClientAuthenticationDisabled = $true }
                $plan.Add(@{ Setting = 'SmtpAuth'; Before = $was; After = 'Disabled'; Command = 'Set-CASMailbox'; Parameters = $parameters })
            }
            else { $plan.Add(@{ Setting = 'SmtpAuth'; Before = 'Disabled'; After = 'Disabled'; Command = $null }) }
        }

        foreach ($step in $plan) {
            $result = 'AlreadyCompliant'
            $errorText = $null
            if ($step.Command) {
                if ($PSCmdlet.ShouldProcess($upn, "$($step.Setting): $($step.Before) -> $($step.After)")) {
                    try {
                        $null = Invoke-KRSExoCommand -Name $step.Command -Parameters $step.Parameters
                        $result = 'Changed'
                        Write-KRSLog -Level Change -Action "Set$($step.Setting)" -Target $upn -Message "$($step.Before) -> $($step.After)"
                    }
                    catch {
                        $result = 'Failed'
                        $errorText = $_.Exception.Message
                        Write-KRSLog -Level Error -Action "Set$($step.Setting)" -Target $upn -Result Failure -Message $errorText
                        Write-Warning "$upn $($step.Setting): $errorText"
                    }
                }
                else {
                    $result = 'WhatIf'
                    Write-KRSLog -Level Change -Action "Set$($step.Setting)" -Target $upn -Result WhatIf -Message "$($step.Before) -> $($step.After)"
                }
            }
            [pscustomobject]@{
                PSTypeName        = 'KRSSecOps.MailboxBaselineChange'
                UserPrincipalName = $upn
                Setting           = $step.Setting
                Before            = $step.Before
                After             = if ($result -in 'Changed', 'AlreadyCompliant') { $step.After } else { $step.Before }
                Result            = $result
                Error             = $errorText
            }
        }
    }
}
