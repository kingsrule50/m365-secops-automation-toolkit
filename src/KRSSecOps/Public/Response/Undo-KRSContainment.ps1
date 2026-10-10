function Undo-KRSContainment {
    <#
    .SYNOPSIS
        Restores sign-in for an account contained by Invoke-KRSContainment, using its containment record.

    .DESCRIPTION
        Reads the JSON containment record and reverses only what that record shows was done:
          - sign-in is re-enabled only if containment blocked it and the account was enabled before;
          - disabled inbox rules stay disabled unless -IncludeInboxRules is used, because a rule that
            forwarded mail outside should be reviewed (and normally deleted by a person), not restored.
        Revoked sessions cannot be undone; the user simply signs in again.

        Like containment, recovery needs a ticket and an approver who is not the operator, and goes
        through ShouldProcess (ConfirmImpact High). An undo record is written next to the original.
        Recover only after the cause is fixed, for example after a password reset and MFA re-registration.

    .PARAMETER RecordPath
        Containment record written by Invoke-KRSContainment.

    .PARAMETER ApprovedBy
        Who approved the recovery. Must be a different person from the operator.

    .PARAMETER IncludeInboxRules
        Also re-enable the inbox rules containment disabled. Normally left off.

    .EXAMPLE
        Undo-KRSContainment -RecordPath $record -ApprovedBy 'J. Mentor' -WhatIf

    .EXAMPLE
        Undo-KRSContainment -RecordPath $record -ApprovedBy 'J. Mentor' -Confirm:$false

        Re-enables sign-in after the password reset; the forwarding rule stays disabled.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ContainmentAction)
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$RecordPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApprovedBy,

        [Parameter()]
        [switch]$IncludeInboxRules
    )

    $null = Get-KRSActiveConfig
    $operator = [Environment]::UserName
    if ($ApprovedBy.Trim() -eq $operator -or $ApprovedBy.Trim() -like "$operator@*") {
        throw "Two-person rule: the approver ('$ApprovedBy') cannot be the operator ('$operator')."
    }

    $containment = Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json
    $upn = [string]$containment.userPrincipalName
    $ticket = [string]$containment.ticketId
    Assert-KRSPilotScope -UserPrincipalName $upn
    $done = @($containment.actions | Where-Object { $_.Result -eq 'Done' })

    $results = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($Name, $Target, $Result, $ErrorText)
        $results.Add([pscustomobject]@{
                PSTypeName        = 'KRSSecOps.ContainmentAction'
                TicketId          = $ticket
                UserPrincipalName = $upn
                Action            = $Name
                Target            = $Target
                Result            = $Result
                Error             = $ErrorText
                TimeUtc           = [datetime]::UtcNow
                RecordPath        = $null
            })
    }

    if (($done | Where-Object Action -eq 'BlockSignIn') -and [bool]$containment.before.accountEnabled) {
        if ($PSCmdlet.ShouldProcess($upn, "[$ticket] Re-enable sign-in (accountEnabled = true)")) {
            try {
                $null = Invoke-KRSGraphRequest -Method PATCH -Uri "users/$($containment.userId)" -Body @{ accountEnabled = $true } -MaxRetries 2
                Write-KRSLog -Level Change -Action 'RestoreSignIn' -Target $upn -Message "$ticket approved by $ApprovedBy"
                & $add 'RestoreSignIn' 'accountEnabled' 'Done' $null
            }
            catch {
                Write-KRSLog -Level Error -Action 'RestoreSignIn' -Target $upn -Result Failure -Message $_.Exception.Message
                & $add 'RestoreSignIn' 'accountEnabled' 'Failed' $_.Exception.Message
            }
        }
        else { & $add 'RestoreSignIn' 'accountEnabled' 'WhatIf' $null }
    }
    else { & $add 'RestoreSignIn' 'accountEnabled' 'NotNeeded' $null }

    foreach ($rule in @($containment.before.externalInboxRules | Where-Object { $_ })) {
        $wasDisabled = $done | Where-Object { $_.Action -eq 'DisableExternalInboxRules' -and $_.Target -like "$($rule.Name) ->*" }
        if (-not $wasDisabled) { continue }
        if (-not $IncludeInboxRules) { & $add 'RestoreInboxRule' $rule.Name 'KeptDisabled' $null; continue }
        if ($PSCmdlet.ShouldProcess($upn, "[$ticket] Re-enable inbox rule '$($rule.Name)'")) {
            try {
                $null = Invoke-KRSExoCommand -Name 'Enable-InboxRule' -Parameters @{ Mailbox = $upn; Identity = [string]$rule.RuleIdentity; Confirm = $false }
                Write-KRSLog -Level Change -Action 'RestoreInboxRule' -Target $upn -Message "$ticket $($rule.Name)"
                & $add 'RestoreInboxRule' $rule.Name 'Done' $null
            }
            catch { & $add 'RestoreInboxRule' $rule.Name 'Failed' $_.Exception.Message }
        }
        else { & $add 'RestoreInboxRule' $rule.Name 'WhatIf' $null }
    }

    $path = $null
    if (@($results | Where-Object Result -in 'Done', 'Failed').Count -gt 0) {
        $path = $RecordPath -replace '\.json$', ('-undo-{0}.json' -f [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
        [ordered]@{
            schemaVersion = 1
            undoOf        = (Split-Path -Path $RecordPath -Leaf)
            ticketId      = $ticket
            approvedBy    = $ApprovedBy
            operator      = $operator
            correlationId = $script:KRSCorrelationId
            actions       = @($results)
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding utf8 -WhatIf:$false -Confirm:$false
    }
    foreach ($row in $results) { $row.RecordPath = $path; $row }
}
