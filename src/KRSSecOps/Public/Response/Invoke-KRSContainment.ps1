function Invoke-KRSContainment {
    <#
    .SYNOPSIS
        Contains a suspected compromised pilot account: blocks sign-in, revokes sessions and disables inbox rules that forward outside.

    .DESCRIPTION
        Approval-gated incident response for one account. Before anything changes:
          - the account must be in the pilot domain (Assert-KRSPilotScope);
          - a ticket ID and a named approver are required, and the approver cannot be the person running it;
          - every action goes through ShouldProcess (ConfirmImpact High), so -WhatIf previews and the default prompts.

        Actions, in this order:
          BlockSignIn                 Graph: accountEnabled = false
          RevokeSessions              Graph: revokeSignInSessions (refresh tokens and session cookies)
          DisableExternalInboxRules   Exchange: Disable-InboxRule for each enabled rule that forwards outside

        The platform enforces the same boundary: in Entra the app holds User Administrator only for the
        'KRS-SecOps Pilot Containment' administrative unit, and in Exchange its role is scoped to tagged
        pilot mailboxes. A containment record (before state, each action and its result) is written as JSON
        for the incident report and for Undo-KRSContainment. Rules are disabled, never deleted: they are evidence.

    .PARAMETER UserPrincipalName
        The account to contain. Must be in the pilot domain.

    .PARAMETER Action
        Actions to take. Default: all three.

    .PARAMETER TicketId
        Incident or change ticket, for example INC-1042. Recorded with every action.

    .PARAMETER ApprovedBy
        Who approved the containment. Must be a different person from the operator (two-person rule).

    .EXAMPLE
        Invoke-KRSContainment -UserPrincipalName amara.okafor@contoso.com -TicketId INC-1042 -ApprovedBy 'J. Mentor' -WhatIf

        Shows every containment step without making it.

    .EXAMPLE
        Invoke-KRSContainment -UserPrincipalName amara.okafor@contoso.com -Action DisableExternalInboxRules -TicketId INC-1042 -ApprovedBy 'J. Mentor' -Confirm:$false

        Disables only the forwarding rules, without prompting.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ContainmentAction)
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateSet('BlockSignIn', 'RevokeSessions', 'DisableExternalInboxRules')]
        [string[]]$Action = @('BlockSignIn', 'RevokeSessions', 'DisableExternalInboxRules'),

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z]{2,10}-\d{1,8}$')]
        [string]$TicketId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApprovedBy
    )

    $null = Get-KRSActiveConfig
    $operator = [Environment]::UserName
    if ($ApprovedBy.Trim() -eq $operator -or $ApprovedBy.Trim() -like "$operator@*") {
        throw "Two-person rule: the approver ('$ApprovedBy') cannot be the operator running containment ('$operator')."
    }
    Assert-KRSPilotScope -UserPrincipalName $UserPrincipalName

    # Before state
    $user = Get-KRSDirectoryUser -UserPrincipalName $UserPrincipalName
    $userId = [string](Get-KRSValue -InputObject $user -Name 'id')
    $wasEnabled = [bool](Get-KRSValue -InputObject $user -Name 'accountEnabled')
    $rules = @()
    if ('DisableExternalInboxRules' -in $Action) {
        $rules = @(Get-KRSExternalInboxRule -UserPrincipalName $UserPrincipalName -AcceptedDomain (Get-KRSAcceptedDomainSet) | Where-Object Enabled)
    }

    $started = [datetime]::UtcNow
    $results = [System.Collections.Generic.List[object]]::new()
    $record = {
        param($Name, $Target, $Result, $ErrorText)
        $results.Add([pscustomobject]@{
                PSTypeName        = 'KRSSecOps.ContainmentAction'
                TicketId          = $TicketId
                UserPrincipalName = $UserPrincipalName
                Action            = $Name
                Target            = $Target
                Result            = $Result
                Error             = $ErrorText
                TimeUtc           = [datetime]::UtcNow
                RecordPath        = $null
            })
    }
    $run = {
        param($Name, $Target, $Description, [scriptblock]$Step)
        if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "[$TicketId] $Description")) {
            Write-KRSLog -Level Change -Action $Name -Target $UserPrincipalName -Result WhatIf -Message "$TicketId $Description"
            & $record $Name $Target 'WhatIf' $null
            return
        }
        try {
            & $Step
            Write-KRSLog -Level Change -Action $Name -Target $UserPrincipalName -Message "$TicketId approved by $ApprovedBy`: $Description"
            & $record $Name $Target 'Done' $null
        }
        catch {
            $message = $_.Exception.Message
            Write-KRSLog -Level Error -Action $Name -Target $UserPrincipalName -Result Failure -Message "$TicketId $message"
            Write-Warning "$Name failed for $UserPrincipalName`: $message"
            & $record $Name $Target 'Failed' $message
        }
    }

    if ('BlockSignIn' -in $Action) {
        if (-not $wasEnabled) { & $record 'BlockSignIn' 'accountEnabled' 'AlreadyBlocked' $null }
        else {
            & $run 'BlockSignIn' 'accountEnabled' 'Block sign-in (accountEnabled = false)' {
                $null = Invoke-KRSGraphRequest -Method PATCH -Uri "users/$userId" -Body @{ accountEnabled = $false } -MaxRetries 2
            }
        }
    }
    if ('RevokeSessions' -in $Action) {
        & $run 'RevokeSessions' 'sign-in sessions' 'Revoke all refresh tokens and session cookies' {
            $null = Invoke-KRSGraphRequest -Method POST -Uri "users/$userId/revokeSignInSessions" -MaxRetries 2
        }
    }
    if ('DisableExternalInboxRules' -in $Action) {
        if (-not $rules) { & $record 'DisableExternalInboxRules' '(none found)' 'NothingToDo' $null }
        foreach ($rule in $rules) {
            $ruleId = $rule.RuleIdentity
            & $run 'DisableExternalInboxRules' "$($rule.Name) -> $($rule.Targets)" "Disable inbox rule '$($rule.Name)' (forwards to $($rule.Targets))" {
                $null = Invoke-KRSExoCommand -Name 'Disable-InboxRule' -Parameters @{ Mailbox = $UserPrincipalName; Identity = $ruleId; Confirm = $false }
            }
        }
    }

    # Containment record: only when something actually ran, so a -WhatIf preview leaves no record
    $path = $null
    if (@($results | Where-Object Result -in 'Done', 'Failed').Count -gt 0) {
        $folder = Get-KRSResponseFolder
        $null = New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false -Confirm:$false
        $path = Join-Path $folder ('{0}-{1}-{2}.json' -f $TicketId, ($UserPrincipalName -split '@')[0], $started.ToString('yyyyMMdd-HHmmss'))
        [ordered]@{
            schemaVersion   = 1
            ticketId        = $TicketId
            approvedBy      = $ApprovedBy
            operator        = $operator
            correlationId   = $script:KRSCorrelationId
            startedUtc      = $started.ToString('o')
            userPrincipalName = $UserPrincipalName
            userId          = $userId
            before          = [ordered]@{ accountEnabled = $wasEnabled; externalInboxRules = @($rules) }
            actions         = @($results)
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding utf8 -WhatIf:$false -Confirm:$false
    }
    foreach ($row in $results) { $row.RecordPath = $path; $row }
}
