function Invoke-KRSIdentityAudit {
    <#
    .SYNOPSIS
        Runs every Part 1 identity check and writes one evidence folder.

    .DESCRIPTION
        Runs the MFA, stale account, privileged role, guest, app credential and Conditional Access
        checks. Each check runs on its own: if one fails (for example a missing permission), the
        failure is recorded and the others still run.

        Writes to <ReportPath>/IdentityAudit-<timestamp>/:
          <Check>.csv     full inventory for each check (findings and Info rows)
          findings.csv    every finding across checks, most severe first
          summary.json    counts by check and severity, run metadata
        Returns the summary object.

    .PARAMETER Scope
        Pilot (default) or Tenant. Applies to user population checks (MFA, stale, guests).
        Role, app and Conditional Access checks are tenant-wide by nature.

    .PARAMETER Redact
        Masks identities outside the pilot in every output. Use it for anything you will share.

    .PARAMETER InactiveDays
        Inactivity threshold for the stale account and guest checks. Defaults to StaleAccountDays in settings (90).
        Recorded in summary.json so every evidence folder states the threshold it used.

    .PARAMETER OutputPath
        Parent folder for the evidence folder. Defaults to ReportPath in settings.

    .PARAMETER Check
        Runs only the named checks.

    .EXAMPLE
        Invoke-KRSIdentityAudit -Scope Tenant -Redact

        Full audit, shareable output.

    .EXAMPLE
        Invoke-KRSIdentityAudit -Scope Pilot -InactiveDays 30 -Redact

        Pilot audit with a 30-day inactivity threshold.

    .EXAMPLE
        Invoke-KRSIdentityAudit -Check MfaGap, StaleAccount | Select-Object -ExpandProperty Checks

        Runs two checks and shows the per-check result.

    .OUTPUTS
        PSCustomObject (KRSSecOps.IdentityAuditSummary)
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
        [ValidateRange(1, 3650)]
        [int]$InactiveDays,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('MfaGap', 'StaleAccount', 'PrivilegedRole', 'GuestAccess', 'AppCredentialRisk', 'ConditionalAccess')]
        [string[]]$Check = @('MfaGap', 'StaleAccount', 'PrivilegedRole', 'GuestAccess', 'AppCredentialRisk', 'ConditionalAccess')
    )

    $config = Get-KRSActiveConfig
    if (-not $OutputPath) { $OutputPath = $config.ReportPath }
    if (-not $PSBoundParameters.ContainsKey('InactiveDays')) { $InactiveDays = [int]$config.StaleAccountDays }
    $started = [datetime]::UtcNow
    $folder = Join-Path $OutputPath ('IdentityAudit-{0}' -f $started.ToString('yyyyMMdd-HHmmss'))
    $null = New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false -Confirm:$false

    $definitions = [ordered]@{
        MfaGap            = { Get-KRSMfaGap -Scope $Scope -Redact:$Redact -IncludeCompliant }
        StaleAccount      = { Get-KRSStaleAccount -Scope $Scope -Redact:$Redact -InactiveDays $InactiveDays }
        PrivilegedRole    = { Get-KRSPrivilegedRoleReport -Redact:$Redact -IncludeCompliant }
        GuestAccess       = { Get-KRSGuestAccessReport -Scope $Scope -Redact:$Redact -InactiveDays $InactiveDays -IncludeCompliant }
        AppCredentialRisk = { Get-KRSAppCredentialRisk -IncludeCompliant }
        ConditionalAccess = { Get-KRSConditionalAccessInventory -Redact:$Redact -IncludeCompliant }
    }

    Write-KRSLog -Action 'AuditStart' -Target $config.TenantId -Message "Scope=$Scope Redact=$([bool]$Redact) InactiveDays=$InactiveDays Checks=$($Check -join ',')"

    $allFindings = [System.Collections.Generic.List[object]]::new()
    $results = foreach ($name in $definitions.Keys) {
        if ($name -notin $Check) { continue }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        try {
            Write-Progress -Activity 'KRSSecOps identity audit' -Status $name
            $rows = @(& $definitions[$name])
            $rows | Sort-Object SeverityRank | Export-Csv -LiteralPath (Join-Path $folder "$name.csv") -NoTypeInformation -Encoding utf8 -WhatIf:$false -Confirm:$false
            $findings = @($rows | Where-Object { $_.Severity -ne 'Info' })
            foreach ($row in $findings) {
                $allFindings.Add([pscustomobject]@{
                        Check        = $name
                        Severity     = $row.Severity
                        SeverityRank = Get-KRSSeverityRank -Severity $row.Severity
                        Subject      = $row.PSObject.Properties | Where-Object { $_.Name -in 'UserPrincipalName', 'PrincipalName', 'AppDisplayName', 'PolicyName' -and $_.Value } | Select-Object -First 1 -ExpandProperty Value
                        Finding      = $row.Finding
                    })
            }
            $status = 'Completed'
            $errorText = $null
        }
        catch {
            $rows = @()
            $findings = @()
            $status = 'Failed'
            $errorText = $_.Exception.Message
            Write-Warning "Check '$name' failed: $errorText"
            Write-KRSLog -Level Error -Action 'AuditCheck' -Target $name -Result Failure -Message $errorText
        }
        [pscustomobject]@{
            Check    = $name
            Status   = $status
            Rows     = $rows.Count
            Findings = $findings.Count
            Critical = @($findings | Where-Object Severity -eq 'Critical').Count
            High     = @($findings | Where-Object Severity -eq 'High').Count
            Medium   = @($findings | Where-Object Severity -eq 'Medium').Count
            Low      = @($findings | Where-Object Severity -eq 'Low').Count
            Seconds  = [math]::Round($timer.Elapsed.TotalSeconds, 1)
            Error    = $errorText
        }
    }
    Write-Progress -Activity 'KRSSecOps identity audit' -Completed

    $allFindings | Sort-Object SeverityRank, Check |
        Select-Object Check, Severity, Subject, Finding |
        Export-Csv -LiteralPath (Join-Path $folder 'findings.csv') -NoTypeInformation -Encoding utf8 -WhatIf:$false -Confirm:$false

    $summary = [pscustomobject]@{
        PSTypeName      = 'KRSSecOps.IdentityAuditSummary'
        AuditId         = $script:KRSCorrelationId
        TenantId        = $config.TenantId
        PilotDomain     = $config.PilotDomain
        Scope           = $Scope
        Redacted        = [bool]$Redact
        InactiveDays    = $InactiveDays
        StartedUtc      = $started
        DurationSeconds = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 1)
        TotalFindings   = $allFindings.Count
        Critical        = @($allFindings | Where-Object Severity -eq 'Critical').Count
        High            = @($allFindings | Where-Object Severity -eq 'High').Count
        Medium          = @($allFindings | Where-Object Severity -eq 'Medium').Count
        Low             = @($allFindings | Where-Object Severity -eq 'Low').Count
        FailedChecks    = @($results | Where-Object Status -eq 'Failed').Count
        Checks          = @($results)
        OutputFolder    = $folder
    }
    $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $folder 'summary.json') -Encoding utf8 -WhatIf:$false -Confirm:$false

    Write-KRSLog -Action 'AuditComplete' -Target $config.TenantId -Result $(if ($summary.FailedChecks) { 'Failure' } else { 'Success' }) -Message "Findings=$($summary.TotalFindings) Critical=$($summary.Critical) High=$($summary.High) Folder=$folder"
    $summary
}
