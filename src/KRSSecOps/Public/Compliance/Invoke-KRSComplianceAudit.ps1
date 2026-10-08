function Invoke-KRSComplianceAudit {
    <#
    .SYNOPSIS
        Runs every Part 2 check (mailbox security, Exchange organisation risk, Purview drift) and writes one evidence folder.

    .DESCRIPTION
        Each check runs on its own: if one fails, the failure is recorded and the others still run.
        Purview drift needs a baseline; without one the check is reported as Skipped, not Failed.

        Writes to <ReportPath>/ComplianceAudit-<timestamp>/:
          <Check>.csv     full rows for each check (findings and Info rows)
          findings.csv    every finding across checks, most severe first
          summary.json    counts by check and severity, run metadata
        Returns the summary object.

    .PARAMETER Scope
        Pilot (default) or Tenant, for the mailbox check. Organisation and Purview checks are tenant-wide by nature.

    .PARAMETER Redact
        Masks mailboxes outside the pilot, and domain, rule and policy names that are not the pilot's.
        Use it for anything you will share.

    .PARAMETER BaselinePath
        Purview baseline to compare against. Default: the newest baseline in the default folder.

    .PARAMETER OutputPath
        Parent folder for the evidence folder. Defaults to ReportPath in settings.

    .PARAMETER Check
        Runs only the named checks.

    .EXAMPLE
        Invoke-KRSComplianceAudit -Redact

        Full Part 2 audit for the pilot, shareable output.

    .EXAMPLE
        Invoke-KRSComplianceAudit -Check PurviewDrift -BaselinePath ./purview-baseline.json

        Drift check only, against a chosen baseline.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ComplianceAuditSummary)
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
        [string]$BaselinePath,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('MailboxSecurity', 'ExchangeTenantRisk', 'PurviewDrift')]
        [string[]]$Check = @('MailboxSecurity', 'ExchangeTenantRisk', 'PurviewDrift')
    )

    $config = Get-KRSActiveConfig
    if (-not $OutputPath) { $OutputPath = $config.ReportPath }
    $started = [datetime]::UtcNow
    $folder = Join-Path $OutputPath ('ComplianceAudit-{0}' -f $started.ToString('yyyyMMdd-HHmmss'))
    $null = New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false -Confirm:$false

    $baselineArgs = @{ IncludeCompliant = $true }
    if ($BaselinePath) { $baselineArgs.BaselinePath = $BaselinePath }
    $definitions = [ordered]@{
        MailboxSecurity    = { Get-KRSMailboxSecurityState -Scope $Scope -Redact:$Redact -IncludeCompliant }
        ExchangeTenantRisk = { Get-KRSExchangeTenantRisk -Redact:$Redact -IncludeCompliant }
        PurviewDrift       = { Compare-KRSComplianceBaseline @baselineArgs }
    }

    Write-KRSLog -Action 'AuditStart' -Target 'Compliance' -Message "Scope=$Scope Redact=$([bool]$Redact) Checks=$($Check -join ',')"

    $allFindings = [System.Collections.Generic.List[object]]::new()
    $results = foreach ($name in $definitions.Keys) {
        if ($name -notin $Check) { continue }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $errorText = $null
        try {
            Write-Progress -Activity 'KRSSecOps compliance audit' -Status $name
            $rows = @(& $definitions[$name])
            $rows | Sort-Object SeverityRank | Export-Csv -LiteralPath (Join-Path $folder "$name.csv") -NoTypeInformation -Encoding utf8 -WhatIf:$false -Confirm:$false
            $findings = @($rows | Where-Object { $_.Severity -ne 'Info' })
            foreach ($row in $findings) {
                $subject = foreach ($property in 'UserPrincipalName', 'Subject', 'Name') {
                    $value = Get-KRSValue -InputObject $row -Name $property
                    if ($value) { $value; break }
                }
                $allFindings.Add([pscustomobject]@{
                        Check        = $name
                        Severity     = $row.Severity
                        SeverityRank = Get-KRSSeverityRank -Severity $row.Severity
                        Subject      = $subject
                        Setting      = @(Get-KRSValue -InputObject $row -Name 'Setting'; Get-KRSValue -InputObject $row -Name 'Area'; Get-KRSValue -InputObject $row -Name 'Property') | Where-Object { $_ } | Select-Object -First 1
                        Finding      = $row.Finding
                    })
            }
            $status = 'Completed'
        }
        catch {
            $rows = @()
            $findings = @()
            $errorText = $_.Exception.Message
            $status = if ($name -eq 'PurviewDrift' -and $errorText -like 'No baseline found*') { 'Skipped' } else { 'Failed' }
            if ($status -eq 'Failed') {
                Write-Warning "Check '$name' failed: $errorText"
                Write-KRSLog -Level Error -Action 'AuditCheck' -Target $name -Result Failure -Message $errorText
            }
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
    Write-Progress -Activity 'KRSSecOps compliance audit' -Completed

    $allFindings | Sort-Object SeverityRank, Check |
        Select-Object Check, Severity, Subject, Setting, Finding |
        Export-Csv -LiteralPath (Join-Path $folder 'findings.csv') -NoTypeInformation -Encoding utf8 -WhatIf:$false -Confirm:$false

    $summary = [pscustomobject]@{
        PSTypeName      = 'KRSSecOps.ComplianceAuditSummary'
        AuditId         = $script:KRSCorrelationId
        PilotDomain     = $config.PilotDomain
        Scope           = $Scope
        Redacted        = [bool]$Redact
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

    Write-KRSLog -Action 'AuditComplete' -Target 'Compliance' -Result $(if ($summary.FailedChecks) { 'Failure' } else { 'Success' }) -Message "Findings=$($summary.TotalFindings) High=$($summary.High) Folder=$folder"
    $summary
}
