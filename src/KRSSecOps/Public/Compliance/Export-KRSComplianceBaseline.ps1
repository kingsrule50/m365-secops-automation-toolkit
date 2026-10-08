function Export-KRSComplianceBaseline {
    <#
    .SYNOPSIS
        Saves the current Purview configuration (labels, label policies, DLP, retention) as a JSON baseline.

    .DESCRIPTION
        Reads sensitivity labels, label policies, DLP policies and rules, and retention policies and rules,
        keeps only the properties that define protection (see the spec in Private/Exchange.ps1), and writes
        one JSON file. Compare-KRSComplianceBaseline later reports any difference from it as drift.

        The baseline is the approved state: export it after a reviewed change, keep it under version
        control in a private repository, and treat any later drift as an unapproved change until reviewed.
        By default it is written outside this repository, because a shared tenant's policy names are not
        mine to publish.

    .PARAMETER Path
        File to write. Default: <ReportPath parent>/baselines/purview-baseline-<timestamp>.json.

    .EXAMPLE
        Export-KRSComplianceBaseline

        Writes a timestamped baseline and returns its path and object counts.

    .EXAMPLE
        Export-KRSComplianceBaseline -Path ./purview-baseline.json

        Writes the baseline to a chosen file, for example in a private configuration repository.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ComplianceBaseline)

    .NOTES
        Security & Compliance PowerShell with view-only roles. Commands used: Get-Label, Get-LabelPolicy,
        and the Get commands for DLP and retention policies and rules.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$Path
    )

    $null = Get-KRSActiveConfig
    $exported = [datetime]::UtcNow
    if (-not $Path) {
        $Path = Join-Path (Get-KRSBaselineFolder) ('purview-baseline-{0}.json' -f $exported.ToString('yyyyMMdd-HHmmss'))
    }
    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        $null = New-Item -ItemType Directory -Path $parent -Force -WhatIf:$false -Confirm:$false
    }

    $objects = @(Get-KRSPurviewSnapshot)
    $counts = [ordered]@{}
    foreach ($type in $script:KRSPurviewBaselineSpec.Keys) {
        $counts[$type] = @($objects | Where-Object Type -eq $type).Count
    }

    $document = [ordered]@{
        schemaVersion = 1
        exportedUtc   = $exported.ToString('o')
        exportedBy    = 'KRSSecOps Export-KRSComplianceBaseline'
        objectCounts  = $counts
        objects       = $objects
    }
    $document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8 -WhatIf:$false -Confirm:$false
    Write-KRSLog -Action 'BaselineExport' -Target $Path -Message "Objects=$($objects.Count)"

    [pscustomobject]@{
        PSTypeName       = 'KRSSecOps.ComplianceBaseline'
        Path             = (Resolve-Path -LiteralPath $Path).Path
        ExportedUtc      = $exported
        Objects          = $objects.Count
        Labels           = $counts['Label']
        LabelPolicies    = $counts['LabelPolicy']
        DlpPolicies      = $counts['DlpPolicy']
        DlpRules         = $counts['DlpRule']
        RetentionPolicies = $counts['RetentionPolicy']
        RetentionRules   = $counts['RetentionRule']
    }
}
