function Export-KRSIncidentReport {
    <#
    .SYNOPSIS
        Writes an incident report for one pilot account: indicators, sign-in timeline, containment actions and current state.

    .DESCRIPTION
        Collects the evidence for a ticket into one folder under ReportPath:
          report.html      self-contained page (no external resources) for the ticket or a reviewer
          indicators.csv   Find-KRSCompromiseIndicator rows
          signins.csv      sign-in timeline for the window
          incident.json    everything above plus the containment records for this ticket and user

        Containment records are matched by ticket and account from the containment folder, including
        undo records, so the report shows who approved each action and what happened.

    .PARAMETER UserPrincipalName
        The account the incident is about. Must be in the pilot domain.

    .PARAMETER TicketId
        The incident ticket, for example INC-1042.

    .PARAMETER Days
        Look-back window for indicators and sign-ins. Default 7.

    .PARAMETER Redact
        Masks actors outside the pilot and shortens IP addresses (a.b.x.x). Use it for anything you will share.

    .PARAMETER OutputPath
        Parent folder for the report folder. Defaults to ReportPath in settings.

    .EXAMPLE
        Export-KRSIncidentReport -UserPrincipalName amara.okafor@contoso.com -TicketId INC-1042 -Redact

    .EXAMPLE
        (Export-KRSIncidentReport -UserPrincipalName amara.okafor@contoso.com -TicketId INC-1042 -Redact).ReportPath | Invoke-Item

        Builds the report and opens it in the default browser.

    .OUTPUTS
        PSCustomObject (KRSSecOps.IncidentReport)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z]{2,10}-\d{1,8}$')]
        [string]$TicketId,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7,

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [string]$OutputPath
    )

    $config = Get-KRSActiveConfig
    if (-not $OutputPath) { $OutputPath = $config.ReportPath }
    $generated = [datetime]::UtcNow
    $maskIp = [bool]$Redact

    $indicators = @(Find-KRSCompromiseIndicator -UserPrincipalName $UserPrincipalName -Days $Days -Redact:$Redact)
    $user = Get-KRSDirectoryUser -UserPrincipalName $UserPrincipalName
    $userId = [string](Get-KRSValue -InputObject $user -Name 'id')
    $signIns = @()
    try { $signIns = @(Get-KRSSignInEvent -UserId $userId -Days $Days | Sort-Object TimeUtc -Descending) }
    catch { Write-Warning "Sign-in timeline unavailable: $($_.Exception.Message)" }
    if ($maskIp) {
        foreach ($event in $signIns) {
            $event.IpAddress = ConvertTo-KRSMaskedIp -IpAddress ([string]$event.IpAddress)
        }
    }

    $short = ($UserPrincipalName -split '@')[0]
    $records = @(Get-ChildItem -Path (Get-KRSResponseFolder) -Filter "$TicketId-$short-*.json" -File -ErrorAction SilentlyContinue | Sort-Object Name)
    $actions = foreach ($file in $records) {
        $content = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        foreach ($entry in @($content.actions)) {
            [pscustomobject]@{
                TimeUtc    = ConvertTo-KRSUtcDate $entry.TimeUtc
                Action     = $entry.Action
                Target     = $entry.Target
                Result     = $entry.Result
                # Who ran it and who approved it: two different people (two-person rule)
                Operator   = $content.operator
                ApprovedBy = $content.approvedBy
                Record     = $file.Name
            }
        }
    }
    $actions = @($actions | Sort-Object TimeUtc)

    $findings = @($indicators | Where-Object Severity -ne 'Info')
    $highest = ($findings | Sort-Object SeverityRank | Select-Object -First 1).Severity
    if (-not $highest) { $highest = 'None' }

    $folder = Join-Path $OutputPath ('Incident-{0}-{1}' -f $TicketId, $generated.ToString('yyyyMMdd-HHmmss'))
    $null = New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false -Confirm:$false
    $indicators | Sort-Object SeverityRank | Select-Object Severity, Signal, Detail, Source, ObservedUtc |
        Export-Csv -LiteralPath (Join-Path $folder 'indicators.csv') -NoTypeInformation -Encoding utf8 -WhatIf:$false -Confirm:$false
    $signIns | Export-Csv -LiteralPath (Join-Path $folder 'signins.csv') -NoTypeInformation -Encoding utf8 -WhatIf:$false -Confirm:$false

    $h = { param($Value) ConvertTo-KRSHtmlText -Value $Value }
    $badge = { param($Severity) "<span class=""sev sev-$((& $h $Severity).ToLowerInvariant())"">$(& $h $Severity)</span>" }
    $table = {
        param([object[]]$Rows, [string[]]$Columns, [string]$Empty)
        if (-not $Rows) { return "<p class=""empty"">$(& $h $Empty)</p>" }
        $head = ($Columns | ForEach-Object { "<th>$(& $h $_)</th>" }) -join ''
        $body = foreach ($row in $Rows) {
            $cells = foreach ($column in $Columns) {
                $value = Get-KRSValue -InputObject $row -Name $column
                if ($column -eq 'Severity') { "<td>$(& $badge $value)</td>" } else { "<td>$(& $h $value)</td>" }
            }
            "<tr>$($cells -join '')</tr>"
        }
        "<table><thead><tr>$head</tr></thead><tbody>$($body -join '')</tbody></table>"
    }

    $state = if ((Get-KRSValue -InputObject $user -Name 'accountEnabled') -eq $false) { 'Sign-in blocked' } else { 'Sign-in allowed' }
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident $(& $h $TicketId)</title>
<style>
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1b1f24}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
header{background:#14213d;color:#fff;padding:20px 16px}header div{max-width:1100px;margin:0 auto}
h1{margin:0 0 4px;font-size:22px}h2{font-size:17px;margin:28px 0 10px}
.meta{opacity:.85;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:18px}
.card{background:#fff;border:1px solid #dde1e6;border-radius:8px;padding:12px 14px}.card b{display:block;font-size:20px;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #dde1e6;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eceff2;vertical-align:top}th{background:#f0f2f5}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;font-weight:600;font-size:12px}
.sev-critical{background:#7a0c1e;color:#fff}.sev-high{background:#d1342f;color:#fff}.sev-medium{background:#f2a33a;color:#1b1f24}
.sev-low{background:#9fc5e8}.sev-info,.sev-none{background:#e3e6ea}
.empty{color:#5c6670;font-style:italic}footer{font-size:12px;color:#5c6670;margin:32px 0 8px}
</style></head><body>
<header><div><h1>Incident $(& $h $TicketId): suspected account compromise</h1>
<div class="meta">Account $(& $h $UserPrincipalName) &middot; generated $(& $h $generated) &middot; window $(& $h (Format-KRSDayCount -Days $Days)) &middot; KRSSecOps</div></div></header>
<main>
<div class="cards">
<div class="card">Highest severity<b>$(& $badge $highest)</b></div>
<div class="card">Findings<b>$($findings.Count)</b></div>
<div class="card">Containment / recovery<b>$(@($actions | Where-Object { $_.Result -eq 'Done' -and $_.Action -notlike 'Restore*' }).Count) / $(@($actions | Where-Object { $_.Result -eq 'Done' -and $_.Action -like 'Restore*' }).Count) done</b></div>
<div class="card">Current state<b>$(& $h $state)</b></div>
</div>
<h2>Indicators</h2>
$(& $table ($indicators | Sort-Object SeverityRank) @('Severity', 'Signal', 'Detail', 'Source', 'ObservedUtc') 'No indicators.')
<h2>Containment and recovery</h2>
$(& $table $actions @('TimeUtc', 'Action', 'Target', 'Result', 'Operator', 'ApprovedBy', 'Record') 'No containment recorded for this ticket.')
<h2>Sign-in timeline</h2>
$(& $table ($signIns | Select-Object -First 25) @('TimeUtc', 'Result', 'Application', 'ClientApp', 'IpAddress', 'Country', 'FailureReason') 'No sign-ins in the window.')
<footer>Evidence files: indicators.csv, signins.csv, incident.json. Correlation ID $(& $h $script:KRSCorrelationId).$(if ($Redact) { ' Redacted: actors outside the pilot are masked and IP addresses are shortened.' })</footer>
</main></body></html>
"@
    $reportPath = Join-Path $folder 'report.html'
    Set-Content -LiteralPath $reportPath -Value $html -Encoding utf8 -WhatIf:$false -Confirm:$false

    [ordered]@{
        schemaVersion     = 1
        ticketId          = $TicketId
        userPrincipalName = $UserPrincipalName
        generatedUtc      = $generated.ToString('o')
        days              = $Days
        redacted          = [bool]$Redact
        highestSeverity   = $highest
        indicators        = $indicators
        containment       = $actions
        signIns           = $signIns
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $folder 'incident.json') -Encoding utf8 -WhatIf:$false -Confirm:$false
    Write-KRSLog -Action 'IncidentReport' -Target $UserPrincipalName -Message "$TicketId Highest=$highest Folder=$folder"

    [pscustomobject]@{
        PSTypeName         = 'KRSSecOps.IncidentReport'
        TicketId           = $TicketId
        UserPrincipalName  = $UserPrincipalName
        HighestSeverity    = $highest
        Findings           = $findings.Count
        ContainmentActions = @($actions | Where-Object { $_.Result -eq 'Done' -and $_.Action -notlike 'Restore*' }).Count
        RecoveryActions    = @($actions | Where-Object { $_.Result -eq 'Done' -and $_.Action -like 'Restore*' }).Count
        SignIns            = $signIns.Count
        CurrentState       = $state
        ReportPath         = $reportPath
    }
}
