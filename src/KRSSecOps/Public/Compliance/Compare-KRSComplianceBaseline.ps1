function Compare-KRSComplianceBaseline {
    <#
    .SYNOPSIS
        Reports drift between the live Purview configuration and an approved baseline.

    .DESCRIPTION
        Reads the current labels, label policies, DLP and retention configuration and compares it,
        object by object and property by property, with a baseline from Export-KRSComplianceBaseline.
        Objects are matched by their immutable Guid, so a rename is reported as a change, not as a
        removal plus an addition.

          High    an object was removed, or a protective setting changed (mode, enabled, locations,
                  retention duration or action, preservation lock, block access, label encryption)
          Medium  any other tracked setting changed
          Low     a new object exists that the baseline does not know about

    .PARAMETER BaselinePath
        Baseline file. Default: the newest purview-baseline-*.json in the default baseline folder.

    .PARAMETER IncludeCompliant
        Also return one Info row per object that matches the baseline.

    .EXAMPLE
        Compare-KRSComplianceBaseline | Format-Table Type, Name, Change, Property, Baseline, Current, Severity

    .EXAMPLE
        Compare-KRSComplianceBaseline -BaselinePath ./purview-baseline.json | Where-Object Severity -eq 'High'

        Only the drift that weakens protection.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ComplianceDrift)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$BaselinePath,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $null = Get-KRSActiveConfig
    if (-not $BaselinePath) {
        $folder = Get-KRSBaselineFolder
        $latest = Get-ChildItem -Path $folder -Filter 'purview-baseline-*.json' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if (-not $latest) { throw "No baseline found in '$folder'. Run Export-KRSComplianceBaseline first." }
        $BaselinePath = $latest.FullName
    }
    if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) { throw "Baseline file '$BaselinePath' not found." }

    $document = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
    if ([int](Get-KRSValue -InputObject $document -Name 'schemaVersion') -ne 1) { throw "Unsupported baseline schema in '$BaselinePath'." }
    Write-KRSLog -Action 'DriftCompare' -Target $BaselinePath

    $baseline = @{}
    foreach ($object in @(Get-KRSValue -InputObject $document -Name 'objects')) {
        if ($object) { $baseline[[string]$object.Key] = $object }
    }
    $current = @{}
    foreach ($object in @(Get-KRSPurviewSnapshot)) { $current[[string]$object.Key] = $object }

    $newRow = {
        param($Object, $Change, $Property, $Old, $New, $Severity, $Finding)
        [pscustomobject]@{
            PSTypeName   = 'KRSSecOps.ComplianceDrift'
            Type         = $Object.Type
            Name         = $Object.Name
            Change       = $Change
            Property     = $Property
            Baseline     = $Old
            Current      = $New
            Finding      = $Finding
            Severity     = $Severity
            SeverityRank = Get-KRSSeverityRank -Severity $Severity
        }
    }

    foreach ($key in ($baseline.Keys | Sort-Object)) {
        $old = $baseline[$key]
        if (-not $current.ContainsKey($key)) {
            & $newRow $old 'Removed' '(object)' $null $null 'High' "$($old.Type) '$($old.Name)' was removed since the baseline"
            continue
        }
        $new = $current[$key]
        $drift = 0
        if ([string]$old.Name -ne [string]$new.Name) {
            $drift++
            & $newRow $new 'Modified' 'Name' $old.Name $new.Name 'Medium' "$($new.Type) renamed from '$($old.Name)'"
        }
        $names = @($old.Properties.PSObject.Properties.Name) + @($new.Properties.PSObject.Properties.Name) | Sort-Object -Unique
        foreach ($property in $names) {
            $was = [string](Get-KRSValue -InputObject $old.Properties -Name $property)
            $is = [string](Get-KRSValue -InputObject $new.Properties -Name $property)
            if ($was -ceq $is) { continue }
            $drift++
            $severity = if ($property -in $script:KRSPurviewCriticalProperties) { 'High' } else { 'Medium' }
            & $newRow $new 'Modified' $property $was $is $severity "$property changed on $($new.Type) '$($new.Name)'"
        }
        if (-not $drift -and $IncludeCompliant) {
            & $newRow $new 'None' $null $null $null 'Info' 'Matches baseline'
        }
    }

    foreach ($key in ($current.Keys | Sort-Object)) {
        if ($baseline.ContainsKey($key)) { continue }
        $new = $current[$key]
        & $newRow $new 'Added' '(object)' $null $null 'Low' "New $($new.Type) '$($new.Name)' is not in the baseline: review, then re-baseline"
    }
}
