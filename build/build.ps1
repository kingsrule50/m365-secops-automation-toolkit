#Requires -Version 7.4
<#
.SYNOPSIS
    Local and CI build: static analysis, unit tests with coverage, and packaging.

.DESCRIPTION
    Analyze  PSScriptAnalyzer over src/, setup/ and build/ with build/PSScriptAnalyzerSettings.psd1. Fails on any finding.
    Test     Pester 5 over tests/, writes NUnit XML and JaCoCo coverage to build/output. Fails under the coverage target.
    Package  Copies the module into build/output/KRSSecOps/<version> ready for Publish-PSResource or a file share.

    Each task runs in its own clean 'pwsh -NoProfile' process. Nothing loaded in your session (another
    Pester version, a profile, other modules) can affect the result, and the analyzer and Pester never share
    a process. This is the same isolation a CI runner gives you.

.PARAMETER Task
    One or more of Analyze, Test, Package, run in that order. Default: Analyze, Test.

.PARAMETER CoverageTarget
    Minimum line coverage percentage. Default 80.

.EXAMPLE
    ./build/build.ps1

.EXAMPLE
    ./build/build.ps1 -Task Analyze, Test, Package
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Analyze', 'Test', 'Package')]
    [string[]]$Task = @('Analyze', 'Test'),

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$CoverageTarget = 80
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $PSScriptRoot 'output'
$moduleSource = Join-Path -Path $root -ChildPath 'src' -AdditionalChildPath 'KRSSecOps'

# Orchestrator: run each task in a fresh process, in a fixed order.
if (-not $env:KRS_BUILD_WORKER) {
    $pwsh = (Get-Process -Id $PID).Path
    $null = New-Item -ItemType Directory -Path $output -Force
    foreach ($name in @('Analyze', 'Test', 'Package') | Where-Object { $_ -in $Task }) {
        $env:KRS_BUILD_WORKER = '1'
        try {
            & $pwsh -NoProfile -NonInteractive -Command "& '$PSCommandPath' -Task $name -CoverageTarget $CoverageTarget; exit `$LASTEXITCODE"
            $code = $LASTEXITCODE
        }
        finally {
            Remove-Item Env:\KRS_BUILD_WORKER -ErrorAction SilentlyContinue
        }
        if ($code -ne 0) { throw "Build task '$name' failed (exit code $code)." }
    }
    Write-Information "Build succeeded: $($Task -join ', ')." -InformationAction Continue
    return
}

# Worker: exactly one task, in a clean process.
switch ($Task) {
    'Analyze' {
        Write-Information '== Analyze' -InformationAction Continue
        Import-Module PSScriptAnalyzer -MinimumVersion 1.23.0
        Write-Information "Using PSScriptAnalyzer $((Get-Module PSScriptAnalyzer).Version)" -InformationAction Continue
        $settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
        # File by file, not folder -Recurse: folder mode analyzes in parallel and can crash intermittently
        # with a NullReferenceException on Windows. Per-file runs are stable and name the file if one fails.
        $files = Get-ChildItem -Path (Join-Path $root 'src'), (Join-Path $root 'setup'), (Join-Path $root 'build') -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File |
            Where-Object { $_.FullName -notmatch '[\\/]output[\\/]' } | Sort-Object FullName
        $findings = foreach ($file in $files) {
            $attempt = 0
            while ($true) {
                try {
                    Invoke-ScriptAnalyzer -Path $file.FullName -Settings $settings -ErrorAction Stop
                    break
                }
                catch {
                    if (++$attempt -ge 3) { throw "PSScriptAnalyzer crashed on '$($file.FullName)': $($_.Exception.Message)" }
                    Write-Warning "PSScriptAnalyzer crashed on $($file.Name) (attempt $attempt), retrying."
                }
            }
        }
        $findings = @($findings)
        Write-Information "Analyzed $($files.Count) files." -InformationAction Continue
        if ($findings.Count) {
            $findings | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-String | Write-Information -InformationAction Continue
            throw "PSScriptAnalyzer reported $($findings.Count) finding(s)."
        }
        Write-Information 'PSScriptAnalyzer: no findings.' -InformationAction Continue
    }

    'Test' {
        Write-Information '== Test' -InformationAction Continue
        Import-Module Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99
        Write-Information "Using Pester $((Get-Module Pester).Version)" -InformationAction Continue
        $config = New-PesterConfiguration
        $config.Run.Path = Join-Path $root 'tests'
        $config.Run.PassThru = $true
        $config.Output.Verbosity = 'Normal'
        $config.TestResult.Enabled = $true
        $config.TestResult.OutputFormat = 'NUnitXml'
        $config.TestResult.OutputPath = Join-Path $output 'testResults.xml'
        $config.CodeCoverage.Enabled = $true
        $config.CodeCoverage.Path = @((Join-Path $moduleSource 'Public'), (Join-Path $moduleSource 'Private'))
        $config.CodeCoverage.OutputFormat = 'JaCoCo'
        $config.CodeCoverage.OutputPath = Join-Path $output 'coverage.xml'
        $config.CodeCoverage.CoveragePercentTarget = $CoverageTarget

        $result = Invoke-Pester -Configuration $config
        $coverage = [math]::Round($result.CodeCoverage.CoveragePercent, 1)
        Set-Content -Path (Join-Path $output 'coverage.txt') -Value $coverage

        if ($result.FailedCount -gt 0) { throw "$($result.FailedCount) test(s) failed." }
        if ($coverage -lt $CoverageTarget) { throw "Coverage $coverage% is below the $CoverageTarget% target." }
        Write-Information "Tests passed: $($result.PassedCount). Coverage: $coverage%." -InformationAction Continue
    }

    'Package' {
        Write-Information '== Package' -InformationAction Continue
        $manifest = Import-PowerShellDataFile -Path (Join-Path $moduleSource 'KRSSecOps.psd1')
        $target = Join-Path -Path $output -ChildPath 'KRSSecOps' -AdditionalChildPath $manifest.ModuleVersion
        if (Test-Path $target) { Remove-Item $target -Recurse -Force }
        $null = New-Item -ItemType Directory -Path $target -Force
        Copy-Item -Path (Join-Path $moduleSource '*') -Destination $target -Recurse -Exclude 'settings.json'
        Write-Information "Packaged KRSSecOps $($manifest.ModuleVersion) to $target" -InformationAction Continue
    }
}
