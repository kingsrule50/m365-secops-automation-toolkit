#Requires -Version 7.4
<#
.SYNOPSIS
    Installs the PowerShell modules the toolkit needs, for the current user only.

.DESCRIPTION
    Installs or updates:
      Microsoft.Graph.Authentication  Graph connection and requests (the only module the toolkit loads)
      ExchangeOnlineManagement        Exchange Online and Security & Compliance PowerShell (Part 2)
      Pester                          unit tests
      PSScriptAnalyzer                static analysis
    Uses PSResourceGet when present, otherwise PowerShellGet. Supports -WhatIf.

.EXAMPLE
    ./setup/01-Install-Prerequisites.ps1 -WhatIf

.EXAMPLE
    ./setup/01-Install-Prerequisites.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

$modules = @(
    @{ Name = 'Microsoft.Graph.Authentication'; Minimum = '2.20.0'; Maximum = $null }
    @{ Name = 'ExchangeOnlineManagement'; Minimum = '3.5.0'; Maximum = $null }
    # Test framework pinned to one major version, so a new major release cannot change test behaviour unannounced.
    @{ Name = 'Pester'; Minimum = '5.5.0'; Maximum = '5.99.99' }
    @{ Name = 'PSScriptAnalyzer'; Minimum = '1.23.0'; Maximum = $null }
)

$usePSResourceGet = [bool](Get-Command Install-PSResource -ErrorAction SilentlyContinue)

foreach ($module in $modules) {
    $inRange = Get-Module -ListAvailable -Name $module.Name |
        Where-Object { $_.Version -ge [version]$module.Minimum -and (-not $module.Maximum -or $_.Version -le [version]$module.Maximum) } |
        Sort-Object Version -Descending | Select-Object -First 1
    $range = if ($module.Maximum) { "$($module.Minimum) to $($module.Maximum)" } else { "$($module.Minimum)+" }
    if ($inRange) {
        [pscustomobject]@{ Module = $module.Name; Version = $inRange.Version.ToString(); Required = $range; Action = 'Already installed' }
        continue
    }

    if ($PSCmdlet.ShouldProcess($module.Name, "Install ($range) for CurrentUser")) {
        if ($usePSResourceGet) {
            $versionRange = if ($module.Maximum) { "[$($module.Minimum),$($module.Maximum)]" } else { "[$($module.Minimum),)" }
            Install-PSResource -Name $module.Name -Version $versionRange -Scope CurrentUser -TrustRepository
        }
        else {
            $extra = @{}
            if ($module.Maximum) { $extra.MaximumVersion = $module.Maximum }
            if ($module.Name -eq 'Pester') { $extra.SkipPublisherCheck = $true }
            Install-Module -Name $module.Name -MinimumVersion $module.Minimum -Scope CurrentUser -Force -AllowClobber @extra
        }
        $now = Get-Module -ListAvailable -Name $module.Name |
            Where-Object { $_.Version -ge [version]$module.Minimum -and (-not $module.Maximum -or $_.Version -le [version]$module.Maximum) } |
            Sort-Object Version -Descending | Select-Object -First 1
        [pscustomobject]@{ Module = $module.Name; Version = $now.Version.ToString(); Required = $range; Action = 'Installed' }
    }
}
