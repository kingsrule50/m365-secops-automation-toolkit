#Requires -Version 7.4
Set-StrictMode -Version Latest

# Module-wide state. Populated by Connect-KRSTenant and cleared by Disconnect-KRSTenant.
$script:KRSModuleRoot     = $PSScriptRoot
$script:KRSConfig         = $null
$script:KRSCorrelationId  = $null
$script:KRSPrincipalCache = @{}
$script:KRSPilotMemberIds = $null
$script:KRSPrivilegedPrincipalIds = $null
$script:KRSGraphRequestCount = 0

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "KRSSecOps: failed to import '$($file.FullName)': $_"
    }
}

Export-ModuleMember -Function $public.BaseName
