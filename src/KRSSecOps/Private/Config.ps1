function Get-KRSConfig {
    <#
    .SYNOPSIS
        Loads and validates the KRSSecOps settings file.
    .DESCRIPTION
        Resolution order: -Path, then $env:KRS_SECOPS_CONFIG, then Config/settings.json in the module folder.
        Fails fast on missing or placeholder values so a half-configured run never reaches the tenant.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$Path
    )

    if (-not $Path) {
        $Path = if ($env:KRS_SECOPS_CONFIG) { $env:KRS_SECOPS_CONFIG } else { Join-Path $script:KRSModuleRoot 'Config/settings.json' }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "KRSSecOps settings file not found at '$Path'. Copy Config/settings.example.json to settings.json and fill it in, or set `$env:KRS_SECOPS_CONFIG."
    }

    $config = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json

    foreach ($key in 'TenantId', 'ClientId', 'CertificateThumbprint', 'PilotDomain') {
        $value = Get-KRSValue -InputObject $config -Name $key
        if ([string]::IsNullOrWhiteSpace($value) -or $value -like '<*>') {
            throw "Setting '$key' is missing or still a placeholder in '$Path'."
        }
    }

    $userHome = [Environment]::GetFolderPath('UserProfile')
    $defaults = [ordered]@{
        Organization         = $null
        PilotGroupId         = $null
        StaleAccountDays     = 90
        CredentialExpiryDays = 30
        LogPath              = Join-Path $userHome 'KRSSecOps/logs'
        ReportPath           = Join-Path $userHome 'KRSSecOps/reports'
    }
    foreach ($key in $defaults.Keys) {
        $value = Get-KRSValue -InputObject $config -Name $key
        if ($null -eq $value -or ($value -is [string] -and ([string]::IsNullOrWhiteSpace($value) -or $value -like '<*>'))) {
            $config | Add-Member -NotePropertyName $key -NotePropertyValue $defaults[$key] -Force
        }
    }

    $config.PilotDomain = $config.PilotDomain.Trim().TrimStart('@').ToLowerInvariant()
    $config
}

function Get-KRSActiveConfig {
    # Returns the configuration of the current session, or stops if Connect-KRSTenant has not run.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if ($null -eq $script:KRSConfig) {
        throw 'Not connected. Run Connect-KRSTenant first.'
    }
    $script:KRSConfig
}

function Get-KRSValue {
    # StrictMode-safe property read: returns $null when the property does not exist.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $null
}

function ConvertTo-KRSUtcDate {
    # Normalises Graph date values (string or DateTime) to UTC DateTime; $null stays $null.
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}

function Get-KRSSeverityRank {
    # Sort key: lower number = more severe.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { 0 }
        'High' { 1 }
        'Medium' { 2 }
        'Low' { 3 }
        default { 4 }
    }
}

function Format-KRSDayCount {
    # "1 day", "5 days": keeps finding text grammatical in reports people read.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int]$Days
    )

    if ([math]::Abs($Days) -eq 1) { "$Days day" } else { "$Days days" }
}
