# Part 2 helpers: Exchange Online and Security & Compliance (Purview) sessions and data shaping.

# Commands the toolkit loads in each session. Loading only these keeps the session surface small,
# and each one maps to a role the app holds (see docs/permission-matrix.md).
$script:KRSExchangeCommands = @(
    'Get-Mailbox', 'Get-CASMailbox', 'Get-InboxRule', 'Get-Recipient', 'Set-Mailbox', 'Set-CASMailbox',
    'Get-AcceptedDomain', 'Get-HostedOutboundSpamFilterPolicy', 'Get-TransportRule', 'Get-RemoteDomain',
    'Get-DkimSigningConfig', 'Get-TransportConfig', 'Get-OrganizationConfig'
)
$script:KRSPurviewCommands = @(
    'Get-Label', 'Get-LabelPolicy', 'Get-DlpCompliancePolicy', 'Get-DlpComplianceRule',
    'Get-RetentionCompliancePolicy', 'Get-RetentionComplianceRule'
)

function Connect-KRSExoSession {
    <#
    .SYNOPSIS
        Opens one app-only session to Exchange Online or Security & Compliance PowerShell.
    .DESCRIPTION
        Thin wrapper so the public function can be tested without the ExchangeOnlineManagement module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Exchange', 'Purview')]
        [string]$Service,

        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter(Mandatory)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory)]
        [string]$Organization,

        [Parameter(Mandatory)]
        [string[]]$CommandName
    )

    if (-not (Get-Module -Name ExchangeOnlineManagement)) {
        Import-Module ExchangeOnlineManagement -MinimumVersion 3.5.0 -ErrorAction Stop
    }
    $connect = @{
        AppId                 = $AppId
        CertificateThumbprint = $CertificateThumbprint
        Organization          = $Organization
        CommandName           = $CommandName
        ShowBanner            = $false
        ErrorAction           = 'Stop'
    }
    if ($Service -eq 'Exchange') { Connect-ExchangeOnline @connect }
    else { Connect-IPPSSession @connect }
}

function Disconnect-KRSExoSession {
    # Closes every Exchange Online and Security & Compliance session in this PowerShell process.
    [CmdletBinding()]
    param()

    if (Get-Command -Name Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Invoke-KRSExoCommand {
    <#
    .SYNOPSIS
        Runs one Exchange Online or Security & Compliance command with errors that stop.
    .DESCRIPTION
        The ExchangeOnlineManagement module generates its commands inside a temporary module, which does
        not inherit $ErrorActionPreference from the caller. Without -ErrorAction Stop a refused write is
        printed and execution carries on as if it worked. Every call goes through here so that cannot happen.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [hashtable]$Parameters = @{}
    )

    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Command '$Name' is not available in this session. Run Connect-KRSCompliance, and check the app's Exchange or Purview role group includes it."
    }
    & $command @Parameters -ErrorAction Stop
}

function Get-KRSAcceptedDomainSet {
    # The tenant's accepted domains, used to tell internal from external forwarding targets.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param()

    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($domain in @(Invoke-KRSExoCommand -Name 'Get-AcceptedDomain')) {
            $name = [string](Get-KRSValue -InputObject $domain -Name 'DomainName')
            if ($name) { $null = $set.Add($name) }
        }
    }
    catch {
        Write-Warning "Could not read accepted domains; every forwarding address will be treated as external. $($_.Exception.Message)"
    }
    Write-Output -InputObject $set -NoEnumerate
}

function Get-KRSSmtpAddress {
    <#
    .SYNOPSIS
        Extracts SMTP addresses from Exchange recipient strings.
    .DESCRIPTION
        Handles 'smtp:user@contoso.com', '"Name" [SMTP:user@contoso.com]' and plain addresses.
        Internal X.500 references ('[EX:/o=...]') carry no SMTP address and are skipped.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Value
    )

    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $match = [regex]::Match($text, '(?i)smtp:([^\]\s"]+@[^\]\s"]+)')
        if ($match.Success) { $match.Groups[1].Value.ToLowerInvariant(); continue }
        if ($text -match '\[EX:') { continue }
        $plain = [regex]::Match($text, '[^\s"\[\]<>]+@[^\s"\[\]<>]+')
        if ($plain.Success) { $plain.Value.ToLowerInvariant() }
    }
}

function Test-KRSExternalAddress {
    # True when the address's domain is not one of the tenant's accepted domains.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Address,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$AcceptedDomain
    )

    $domain = ($Address -split '@')[-1]
    -not $AcceptedDomain.Contains($domain)
}

function ConvertTo-KRSComparableValue {
    <#
    .SYNOPSIS
        Turns a Purview property value into a stable string for baselines and drift comparison.
    .DESCRIPTION
        Collections become sorted, '; '-joined lists so ordering differences are not reported as drift.
        Objects with a Name or DisplayName (for example policy locations) collapse to that name.
        Anything else complex is serialised to compact JSON.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool] -or $Value -is [ValueType]) {
        if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
        return [string]$Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        # Hashtable key order depends on per-process string hashing, so sort keys to keep the text stable
        # between the day a baseline is exported and the day it is compared.
        $sorted = [ordered]@{}
        foreach ($key in ($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $sorted[$key] = ConvertTo-KRSComparableValue -Value $Value[$key]
        }
        return ($sorted | ConvertTo-Json -Compress -Depth 6)
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($item in $Value) { ConvertTo-KRSComparableValue -Value $item }) | Where-Object { $null -ne $_ -and $_ -ne '' } | Sort-Object
        if (-not $items) { return $null }
        return ($items -join '; ')
    }
    foreach ($name in 'Name', 'DisplayName') {
        $inner = Get-KRSValue -InputObject $Value -Name $name
        if ($inner) { return [string]$inner }
    }
    $Value | ConvertTo-Json -Compress -Depth 6
}

# Which properties make up each Purview object's baseline. Anything not listed (timestamps,
# distribution status, internal IDs) changes on its own and would only be noise.
$script:KRSPurviewBaselineSpec = [ordered]@{
    Label                    = @{ Command = 'Get-Label'; Properties = @('DisplayName', 'Priority', 'ParentId', 'Disabled', 'Tooltip', 'ContentType', 'EncryptionEnabled', 'ApplyContentMarkingHeaderEnabled', 'ApplyContentMarkingFooterEnabled', 'ApplyWaterMarkingEnabled') }
    LabelPolicy              = @{ Command = 'Get-LabelPolicy'; Properties = @('Enabled', 'Mode', 'Labels', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'ModernGroupLocation') }
    DlpPolicy                = @{ Command = 'Get-DlpCompliancePolicy'; Properties = @('Enabled', 'Mode', 'Priority', 'Workload', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'TeamsLocation', 'EndpointDlpLocation') }
    DlpRule                  = @{ Command = 'Get-DlpComplianceRule'; Properties = @('ParentPolicyName', 'Disabled', 'Priority', 'BlockAccess', 'BlockAccessScope', 'NotifyUser', 'GenerateIncidentReport', 'ReportSeverityLevel', 'AccessScope', 'ContentContainsSensitiveInformation') }
    RetentionPolicy          = @{ Command = 'Get-RetentionCompliancePolicy'; Properties = @('Enabled', 'Mode', 'RestrictiveRetention', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'ModernGroupLocation', 'TeamsChannelLocation', 'TeamsChatLocation') }
    RetentionRule            = @{ Command = 'Get-RetentionComplianceRule'; Properties = @('Policy', 'RetentionDuration', 'RetentionDurationDisplayHint', 'RetentionComplianceAction', 'ExpirationDateOption', 'ApplyComplianceTag', 'Disabled') }
}

# Changes to these weaken protection directly, so drift on them is High rather than Medium.
$script:KRSPurviewCriticalProperties = @(
    'Enabled', 'Disabled', 'Mode', 'RestrictiveRetention', 'RetentionDuration', 'RetentionComplianceAction',
    'BlockAccess', 'BlockAccessScope', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation',
    'TeamsLocation', 'EndpointDlpLocation', 'ModernGroupLocation', 'TeamsChannelLocation', 'TeamsChatLocation',
    'EncryptionEnabled', 'Labels', 'ContentContainsSensitiveInformation'
)

function Get-KRSPurviewSnapshot {
    <#
    .SYNOPSIS
        Reads labels, label policies, DLP and retention configuration into baseline-shaped records.
    .DESCRIPTION
        One record per object: Type, Key (Guid where available, else Name), Name and a sorted property bag
        of comparable strings. Read-only: the app holds only view roles in Security & Compliance.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    foreach ($type in $script:KRSPurviewBaselineSpec.Keys) {
        $spec = $script:KRSPurviewBaselineSpec[$type]
        Write-KRSLog -Action 'Read' -Target $spec.Command
        foreach ($object in @(Invoke-KRSExoCommand -Name $spec.Command)) {
            if ($null -eq $object) { continue }
            $name = [string](Get-KRSValue -InputObject $object -Name 'Name')
            $guid = [string](Get-KRSValue -InputObject $object -Name 'Guid')
            if (-not $guid) { $guid = [string](Get-KRSValue -InputObject $object -Name 'ImmutableId') }
            $properties = [ordered]@{}
            foreach ($property in ($spec.Properties | Sort-Object)) {
                $properties[$property] = ConvertTo-KRSComparableValue -Value (Get-KRSValue -InputObject $object -Name $property)
            }
            [pscustomobject]@{
                Type       = $type
                Key        = if ($guid) { "$type|$guid" } else { "$type|name:$name" }
                Name       = $name
                Properties = [pscustomobject]$properties
            }
        }
    }
}

function Get-KRSBaselineFolder {
    # Default baseline location: next to the reports folder, outside the repository.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $reportPath = (Get-KRSActiveConfig).ReportPath
    Join-Path (Split-Path -Path $reportPath -Parent) 'baselines'
}

function ConvertTo-KRSMaskedName {
    <#
    .SYNOPSIS
        Masks a tenant object name (domain, rule, policy) that does not belong to the pilot.
    .DESCRIPTION
        Shared tenants contain other people's domains and rules. Masked names are stable
        ('dkim-3f2a91c0' is the same domain in every report) so findings can still be tracked,
        but the real name never appears in shared output. Generic values stay readable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory)]
        [string]$Kind,

        [Parameter(Mandatory)]
        [string]$PilotDomain
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -in '*', 'Default', '(organisation)', '(not checked)') { return $Value }
    $pilot = $PilotDomain.Trim().TrimStart('@').ToLowerInvariant()
    $lower = $Value.ToLowerInvariant()
    if ($lower -eq $pilot -or $lower.EndsWith(".$pilot") -or $lower -like "*$pilot*") { return $Value }
    $bytes = [Text.Encoding]::UTF8.GetBytes($lower)
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).Substring(0, 8).ToLowerInvariant()
    '{0}-{1}' -f $Kind.ToLowerInvariant(), $hash
}
