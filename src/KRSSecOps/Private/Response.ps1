# Part 3 helpers: sign-in and risk evidence (Graph), mailbox audit (Exchange), containment records.

# Client apps that use basic (legacy) authentication protocols, as reported in sign-in logs.
$script:KRSLegacyClientApps = @(
    'Authenticated SMTP', 'AutoDiscover', 'Exchange ActiveSync', 'Exchange Online PowerShell', 'Exchange Web Services',
    'IMAP4', 'MAPI Over HTTP', 'Offline Address Book', 'Other clients', 'Outlook Anywhere (RPC over HTTP)', 'POP3',
    'Reporting Web Services'
)

# Audit operations that create or change inbox rules or mailbox forwarding.
$script:KRSRuleAuditOperations = @('New-InboxRule', 'Set-InboxRule', 'Enable-InboxRule', 'UpdateInboxRules', 'Set-Mailbox')

function Get-KRSResponseFolder {
    # Containment records live next to the reports folder, outside the repository.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Join-Path (Split-Path -Path (Get-KRSActiveConfig).ReportPath -Parent) 'containment'
}

function Get-KRSDirectoryUser {
    # One user's id, name and sign-in state from Graph.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    Invoke-KRSGraphRequest -Uri "users/$UserPrincipalName`?`$select=id,displayName,userPrincipalName,accountEnabled"
}

function Get-KRSSignInEvent {
    <#
    .SYNOPSIS
        Recent sign-ins for one user, shaped for investigation.
    .DESCRIPTION
        Graph auditLogs/signIns filtered by user and time. Needs AuditLog.Read.All (granted in Part 1).
        Result is Success when errorCode is 0. IsLegacy marks basic-authentication client apps.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserId,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7
    )

    $since = [datetime]::UtcNow.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $uri = "auditLogs/signIns?`$filter=userId eq '$UserId' and createdDateTime ge $since&`$top=200"
    foreach ($event in @(Invoke-KRSGraphRequest -Uri $uri -All)) {
        if ($null -eq $event) { continue }
        $status = Get-KRSValue -InputObject $event -Name 'status'
        $code = [int](Get-KRSValue -InputObject $status -Name 'errorCode')
        $location = Get-KRSValue -InputObject $event -Name 'location'
        $clientApp = [string](Get-KRSValue -InputObject $event -Name 'clientAppUsed')
        [pscustomobject]@{
            TimeUtc       = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $event -Name 'createdDateTime')
            Application   = Get-KRSValue -InputObject $event -Name 'appDisplayName'
            ClientApp     = $clientApp
            IsLegacy      = $clientApp -in $script:KRSLegacyClientApps
            IpAddress     = Get-KRSValue -InputObject $event -Name 'ipAddress'
            Country       = Get-KRSValue -InputObject $location -Name 'countryOrRegion'
            City          = Get-KRSValue -InputObject $location -Name 'city'
            Result        = if ($code -eq 0) { 'Success' } else { 'Failure' }
            ErrorCode     = $code
            # Graph reports 'Other.' as the reason even for successful sign-ins; only failures get one
            FailureReason = if ($code -eq 0) { $null } else { Get-KRSValue -InputObject $status -Name 'failureReason' }
        }
    }
}

function Get-KRSUserRisk {
    <#
    .SYNOPSIS
        Entra ID Protection risk for one user, or $null when the user has never been flagged.
    .DESCRIPTION
        Graph identityProtection/riskyUsers. Needs IdentityRiskyUser.Read.All. A 404 means no risk
        record exists, which is normal; any other error is raised so the caller can report it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    try {
        $risk = Invoke-KRSGraphRequest -Uri "identityProtection/riskyUsers/$UserId" -MaxRetries 2
    }
    catch {
        if ((Get-KRSHttpStatus -ErrorRecord $_) -eq 404) { return $null }
        throw
    }
    [pscustomobject]@{
        RiskLevel   = [string](Get-KRSValue -InputObject $risk -Name 'riskLevel')
        RiskState   = [string](Get-KRSValue -InputObject $risk -Name 'riskState')
        RiskDetail  = [string](Get-KRSValue -InputObject $risk -Name 'riskDetail')
        UpdatedUtc  = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $risk -Name 'riskLastUpdatedDateTime')
    }
}

function Search-KRSMailboxAudit {
    <#
    .SYNOPSIS
        Unified audit log events that created or changed inbox rules or forwarding for one mailbox.
    .DESCRIPTION
        Exchange Search-UnifiedAuditLog (View-Only Audit Logs role). Matches events whose audit data
        mentions the mailbox, then extracts who did it, when, from where, and the rule parameters.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$Days = 7
    )

    $records = @(Invoke-KRSExoCommand -Name 'Search-UnifiedAuditLog' -Parameters @{
            StartDate  = [datetime]::UtcNow.AddDays(-$Days)
            EndDate    = [datetime]::UtcNow
            Operations = $script:KRSRuleAuditOperations
            ResultSize = 1000
        })
    foreach ($record in $records) {
        if ($null -eq $record) { continue }
        $raw = [string](Get-KRSValue -InputObject $record -Name 'AuditData')
        if (-not $raw -or $raw.IndexOf($UserPrincipalName, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $data = $raw | ConvertFrom-Json
        $parameters = @(Get-KRSValue -InputObject $data -Name 'Parameters') | Where-Object { $_ }
        $interesting = $parameters | Where-Object { [string]$_.Name -in 'Name', 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo', 'ForwardingSmtpAddress', 'DeleteMessage', 'MoveToFolder' }
        # Audit CreationTime is UTC but carries no zone marker; never let it be read as local time.
        $created = Get-KRSValue -InputObject $data -Name 'CreationTime'
        $time = if ($created -is [datetime]) { [datetime]::SpecifyKind($created, [DateTimeKind]::Utc) }
        else { [datetime]::Parse([string]$created, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal) }
        [pscustomobject]@{
            TimeUtc   = $time
            Operation = [string](Get-KRSValue -InputObject $data -Name 'Operation')
            Actor     = [string](Get-KRSValue -InputObject $data -Name 'UserId')
            ClientIp  = [string](Get-KRSValue -InputObject $data -Name 'ClientIP')
            Detail    = (@($interesting | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ')
        }
    }
}

function Get-KRSExternalInboxRule {
    # Enabled or disabled inbox rules on one mailbox that forward or redirect outside the organisation.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$AcceptedDomain
    )

    foreach ($rule in @(Invoke-KRSExoCommand -Name 'Get-InboxRule' -Parameters @{ Mailbox = $UserPrincipalName })) {
        if ($null -eq $rule) { continue }
        $targets = foreach ($property in 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo') {
            Get-KRSSmtpAddress -Value (Get-KRSValue -InputObject $rule -Name $property)
        }
        $outside = @($targets | Where-Object { $_ -and (Test-KRSExternalAddress -Address $_ -AcceptedDomain $AcceptedDomain) } | Sort-Object -Unique)
        if (-not $outside) { continue }
        [pscustomobject]@{
            Name         = [string](Get-KRSValue -InputObject $rule -Name 'Name')
            RuleIdentity = [string](Get-KRSValue -InputObject $rule -Name 'RuleIdentity')
            Enabled      = [bool](Get-KRSValue -InputObject $rule -Name 'Enabled')
            Targets      = $outside -join ', '
        }
    }
}

function ConvertTo-KRSHtmlText {
    # HTML-encodes any value for the incident report; collections are joined.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { $Value = $Value.ToString('yyyy-MM-dd HH:mm') + ' UTC' }
    elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { $Value = (@($Value) -join ', ') }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-KRSMaskedIp {
    # Shortens an IP address for shared output: 203.0.113.7 -> 203.0.x.x ; 2001:db8::1 -> 2001:db8:x
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$IpAddress
    )

    if ([string]::IsNullOrWhiteSpace($IpAddress)) { return $IpAddress }
    # Audit ClientIP can carry a port and brackets: [2001:db8::1]:51234, 203.0.113.7:443, ::ffff:203.0.113.7
    $ip = $IpAddress.Trim()
    if ($ip -match '^\[([^\]]+)\](:\d+)?$') { $ip = $Matches[1] }
    if ($ip -match '^(?:::ffff:)?(\d+\.\d+\.\d+\.\d+)(:\d+)?$') { $ip = $Matches[1] }
    if ($ip -match '^(\d+)\.(\d+)\.\d+\.\d+$') { return "$($Matches[1]).$($Matches[2]).x.x" }
    if ($ip -match '^[0-9a-fA-F:]+$' -and $ip -match ':') { return ((($ip -split ':')[0..1]) -join ':') + ':x' }
    # Anything unrecognised is withheld rather than shown
    'x.x.x.x'
}

function ConvertTo-KRSMaskedActor {
    # Anyone outside the pilot (for example the admin who made a change) becomes a stable hashed name, domain included.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Actor,

        [Parameter(Mandatory)]
        [string]$PilotDomain
    )

    if ([string]::IsNullOrWhiteSpace($Actor) -or (Test-KRSPilotScope -UserPrincipalName $Actor -PilotDomain $PilotDomain)) { return $Actor }
    $bytes = [Text.Encoding]::UTF8.GetBytes($Actor.ToLowerInvariant())
    'actor-{0} (outside pilot)' -f [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).Substring(0, 8).ToLowerInvariant()
}
