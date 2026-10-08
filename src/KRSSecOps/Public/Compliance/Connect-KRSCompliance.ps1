function Connect-KRSCompliance {
    <#
    .SYNOPSIS
        Connects to Exchange Online and Purview (Security & Compliance) as the automation app, with the certificate only.

    .DESCRIPTION
        Opens app-only sessions with the same certificate and app as Connect-KRSTenant. No client secret
        and no admin account is used. Each session loads only the commands the toolkit runs, and the app's
        access comes from two role groups created by the setup scripts:

          Exchange  KRS-SecOps Pilot Mailbox Automation   writes limited by Exchange to tagged pilot mailboxes
          Purview   KRS-SecOps Purview Baseline Reader    read-only labels, DLP and retention

        Needs Organization (the tenant's .onmicrosoft.com domain) in settings.json.
        Works with or without Connect-KRSTenant: it loads settings itself when needed.

    .PARAMETER Service
        Which services to connect. Default: Exchange and Purview.

    .PARAMETER ConfigPath
        Path to a settings file. Defaults to $env:KRS_SECOPS_CONFIG, then Config/settings.json.

    .EXAMPLE
        Connect-KRSCompliance

        Connects to both services and returns the session summary.

    .EXAMPLE
        Connect-KRSCompliance -Service Exchange

        Connects to Exchange Online only, for the mailbox checks.

    .OUTPUTS
        PSCustomObject (KRSSecOps.ComplianceSession)

    .NOTES
        Requires: ExchangeOnlineManagement 3.5 or later, Windows (certificate thumbprint authentication).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateSet('Exchange', 'Purview')]
        [string[]]$Service = @('Exchange', 'Purview'),

        [Parameter()]
        [string]$ConfigPath
    )

    $config = if ($null -ne $script:KRSConfig -and -not $ConfigPath) { $script:KRSConfig } else { Get-KRSConfig -Path $ConfigPath }
    $organization = [string](Get-KRSValue -InputObject $config -Name 'Organization')
    if (-not $organization -or $organization -notmatch '\.onmicrosoft\.com$') {
        throw "Set Organization in settings.json to the tenant's initial domain (<name>.onmicrosoft.com). Exchange app-only sign-in needs it."
    }

    $script:KRSConfig = $config
    if (-not $script:KRSCorrelationId) { $script:KRSCorrelationId = [guid]::NewGuid().ToString() }

    $loaded = 0
    foreach ($name in ($Service | Sort-Object -Unique)) {
        $commands = if ($name -eq 'Exchange') { $script:KRSExchangeCommands } else { $script:KRSPurviewCommands }
        Write-Verbose "Connecting to $name as app $($config.ClientId) (certificate)"
        Connect-KRSExoSession -Service $name -AppId $config.ClientId -CertificateThumbprint $config.CertificateThumbprint -Organization $organization -CommandName $commands
        $available = @($commands | Where-Object { Get-Command -Name $_ -ErrorAction SilentlyContinue })
        $loaded += $available.Count
        Write-KRSLog -Action 'Connect' -Target $name -Message "App-only session; $($available.Count) of $($commands.Count) commands available"
    }

    [pscustomobject]@{
        PSTypeName       = 'KRSSecOps.ComplianceSession'
        Services         = ($Service | Sort-Object -Unique) -join ', '
        AuthType         = 'AppOnly (certificate)'
        CommandsLoaded   = $loaded
        PilotDomain      = $config.PilotDomain
        PilotMailboxTag  = 'CustomAttribute15 = KRS-SecOps-Pilot'
        CorrelationId    = $script:KRSCorrelationId
    }
}
