function Connect-KRSTenant {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with certificate-based, app-only authentication.

    .DESCRIPTION
        Reads settings.json, checks the certificate in the current user's store (present, has a
        private key, not near expiry), connects to Microsoft Graph as the automation app and
        confirms the session is app-only. No client secret is ever used or stored.
        Starts a new correlation ID that ties together every log record from this session.

    .PARAMETER ConfigPath
        Path to a settings file. Defaults to $env:KRS_SECOPS_CONFIG, then Config/settings.json.

    .EXAMPLE
        Connect-KRSTenant

        Connects with the default settings file and returns the session summary.

    .EXAMPLE
        Connect-KRSTenant -ConfigPath "$HOME/KRSSecOps/settings.json" -Verbose

        Connects with a settings file kept outside the repo and shows each check.

    .OUTPUTS
        PSCustomObject (KRSSecOps.Session)

    .NOTES
        Requires: Microsoft.Graph.Authentication 2.x, and the app's certificate in Cert:\CurrentUser\My.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $config = Get-KRSConfig -Path $ConfigPath

    if ($IsWindows) {
        $cert = Get-Item -Path "Cert:\CurrentUser\My\$($config.CertificateThumbprint)" -ErrorAction SilentlyContinue
        if (-not $cert) {
            throw "Certificate $($config.CertificateThumbprint) was not found in Cert:\CurrentUser\My. Run setup/02-New-KRSAuthCertificate.ps1."
        }
        if (-not $cert.HasPrivateKey) {
            throw "Certificate $($config.CertificateThumbprint) has no private key on this machine."
        }
        $daysLeft = [int]($cert.NotAfter - (Get-Date)).TotalDays
        if ($daysLeft -lt 0) { throw "Certificate $($config.CertificateThumbprint) expired on $($cert.NotAfter)." }
        if ($daysLeft -lt 30) { Write-Warning "Authentication certificate expires in $daysLeft days ($($cert.NotAfter)). Rotate it soon." }
        Write-Verbose "Certificate OK: $($cert.Subject), expires $($cert.NotAfter)"
    }

    $connect = @{
        TenantId              = $config.TenantId
        ClientId              = $config.ClientId
        CertificateThumbprint = $config.CertificateThumbprint
        NoWelcome             = $true
        ErrorAction           = 'Stop'
    }
    Connect-MgGraph @connect

    $context = Get-MgContext
    if (-not $context -or [string]$context.AuthType -ne 'AppOnly') {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        throw "Expected an app-only Graph session but got '$($context.AuthType)'. Check ClientId and certificate."
    }

    $script:KRSConfig = $config
    $script:KRSCorrelationId = [guid]::NewGuid().ToString()
    $script:KRSPrincipalCache = @{}
    $script:KRSPilotMemberIds = $null
    $script:KRSPrivilegedPrincipalIds = $null

    Write-KRSLog -Action 'Connect' -Target $config.TenantId -Message "App-only Graph session as '$($context.AppName)'"

    [pscustomobject]@{
        PSTypeName    = 'KRSSecOps.Session'
        TenantId      = $context.TenantId
        AppName       = $context.AppName
        ClientId      = $context.ClientId
        AuthType      = [string]$context.AuthType
        Permissions   = (@($context.Scopes) | Sort-Object) -join ', '
        PilotDomain   = $config.PilotDomain
        CorrelationId = $script:KRSCorrelationId
    }
}
