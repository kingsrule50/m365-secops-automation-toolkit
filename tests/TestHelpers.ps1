# Shared test setup. Tests never touch a tenant: every Graph call is mocked at Invoke-KRSGraphRequest.

$script:ModuleManifest = Join-Path $PSScriptRoot '..' 'src' 'KRSSecOps' 'KRSSecOps.psd1'
$script:PilotDomain = 'm365.kingsruleusa.com'

function Initialize-TestSession {
    # Puts the module in a connected state without connecting to anything.
    param(
        [Parameter(Mandatory)]
        [string]$Drive,

        [string[]]$PilotMemberIds = @()
    )

    InModuleScope KRSSecOps -Parameters @{ Drive = $Drive; Members = $PilotMemberIds } {
        param($Drive, $Members)
        $script:KRSConfig = [pscustomobject]@{
            TenantId              = '00000000-0000-0000-0000-000000000001'
            ClientId              = '00000000-0000-0000-0000-000000000002'
            CertificateThumbprint = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
            Organization          = 'contoso.onmicrosoft.com'
            PilotDomain           = 'm365.kingsruleusa.com'
            PilotGroupId          = $null
            StaleAccountDays      = 90
            CredentialExpiryDays  = 30
            LogPath               = Join-Path $Drive 'logs'
            ReportPath            = Join-Path $Drive 'reports'
        }
        $script:KRSCorrelationId = 'test-correlation-id'
        $script:KRSPrincipalCache = @{}
        $script:KRSPrivilegedPrincipalIds = $null
        $script:KRSPilotMemberIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($id in $Members) { $null = $script:KRSPilotMemberIds.Add($id) }
    }
}

function Get-TestDate {
    # ISO 8601 UTC string, the shape Graph returns, offset by days from now.
    param([int]$DaysAgo)
    [datetime]::UtcNow.AddDays(-$DaysAgo).ToString('yyyy-MM-ddTHH:mm:ssZ')
}
