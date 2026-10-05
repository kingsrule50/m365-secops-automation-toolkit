function Test-KRSPilotScope {
    <#
    .SYNOPSIS
        Tests whether user principal names fall inside the pilot domain.

    .DESCRIPTION
        Returns $true only for UPNs whose domain is exactly the pilot domain. Subdomains,
        look-alike domains and guest (#EXT#) accounts return $false. This is the same test the
        write-side scope guard uses before any change is made to the shared tenant.

    .PARAMETER UserPrincipalName
        One or more UPNs. Accepts pipeline input, including objects with a UserPrincipalName property.

    .PARAMETER PilotDomain
        The pilot domain to test against. Defaults to PilotDomain from the connected session's settings.

    .EXAMPLE
        Test-KRSPilotScope -UserPrincipalName 'amara.okafor@m365.kingsruleusa.com' -PilotDomain 'm365.kingsruleusa.com'

        Returns True.

    .EXAMPLE
        'admin@contoso.com', 'x@evil.m365.kingsruleusa.com' | Test-KRSPilotScope -PilotDomain 'm365.kingsruleusa.com'

        Returns False twice: a different domain and a look-alike subdomain.

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [AllowEmptyString()]
        [AllowNull()]
        [Alias('UPN')]
        [string[]]$UserPrincipalName,

        [Parameter()]
        [ValidatePattern('^@?[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')]
        [string]$PilotDomain
    )

    begin {
        if (-not $PilotDomain) {
            $PilotDomain = (Get-KRSActiveConfig).PilotDomain
        }
        $suffix = '@' + $PilotDomain.Trim().TrimStart('@').ToLowerInvariant()
    }

    process {
        foreach ($upn in $UserPrincipalName) {
            if ([string]::IsNullOrWhiteSpace($upn) -or $upn -match '#EXT#') {
                $false
                continue
            }
            $candidate = $upn.Trim().ToLowerInvariant()
            ($candidate.EndsWith($suffix) -and $candidate.IndexOf('@') -eq $candidate.LastIndexOf('@') -and $candidate.Length -gt $suffix.Length)
        }
    }
}
