function Disconnect-KRSTenant {
    <#
    .SYNOPSIS
        Ends the Graph session and clears the module's cached state.

    .DESCRIPTION
        Disconnects Microsoft Graph, logs the disconnect under the current correlation ID and clears
        the cached settings, principal lookups and pilot group membership.

    .EXAMPLE
        Disconnect-KRSTenant

    .EXAMPLE
        Invoke-KRSIdentityAudit; Disconnect-KRSTenant

        Runs an audit and closes the session straight after.
    #>
    [CmdletBinding()]
    param()

    if ($script:KRSConfig) {
        Write-KRSLog -Action 'Disconnect' -Target $script:KRSConfig.TenantId
    }
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    $script:KRSConfig = $null
    $script:KRSCorrelationId = $null
    $script:KRSPrincipalCache = @{}
    $script:KRSPilotMemberIds = $null
}
