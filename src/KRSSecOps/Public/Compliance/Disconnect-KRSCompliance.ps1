function Disconnect-KRSCompliance {
    <#
    .SYNOPSIS
        Closes the toolkit's Exchange Online and Purview sessions.

    .DESCRIPTION
        Disconnects every Exchange Online and Security & Compliance session in this PowerShell process
        and logs the disconnect. Safe to run when nothing is connected.

    .EXAMPLE
        Disconnect-KRSCompliance

    .OUTPUTS
        None
    #>
    [CmdletBinding()]
    param()

    Disconnect-KRSExoSession
    if ($null -ne $script:KRSConfig) { Write-KRSLog -Action 'Disconnect' -Target 'Exchange, Purview' }
}
