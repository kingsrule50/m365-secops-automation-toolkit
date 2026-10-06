function Get-KRSPrivilegedRoleName {
    # Built-in Entra ID roles treated as privileged, in addition to any role Graph marks isPrivileged.
    [CmdletBinding()]
    [OutputType([System.Array])]
    param()

    @(
        'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
        'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'User Administrator',
        'Application Administrator', 'Cloud Application Administrator', 'Authentication Administrator',
        'Conditional Access Administrator', 'Helpdesk Administrator', 'Hybrid Identity Administrator',
        'Intune Administrator', 'Compliance Administrator', 'Billing Administrator', 'Groups Administrator',
        'Authentication Policy Administrator', 'Domain Name Administrator', 'Partner Tier2 Support'
    )
}

function Get-KRSPrivilegedPrincipalSet {
    <#
    .SYNOPSIS
        IDs of principals that currently hold an active privileged directory role, cached for the session.
    .DESCRIPTION
        Read straight from role assignments, so it reflects role changes immediately. The isAdmin flag in the
        authentication methods registration report can lag role changes by a day or more.
        Returns an empty set (and warns) if role data cannot be read, so callers fall back to the report flag.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param()

    if ($null -ne $script:KRSPrivilegedPrincipalIds) {
        Write-Output -InputObject $script:KRSPrivilegedPrincipalIds -NoEnumerate
        return
    }

    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $names = Get-KRSPrivilegedRoleName
        $privilegedRoleIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($definition in (Invoke-KRSGraphRequest -Uri 'roleManagement/directory/roleDefinitions' -All)) {
            $flag = Get-KRSValue -InputObject $definition -Name 'isPrivileged'
            if ((Get-KRSValue -InputObject $definition -Name 'displayName') -in $names -or ($null -ne $flag -and [bool]$flag)) {
                $null = $privilegedRoleIds.Add([string]$definition.id)
                $templateId = Get-KRSValue -InputObject $definition -Name 'templateId'
                if ($templateId) { $null = $privilegedRoleIds.Add([string]$templateId) }
            }
        }
        foreach ($assignment in (Invoke-KRSGraphRequest -Uri 'roleManagement/directory/roleAssignments?$select=principalId,roleDefinitionId' -All)) {
            if ($privilegedRoleIds.Contains([string](Get-KRSValue -InputObject $assignment -Name 'roleDefinitionId'))) {
                $null = $ids.Add([string](Get-KRSValue -InputObject $assignment -Name 'principalId'))
            }
        }
    }
    catch {
        Write-Warning "Could not read role assignments; admin status falls back to the registration report. $($_.Exception.Message)"
    }
    $script:KRSPrivilegedPrincipalIds = $ids
    Write-Output -InputObject $ids -NoEnumerate
}
