function Get-KRSPrivilegedRoleReport {
    <#
    .SYNOPSIS
        Reports who holds Entra ID directory roles, and whether that access is standing or just-in-time.

    .DESCRIPTION
        Combines active and PIM-eligible role assignments and flags:
          High    standing (permanent) privileged role held by a user
          High    privileged role held by an app (service principal)
          High    more than 4 Global Administrators
          Medium  standing privileged role held by a group
          Medium  fewer than 2 Global Administrators (no break-glass margin)
        Eligible and PIM-activated assignments are returned as Info with -IncludeCompliant.
        If PIM data is not available (no Entra ID P2), active assignments are read directly and
        all are treated as standing.
        This is a tenant-wide report: there is no pilot filter, so use -Redact before sharing it.

    .PARAMETER Redact
        Masks users outside the pilot.

    .PARAMETER IncludeCompliant
        Also return eligible, activated and non-privileged assignments (Severity Info).

    .EXAMPLE
        Get-KRSPrivilegedRoleReport -Redact

        Privileged access findings with users outside the pilot masked.

    .EXAMPLE
        Get-KRSPrivilegedRoleReport -IncludeCompliant | Group-Object RoleName | Sort-Object Count -Descending

        Full role inventory grouped by role.

    .OUTPUTS
        PSCustomObject (KRSSecOps.PrivilegedRole)

    .NOTES
        Graph: /roleManagement/directory/roleDefinitions, roleAssignmentScheduleInstances,
               roleEligibilityScheduleInstances, roleAssignments (fallback)
        Permission: RoleManagement.Read.Directory (application). PIM data needs Entra ID P2.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [switch]$IncludeCompliant
    )

    $null = Get-KRSActiveConfig
    $privilegedNames = @(
        'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
        'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'User Administrator',
        'Application Administrator', 'Cloud Application Administrator', 'Authentication Administrator',
        'Conditional Access Administrator', 'Helpdesk Administrator', 'Hybrid Identity Administrator',
        'Intune Administrator', 'Compliance Administrator', 'Billing Administrator', 'Groups Administrator',
        'Authentication Policy Administrator', 'Domain Name Administrator', 'Partner Tier2 Support'
    )

    Write-KRSLog -Action 'Read' -Target 'roleManagement/directory'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $requestsAtStart = $script:KRSGraphRequestCount
    $stage = {
        param([string]$Name)
        Write-Verbose ('Timing {0,-22} {1,6:N1} s  Graph requests so far: {2}' -f $Name, $timer.Elapsed.TotalSeconds, ($script:KRSGraphRequestCount - $requestsAtStart))
    }
    $definitions = @{}
    foreach ($definition in (Invoke-KRSGraphRequest -Uri 'roleManagement/directory/roleDefinitions' -All)) {
        $name = Get-KRSValue -InputObject $definition -Name 'displayName'
        $flag = Get-KRSValue -InputObject $definition -Name 'isPrivileged'
        $entry = [pscustomobject]@{
            Name         = $name
            IsPrivileged = if ($null -ne $flag) { [bool]$flag -or $name -in $privilegedNames } else { $name -in $privilegedNames }
        }
        $definitions[[string]$definition.id] = $entry
        $templateId = Get-KRSValue -InputObject $definition -Name 'templateId'
        if ($templateId) { $definitions[[string]$templateId] = $entry }
    }

    & $stage 'role definitions'
    $assignments = [System.Collections.Generic.List[object]]::new()
    $pimAvailable = $true
    try {
        foreach ($item in (Invoke-KRSGraphRequest -Uri 'roleManagement/directory/roleAssignmentScheduleInstances?$select=principalId,roleDefinitionId,directoryScopeId,assignmentType,memberType,endDateTime' -All -MaxRetries 2)) {
            $assignmentType = Get-KRSValue -InputObject $item -Name 'assignmentType'
            $end = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $item -Name 'endDateTime')
            $state = if ($assignmentType -eq 'Activated') { 'Active (PIM activation)' } elseif ($end) { 'Active (time-bound)' } else { 'Active (permanent)' }
            $assignments.Add([pscustomobject]@{ Item = $item; State = $state; End = $end })
        }
    }
    catch {
        $pimAvailable = $false
        Write-Warning "PIM schedule data unavailable ($($_.Exception.Message)). Reading active assignments directly; all are treated as standing."
        foreach ($item in (Invoke-KRSGraphRequest -Uri 'roleManagement/directory/roleAssignments' -All)) {
            $assignments.Add([pscustomobject]@{ Item = $item; State = 'Active (permanent)'; End = $null })
        }
    }

    & $stage "active ($($assignments.Count))"
    if ($pimAvailable) {
        try {
            foreach ($item in (Invoke-KRSGraphRequest -Uri 'roleManagement/directory/roleEligibilityScheduleInstances?$select=principalId,roleDefinitionId,directoryScopeId,memberType,endDateTime' -All -MaxRetries 2)) {
                $assignments.Add([pscustomobject]@{ Item = $item; State = 'Eligible'; End = ConvertTo-KRSUtcDate (Get-KRSValue -InputObject $item -Name 'endDateTime') })
            }
        }
        catch {
            Write-Warning "Could not read PIM eligible assignments: $($_.Exception.Message)"
        }
    }

    # Bulk-load principals when there are many to resolve (one paged read instead of thousands of single lookups).
    $unresolved = @($assignments | ForEach-Object { [string](Get-KRSValue -InputObject $_.Item -Name 'principalId') } |
            Sort-Object -Unique | Where-Object { $_ -and -not $script:KRSPrincipalCache.ContainsKey($_) })
    & $stage "eligible (total $($assignments.Count))"
    if ($unresolved.Count -gt 25) { Initialize-KRSPrincipalCache }
    & $stage "principal cache ($($unresolved.Count))"

    $globalAdmins = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($assignment in $assignments) {
        $item = $assignment.Item
        $roleId = [string](Get-KRSValue -InputObject $item -Name 'roleDefinitionId')
        $role = if ($definitions.ContainsKey($roleId)) { $definitions[$roleId] } else { [pscustomobject]@{ Name = $roleId; IsPrivileged = $false } }
        $principal = Resolve-KRSPrincipal -Id ([string](Get-KRSValue -InputObject $item -Name 'principalId'))

        $name = $principal.DisplayName
        $upn = $principal.UserPrincipalName
        if ($principal.Type -eq 'User') {
            $identity = Format-KRSIdentity -UserPrincipalName $upn -DisplayName $name -Id $principal.Id -Redact:$Redact
            $name = $identity.DisplayName
            $upn = $identity.UserPrincipalName
        }

        $isActive = $assignment.State -like 'Active*'
        $isStanding = $assignment.State -eq 'Active (permanent)'
        if ($role.Name -eq 'Global Administrator' -and $isActive) { $null = $globalAdmins.Add($principal.Id) }

        $finding, $severity = switch ($true) {
            ($role.IsPrivileged -and $principal.Type -eq 'ServicePrincipal' -and $isActive) { 'App holds a privileged directory role'; 'High'; break }
            ($role.IsPrivileged -and $isStanding -and $principal.Type -eq 'User') { 'Standing privileged access: make it eligible through PIM'; 'High'; break }
            ($role.IsPrivileged -and $isStanding -and $principal.Type -eq 'Group') { 'Group holds a standing privileged role: review its members'; 'Medium'; break }
            ($assignment.State -eq 'Eligible') { 'OK: eligible through PIM'; 'Info'; break }
            ($assignment.State -eq 'Active (PIM activation)') { 'OK: just-in-time activation'; 'Info'; break }
            default { 'OK'; 'Info' }
        }
        if ($severity -eq 'Info' -and -not $IncludeCompliant) { continue }

        [pscustomobject]@{
            PSTypeName        = 'KRSSecOps.PrivilegedRole'
            RoleName          = $role.Name
            IsPrivileged      = $role.IsPrivileged
            PrincipalType     = $principal.Type
            PrincipalName     = $name
            UserPrincipalName = $upn
            AssignmentState   = $assignment.State
            EndDateTime       = $assignment.End
            DirectoryScope    = Get-KRSValue -InputObject $item -Name 'directoryScopeId'
            Finding           = $finding
            Severity          = $severity
            SeverityRank      = Get-KRSSeverityRank -Severity $severity
        }
    }

    & $stage 'rows built'
    $gaCount = $globalAdmins.Count
    $gaFinding = if ($gaCount -gt 4) { "$gaCount active Global Administrators (recommended 2 to 4)"; 'High' }
    elseif ($gaCount -lt 2) { "$gaCount active Global Administrator(s): keep at least 2, including break-glass"; 'Medium' }
    if ($gaFinding) {
        [pscustomobject]@{
            PSTypeName        = 'KRSSecOps.PrivilegedRole'
            RoleName          = 'Global Administrator'
            IsPrivileged      = $true
            PrincipalType     = 'Tenant'
            PrincipalName     = '(tenant baseline)'
            UserPrincipalName = $null
            AssignmentState   = "$gaCount active"
            EndDateTime       = $null
            DirectoryScope    = '/'
            Finding           = $gaFinding[0]
            Severity          = $gaFinding[1]
            SeverityRank      = Get-KRSSeverityRank -Severity $gaFinding[1]
        }
    }
}
