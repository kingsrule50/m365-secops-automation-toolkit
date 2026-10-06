#Requires -Version 7.4
<#
.SYNOPSIS
    Gives the automation app least-privilege, pilot-only access to Exchange Online.

.DESCRIPTION
    Idempotent. Run it signed in to Exchange Online PowerShell as an Exchange admin
    (Connect-ExchangeOnline). It builds a server-side boundary that Exchange itself enforces:

      1. Tags each pilot mailbox with CustomAttribute15 = KRS-SecOps-Pilot.
         Every mailbox must be in the pilot domain. Exact-match tags are used because Exchange
         filters do not support leading wildcards such as '*@domain'.
      2. Checks the scope filter returns exactly the pilot mailboxes, and stops if it doesn't.
      3. Creates management scope 'KRS-SecOps Pilot Mailboxes' on that tag.
      4. Creates custom role 'KRS-SecOps Mailbox Hardening' from 'Mail Recipients', trimmed to
         Get-Mailbox, Get-CASMailbox, Get-InboxRule, Get-Recipient, and Set-Mailbox / Set-CASMailbox
         limited to the forwarding and legacy-protocol parameters.
      5. Creates role group 'KRS-SecOps Pilot Mailbox Automation' with the custom role scoped to the
         pilot, plus the read-only 'View-Only Configuration' role for tenant mail settings.
      6. Registers the app's service principal in Exchange and makes it the role group's member.

    The app gets no Microsoft Entra role, so these role assignments are its only Exchange access.
    Get the tenant owner's approval before running this in a shared tenant.

.PARAMETER PilotMailbox
    UPNs of the mailboxes to bring into scope. Each must be in PilotDomain.

.PARAMETER ServicePrincipalId
    Object ID of the app's service principal (Enterprise application), from 03-New-KRSAppRegistration.ps1.

.PARAMETER ConfigPath
    settings.json with ClientId and PilotDomain. Default src/KRSSecOps/Config/settings.json.

.EXAMPLE
    ./setup/05-Set-KRSExchangePilotRbac.ps1 -PilotMailbox amara.okafor@contoso.com, marcus.bennett@contoso.com -ServicePrincipalId <sp-object-id> -WhatIf

    Shows every change without making it.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string[]]$PilotMailbox,

    [Parameter(Mandatory)]
    [guid]$ServicePrincipalId,

    [Parameter()]
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'src', 'KRSSecOps', 'Config', 'settings.json')
)

$ErrorActionPreference = 'Stop'

$tagValue = 'KRS-SecOps-Pilot'
$scopeName = 'KRS-SecOps Pilot Mailboxes'
$scopeFilter = "CustomAttribute15 -eq '$tagValue'"
$roleName = 'KRS-SecOps Mailbox Hardening'
$roleGroupName = 'KRS-SecOps Pilot Mailbox Automation'
$spDisplayName = 'KRS-SecOps automation (app-only)'

$keepCmdlets = 'Get-Mailbox', 'Get-CASMailbox', 'Get-InboxRule', 'Get-Recipient', 'Set-Mailbox', 'Set-CASMailbox'
$writeParameters = @{
    'Set-Mailbox'    = 'Identity', 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward'
    'Set-CASMailbox' = 'Identity', 'SmtpClientAuthenticationDisabled', 'PopEnabled', 'ImapEnabled'
}
$commonParameters = 'Confirm', 'WhatIf', 'ErrorAction', 'ErrorVariable', 'WarningAction', 'WarningVariable',
'InformationAction', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'Verbose', 'Debug', 'ProgressAction'

# 0. Preconditions
if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) -or
    -not (Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession })) {
    throw 'Connect to Exchange Online PowerShell as an Exchange admin first: Connect-ExchangeOnline'
}
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$pilotDomain = ([string]$config.PilotDomain).Trim().TrimStart('@').ToLowerInvariant()
$clientId = [string]$config.ClientId
if (-not $pilotDomain -or -not $clientId -or $clientId -like '<*>') { throw "PilotDomain and ClientId must be set in $ConfigPath." }

$expected = foreach ($upn in $PilotMailbox) {
    $upn = $upn.Trim().ToLowerInvariant()
    if (-not $upn.EndsWith("@$pilotDomain")) { throw "Refusing '$upn': not in the pilot domain $pilotDomain." }
    $upn
}

# 1. Tag pilot mailboxes
foreach ($upn in $expected) {
    $mailbox = Get-Mailbox -Identity $upn
    if ($mailbox.RecipientTypeDetails -ne 'UserMailbox') { throw "Refusing '$upn': $($mailbox.RecipientTypeDetails), not a user mailbox." }
    if ($mailbox.CustomAttribute15 -eq $tagValue) { Write-Verbose "$upn already tagged."; continue }
    if ($mailbox.CustomAttribute15) { throw "Refusing '$upn': CustomAttribute15 already holds '$($mailbox.CustomAttribute15)'." }
    if ($PSCmdlet.ShouldProcess($upn, "Set CustomAttribute15 = $tagValue")) {
        Set-Mailbox -Identity $upn -CustomAttribute15 $tagValue
    }
}

# 2. The scope filter must return exactly the pilot mailboxes
$matched = @(Get-Recipient -RecipientPreviewFilter $scopeFilter -ResultSize Unlimited | ForEach-Object { ([string]$_.PrimarySmtpAddress).ToLowerInvariant() })
$missing = @($expected | Where-Object { $_ -notin $matched })
$extra = @($matched | Where-Object { $_ -notin $expected })
if ($extra) { throw "Scope filter also matches mailboxes outside the list: $($extra -join ', '). Stopping." }
if ($missing) {
    if ($WhatIfPreference) { Write-Warning "Not tagged yet (expected under -WhatIf): $($missing -join ', ')" }
    else { throw "Scope filter does not match: $($missing -join ', '). Tags may still be replicating; rerun in a minute." }
}

# 3. Management scope
$scope = Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue
if (-not $scope) {
    if ($PSCmdlet.ShouldProcess($scopeName, "Create management scope: $scopeFilter")) {
        $scope = New-ManagementScope -Name $scopeName -RecipientRestrictionFilter $scopeFilter
    }
}
elseif ($scope.RecipientFilter -notmatch [regex]::Escape($tagValue)) {
    throw "Scope '$scopeName' exists with a different filter: $($scope.RecipientFilter)"
}

# 4. Custom role, trimmed to what the toolkit runs
$role = Get-ManagementRole -Identity $roleName -ErrorAction SilentlyContinue
if (-not $role -and $PSCmdlet.ShouldProcess($roleName, "Create custom role from 'Mail Recipients'")) {
    $role = New-ManagementRole -Name $roleName -Parent 'Mail Recipients' -Description 'KRSSecOps: read pilot mailboxes; clear forwarding and disable legacy protocols only.'
}
if ($role) {
    $remove = @(Get-ManagementRoleEntry -Identity "$roleName\*" | Where-Object { $_.Name -notin $keepCmdlets })
    if ($remove -and $PSCmdlet.ShouldProcess($roleName, "Remove $($remove.Count) role entries not used by the toolkit")) {
        $i = 0
        foreach ($entry in $remove) {
            $i++
            Write-Progress -Activity "Trimming $roleName" -Status $entry.Name -PercentComplete (100 * $i / $remove.Count)
            Remove-ManagementRoleEntry -Identity "$roleName\$($entry.Name)" -Confirm:$false
        }
        Write-Progress -Activity "Trimming $roleName" -Completed
    }
    foreach ($cmdlet in $writeParameters.Keys) {
        $entry = Get-ManagementRoleEntry -Identity "$roleName\$cmdlet"
        $keep = @($entry.Parameters | Where-Object { $_ -in $writeParameters[$cmdlet] -or $_ -in $commonParameters })
        $drop = @($entry.Parameters | Where-Object { $_ -notin $keep })
        if ($drop -and $PSCmdlet.ShouldProcess("$roleName\$cmdlet", "Limit to parameters: $(($keep | Where-Object { $_ -notin $commonParameters }) -join ', ')")) {
            Set-ManagementRoleEntry -Identity "$roleName\$cmdlet" -Parameters $keep
        }
    }
}

# 5. Role group: custom role scoped to the pilot, plus read-only tenant configuration
$group = Get-RoleGroup -Identity $roleGroupName -ErrorAction SilentlyContinue
if (-not $group -and $scope -and $role -and $PSCmdlet.ShouldProcess($roleGroupName, "Create role group with '$roleName' scoped to '$scopeName'")) {
    $group = New-RoleGroup -Name $roleGroupName -Roles $roleName -CustomRecipientWriteScope $scopeName `
        -Description 'KRSSecOps automation app. Pilot mailboxes only. Owner: Chinedu. See docs/permission-matrix.md.'
}
if ($group) {
    $assigned = @(Get-ManagementRoleAssignment -RoleAssignee $roleGroupName | ForEach-Object { [string]$_.Role })
    if ('View-Only Configuration' -notin $assigned -and $PSCmdlet.ShouldProcess($roleGroupName, "Add read-only role 'View-Only Configuration'")) {
        $null = New-ManagementRoleAssignment -SecurityGroup $roleGroupName -Role 'View-Only Configuration'
    }
}

# 6. Service principal as the only member
$sp = Get-ServicePrincipal -Identity $ServicePrincipalId.ToString() -ErrorAction SilentlyContinue
if (-not $sp -and $PSCmdlet.ShouldProcess($spDisplayName, "Register service principal for app $clientId in Exchange")) {
    $sp = New-ServicePrincipal -AppId $clientId -ObjectId $ServicePrincipalId.ToString() -DisplayName $spDisplayName
}
if ($sp -and $group) {
    $members = @(Get-RoleGroupMember -Identity $roleGroupName | ForEach-Object { [string]$_.ExternalDirectoryObjectId })
    if ($ServicePrincipalId.ToString() -notin $members -and $PSCmdlet.ShouldProcess($roleGroupName, "Add member $spDisplayName")) {
        Add-RoleGroupMember -Identity $roleGroupName -Member $sp.Identity
    }
}

# Result
if ($group) {
    Get-ManagementRoleAssignment -RoleAssignee $roleGroupName |
        Select-Object Role, CustomRecipientWriteScope, RecipientWriteScope |
        Format-Table -AutoSize | Out-Host
    Get-ManagementRoleEntry -Identity "$roleName\*" -ErrorAction SilentlyContinue |
        Select-Object Name, @{ n = 'Parameters'; e = { ($_.Parameters | Where-Object { $_ -notin $commonParameters }) -join ', ' } } |
        Format-Table -Wrap -AutoSize | Out-Host
}
[pscustomobject]@{
    PilotMailboxes = $expected -join ', '
    ScopeFilter    = $scopeFilter
    RoleGroup      = $roleGroupName
    Member         = $spDisplayName
    NextStep       = 'Wait up to 30 minutes for Exchange permissions to apply, then test the app-only connection.'
}
