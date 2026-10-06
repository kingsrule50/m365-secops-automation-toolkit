BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $ModuleManifest -Force
}

Describe 'Get-KRSMfaGap' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'roleManagement/directory/roleDefinitions' } -MockWith {
            [pscustomobject]@{ id = 'ua'; templateId = 'ua'; displayName = 'User Administrator' }
            [pscustomobject]@{ id = 'dr'; templateId = 'dr'; displayName = 'Directory Readers' }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignments*' } -MockWith { }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'reports/authenticationMethods/userRegistrationDetails*' } -MockWith {
            @(
                [pscustomobject]@{ id = '1'; userPrincipalName = 'priya.shah@m365.kingsruleusa.com'; userDisplayName = 'Priya Shah'; userType = 'member'; isAdmin = $true; isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @() }
                [pscustomobject]@{ id = '2'; userPrincipalName = 'amara.okafor@m365.kingsruleusa.com'; userDisplayName = 'Amara Okafor'; userType = 'member'; isAdmin = $false; isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @() }
                [pscustomobject]@{ id = '3'; userPrincipalName = 'daniel.reyes@m365.kingsruleusa.com'; userDisplayName = 'Daniel Reyes'; userType = 'member'; isAdmin = $true; isMfaRegistered = $true; isMfaCapable = $true; methodsRegistered = @('microsoftAuthenticatorPush') }
                [pscustomobject]@{ id = '4'; userPrincipalName = 'sofia.laurent@m365.kingsruleusa.com'; userDisplayName = 'Sofia Laurent'; userType = 'member'; isAdmin = $true; isMfaRegistered = $true; isMfaCapable = $true; methodsRegistered = @('fido2SecurityKey') }
                [pscustomobject]@{ id = '5'; userPrincipalName = 'g_contoso.com#EXT#@tenant.onmicrosoft.com'; userDisplayName = 'Guest'; userType = 'guest'; isAdmin = $false; isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @() }
                [pscustomobject]@{ id = '6'; userPrincipalName = 'colleague@contoso.com'; userDisplayName = 'Colleague'; userType = 'member'; isAdmin = $false; isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @() }
            )
        }
    }

    It 'rates an admin without MFA as Critical' {
        (Get-KRSMfaGap | Where-Object UserPrincipalName -eq 'priya.shah@m365.kingsruleusa.com').Severity | Should -Be 'Critical'
    }

    It 'rates a member without MFA as High' {
        (Get-KRSMfaGap | Where-Object UserPrincipalName -eq 'amara.okafor@m365.kingsruleusa.com').Severity | Should -Be 'High'
    }

    It 'rates an admin without a phishing-resistant method as Medium' {
        (Get-KRSMfaGap | Where-Object UserPrincipalName -eq 'daniel.reyes@m365.kingsruleusa.com').Severity | Should -Be 'Medium'
    }

    It 'returns no row for a compliant admin unless asked' {
        Get-KRSMfaGap | Where-Object UserPrincipalName -eq 'sofia.laurent@m365.kingsruleusa.com' | Should -BeNullOrEmpty
        (Get-KRSMfaGap -IncludeCompliant | Where-Object UserPrincipalName -eq 'sofia.laurent@m365.kingsruleusa.com').Severity | Should -Be 'Info'
    }

    It 'keeps Pilot scope inside the pilot' {
        @(Get-KRSMfaGap).Count | Should -Be 3
        Get-KRSMfaGap | Where-Object InPilot -eq $false | Should -BeNullOrEmpty
    }

    It 'redacts users outside the pilot in Tenant scope' {
        $row = Get-KRSMfaGap -Scope Tenant -Redact | Where-Object InPilot -eq $false
        $row.UserPrincipalName | Should -Be 'c***@contoso.com'
        $row.DisplayName | Should -Be 'Redacted (outside pilot)'
    }

    It 'treats a live privileged role holder as admin even when the report lags' {
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignments*' } -MockWith {
            [pscustomobject]@{ principalId = '2'; roleDefinitionId = 'ua' }
        }
        $row = Get-KRSMfaGap | Where-Object UserPrincipalName -eq 'amara.okafor@m365.kingsruleusa.com'
        $row.IsAdmin | Should -BeTrue
        $row.AdminSource | Should -Be 'RoleAssignment'
        $row.Severity | Should -Be 'Critical'
    }

    It 'does not treat a non-privileged role as admin' {
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignments*' } -MockWith {
            [pscustomobject]@{ principalId = '2'; roleDefinitionId = 'dr' }
        }
        (Get-KRSMfaGap | Where-Object UserPrincipalName -eq 'amara.okafor@m365.kingsruleusa.com').Severity | Should -Be 'High'
    }

    It 'falls back to the report flag when role data cannot be read' {
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignments*' } -MockWith { throw 'Forbidden (403)' }
        $row = Get-KRSMfaGap -WarningAction SilentlyContinue | Where-Object UserPrincipalName -eq 'priya.shah@m365.kingsruleusa.com'
        $row.AdminSource | Should -Be 'Report'
        $row.Severity | Should -Be 'Critical'
    }

    It 'skips guests unless -IncludeGuests' {
        Get-KRSMfaGap -Scope Tenant | Where-Object UserType -eq 'guest' | Should -BeNullOrEmpty
        Get-KRSMfaGap -Scope Tenant -IncludeGuests | Where-Object UserType -eq 'guest' | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-KRSStaleAccount' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users?*' } -MockWith {
            @(
                [pscustomobject]@{ id = '1'; displayName = 'Old Sign-in'; userPrincipalName = 'old@m365.kingsruleusa.com'; accountEnabled = $true; userType = 'Member'; createdDateTime = (Get-TestDate 400); signInActivity = [pscustomobject]@{ lastSignInDateTime = (Get-TestDate 200); lastNonInteractiveSignInDateTime = (Get-TestDate 150); lastSuccessfulSignInDateTime = $null } }
                [pscustomobject]@{ id = '2'; displayName = 'Recent'; userPrincipalName = 'recent@m365.kingsruleusa.com'; accountEnabled = $true; userType = 'Member'; createdDateTime = (Get-TestDate 400); signInActivity = [pscustomobject]@{ lastSignInDateTime = (Get-TestDate 200); lastNonInteractiveSignInDateTime = (Get-TestDate 3); lastSuccessfulSignInDateTime = $null } }
                [pscustomobject]@{ id = '3'; displayName = 'Never'; userPrincipalName = 'never@m365.kingsruleusa.com'; accountEnabled = $true; userType = 'Member'; createdDateTime = (Get-TestDate 120); signInActivity = $null }
                [pscustomobject]@{ id = '4'; displayName = 'New Hire'; userPrincipalName = 'new@m365.kingsruleusa.com'; accountEnabled = $true; userType = 'Member'; createdDateTime = (Get-TestDate 5) }
                [pscustomobject]@{ id = '5'; displayName = 'Disabled'; userPrincipalName = 'disabled@m365.kingsruleusa.com'; accountEnabled = $false; userType = 'Member'; createdDateTime = (Get-TestDate 400); signInActivity = $null }
            )
        }
    }

    It 'flags an account whose latest sign-in is past the threshold' {
        $row = Get-KRSStaleAccount | Where-Object UserPrincipalName -eq 'old@m365.kingsruleusa.com'
        $row.DaysInactive | Should -BeIn 149, 150, 151
        $row.Finding | Should -BeLike 'No sign-in for*'
    }

    It 'uses the most recent of all sign-in timestamps' {
        Get-KRSStaleAccount | Where-Object UserPrincipalName -eq 'recent@m365.kingsruleusa.com' | Should -BeNullOrEmpty
    }

    It 'flags an old account that never signed in' {
        (Get-KRSStaleAccount | Where-Object UserPrincipalName -eq 'never@m365.kingsruleusa.com').Finding | Should -Be 'Enabled but never signed in'
    }

    It 'ignores new and disabled accounts' {
        Get-KRSStaleAccount | Where-Object UserPrincipalName -in 'new@m365.kingsruleusa.com', 'disabled@m365.kingsruleusa.com' | Should -BeNullOrEmpty
    }

    It 'honours -InactiveDays' {
        @(Get-KRSStaleAccount -InactiveDays 200).UserPrincipalName | Should -Not -Contain 'old@m365.kingsruleusa.com'
    }
}

Describe 'Get-KRSPrivilegedRoleReport' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'roleManagement/directory/roleDefinitions' } -MockWith {
            @(
                [pscustomobject]@{ id = 'ga'; templateId = 'ga'; displayName = 'Global Administrator' }
                [pscustomobject]@{ id = 'reader'; templateId = 'reader'; displayName = 'Directory Readers' }
            )
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignmentScheduleInstances*' } -MockWith {
            @(
                [pscustomobject]@{ principalId = 'u1'; roleDefinitionId = 'ga'; directoryScopeId = '/'; assignmentType = 'Assigned'; endDateTime = $null }
                [pscustomobject]@{ principalId = 'sp1'; roleDefinitionId = 'ga'; directoryScopeId = '/'; assignmentType = 'Assigned'; endDateTime = $null }
                [pscustomobject]@{ principalId = 'u2'; roleDefinitionId = 'reader'; directoryScopeId = '/'; assignmentType = 'Assigned'; endDateTime = $null }
            )
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleEligibilityScheduleInstances*' } -MockWith {
            [pscustomobject]@{ principalId = 'u2'; roleDefinitionId = 'ga'; directoryScopeId = '/'; endDateTime = $null }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users/u1*' } -MockWith { [pscustomobject]@{ id = 'u1'; displayName = 'Tenant Owner'; userPrincipalName = 'owner@contoso.com' } }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users/u2*' } -MockWith { [pscustomobject]@{ id = 'u2'; displayName = 'Priya Shah'; userPrincipalName = 'priya.shah@m365.kingsruleusa.com' } }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users/sp1*' -or $Uri -like 'groups/sp1*' } -MockWith { throw 'Request_ResourceNotFound (404)' }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'servicePrincipals/sp1*' } -MockWith { [pscustomobject]@{ id = 'sp1'; displayName = 'Legacy Sync App'; appId = 'x' } }
    }

    It 'flags standing Global Administrator held by a user as High' {
        $row = Get-KRSPrivilegedRoleReport | Where-Object { $_.PrincipalType -eq 'User' -and $_.RoleName -eq 'Global Administrator' }
        $row.Severity | Should -Be 'High'
        $row.AssignmentState | Should -Be 'Active (permanent)'
    }

    It 'flags an app holding a privileged role as High' {
        (Get-KRSPrivilegedRoleReport | Where-Object PrincipalType -eq 'ServicePrincipal').Finding | Should -Be 'App holds a privileged directory role'
    }

    It 'returns PIM-eligible and non-privileged assignments only with -IncludeCompliant' {
        Get-KRSPrivilegedRoleReport | Where-Object AssignmentState -eq 'Eligible' | Should -BeNullOrEmpty
        (Get-KRSPrivilegedRoleReport -IncludeCompliant | Where-Object AssignmentState -eq 'Eligible').Severity | Should -Be 'Info'
    }

    It 'redacts users outside the pilot' {
        $row = Get-KRSPrivilegedRoleReport -Redact | Where-Object PrincipalType -eq 'User'
        $row.UserPrincipalName | Should -Be 'o***@contoso.com'
    }

    It 'falls back to roleAssignments when PIM data is unavailable' {
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignmentScheduleInstances*' } -MockWith { throw 'Forbidden (403)' }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'roleManagement/directory/roleAssignments' } -MockWith {
            [pscustomobject]@{ principalId = 'u1'; roleDefinitionId = 'ga'; directoryScopeId = '/' }
        }
        $rows = Get-KRSPrivilegedRoleReport -WarningAction SilentlyContinue
        ($rows | Where-Object PrincipalType -eq 'User').AssignmentState | Should -Be 'Active (permanent)'
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleEligibilityScheduleInstances*' } -Times 0
    }

    It 'adds a tenant baseline row when there are fewer than 2 Global Administrators' {
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignmentScheduleInstances*' } -MockWith {
            [pscustomobject]@{ principalId = 'u1'; roleDefinitionId = 'ga'; directoryScopeId = '/'; assignmentType = 'Assigned'; endDateTime = $null }
        }
        (Get-KRSPrivilegedRoleReport | Where-Object PrincipalType -eq 'Tenant').Severity | Should -Be 'Medium'
    }
}

Describe 'Get-KRSGuestAccessReport' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive -PilotMemberIds 'g-pilot'
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like "users?`$filter=userType eq 'Guest'*" } -MockWith {
            @(
                [pscustomobject]@{ id = 'g-pending'; displayName = 'Pending'; mail = 'p@partner.com'; userPrincipalName = 'p_partner.com#EXT#@t.onmicrosoft.com'; accountEnabled = $true; createdDateTime = (Get-TestDate 60); externalUserState = 'PendingAcceptance'; externalUserStateChangeDateTime = (Get-TestDate 60); signInActivity = $null }
                [pscustomobject]@{ id = 'g-idle'; displayName = 'Idle'; mail = 'i@partner.com'; userPrincipalName = 'i_partner.com#EXT#@t.onmicrosoft.com'; accountEnabled = $true; createdDateTime = (Get-TestDate 300); externalUserState = 'Accepted'; externalUserStateChangeDateTime = (Get-TestDate 300); signInActivity = [pscustomobject]@{ lastSignInDateTime = (Get-TestDate 120) } }
                [pscustomobject]@{ id = 'g-pilot'; displayName = 'Pilot Guest'; mail = 'pg@partner.com'; userPrincipalName = 'pg_partner.com#EXT#@t.onmicrosoft.com'; accountEnabled = $true; createdDateTime = (Get-TestDate 20); externalUserState = 'Accepted'; externalUserStateChangeDateTime = (Get-TestDate 20); signInActivity = [pscustomobject]@{ lastSignInDateTime = (Get-TestDate 1) } }
            )
        }
    }

    It 'flags an invitation pending past the limit' {
        (Get-KRSGuestAccessReport -Scope Tenant | Where-Object InvitationState -eq 'PendingAcceptance').Finding | Should -BeLike 'Invitation not redeemed for 60 days'
    }

    It 'flags an inactive accepted guest' {
        (Get-KRSGuestAccessReport -Scope Tenant | Where-Object DaysInactive -ge 119).Finding | Should -BeLike 'No sign-in for*'
    }

    It 'scopes Pilot to guests in the pilot group' {
        $rows = @(Get-KRSGuestAccessReport -IncludeCompliant)
        $rows.Count | Should -Be 1
        $rows[0].DisplayName | Should -Be 'Pilot Guest'
    }

    It 'masks guest identity and mail outside the pilot' {
        $row = Get-KRSGuestAccessReport -Scope Tenant -Redact | Where-Object InvitationState -eq 'PendingAcceptance'
        $row.UserPrincipalName | Should -Match '^guest-'
        $row.Mail | Should -Be 'p***@partner.com'
    }
}

Describe 'Get-KRSAppCredentialRisk' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'applications?*' } -MockWith {
            [pscustomobject]@{
                id = 'app1'; appId = 'a1'; displayName = 'HR Connector'
                passwordCredentials = @(
                    [pscustomobject]@{ displayName = 'soon'; keyId = 'k1'; startDateTime = (Get-TestDate 80); endDateTime = [datetime]::UtcNow.AddDays(10).ToString('o') }
                    [pscustomobject]@{ displayName = 'long'; keyId = 'k2'; startDateTime = (Get-TestDate 10); endDateTime = [datetime]::UtcNow.AddDays(700).ToString('o') }
                    [pscustomobject]@{ displayName = 'old'; keyId = 'k3'; startDateTime = (Get-TestDate 400); endDateTime = (Get-TestDate 5) }
                )
                keyCredentials = @(
                    [pscustomobject]@{ displayName = 'CN=ok'; keyId = 'k4'; startDateTime = (Get-TestDate 10); endDateTime = [datetime]::UtcNow.AddDays(300).ToString('o') }
                )
            }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like "servicePrincipals(appId=*" } -MockWith {
            [pscustomobject]@{ id = 'graph-sp'; appRoles = @(
                    [pscustomobject]@{ id = 'r-rm'; value = 'RoleManagement.ReadWrite.Directory' }
                    [pscustomobject]@{ id = 'r-mail'; value = 'Mail.Send' }
                    [pscustomobject]@{ id = 'r-user'; value = 'User.Read.All' }
                ) 
            }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'servicePrincipals/graph-sp/appRoleAssignedTo*' } -MockWith {
            @(
                [pscustomobject]@{ principalDisplayName = 'Risky App'; principalId = 'p1'; appRoleId = 'r-rm' }
                [pscustomobject]@{ principalDisplayName = 'Mailer'; principalId = 'p2'; appRoleId = 'r-mail' }
                [pscustomobject]@{ principalDisplayName = 'Reader'; principalId = 'p3'; appRoleId = 'r-user' }
            )
        }
    }

    It 'rates a credential expiring within the window as High' {
        (Get-KRSAppCredentialRisk | Where-Object Detail -eq 'Secret: soon').Severity | Should -Be 'High'
    }

    It 'rates a secret valid for more than a year as Medium' {
        (Get-KRSAppCredentialRisk | Where-Object Detail -eq 'Secret: long').Severity | Should -Be 'Medium'
    }

    It 'rates an expired credential as Low' {
        (Get-KRSAppCredentialRisk | Where-Object Detail -eq 'Secret: old').Finding | Should -BeLike 'Expired secret*'
    }

    It 'does not flag a healthy certificate' {
        Get-KRSAppCredentialRisk | Where-Object Detail -eq 'Certificate: CN=ok' | Should -BeNullOrEmpty
    }

    It 'rates privilege-escalation permissions as Critical and ignores low-risk ones' {
        $perms = Get-KRSAppCredentialRisk | Where-Object FindingType -eq 'HighPrivilegePermission'
        ($perms | Where-Object AppDisplayName -eq 'Risky App').Severity | Should -Be 'Critical'
        ($perms | Where-Object AppDisplayName -eq 'Mailer').Severity | Should -Be 'High'
        $perms | Where-Object AppDisplayName -eq 'Reader' | Should -BeNullOrEmpty
    }
}

Describe 'Get-KRSConditionalAccessInventory' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'policies/identitySecurityDefaultsEnforcementPolicy' } -MockWith { [pscustomobject]@{ isEnabled = $false } }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users/*' } -MockWith { [pscustomobject]@{ id = 'x'; displayName = 'Someone'; userPrincipalName = 'someone@contoso.com' } }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'identity/conditionalAccess/policies' } -MockWith {
            @(
                [pscustomobject]@{ displayName = 'CA001 Require MFA'; state = 'disabled'; modifiedDateTime = (Get-TestDate 3)
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @() ; excludeGroups = @() }; applications = [pscustomobject]@{ includeApplications = @('All') }; clientAppTypes = @('all') }
                    grantControls = [pscustomobject]@{ builtInControls = @('mfa'); authenticationStrength = $null } 
                }
                [pscustomobject]@{ displayName = 'CA002 Too many exclusions'; state = 'enabled'; modifiedDateTime = (Get-TestDate 3)
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333'); excludeGroups = @() }; applications = [pscustomobject]@{ includeApplications = @('Office365') }; clientAppTypes = @('all') }
                    grantControls = [pscustomobject]@{ builtInControls = @('compliantDevice') } 
                }
            )
        }
    }

    It 'flags a disabled policy as Low' {
        (Get-KRSConditionalAccessInventory | Where-Object PolicyName -eq 'CA001 Require MFA').Severity | Should -Be 'Low'
    }

    It 'flags too many direct exclusions as Medium and resolves them with redaction' {
        $row = Get-KRSConditionalAccessInventory -Redact | Where-Object PolicyName -eq 'CA002 Too many exclusions'
        $row.Severity | Should -Be 'Medium'
        $row.ExcludedUsers | Should -BeLike 's***@contoso.com*'
    }

    It 'reports missing MFA-for-all and legacy-auth baselines as High' {
        $baseline = Get-KRSConditionalAccessInventory | Where-Object PolicyName -eq '(tenant baseline)'
        @($baseline).Count | Should -Be 2
        $baseline.Severity | Should -Be @('High', 'High')
    }

    It 'treats the baselines as covered when security defaults are on' {
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'policies/identitySecurityDefaultsEnforcementPolicy' } -MockWith { [pscustomobject]@{ isEnabled = $true } }
        Get-KRSConditionalAccessInventory | Where-Object PolicyName -eq '(tenant baseline)' | Should -BeNullOrEmpty
    }
}

Describe 'Principal cache priming' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        $ids = 1..30 | ForEach-Object { "u$_" }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'roleManagement/directory/roleDefinitions' } -MockWith {
            [pscustomobject]@{ id = 'ga'; templateId = 'ga'; displayName = 'Global Administrator' }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleAssignmentScheduleInstances*' } -MockWith {
            1..30 | ForEach-Object { [pscustomobject]@{ principalId = "u$_"; roleDefinitionId = 'ga'; directoryScopeId = '/'; assignmentType = 'Assigned'; endDateTime = $null } }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'roleManagement/directory/roleEligibilityScheduleInstances*' } -MockWith { }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users?$select=id,displayName,userPrincipalName*' } -MockWith {
            1..30 | ForEach-Object { [pscustomobject]@{ id = "u$_"; displayName = "User $_"; userPrincipalName = "user$_@contoso.com" } }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'servicePrincipals?$select*' } -MockWith { }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users/*' } -MockWith { throw 'should not be called' }
    }

    It 'resolves many principals from one bulk read instead of per-ID lookups' {
        $rows = @(Get-KRSPrivilegedRoleReport | Where-Object PrincipalType -eq 'User')
        $rows.Count | Should -Be 30
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users/*' } -Times 0
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users?$select=id,displayName,userPrincipalName*' } -Times 1 -Exactly
    }

    It 'still flags too many Global Administrators' {
        (Get-KRSPrivilegedRoleReport | Where-Object PrincipalType -eq 'Tenant').Finding | Should -BeLike '30 active Global Administrators*'
    }
}
