BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $ModuleManifest -Force
}

Describe 'Test-KRSPilotScope' {
    It 'returns <Expected> for <Upn>' -ForEach @(
        @{ Upn = 'amara.okafor@m365.kingsruleusa.com'; Expected = $true }
        @{ Upn = 'Amara.Okafor@M365.KingsRuleUSA.com'; Expected = $true }
        @{ Upn = 'admin@contoso.com'; Expected = $false }
        @{ Upn = 'user@evil.m365.kingsruleusa.com'; Expected = $false }
        @{ Upn = 'user@m365.kingsruleusa.com.evil.com'; Expected = $false }
        @{ Upn = 'user_m365.kingsruleusa.com#EXT#@contoso.onmicrosoft.com'; Expected = $false }
        @{ Upn = '@m365.kingsruleusa.com'; Expected = $false }
        @{ Upn = ''; Expected = $false }
    ) {
        Test-KRSPilotScope -UserPrincipalName $Upn -PilotDomain $PilotDomain | Should -Be $Expected
    }

    It 'accepts pipeline input by property name' {
        $users = [pscustomobject]@{ UserPrincipalName = 'a@m365.kingsruleusa.com' }, [pscustomobject]@{ UserPrincipalName = 'b@contoso.com' }
        @($users | Test-KRSPilotScope -PilotDomain $PilotDomain) | Should -Be @($true, $false)
    }

    It 'uses the connected session pilot domain when none is given' {
        Initialize-TestSession -Drive $TestDrive
        Test-KRSPilotScope -UserPrincipalName 'a@m365.kingsruleusa.com' | Should -BeTrue
    }

    It 'fails when not connected and no domain is given' {
        InModuleScope KRSSecOps { $script:KRSConfig = $null }
        { Test-KRSPilotScope -UserPrincipalName 'a@m365.kingsruleusa.com' } | Should -Throw '*Connect-KRSTenant*'
    }
}

Describe 'Assert-KRSPilotScope (write guard)' {
    BeforeEach { Initialize-TestSession -Drive $TestDrive }

    It 'allows pilot users' {
        InModuleScope KRSSecOps { { Assert-KRSPilotScope -UserPrincipalName 'amara.okafor@m365.kingsruleusa.com' } | Should -Not -Throw }
    }

    It 'blocks a user outside the pilot and logs the violation' {
        InModuleScope KRSSecOps -Parameters @{ Drive = $TestDrive } {
            param($Drive)
            { Assert-KRSPilotScope -UserPrincipalName 'ceo@contoso.com' } | Should -Throw '*Scope guard blocked*'
            $log = Get-ChildItem (Join-Path $Drive 'logs') -Filter '*.jsonl' | Get-Content | ConvertFrom-Json
            $log.action | Should -Contain 'ScopeViolation'
        }
    }

    It 'blocks the whole batch if any one target is outside the pilot' {
        InModuleScope KRSSecOps {
            { Assert-KRSPilotScope -UserPrincipalName 'a@m365.kingsruleusa.com', 'b@contoso.com' } | Should -Throw
        }
    }
}

Describe 'Redaction' {
    BeforeEach { Initialize-TestSession -Drive $TestDrive -PilotMemberIds 'group-member-id' }

    It 'masks a member UPN to its first letter and domain' {
        InModuleScope KRSSecOps {
            ConvertTo-KRSMaskedUpn -UserPrincipalName 'john.doe@contoso.com' | Should -Be 'j***@contoso.com'
        }
    }

    It 'returns empty for an empty UPN' {
        InModuleScope KRSSecOps {
            ConvertTo-KRSMaskedUpn -UserPrincipalName $null | Should -BeNullOrEmpty
        }
    }

    It 'replaces guest UPNs with a stable hash' {
        InModuleScope KRSSecOps {
            $first = ConvertTo-KRSMaskedUpn -UserPrincipalName 'x_contoso.com#EXT#@tenant.onmicrosoft.com'
            $first | Should -Match '^guest-[0-9a-f]{8}$'
            ConvertTo-KRSMaskedUpn -UserPrincipalName 'x_contoso.com#EXT#@tenant.onmicrosoft.com' | Should -Be $first
        }
    }

    It 'leaves pilot identities readable and masks the rest' {
        InModuleScope KRSSecOps {
            $pilot = Format-KRSIdentity -UserPrincipalName 'amara.okafor@m365.kingsruleusa.com' -DisplayName 'Amara Okafor' -Redact
            $pilot.DisplayName | Should -Be 'Amara Okafor'
            $pilot.InPilot | Should -BeTrue

            $other = Format-KRSIdentity -UserPrincipalName 'jane@contoso.com' -DisplayName 'Jane Smith' -Redact
            $other.DisplayName | Should -Be 'Redacted (outside pilot)'
            $other.UserPrincipalName | Should -Be 'j***@contoso.com'
            $other.InPilot | Should -BeFalse
        }
    }

    It 'loads pilot group members once and keeps users only' {
        InModuleScope KRSSecOps {
            $script:KRSConfig.PilotGroupId = 'pilot-group'
            $script:KRSPilotMemberIds = $null
            Mock Invoke-KRSGraphRequest -ParameterFilter { $Uri -like 'groups/pilot-group/transitiveMembers*' } -MockWith {
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'user-in-group' }
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'nested-group' }
            }
            (Format-KRSIdentity -Id 'user-in-group').InPilot | Should -BeTrue
            (Format-KRSIdentity -Id 'nested-group').InPilot | Should -BeFalse
            Should -Invoke Invoke-KRSGraphRequest -Times 1 -Exactly
        }
    }

    It 'treats pilot group members as in pilot for reads' {
        InModuleScope KRSSecOps {
            (Format-KRSIdentity -UserPrincipalName 'guest_x#EXT#@t.onmicrosoft.com' -Id 'group-member-id').InPilot | Should -BeTrue
        }
    }
}
