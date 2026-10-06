BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $ModuleManifest -Force
}

Describe 'Invoke-KRSGraphRequest' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Start-Sleep -ModuleName KRSSecOps
    }

    It 'follows @odata.nextLink with -All' {
        Mock Invoke-MgGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like '*page=2' } -MockWith { [pscustomobject]@{ value = @([pscustomobject]@{ id = 3 }) } }
        Mock Invoke-MgGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -notlike '*page=2' } -MockWith {
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 1 }, [pscustomobject]@{ id = 2 }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?page=2' }
        }
        InModuleScope KRSSecOps { @(Invoke-KRSGraphRequest -Uri 'users' -All).id | Should -Be @(1, 2, 3) }
    }

    It 'returns only the first page without -All' {
        Mock Invoke-MgGraphRequest -ModuleName KRSSecOps -MockWith {
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 1 }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?page=2' }
        }
        InModuleScope KRSSecOps { @(Invoke-KRSGraphRequest -Uri 'users').Count | Should -Be 1 }
        Should -Invoke Invoke-MgGraphRequest -ModuleName KRSSecOps -Times 1 -Exactly
    }

    It 'prefixes relative URIs with the v1.0 endpoint' {
        Mock Invoke-MgGraphRequest -ModuleName KRSSecOps -MockWith { [pscustomobject]@{ id = 'x' } }
        InModuleScope KRSSecOps { $null = Invoke-KRSGraphRequest -Uri '/organization' }
        Should -Invoke Invoke-MgGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/organization' }
    }

    It 'retries on throttling and then succeeds' {
        $state = @{ Calls = 0 }
        Mock Invoke-MgGraphRequest -ModuleName KRSSecOps -MockWith {
            $state.Calls++
            if ($state.Calls -lt 3) { throw 'Response status code does not indicate success: TooManyRequests (Too Many Requests).' }
            [pscustomobject]@{ id = 'ok' }
        }
        InModuleScope KRSSecOps { (Invoke-KRSGraphRequest -Uri 'organization').id | Should -Be 'ok' }
        $state.Calls | Should -Be 3
        Should -Invoke Start-Sleep -ModuleName KRSSecOps -Times 2 -Exactly
    }

    It 'does not retry a permission error' {
        Mock Invoke-MgGraphRequest -ModuleName KRSSecOps -MockWith { throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
        InModuleScope KRSSecOps { { Invoke-KRSGraphRequest -Uri 'organization' } | Should -Throw '*Forbidden*' }
        Should -Invoke Start-Sleep -ModuleName KRSSecOps -Times 0
    }

    It 'gives up after -MaxRetries' {
        Mock Invoke-MgGraphRequest -ModuleName KRSSecOps -MockWith { throw 'ServiceUnavailable (503)' }
        InModuleScope KRSSecOps { { Invoke-KRSGraphRequest -Uri 'organization' -MaxRetries 2 } | Should -Throw }
        Should -Invoke Invoke-MgGraphRequest -ModuleName KRSSecOps -Times 3 -Exactly
    }
}

Describe 'Get-KRSConfig' {
    It 'loads a complete settings file and applies defaults' {
        $path = Join-Path $TestDrive 'settings.json'
        @{ TenantId = 't'; ClientId = 'c'; CertificateThumbprint = 'ABC'; PilotDomain = '@M365.KingsRuleUSA.com'; LogPath = '' } | ConvertTo-Json | Set-Content $path
        InModuleScope KRSSecOps -Parameters @{ Path = $path } {
            param($Path)
            $config = Get-KRSConfig -Path $Path
            $config.PilotDomain | Should -Be 'm365.kingsruleusa.com'
            $config.StaleAccountDays | Should -Be 90
            $config.LogPath | Should -Not -BeNullOrEmpty
        }
    }

    It 'rejects placeholder values' {
        $path = Join-Path $TestDrive 'placeholder.json'
        Copy-Item (Join-Path $PSScriptRoot '..' 'src' 'KRSSecOps' 'Config' 'settings.example.json') $path
        InModuleScope KRSSecOps -Parameters @{ Path = $path } {
            param($Path)
            { Get-KRSConfig -Path $Path } | Should -Throw '*placeholder*'
        }
    }

    It 'reports a missing file clearly' {
        InModuleScope KRSSecOps { { Get-KRSConfig -Path '/nope/settings.json' } | Should -Throw '*not found*' }
    }
}

Describe 'Format-KRSDayCount' {
    It 'formats <Days> as <Expected>' -ForEach @(
        @{ Days = 1; Expected = '1 day' }
        @{ Days = 0; Expected = '0 days' }
        @{ Days = 5; Expected = '5 days' }
        @{ Days = -1; Expected = '-1 day' }
    ) {
        InModuleScope KRSSecOps -Parameters @{ Days = $Days; Expected = $Expected } {
            param($Days, $Expected)
            Format-KRSDayCount -Days $Days | Should -Be $Expected
        }
    }
}

Describe 'Write-KRSLog' {
    It 'writes one JSON line with the correlation ID, even under -WhatIf' {
        Initialize-TestSession -Drive $TestDrive
        InModuleScope KRSSecOps -Parameters @{ Drive = $TestDrive } {
            param($Drive)
            $WhatIfPreference = $true
            Write-KRSLog -Action 'UnitTest' -Target 'target-1' -Message 'hello'
            $WhatIfPreference = $false
            $record = Get-ChildItem (Join-Path $Drive 'logs') -Filter '*.jsonl' | Get-Content | ConvertFrom-Json | Where-Object action -eq 'UnitTest'
            $record.correlationId | Should -Be 'test-correlation-id'
            $record.target | Should -Be 'target-1'
            $record.level | Should -Be 'Info'
        }
    }
}

Describe 'Invoke-KRSIdentityAudit' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        $row = { param($Severity, $Upn) [pscustomobject]@{ UserPrincipalName = $Upn; Finding = "test $Severity"; Severity = $Severity; SeverityRank = 0 } }
        Mock Get-KRSMfaGap -ModuleName KRSSecOps -MockWith { & $row 'Critical' 'a@m365.kingsruleusa.com'; & $row 'Info' 'b@m365.kingsruleusa.com' }
        Mock Get-KRSStaleAccount -ModuleName KRSSecOps -MockWith { & $row 'Medium' 'c@m365.kingsruleusa.com' }
        Mock Get-KRSPrivilegedRoleReport -ModuleName KRSSecOps -MockWith { & $row 'High' 'd@m365.kingsruleusa.com' }
        Mock Get-KRSGuestAccessReport -ModuleName KRSSecOps -MockWith { }
        Mock Get-KRSAppCredentialRisk -ModuleName KRSSecOps -MockWith { throw 'Forbidden: Application.Read.All missing' }
        Mock Get-KRSConditionalAccessInventory -ModuleName KRSSecOps -MockWith { & $row 'Low' $null }
    }

    It 'counts findings by severity and excludes Info rows' {
        $summary = Invoke-KRSIdentityAudit -WarningAction SilentlyContinue
        $summary.TotalFindings | Should -Be 4
        $summary.Critical | Should -Be 1
        $summary.High | Should -Be 1
        $summary.Medium | Should -Be 1
        $summary.Low | Should -Be 1
    }

    It 'keeps going when one check fails and records the failure' {
        $summary = Invoke-KRSIdentityAudit -WarningAction SilentlyContinue
        $summary.FailedChecks | Should -Be 1
        ($summary.Checks | Where-Object Check -eq 'AppCredentialRisk').Status | Should -Be 'Failed'
        ($summary.Checks | Where-Object Check -eq 'ConditionalAccess').Status | Should -Be 'Completed'
    }

    It 'writes per-check CSVs, findings.csv and summary.json' {
        $summary = Invoke-KRSIdentityAudit -WarningAction SilentlyContinue
        foreach ($file in 'MfaGap.csv', 'StaleAccount.csv', 'findings.csv', 'summary.json') {
            Join-Path $summary.OutputFolder $file | Should -Exist
        }
        $findings = Import-Csv (Join-Path $summary.OutputFolder 'findings.csv')
        $findings[0].Severity | Should -Be 'Critical'
        (Get-Content (Join-Path $summary.OutputFolder 'summary.json') -Raw | ConvertFrom-Json).TotalFindings | Should -Be 4
    }

    It 'runs only the checks requested' {
        $null = Invoke-KRSIdentityAudit -Check MfaGap
        Should -Invoke Get-KRSMfaGap -ModuleName KRSSecOps -Times 1 -Exactly
        Should -Invoke Get-KRSStaleAccount -ModuleName KRSSecOps -Times 0
    }

    It 'passes -InactiveDays to the stale and guest checks and records it' {
        $summary = Invoke-KRSIdentityAudit -Check StaleAccount, GuestAccess -InactiveDays 1
        Should -Invoke Get-KRSStaleAccount -ModuleName KRSSecOps -ParameterFilter { $InactiveDays -eq 1 }
        Should -Invoke Get-KRSGuestAccessReport -ModuleName KRSSecOps -ParameterFilter { $InactiveDays -eq 1 }
        $summary.InactiveDays | Should -Be 1
    }

    It 'defaults -InactiveDays to the settings value' {
        $summary = Invoke-KRSIdentityAudit -Check StaleAccount
        Should -Invoke Get-KRSStaleAccount -ModuleName KRSSecOps -ParameterFilter { $InactiveDays -eq 90 }
        $summary.InactiveDays | Should -Be 90
    }

    It 'passes Scope and Redact through to the checks' {
        $null = Invoke-KRSIdentityAudit -Check MfaGap -Scope Tenant -Redact
        Should -Invoke Get-KRSMfaGap -ModuleName KRSSecOps -ParameterFilter { $Scope -eq 'Tenant' -and $Redact }
    }
}
