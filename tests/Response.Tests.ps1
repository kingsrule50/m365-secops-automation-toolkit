BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $ModuleManifest -Force

    $script:Amara = 'amara.okafor@m365.kingsruleusa.com'

    function Set-ResponseMock {
        # Fake Graph and Exchange for one compromised pilot user. $script:State drives what they return.
        param([int]$FailedSignIns = 4, [string]$RiskLevel = '', [switch]$RiskForbidden, [switch]$AccountDisabled, [switch]$RuleDisabled)
        $script:State = @{ Enabled = -not $AccountDisabled; RuleOn = -not $RuleDisabled; Failed = $FailedSignIns; Risk = $RiskLevel; RiskForbidden = [bool]$RiskForbidden }

        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -MockWith { throw "Unexpected Graph call $Method $Uri" }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'users/*' -and $Uri -notlike '*/revokeSignInSessions' -and $Method -notin 'PATCH', 'POST' } -MockWith {
            [pscustomobject]@{ id = 'u-amara'; displayName = 'Amara'; userPrincipalName = 'amara.okafor@m365.kingsruleusa.com'; accountEnabled = $script:State.Enabled }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'auditLogs/signIns*' } -MockWith {
            for ($i = 1; $i -le $script:State.Failed; $i++) {
                [pscustomobject]@{ createdDateTime = (Get-TestDate -DaysAgo 1); appDisplayName = 'Office 365 Exchange Online'; clientAppUsed = 'Browser'; ipAddress = "203.0.113.$i"; location = [pscustomobject]@{ countryOrRegion = 'NG'; city = 'Lagos' }; status = [pscustomobject]@{ errorCode = 50126; failureReason = 'Invalid username or password.' } }
            }
            [pscustomobject]@{ createdDateTime = (Get-TestDate -DaysAgo 1); appDisplayName = 'Authenticated SMTP'; clientAppUsed = 'Authenticated SMTP'; ipAddress = '198.51.100.7'; location = [pscustomobject]@{ countryOrRegion = 'US'; city = 'Newark' }; status = [pscustomobject]@{ errorCode = 0; failureReason = $null } }
            [pscustomobject]@{ createdDateTime = (Get-TestDate -DaysAgo 2); appDisplayName = 'Outlook'; clientAppUsed = 'Browser'; ipAddress = '2001:db8::1'; location = [pscustomobject]@{ countryOrRegion = 'NG'; city = 'Lagos' }; status = [pscustomobject]@{ errorCode = 0; failureReason = 'Other.' } }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like 'identityProtection/riskyUsers/*' } -MockWith {
            if ($script:State.RiskForbidden) { throw [System.Exception]::new('Forbidden (403): Authorization_RequestDenied') }
            if (-not $script:State.Risk) { throw [System.Exception]::new('Response status code does not indicate success: NotFound (Not Found).') }
            [pscustomobject]@{ riskLevel = $script:State.Risk; riskState = 'atRisk'; riskDetail = 'none'; riskLastUpdatedDateTime = (Get-TestDate -DaysAgo 1) }
        }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Method -eq 'PATCH' } -MockWith { $script:State.Enabled = [bool]$Body.accountEnabled }
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Uri -like '*/revokeSignInSessions' } -MockWith { }

        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -MockWith { throw "Unexpected Exchange call $Name" }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-InboxRule' } -MockWith {
            [pscustomobject]@{ Name = 'Forward invoices'; RuleIdentity = '7062594198058303489'; Enabled = $script:State.RuleOn; ForwardTo = @('"collector@example.net" [SMTP:collector@example.net]'); ForwardAsAttachmentTo = $null; RedirectTo = $null }
            [pscustomobject]@{ Name = 'Move newsletters'; RuleIdentity = '1'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-AcceptedDomain' } -MockWith { [pscustomobject]@{ DomainName = 'm365.kingsruleusa.com' } }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-Mailbox' } -MockWith {
            if ($Parameters.ContainsKey('Identity')) { [pscustomobject]@{ UserPrincipalName = $Parameters['Identity']; ForwardingSmtpAddress = $null } }
            else { [pscustomobject]@{ UserPrincipalName = 'amara.okafor@m365.kingsruleusa.com' }; [pscustomobject]@{ UserPrincipalName = 'colleague@contoso.com' } }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Search-UnifiedAuditLog' } -MockWith {
            [pscustomobject]@{ AuditData = (@{ CreationTime = '2026-10-07T23:13:00'; Operation = 'New-InboxRule'; UserId = 'admin@contoso.com'; ClientIP = '203.0.113.50'; Parameters = @(@{ Name = 'Mailbox'; Value = 'amara.okafor@m365.kingsruleusa.com' }, @{ Name = 'Name'; Value = 'Forward invoices' }, @{ Name = 'ForwardTo'; Value = 'collector@example.net' }) } | ConvertTo-Json -Depth 4) }
            [pscustomobject]@{ AuditData = (@{ CreationTime = '2026-10-07T20:00:00'; Operation = 'Set-Mailbox'; UserId = 'admin@contoso.com'; ClientIP = '203.0.113.50'; Parameters = @(@{ Name = 'Identity'; Value = 'someone.else@contoso.com' }) } | ConvertTo-Json -Depth 4) }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Disable-InboxRule' } -MockWith { $script:State.RuleOn = $false }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Enable-InboxRule' } -MockWith { $script:State.RuleOn = $true }
    }
}

Describe 'Response helpers' {
    It 'shortens <Ip> to <Expected>' -ForEach @(
        @{ Ip = '203.0.113.7'; Expected = '203.0.x.x' }
        @{ Ip = '2001:db8::1'; Expected = '2001:db8:x' }
        @{ Ip = '[2001:db8:85a3::7]:51234'; Expected = '2001:db8:x' }
        @{ Ip = '203.0.113.7:443'; Expected = '203.0.x.x' }
        @{ Ip = '::ffff:203.0.113.7'; Expected = '203.0.x.x' }
        @{ Ip = 'not-an-ip'; Expected = 'x.x.x.x' }
        @{ Ip = ''; Expected = '' }
    ) {
        InModuleScope KRSSecOps -Parameters @{ Ip = $Ip; Expected = $Expected } {
            param($Ip, $Expected)
            ConvertTo-KRSMaskedIp -IpAddress $Ip | Should -Be $Expected
        }
    }

    It 'gives a failure reason only to failed sign-ins' {
        Set-ResponseMock -FailedSignIns 1
        InModuleScope KRSSecOps {
            $events = @(Get-KRSSignInEvent -UserId 'u-amara' -Days 7)
            ($events | Where-Object Result -eq 'Failure').FailureReason | Should -Be 'Invalid username or password.'
            @($events | Where-Object Result -eq 'Success' | Where-Object FailureReason).Count | Should -Be 0
        }
    }

    It 'masks actors outside the pilot, domain included, and keeps pilot actors' {
        InModuleScope KRSSecOps {
            ConvertTo-KRSMaskedActor -Actor 'admin@contoso.com' -PilotDomain 'm365.kingsruleusa.com' | Should -Match '^actor-[0-9a-f]{8} \(outside pilot\)$'
            ConvertTo-KRSMaskedActor -Actor 'amara.okafor@m365.kingsruleusa.com' -PilotDomain 'm365.kingsruleusa.com' | Should -Be 'amara.okafor@m365.kingsruleusa.com'
        }
    }
}

Describe 'Find-KRSCompromiseIndicator' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Set-ResponseMock
    }

    It 'rates an enabled external forwarding rule High' {
        $row = Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara | Where-Object Signal -eq 'ExternalInboxRule'
        $row.Severity | Should -Be 'High'
        $row.Detail | Should -BeLike "*'Forward invoices'*collector@example.net*"
    }

    It 'keeps a disabled forwarding rule visible as Low evidence' {
        Set-ResponseMock -RuleDisabled
        $row = Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara | Where-Object Signal -eq 'ExternalInboxRule'
        $row.Severity | Should -Be 'Low'
        $row.Detail | Should -BeLike '*disabled*'
    }

    It 'reports who created the rule, only for this mailbox, in UTC' {
        $row = Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara | Where-Object Signal -eq 'RuleChangeAudit'
        $row.Detail | Should -BeLike '1 rule/forwarding change(s); latest New-InboxRule by admin@contoso.com from 203.0.113.50*'
        $row.ObservedUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-07T23:13:00', 'Utc'))
    }

    It 'masks the actor and IP with -Redact' {
        $row = Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara -Redact | Where-Object Signal -eq 'RuleChangeAudit'
        $row.Detail | Should -Not -BeLike '*contoso.com*'
        $row.Detail | Should -Not -BeLike '*203.0.113.50*'
        $row.Detail | Should -BeLike '*actor-* (outside pilot) from 203.0.x.x*'
    }

    It 'rates <Failed> failed sign-ins <Expected>' -ForEach @(
        @{ Failed = 2; Expected = $null }
        @{ Failed = 4; Expected = 'Medium' }
        @{ Failed = 12; Expected = 'High' }
    ) {
        Set-ResponseMock -FailedSignIns $Failed
        (Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara | Where-Object Signal -eq 'FailedSignIns').Severity | Should -Be $Expected
    }

    It 'flags a successful legacy-protocol sign-in and sign-ins from more than one country' {
        $rows = @(Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara)
        ($rows | Where-Object Signal -eq 'LegacySignIn').Detail | Should -BeLike '*Authenticated SMTP*'
        ($rows | Where-Object Signal -eq 'MultipleCountries').Detail | Should -BeLike '*NG*'
    }

    It 'maps Entra ID Protection risk <Level> to <Expected>' -ForEach @(
        @{ Level = 'high'; Expected = 'Critical' }
        @{ Level = 'medium'; Expected = 'High' }
        @{ Level = 'low'; Expected = 'Medium' }
    ) {
        Set-ResponseMock -RiskLevel $Level
        (Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara | Where-Object Signal -eq 'UserRisk').Severity | Should -Be $Expected
    }

    It 'treats a user never flagged by Identity Protection as no risk' {
        (Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara -IncludeCompliant | Where-Object Signal -eq 'UserRisk').Severity | Should -Be 'Info'
    }

    It 'shows a source it could not read instead of reading it as clean' {
        Set-ResponseMock -RiskForbidden
        (Find-KRSCompromiseIndicator -UserPrincipalName $script:Amara | Where-Object Signal -eq 'UserRisk').Detail | Should -BeLike '(not checked)*Forbidden*'
    }

    It 'investigates every pilot mailbox by default and nobody else' {
        @(Find-KRSCompromiseIndicator).UserPrincipalName | Sort-Object -Unique | Should -Be @($script:Amara)
    }

    It 'refuses to investigate an account outside the pilot' {
        { Find-KRSCompromiseIndicator -UserPrincipalName 'colleague@contoso.com' } | Should -Throw '*limited to the pilot domain*'
    }
}

Describe 'Invoke-KRSContainment' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Get-ChildItem -Path (Join-Path $TestDrive 'containment') -ErrorAction SilentlyContinue | Remove-Item -Force
        Set-ResponseMock
        $script:Contain = @{ UserPrincipalName = $script:Amara; TicketId = 'INC-1042'; ApprovedBy = 'J. Mentor' }
    }

    It 'enforces the two-person rule before touching anything' {
        { Invoke-KRSContainment -UserPrincipalName $script:Amara -TicketId 'INC-1042' -ApprovedBy ([Environment]::UserName) -Confirm:$false } | Should -Throw '*Two-person rule*'
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -Times 0
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 0
    }

    It 'blocks an account outside the pilot before touching anything' {
        { Invoke-KRSContainment -UserPrincipalName 'colleague@contoso.com' -TicketId 'INC-1042' -ApprovedBy 'J. Mentor' -Confirm:$false } | Should -Throw '*Scope guard blocked*'
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -Times 0
    }

    It 'requires a ticket ID in the expected format' {
        { Invoke-KRSContainment -UserPrincipalName $script:Amara -TicketId 'urgent' -ApprovedBy 'J. Mentor' -Confirm:$false } | Should -Throw
    }

    It 'changes nothing and writes no record under -WhatIf' {
        $rows = @(Invoke-KRSContainment @script:Contain -WhatIf)
        @($rows | Where-Object Result -eq 'WhatIf').Count | Should -Be 3
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -Times 0 -ParameterFilter { $Method -in 'PATCH', 'POST' }
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 0 -ParameterFilter { $Name -eq 'Disable-InboxRule' }
        Join-Path $TestDrive 'containment' | Get-ChildItem -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'blocks sign-in, revokes sessions and disables only the external rule' {
        $rows = @(Invoke-KRSContainment @script:Contain -Confirm:$false)
        $rows.Action | Should -Be @('BlockSignIn', 'RevokeSessions', 'DisableExternalInboxRules')
        $rows.Result | Should -Be @('Done', 'Done', 'Done')
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -Times 1 -Exactly -ParameterFilter { $Method -eq 'PATCH' -and $Uri -eq 'users/u-amara' -and $Body.accountEnabled -eq $false }
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 1 -Exactly -ParameterFilter { $Name -eq 'Disable-InboxRule' -and $Parameters['Identity'] -eq '7062594198058303489' }
    }

    It 'writes a containment record with the approver and the before state' {
        $rows = @(Invoke-KRSContainment @script:Contain -Confirm:$false)
        $rows[0].RecordPath | Should -Exist
        $record = Get-Content -LiteralPath $rows[0].RecordPath -Raw | ConvertFrom-Json
        $record.approvedBy | Should -Be 'J. Mentor'
        $record.before.accountEnabled | Should -BeTrue
        $record.before.externalInboxRules[0].Name | Should -Be 'Forward invoices'
    }

    It 'skips blocking an account that is already blocked' {
        Set-ResponseMock -AccountDisabled
        $rows = @(Invoke-KRSContainment @script:Contain -Action BlockSignIn -Confirm:$false)
        $rows[0].Result | Should -Be 'AlreadyBlocked'
        Should -Invoke Invoke-KRSGraphRequest -ModuleName KRSSecOps -Times 0 -ParameterFilter { $Method -eq 'PATCH' }
    }

    It 'records a refused action as Failed and carries on' {
        Mock Invoke-KRSGraphRequest -ModuleName KRSSecOps -ParameterFilter { $Method -eq 'PATCH' } -MockWith { throw 'Forbidden (403): Insufficient privileges' }
        $rows = @(Invoke-KRSContainment @script:Contain -Confirm:$false -WarningAction SilentlyContinue)
        ($rows | Where-Object Action -eq 'BlockSignIn').Result | Should -Be 'Failed'
        ($rows | Where-Object Action -eq 'DisableExternalInboxRules').Result | Should -Be 'Done'
    }
}

Describe 'Undo-KRSContainment' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Get-ChildItem -Path (Join-Path $TestDrive 'containment') -ErrorAction SilentlyContinue | Remove-Item -Force
        Set-ResponseMock
        $script:RecordPath = @(Invoke-KRSContainment -UserPrincipalName $script:Amara -TicketId 'INC-1042' -ApprovedBy 'J. Mentor' -Confirm:$false)[0].RecordPath
    }

    It 'restores sign-in but keeps the malicious rule disabled' {
        $rows = @(Undo-KRSContainment -RecordPath $script:RecordPath -ApprovedBy 'J. Mentor' -Confirm:$false)
        ($rows | Where-Object Action -eq 'RestoreSignIn').Result | Should -Be 'Done'
        ($rows | Where-Object Action -eq 'RestoreInboxRule').Result | Should -Be 'KeptDisabled'
        $script:State.Enabled | Should -BeTrue
        $script:State.RuleOn | Should -BeFalse
    }

    It 're-enables the rule only with -IncludeInboxRules' {
        $null = Undo-KRSContainment -RecordPath $script:RecordPath -ApprovedBy 'J. Mentor' -IncludeInboxRules -Confirm:$false
        $script:State.RuleOn | Should -BeTrue
    }

    It 'enforces the two-person rule for recovery too' {
        { Undo-KRSContainment -RecordPath $script:RecordPath -ApprovedBy ([Environment]::UserName) -Confirm:$false } | Should -Throw '*Two-person rule*'
    }

    It 'writes an undo record next to the containment record' {
        $rows = @(Undo-KRSContainment -RecordPath $script:RecordPath -ApprovedBy 'J. Mentor' -Confirm:$false)
        $rows[0].RecordPath | Should -BeLike '*-undo-*.json'
        $rows[0].RecordPath | Should -Exist
    }
}

Describe 'Export-KRSIncidentReport' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Get-ChildItem -Path (Join-Path $TestDrive 'containment') -ErrorAction SilentlyContinue | Remove-Item -Force
        Set-ResponseMock
    }

    It 'writes the HTML report and evidence files with the containment actions' {
        $null = Invoke-KRSContainment -UserPrincipalName $script:Amara -TicketId 'INC-1042' -ApprovedBy 'J. Mentor' -Confirm:$false
        $report = Export-KRSIncidentReport -UserPrincipalName $script:Amara -TicketId 'INC-1042' -Redact
        $report.ReportPath | Should -Exist
        $folder = Split-Path $report.ReportPath -Parent
        Join-Path $folder 'indicators.csv' | Should -Exist
        Join-Path $folder 'signins.csv' | Should -Exist
        Join-Path $folder 'incident.json' | Should -Exist
        $report.ContainmentActions | Should -Be 3
        $report.CurrentState | Should -Be 'Sign-in blocked'
    }

    It 'shows who ran each action next to who approved it' {
        $null = Invoke-KRSContainment -UserPrincipalName $script:Amara -TicketId 'INC-1042' -ApprovedBy 'J. Mentor' -Confirm:$false
        $report = Export-KRSIncidentReport -UserPrincipalName $script:Amara -TicketId 'INC-1042'
        $html = Get-Content -LiteralPath $report.ReportPath -Raw
        $html | Should -Match '<th>Operator</th>'
        $html | Should -Match ([regex]::Escape([System.Net.WebUtility]::HtmlEncode([Environment]::UserName)))
        $html | Should -Match 'J\. Mentor'
    }

    It 'shortens IP addresses and masks outside actors in the shared report' {
        $report = Export-KRSIncidentReport -UserPrincipalName $script:Amara -TicketId 'INC-1042' -Redact
        $html = Get-Content -LiteralPath $report.ReportPath -Raw
        $html | Should -Not -Match '203\.0\.113\.\d+'
        $html | Should -Not -Match 'admin@contoso\.com'
        $html | Should -Match '203\.0\.x\.x'
    }

    It 'HTML-encodes values from the tenant' {
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-InboxRule' } -MockWith {
            [pscustomobject]@{ Name = '<script>alert(1)</script>'; RuleIdentity = '9'; Enabled = $true; ForwardTo = @('[SMTP:x@example.net]'); ForwardAsAttachmentTo = $null; RedirectTo = $null }
        }
        $html = Get-Content -LiteralPath (Export-KRSIncidentReport -UserPrincipalName $script:Amara -TicketId 'INC-1042').ReportPath -Raw
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;'
    }
}
