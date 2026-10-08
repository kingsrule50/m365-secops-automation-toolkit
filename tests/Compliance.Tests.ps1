BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $ModuleManifest -Force

    # Fake Exchange Online / Purview data, shaped like the real deserialized objects.
    function New-TestMailbox {
        param([string]$Upn, [string]$ForwardingSmtpAddress, [string]$ForwardingAddress, [bool]$Deliver = $false, [bool]$Audit = $true)
        [pscustomobject]@{ UserPrincipalName = $Upn; DisplayName = ($Upn -split '@')[0]; ForwardingSmtpAddress = $ForwardingSmtpAddress; ForwardingAddress = $ForwardingAddress; DeliverToMailboxAndForward = $Deliver; AuditEnabled = $Audit }
    }

    function Set-ExchangeMock {
        # Default Exchange mocks; individual tests override pieces with their own Mock calls.
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -MockWith { throw "Unexpected command $Name" }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-Mailbox' } -MockWith {
            $all = @(
                New-TestMailbox -Upn 'amara.okafor@m365.kingsruleusa.com'
                New-TestMailbox -Upn 'marcus.bennett@m365.kingsruleusa.com' -ForwardingSmtpAddress 'smtp:marcus.home@example.com' -Deliver $true
                New-TestMailbox -Upn 'sofia.laurent@m365.kingsruleusa.com' -Audit $false
                New-TestMailbox -Upn 'colleague@contoso.com' -ForwardingSmtpAddress 'smtp:other@contoso.com'
            )
            if ($Parameters.ContainsKey('Identity')) { $all | Where-Object UserPrincipalName -eq $Parameters['Identity'] } else { $all }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-CASMailbox' } -MockWith {
            if ($Parameters['Identity'] -like 'sofia*') { [pscustomobject]@{ PopEnabled = $false; ImapEnabled = $false; SmtpClientAuthenticationDisabled = $true } }
            else { [pscustomobject]@{ PopEnabled = $true; ImapEnabled = $true; SmtpClientAuthenticationDisabled = $null } }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-InboxRule' } -MockWith {
            if ($Parameters['Mailbox'] -like 'amara*') {
                [pscustomobject]@{ Name = 'Move newsletters'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null }
                [pscustomobject]@{ Name = 'fwd invoices'; Enabled = $true; ForwardTo = @('"Ext" [SMTP:collector@example.net]', '"Marcus" [EX:/o=ExchangeLabs/cn=Recipients/cn=marcus]'); ForwardAsAttachmentTo = $null; RedirectTo = $null }
                [pscustomobject]@{ Name = 'old rule'; Enabled = $false; ForwardTo = @('[SMTP:someone@example.org]'); ForwardAsAttachmentTo = $null; RedirectTo = $null }
            }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-AcceptedDomain' } -MockWith {
            [pscustomobject]@{ DomainName = 'm365.kingsruleusa.com' }
            [pscustomobject]@{ DomainName = 'contoso.com' }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-TransportConfig' } -MockWith { [pscustomobject]@{ SmtpClientAuthenticationDisabled = $false } }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -in 'Set-Mailbox', 'Set-CASMailbox' } -MockWith { }
    }

    function Set-PurviewMock {
        # Shared state read by the mocks below; each call resets it, so a test describes only its change.
        param([string]$DlpMode = 'Enable', [string]$Tooltip = 'Internal only', [switch]$DropRetention, [switch]$AddRetention, [string]$LabelName = 'Confidential', [switch]$ReorderLocations)
        $script:PurviewState = @{ DlpMode = $DlpMode; Tooltip = $Tooltip; DropRetention = [bool]$DropRetention; AddRetention = [bool]$AddRetention; LabelName = $LabelName; ReorderLocations = [bool]$ReorderLocations }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-Label' } -MockWith {
            [pscustomobject]@{ Name = $script:PurviewState.LabelName; Guid = 'label-1'; DisplayName = 'Confidential'; Priority = 1; Disabled = $false; Tooltip = $script:PurviewState.Tooltip; EncryptionEnabled = $true; ContentType = @('File', 'Email') }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-LabelPolicy' } -MockWith {
            [pscustomobject]@{ Name = 'Default label policy'; Guid = 'lp-1'; Enabled = $true; Labels = @('Confidential', 'Public') }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-DlpCompliancePolicy' } -MockWith {
            $locations = if ($script:PurviewState.ReorderLocations) { @([pscustomobject]@{ Name = 'Sales' }, [pscustomobject]@{ Name = 'All' }) } else { @([pscustomobject]@{ Name = 'All' }, [pscustomobject]@{ Name = 'Sales' }) }
            [pscustomobject]@{ Name = 'KRS PII'; Guid = 'dlp-1'; Enabled = $true; Mode = $script:PurviewState.DlpMode; Priority = 0; ExchangeLocation = $locations }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-DlpComplianceRule' } -MockWith {
            [pscustomobject]@{ Name = 'KRS PII rule'; Guid = 'rule-1'; ParentPolicyName = 'KRS PII'; Disabled = $false; BlockAccess = $true; ContentContainsSensitiveInformation = @(@{ name = 'U.S. Social Security Number (SSN)'; mincount = '1'; maxcount = '-1' }) }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-RetentionCompliancePolicy' } -MockWith {
            if (-not $script:PurviewState.DropRetention) { [pscustomobject]@{ Name = 'Mail 7 years'; Guid = 'ret-1'; Enabled = $true; RestrictiveRetention = $false } }
            if ($script:PurviewState.AddRetention) { [pscustomobject]@{ Name = 'Unreviewed policy'; Guid = 'ret-2'; Enabled = $true; RestrictiveRetention = $false } }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-RetentionComplianceRule' } -MockWith {
            [pscustomobject]@{ Name = 'Mail 7 years rule'; Guid = 'retrule-1'; Policy = 'Mail 7 years'; RetentionDuration = 2555; RetentionComplianceAction = 'Keep' }
        }
    }
}

Describe 'Private helpers' {
    It 'extracts SMTP addresses from <Case>' -ForEach @(
        @{ Case = 'smtp: prefix'; Value = 'smtp:User@Example.com'; Expected = @('user@example.com') }
        @{ Case = 'display name + SMTP'; Value = '"Ext" [SMTP:collector@example.net]'; Expected = @('collector@example.net') }
        @{ Case = 'plain address'; Value = 'plain@example.org'; Expected = @('plain@example.org') }
        @{ Case = 'internal X.500 reference'; Value = '"Marcus" [EX:/o=ExchangeLabs/cn=marcus]'; Expected = @() }
    ) {
        InModuleScope KRSSecOps -Parameters @{ Value = $Value; Expected = $Expected } {
            param($Value, $Expected)
            @(Get-KRSSmtpAddress -Value $Value) | Should -Be $Expected
        }
    }

    It 'makes collections order-independent for drift comparison' {
        InModuleScope KRSSecOps {
            ConvertTo-KRSComparableValue -Value @('b', 'a') | Should -Be 'a; b'
            ConvertTo-KRSComparableValue -Value @([pscustomobject]@{ Name = 'Sales' }, [pscustomobject]@{ Name = 'All' }) | Should -Be 'All; Sales'
            ConvertTo-KRSComparableValue -Value $null | Should -BeNullOrEmpty
            ConvertTo-KRSComparableValue -Value $true | Should -Be 'True'
        }
    }

    It 'serialises dictionaries with sorted keys so baselines are stable across sessions' {
        InModuleScope KRSSecOps {
            $a = [ordered]@{ zeta = '1'; alpha = '2' }
            $b = [ordered]@{ alpha = '2'; zeta = '1' }
            ConvertTo-KRSComparableValue -Value $a | Should -Be (ConvertTo-KRSComparableValue -Value $b)
            ConvertTo-KRSComparableValue -Value $a | Should -Be '{"alpha":"2","zeta":"1"}'
        }
    }
}

Describe 'Connect-KRSCompliance' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Connect-KRSExoSession -ModuleName KRSSecOps -MockWith { }
    }

    It 'connects to Exchange and Purview with the certificate and only the toolkit commands' {
        $session = Connect-KRSCompliance
        $session.AuthType | Should -Be 'AppOnly (certificate)'
        Should -Invoke Connect-KRSExoSession -ModuleName KRSSecOps -Times 1 -Exactly -ParameterFilter {
            $Service -eq 'Exchange' -and $CertificateThumbprint -eq 'ABCDEF0123456789ABCDEF0123456789ABCDEF01' -and 'Set-CASMailbox' -in $CommandName -and 'Get-Label' -notin $CommandName
        }
        Should -Invoke Connect-KRSExoSession -ModuleName KRSSecOps -Times 1 -Exactly -ParameterFilter {
            $Service -eq 'Purview' -and 'Get-DlpComplianceRule' -in $CommandName -and -not ($CommandName -like 'Set-*')
        }
    }

    It 'connects only the requested service' {
        $null = Connect-KRSCompliance -Service Exchange
        Should -Invoke Connect-KRSExoSession -ModuleName KRSSecOps -Times 1 -Exactly
    }

    It 'refuses to connect without the tenant .onmicrosoft.com name' {
        InModuleScope KRSSecOps { $script:KRSConfig.Organization = $null }
        { Connect-KRSCompliance } | Should -Throw '*Organization*onmicrosoft.com*'
        Should -Invoke Connect-KRSExoSession -ModuleName KRSSecOps -Times 0
    }
}

Describe 'Disconnect-KRSCompliance' {
    It 'closes the sessions' {
        Initialize-TestSession -Drive $TestDrive
        Mock Disconnect-KRSExoSession -ModuleName KRSSecOps -MockWith { }
        Disconnect-KRSCompliance
        Should -Invoke Disconnect-KRSExoSession -ModuleName KRSSecOps -Times 1 -Exactly
    }
}

Describe 'Get-KRSMailboxSecurityState' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Set-ExchangeMock
    }

    It 'rates mailbox forwarding to an external address High and remediable' {
        $row = Get-KRSMailboxSecurityState | Where-Object { $_.UserPrincipalName -like 'marcus*' -and $_.Setting -eq 'Forwarding' }
        $row.Severity | Should -Be 'High'
        $row.Current | Should -Be 'marcus.home@example.com'
        $row.Remediable | Should -BeTrue
    }

    It 'rates an enabled inbox rule that forwards outside High and report-only' {
        $rows = @(Get-KRSMailboxSecurityState | Where-Object Setting -eq 'InboxRule')
        $rows.Count | Should -Be 1
        $rows[0].Current | Should -Be 'fwd invoices -> collector@example.net'
        $rows[0].Severity | Should -Be 'High'
        $rows[0].Remediable | Should -BeFalse
    }

    It 'flags legacy protocols and inherited SMTP AUTH when the organisation allows it' {
        $amara = @(Get-KRSMailboxSecurityState | Where-Object UserPrincipalName -like 'amara*')
        ($amara | Where-Object Setting -eq 'Pop').Severity | Should -Be 'Medium'
        ($amara | Where-Object Setting -eq 'Imap').Severity | Should -Be 'Medium'
        ($amara | Where-Object Setting -eq 'SmtpAuth').Current | Should -Be 'Inherited (organisation: enabled)'
    }

    It 'treats inherited SMTP AUTH as compliant when the organisation disables it' {
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-TransportConfig' } -MockWith { [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true } }
        Get-KRSMailboxSecurityState | Where-Object Setting -eq 'SmtpAuth' | Should -BeNullOrEmpty
    }

    It 'reports disabled mailbox auditing as report-only' {
        $row = Get-KRSMailboxSecurityState | Where-Object { $_.UserPrincipalName -like 'sofia*' -and $_.Setting -eq 'Audit' }
        $row.Severity | Should -Be 'Medium'
        $row.Remediable | Should -BeFalse
    }

    It 'keeps Pilot scope inside the pilot domain' {
        Get-KRSMailboxSecurityState -IncludeCompliant | Where-Object InPilot -eq $false | Should -BeNullOrEmpty
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 0 -ParameterFilter { $Name -eq 'Get-CASMailbox' -and $Parameters['Identity'] -like '*contoso.com' }
    }

    It 'masks mailboxes outside the pilot in Tenant scope with -Redact' {
        $row = Get-KRSMailboxSecurityState -Scope Tenant -Redact | Where-Object { $_.InPilot -eq $false -and $_.Setting -eq 'Forwarding' }
        $row.UserPrincipalName | Should -Be 'c***@contoso.com'
        $row.Severity | Should -Be 'Medium' -Because 'forwarding to an accepted domain is internal'
    }

    It 'returns compliant settings only with -IncludeCompliant' {
        Get-KRSMailboxSecurityState | Where-Object Severity -eq 'Info' | Should -BeNullOrEmpty
        @(Get-KRSMailboxSecurityState -IncludeCompliant | Where-Object { $_.UserPrincipalName -like 'sofia*' }).Count | Should -Be 6
    }
}

Describe 'Set-KRSMailboxBaseline' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Set-ExchangeMock
    }

    It 'changes nothing under -WhatIf' {
        $rows = @(Set-KRSMailboxBaseline -WhatIf)
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 0 -ParameterFilter { $Name -like 'Set-*' }
        @($rows | Where-Object Result -eq 'WhatIf').Count | Should -Be 7
    }

    It 'clears forwarding with exactly the allowed parameters' {
        $null = Set-KRSMailboxBaseline -Identity marcus.bennett@m365.kingsruleusa.com -Setting Forwarding -Confirm:$false
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'Set-Mailbox' -and $Parameters['Identity'] -eq 'marcus.bennett@m365.kingsruleusa.com' -and
            $Parameters.ContainsKey('ForwardingSmtpAddress') -and $null -eq $Parameters['ForwardingSmtpAddress'] -and
            $Parameters['DeliverToMailboxAndForward'] -eq $false -and $Parameters.Count -eq 4
        }
    }

    It 'only changes settings that differ from the baseline' {
        $rows = @(Set-KRSMailboxBaseline -Identity sofia.laurent@m365.kingsruleusa.com -Confirm:$false)
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 0 -ParameterFilter { $Name -like 'Set-*' }
        @($rows | Where-Object Result -ne 'AlreadyCompliant') | Should -BeNullOrEmpty
    }

    It 'blocks a mailbox outside the pilot before reading or changing anything' {
        { Set-KRSMailboxBaseline -Identity colleague@contoso.com -Confirm:$false } | Should -Throw '*Scope guard blocked*'
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 0
    }

    It 'records a write Exchange refuses as Failed and carries on' {
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Set-CASMailbox' -and $Parameters.ContainsKey('ImapEnabled') } -MockWith { throw "isn't within your current write scopes" }
        $rows = @(Set-KRSMailboxBaseline -Identity amara.okafor@m365.kingsruleusa.com -Confirm:$false -WarningAction SilentlyContinue)
        ($rows | Where-Object Setting -eq 'Imap').Result | Should -Be 'Failed'
        ($rows | Where-Object Setting -eq 'Imap').After | Should -Be 'Enabled'
        ($rows | Where-Object Setting -eq 'SmtpAuth').Result | Should -Be 'Changed'
    }

    It 'enforces only the settings named in -Setting' {
        $null = Set-KRSMailboxBaseline -Identity amara.okafor@m365.kingsruleusa.com -Setting Pop -Confirm:$false
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 1 -Exactly -ParameterFilter { $Name -like 'Set-*' }
        Should -Invoke Invoke-KRSExoCommand -ModuleName KRSSecOps -Times 1 -Exactly -ParameterFilter { $Name -eq 'Set-CASMailbox' -and $Parameters['PopEnabled'] -eq $false }
    }
}

Describe 'Get-KRSExchangeTenantRisk' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -MockWith { throw "The term '$Name' is not recognized" }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-HostedOutboundSpamFilterPolicy' } -MockWith { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'On' } }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-RemoteDomain' } -MockWith { [pscustomobject]@{ DomainName = '*'; AutoForwardEnabled = $false } }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-TransportRule' } -MockWith {
            [pscustomobject]@{ Name = 'BCC legal'; State = 'Enabled'; BlindCopyTo = @('legal@contoso.com'); RedirectMessageTo = $null; CopyTo = $null; AddToRecipients = $null }
            [pscustomobject]@{ Name = 'Old redirect'; State = 'Disabled'; BlindCopyTo = $null; RedirectMessageTo = @('x@example.com'); CopyTo = $null; AddToRecipients = $null }
        }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-TransportConfig' } -MockWith { [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true } }
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-DkimSigningConfig' } -MockWith {
            [pscustomobject]@{ Domain = 'contoso.onmicrosoft.com'; Enabled = $false }
            [pscustomobject]@{ Domain = 'm365.kingsruleusa.com'; Enabled = $false }
        }
    }

    It 'rates automatic external forwarding High' {
        (Get-KRSExchangeTenantRisk | Where-Object Area -eq 'AutoForwarding').Severity | Should -Be 'High'
    }

    It 'flags enabled transport rules that copy mail and ignores disabled ones' {
        $rules = @(Get-KRSExchangeTenantRisk | Where-Object Area -eq 'TransportRule')
        $rules.Count | Should -Be 1
        $rules[0].Subject | Should -Be 'BCC legal'
    }

    It 'flags DKIM off for custom domains and skips the onmicrosoft.com domain' {
        $dkim = @(Get-KRSExchangeTenantRisk | Where-Object Area -eq 'Dkim')
        $dkim.Count | Should -Be 1
        $dkim[0].Subject | Should -Be 'm365.kingsruleusa.com'
    }

    It 'masks other domains and rule names with -Redact but keeps the pilot domain readable' {
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-DkimSigningConfig' } -MockWith {
            [pscustomobject]@{ Domain = 'm365.kingsruleusa.com'; Enabled = $false }
            [pscustomobject]@{ Domain = 'someone-else.com'; Enabled = $false }
        }
        $rows = @(Get-KRSExchangeTenantRisk -Redact)
        $dkim = @($rows | Where-Object Area -eq 'Dkim' | ForEach-Object Subject)
        $dkim | Should -Contain 'm365.kingsruleusa.com'
        $dkim | Should -Not -Contain 'someone-else.com'
        @($dkim | Where-Object { $_ -match '^dkim-[0-9a-f]{8}$' }).Count | Should -Be 1
        ($rows | Where-Object Area -eq 'TransportRule').Subject | Should -Match '^transportrule-[0-9a-f]{8}$'
        @(Get-KRSExchangeTenantRisk -Redact)[0].Subject | Should -Be $rows[0].Subject -Because 'masked names are stable between runs'
    }

    It 'shows a setting it could not read instead of passing it silently' {
        $row = Get-KRSExchangeTenantRisk | Where-Object Area -eq 'MailboxAudit'
        $row.Subject | Should -Be '(not checked)'
        $row.Finding | Should -BeLike '*Get-OrganizationConfig*'
    }
}

Describe 'Purview baseline and drift' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Get-ChildItem -Path (Join-Path $TestDrive 'baselines') -ErrorAction SilentlyContinue | Remove-Item -Force
        Set-PurviewMock
        $script:baseline = Export-KRSComplianceBaseline
    }

    It 'exports every object type with counts' {
        $script:baseline.Objects | Should -Be 6
        $script:baseline.DlpRules | Should -Be 1
        $document = Get-Content -LiteralPath $script:baseline.Path -Raw | ConvertFrom-Json
        $document.schemaVersion | Should -Be 1
        @($document.objects | Where-Object Type -eq 'RetentionRule').Count | Should -Be 1
    }

    It 'reports no drift when nothing changed' {
        Compare-KRSComplianceBaseline | Should -BeNullOrEmpty
    }

    It 'ignores a change in list order' {
        Set-PurviewMock -ReorderLocations
        Compare-KRSComplianceBaseline | Should -BeNullOrEmpty
    }

    It 'rates a DLP policy switched to test mode High' {
        Set-PurviewMock -DlpMode 'TestWithoutNotifications'
        $row = Compare-KRSComplianceBaseline
        $row.Property | Should -Be 'Mode'
        $row.Baseline | Should -Be 'Enable'
        $row.Current | Should -Be 'TestWithoutNotifications'
        $row.Severity | Should -Be 'High'
    }

    It 'rates a cosmetic change Medium' {
        Set-PurviewMock -Tooltip 'Changed text'
        (Compare-KRSComplianceBaseline).Severity | Should -Be 'Medium'
    }

    It 'reports a rename once, matched by Guid' {
        Set-PurviewMock -LabelName 'Confidential-Renamed'
        $rows = @(Compare-KRSComplianceBaseline)
        $rows.Count | Should -Be 1
        $rows[0].Change | Should -Be 'Modified'
        $rows[0].Property | Should -Be 'Name'
    }

    It 'rates a removed policy High and a new one Low' {
        Set-PurviewMock -DropRetention -AddRetention
        $rows = @(Compare-KRSComplianceBaseline)
        ($rows | Where-Object Change -eq 'Removed').Severity | Should -Be 'High'
        ($rows | Where-Object Change -eq 'Added').Severity | Should -Be 'Low'
    }

    It 'uses the newest baseline by default and explains when there is none' {
        Get-ChildItem -Path (Join-Path $TestDrive 'baselines') | Remove-Item -Force
        { Compare-KRSComplianceBaseline } | Should -Throw '*Run Export-KRSComplianceBaseline first*'
    }
}

Describe 'Invoke-KRSComplianceAudit' {
    BeforeEach {
        Initialize-TestSession -Drive $TestDrive
        Get-ChildItem -Path (Join-Path $TestDrive 'baselines') -ErrorAction SilentlyContinue | Remove-Item -Force
        Set-ExchangeMock
        Set-PurviewMock
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -in 'Get-HostedOutboundSpamFilterPolicy', 'Get-RemoteDomain', 'Get-TransportRule', 'Get-DkimSigningConfig', 'Get-OrganizationConfig' } -MockWith { }
    }

    It 'writes the evidence folder and skips drift when no baseline exists' {
        $summary = Invoke-KRSComplianceAudit -Redact
        ($summary.Checks | Where-Object Check -eq 'PurviewDrift').Status | Should -Be 'Skipped'
        ($summary.Checks | Where-Object Check -eq 'MailboxSecurity').Status | Should -Be 'Completed'
        $summary.FailedChecks | Should -Be 0
        Join-Path $summary.OutputFolder 'findings.csv' | Should -Exist
        Join-Path $summary.OutputFolder 'summary.json' | Should -Exist
        $first = Import-Csv (Join-Path $summary.OutputFolder 'findings.csv') | Select-Object -First 1
        $first.Severity | Should -Be 'High'
    }

    It 'includes drift once a baseline exists' {
        $null = Export-KRSComplianceBaseline
        Set-PurviewMock -DlpMode 'TestWithoutNotifications'
        $summary = Invoke-KRSComplianceAudit -Check PurviewDrift
        ($summary.Checks | Where-Object Check -eq 'PurviewDrift').High | Should -Be 1
    }

    It 'records a failed check and still runs the others' {
        Mock Invoke-KRSExoCommand -ModuleName KRSSecOps -ParameterFilter { $Name -eq 'Get-Mailbox' } -MockWith { throw 'Access denied' }
        $summary = Invoke-KRSComplianceAudit -WarningAction SilentlyContinue
        ($summary.Checks | Where-Object Check -eq 'MailboxSecurity').Status | Should -Be 'Failed'
        ($summary.Checks | Where-Object Check -eq 'ExchangeTenantRisk').Status | Should -Be 'Completed'
        $summary.FailedChecks | Should -Be 1
    }
}
