@{
    RootModule           = 'KRSSecOps.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '6f1d3c2a-8b4e-4f7a-9c1d-2e5b7a9f0c31'
    Author               = 'Chinedu (kingsrule50)'
    CompanyName          = 'kingsrule llc'
    Copyright            = '(c) 2026 Chinedu. MIT License.'
    Description          = 'M365 SecOps automation toolkit: identity posture audit, compliance-as-code and incident response for Microsoft Entra ID, Exchange Online and Purview, using certificate-based app-only authentication.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')

    RequiredModules      = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.20.0' }
    )

    FunctionsToExport    = @(
        'Connect-KRSTenant'
        'Disconnect-KRSTenant'
        'Test-KRSPilotScope'
        'Get-KRSMfaGap'
        'Get-KRSStaleAccount'
        'Get-KRSPrivilegedRoleReport'
        'Get-KRSGuestAccessReport'
        'Get-KRSAppCredentialRisk'
        'Get-KRSConditionalAccessInventory'
        'Invoke-KRSIdentityAudit'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'M365', 'EntraID', 'Purview', 'MicrosoftGraph', 'SecOps', 'Audit')
            LicenseUri   = 'https://github.com/kingsrule50/m365-secops-automation-toolkit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/kingsrule50/m365-secops-automation-toolkit'
            ReleaseNotes = 'Part 1: module foundation and Entra ID identity posture audit.'
        }
    }
}
