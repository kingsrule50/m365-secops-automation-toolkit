#Requires -Version 7.4
<#
.SYNOPSIS
    Creates the self-signed certificate the automation app authenticates with.

.DESCRIPTION
    Creates an RSA 3072 / SHA-256 certificate in Cert:\CurrentUser\My with a NON-EXPORTABLE
    private key, so the key cannot be copied off this machine, and exports only the public key
    (.cer) for upload to the app registration. No secret is created anywhere.
    Windows only (uses New-SelfSignedCertificate).

.PARAMETER Subject
    Certificate subject. Default CN=KRSSecOps-Automation.

.PARAMETER ValidityMonths
    Lifetime in months. Default 12. Rotate before expiry; Connect-KRSTenant warns 30 days ahead.

.PARAMETER ExportFolder
    Where to write the public .cer file. Default $HOME\KRSSecOps\certs (outside the repo).

.EXAMPLE
    ./setup/02-New-KRSAuthCertificate.ps1

.EXAMPLE
    ./setup/02-New-KRSAuthCertificate.ps1 -ValidityMonths 6 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidatePattern('^CN=')]
    [string]$Subject = 'CN=KRSSecOps-Automation',

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$ValidityMonths = 12,

    [Parameter()]
    [string]$ExportFolder = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'KRSSecOps\certs')
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This script needs Windows (New-SelfSignedCertificate and the CurrentUser certificate store).' }

$existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) }
if ($existing) {
    Write-Warning "A valid certificate with subject '$Subject' already exists (thumbprint $($existing[0].Thumbprint), expires $($existing[0].NotAfter)). Remove it or use another -Subject to create a new one."
    return
}

if ($PSCmdlet.ShouldProcess("Cert:\CurrentUser\My", "Create certificate $Subject valid $ValidityMonths months")) {
    $certificate = New-SelfSignedCertificate -Subject $Subject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -KeySpec Signature -KeyUsage DigitalSignature `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddMonths($ValidityMonths) `
        -FriendlyName 'KRSSecOps app-only authentication'

    $null = New-Item -ItemType Directory -Path $ExportFolder -Force
    $cerPath = Join-Path $ExportFolder 'KRSSecOps-Automation.cer'
    $null = Export-Certificate -Cert $certificate -FilePath $cerPath -Type CERT

    [pscustomobject]@{
        Subject         = $certificate.Subject
        Thumbprint      = $certificate.Thumbprint
        NotAfter        = $certificate.NotAfter
        PrivateKey      = 'Non-exportable, Cert:\CurrentUser\My'
        PublicKeyFile   = $cerPath
        NextStep        = "./setup/03-New-KRSAppRegistration.ps1 -TenantId <tenant-id> -CertificatePath '$cerPath'"
    }
}
