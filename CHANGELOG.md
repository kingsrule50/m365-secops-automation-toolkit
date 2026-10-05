# Changelog

All notable changes to KRSSecOps are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the module uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Part 1

### Added
- Module foundation: manifest, strict mode, private/public layout, settings validation.
- Certificate-based, app-only connection (`Connect-KRSTenant`, `Disconnect-KRSTenant`).
- Central Graph wrapper with paging and retry on 429, 503 and 504.
- JSON-lines audit log with correlation IDs.
- Pilot scope: `Test-KRSPilotScope`, write guard `Assert-KRSPilotScope`, read-side group membership, redaction.
- Identity checks: `Get-KRSMfaGap`, `Get-KRSStaleAccount`, `Get-KRSPrivilegedRoleReport`, `Get-KRSGuestAccessReport`, `Get-KRSAppCredentialRisk`, `Get-KRSConditionalAccessInventory`.
- Orchestrator `Invoke-KRSIdentityAudit` writing per-check CSVs, `findings.csv` and `summary.json`.
- Setup scripts for modules, certificate, app registration with least-privilege consent, and pilot users.
- Pester 5 test suite with mocked Graph, PSScriptAnalyzer gate, build script and GitHub Actions CI on Windows and Ubuntu.
