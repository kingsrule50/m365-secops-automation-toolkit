# Changelog

All notable changes to KRSSecOps are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the module uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - Part 2

### Added
- `Connect-KRSCompliance` / `Disconnect-KRSCompliance`: app-only Exchange Online and Security & Compliance sessions with the Part 1 certificate, loading only the 19 commands the toolkit uses.
- `Export-KRSComplianceBaseline` and `Compare-KRSComplianceBaseline`: Purview labels, label policies, DLP and retention as a JSON baseline, with Guid-matched, order-independent drift detection and severity.
- `Get-KRSMailboxSecurityState`: external and internal forwarding, external inbox rules, POP, IMAP, SMTP AUTH and mailbox auditing per mailbox.
- `Set-KRSMailboxBaseline`: idempotent desired-state enforcement for forwarding and legacy protocols, with `-WhatIf`, a pilot-domain guard and per-setting before/after results.
- `Get-KRSExchangeTenantRisk`: automatic forwarding, remote domains, transport rules, organisation SMTP AUTH, DKIM and mailbox audit; unreadable settings reported, not passed.
- `Invoke-KRSComplianceAudit`: the three checks with the same evidence folder layout as Part 1.
- `setup/05-Set-KRSExchangePilotRbac.ps1`: pilot mailbox tag, management scope, custom role trimmed to 6 commands and 7 write parameters, role group for the app.
- `setup/06-Set-KRSPurviewReadRbac.ps1`: read-only Purview role group for the app.
- `-Redact` masks other tenants' domains, rules and policies with stable hashed names.
- Standards test: every Exchange and Purview command goes through `Invoke-KRSExoCommand`, which always passes `-ErrorAction Stop`.

### Fixed
- `setup/03-New-KRSAppRegistration.ps1` no longer warns about a different certificate when Graph returns the thumbprint as hex instead of base64.

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
- `Invoke-KRSIdentityAudit -InactiveDays` to override the stale-account threshold for one run; recorded in `summary.json` and the log.
- `AdminSource` on MFA findings, showing whether admin status came from live role assignments, the registration report, or both.

### Changed
- `Get-KRSMfaGap` treats holders of active privileged roles as admins even when the registration report's `isAdmin` flag has not refreshed yet. If role data cannot be read, it warns and falls back to the report.
- `Get-KRSPrivilegedRoleReport` bulk-loads principals and selects only needed fields (61 s down to ~34 s on a tenant with ~2,100 role assignments) and reports stage timing with `-Verbose`.

### Fixed
- Finding text uses correct singular and plural day counts ("1 day", "5 days").
