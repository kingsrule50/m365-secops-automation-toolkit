# M365 SecOps Automation Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-7.4-5391FE?logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-v1.0-0078D4?logo=microsoft&logoColor=white)
![Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-P2%20%2F%20PIM-0078D4?logo=microsoftazure&logoColor=white)
![Pester](https://img.shields.io/badge/Pester-128%20tests-2E7D32)
[![CI](https://github.com/kingsrule50/m365-secops-automation-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/kingsrule50/m365-secops-automation-toolkit/actions/workflows/ci.yml)

**KRSSecOps is a PowerShell 7 module I built to automate Microsoft 365 security operations safely in a tenant I don't own: certificate-only authentication, least-privilege permissions, a pilot-scoped blast radius, and a tested, CI-verified codebase.**

---

## The Series

| Part | What it does | Status |
| --- | --- | --- |
| **[Part 1 — Identity Posture Audit](parts/part-1-identity-audit/README.md)** | One command runs six identity checks (MFA gaps, stale accounts, standing privileged access, guests, app credentials, Conditional Access) and produces ranked, redacted evidence | ✅ Complete |
| **Part 2 — Compliance-as-Code** | Exports Purview labels, DLP and retention to a version-controlled baseline, detects drift, and enforces Exchange mailbox security settings inside the pilot only | 🔨 In progress |
| **Part 3 — Detection & Safe Containment** | Detects risky mailbox and sign-in activity and runs approval-gated containment with a reporting trail | Planned |

---

## Headline Results (Part 1)

![Ranked findings for the pilot](parts/part-1-identity-audit/screenshots/05-findings-csv.png)

- **6 of 6 checks, 0 failures, about 44 seconds** against a live Microsoft 365 E5 tenant
- **Every seeded risk detected**, including an admin with no MFA rated **Critical** from live role data, even though Microsoft's own report hadn't caught up yet
- **6 read-only Graph permissions**, no client secrets, non-exportable certificate
- **128 Pester tests, 87.7% coverage**, CI green on Windows and Ubuntu

---

## Built To Be Safe In A Shared Tenant

| Principle | How |
| --- | --- |
| No secrets | Certificate auth, private key can't be exported; settings, certificates, logs and reports are gitignored, and tests enforce it |
| Least privilege | Per-part permissions, each one justified in [docs/permission-matrix.md](docs/permission-matrix.md) |
| Blast radius | Changes are refused outside the pilot domain `m365.kingsruleusa.com`; output is redacted for sharing |
| Change control | `-WhatIf` on every change; every tenant change is approved and logged in [docs/change-log.md](docs/change-log.md) |

---

## Quick Start

```powershell
./setup/01-Install-Prerequisites.ps1
./build/build.ps1                                   # analyze, test, package
Import-Module ./src/KRSSecOps/KRSSecOps.psd1
Connect-KRSTenant
Invoke-KRSIdentityAudit -Scope Pilot -Redact
```

Full setup, including the certificate and app registration, is in the [Part 1 runbook](parts/part-1-identity-audit/runbook.md).

---

## Repository Structure

```text
m365-secops-automation-toolkit/
|-- README.md                       this overview
|-- parts/                          one write-up per part, with its runbook and screenshots
|-- src/KRSSecOps/                  the module (Public/Core, Public/Identity, Private, Config)
|-- setup/                          numbered setup scripts, all with -WhatIf
|-- tests/                          Pester tests, Microsoft Graph fully mocked
|-- build/                          build.ps1 and analyzer settings
|-- docs/                           permission matrix and tenant change log
|-- .github/workflows/ci.yml        CI on windows-latest and ubuntu-latest
`-- CHANGELOG.md / LICENSE
```

---

*Built by Chinedu Asuzu (CISA, Security+, SC-401) in a shared Microsoft 365 developer tenant with test identities and the tenant owner's approval. Tenant and admin details are redacted from all screenshots.*
