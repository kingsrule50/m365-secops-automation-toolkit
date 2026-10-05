# Permission matrix

The automation app (`app-krs-secops-automation`) uses certificate-based, app-only authentication.
It is granted permissions **part by part**, so at any time it holds only what the current lab part needs.
`setup/03-New-KRSAppRegistration.ps1 -Part <n>` grants each set.

| Part | Permission (application) | Resource | Used by | Why this and not something broader |
| --- | --- | --- | --- | --- |
| 1 | User.Read.All | Microsoft Graph | Stale accounts, guests, principal lookup | Read users only. No write. |
| 1 | AuditLog.Read.All | Microsoft Graph | MFA registration report, signInActivity | Required by both endpoints. |
| 1 | RoleManagement.Read.Directory | Microsoft Graph | Privileged role report | Covers active, PIM eligible and PIM active schedules. |
| 1 | Application.Read.All | Microsoft Graph | App credential and permission risk | Read apps and service principals only. |
| 1 | Policy.Read.All | Microsoft Graph | Conditional Access inventory, security defaults | Read-only policy access. |
| 1 | GroupMember.Read.All | Microsoft Graph | Pilot group membership, group lookups | Avoids Directory.Read.All. |
| 2 | Exchange.ManageAsApp | Office 365 Exchange Online | Exchange Online and Security & Compliance PowerShell | Plus Compliance Administrator role and an EXO management scope on the pilot domain. |
| 3 | IdentityRiskyUser.Read.All | Microsoft Graph | Risky users | Read-only. |
| 3 | IdentityRiskEvent.Read.All | Microsoft Graph | Risk detections | Read-only. |
| 3 (write, approval needed) | User.EnableDisableAccount.All | Microsoft Graph | Containment: block sign-in | Narrower than User.ReadWrite.All. |
| 3 (write, approval needed) | User.RevokeSessions.All | Microsoft Graph | Containment: revoke sessions | Narrower than User.ReadWrite.All. |

## Defence in depth for writes

1. **Code:** every write function calls `Assert-KRSPilotScope` and refuses any account outside `@m365.kingsruleusa.com`.
2. **Change control:** write functions use `SupportsShouldProcess` with `ConfirmImpact='High'`, so `-WhatIf` previews and `-Confirm` prompts.
3. **Server side (Part 2):** Exchange RBAC for Applications with a management scope limited to the pilot domain, so Exchange itself rejects out-of-scope changes even if the code had a bug.
4. **Audit:** every action is written to the JSON-lines log with a correlation ID.

## Deliberately not used

| Permission | Why not |
| --- | --- |
| Directory.Read.All | Typed endpoints cover every lookup with narrower permissions. |
| Any *.ReadWrite.All in Parts 1 and 2 | Part 1 is read-only. Part 2 writes go through Exchange RBAC with a scope. |
| Client secrets | Certificate only. The private key is non-exportable. |
