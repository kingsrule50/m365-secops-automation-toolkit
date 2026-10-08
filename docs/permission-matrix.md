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
| 2 | Exchange.ManageAsApp | Office 365 Exchange Online | Exchange Online and Security & Compliance PowerShell | Grants nothing on its own. No Entra role is assigned; access comes only from the two role groups below. |
| 3 | IdentityRiskyUser.Read.All | Microsoft Graph | Risky users | Read-only. |
| 3 | IdentityRiskEvent.Read.All | Microsoft Graph | Risk detections | Read-only. |
| 3 (write, approval needed) | User.EnableDisableAccount.All | Microsoft Graph | Containment: block sign-in | Narrower than User.ReadWrite.All. |
| 3 (write, approval needed) | User.RevokeSessions.All | Microsoft Graph | Containment: revoke sessions | Narrower than User.ReadWrite.All. |

## Defence in depth for writes

1. **Code:** every write function calls `Assert-KRSPilotScope` and refuses any account outside `@m365.kingsruleusa.com`.
2. **Change control:** write functions use `SupportsShouldProcess` with `ConfirmImpact='High'`, so `-WhatIf` previews and `-Confirm` prompts.
3. **Server side (Part 2):** Exchange RBAC for applications. A custom role limited to six commands and seven write parameters, assigned through a role group with a management scope that matches only mailboxes tagged `CustomAttribute15 = KRS-SecOps-Pilot`. Exchange itself rejects out-of-scope changes even if the code had a bug, and the boundary test proves it.
4. **Audit:** every action is written to the JSON-lines log with a correlation ID.

## Part 2 role groups (Exchange Online and Purview)

| Role group | Roles | Scope | What the app can do |
| --- | --- | --- | --- |
| KRS-SecOps Pilot Mailbox Automation (Exchange) | KRS-SecOps Mailbox Hardening (custom, from Mail Recipients) | KRS-SecOps Pilot Mailboxes (tagged mailboxes only) | Get-Mailbox, Get-CASMailbox, Get-InboxRule, Get-Recipient; Set-Mailbox limited to ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward; Set-CASMailbox limited to PopEnabled, ImapEnabled, SmtpClientAuthenticationDisabled |
| KRS-SecOps Pilot Mailbox Automation (Exchange) | View-Only Configuration | None (no write) | Read outbound spam policies, remote domains, transport rules, transport config, DKIM, accepted domains |
| KRS-SecOps Purview Baseline Reader (Security & Compliance) | Sensitivity Label Reader, View-Only DLP Compliance Management, View-Only Retention Management | Read-only | Read labels, label policies, DLP and retention policies and rules |

Rejected for Part 2: **Mail Recipients** as-is (can change almost any mailbox setting), **Audit Logs** (includes organisation-wide audit settings no recipient scope limits), **Compliance Administrator** and **Exchange Administrator** Entra roles (tenant-wide).

## Deliberately not used

| Permission | Why not |
| --- | --- |
| Directory.Read.All | Typed endpoints cover every lookup with narrower permissions. |
| Any *.ReadWrite.All in Parts 1 and 2 | Part 1 is read-only. Part 2 writes go through Exchange RBAC with a scope. |
| Client secrets | Certificate only. The private key is non-exportable. |
