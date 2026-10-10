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
| 3 | IdentityRiskyUser.Read.All | Microsoft Graph | Entra ID Protection risk for one user | Read-only. Risk level only; individual risk detections are not needed. |

Part 3 adds **no Graph write permission**. Containment writes come from a directory role scoped to an
administrative unit (below), because Graph's narrow write permissions cannot be scoped to users.

## Defence in depth for writes

1. **Code:** every write function calls `Assert-KRSPilotScope` and refuses any account outside `@m365.kingsruleusa.com`.
2. **Change control:** write functions use `SupportsShouldProcess` with `ConfirmImpact='High'`, so `-WhatIf` previews and `-Confirm` prompts.
3. **Server side (Parts 2 and 3):** Exchange RBAC for applications. A custom role limited to six commands and seven write parameters in Part 2 (eight commands after Part 3 added the two inbox-rule commands), assigned through a role group with a management scope that matches only mailboxes tagged `CustomAttribute15 = KRS-SecOps-Pilot`. Exchange itself rejects out-of-scope changes even if the code had a bug, and the boundary test proves it. In Part 3, Entra does the same for user accounts: the app's only directory role is scoped to an administrative unit holding the three pilot users, and Graph returns 403 for anyone else.
4. **Separation of duties (Part 3):** containment and recovery require a ticket ID and an approver who is not the operator; both are recorded with every action.
5. **Audit:** every action is written to the JSON-lines log with a correlation ID.

## Part 2 role groups (Exchange Online and Purview)

| Role group | Roles | Scope | What the app can do |
| --- | --- | --- | --- |
| KRS-SecOps Pilot Mailbox Automation (Exchange) | KRS-SecOps Mailbox Hardening (custom, from Mail Recipients) | KRS-SecOps Pilot Mailboxes (tagged mailboxes only) | Get-Mailbox, Get-CASMailbox, Get-InboxRule, Get-Recipient; Set-Mailbox limited to ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward; Set-CASMailbox limited to PopEnabled, ImapEnabled, SmtpClientAuthenticationDisabled |
| KRS-SecOps Pilot Mailbox Automation (Exchange) | View-Only Configuration | None (no write) | Read outbound spam policies, remote domains, transport rules, transport config, DKIM, accepted domains |
| KRS-SecOps Purview Baseline Reader (Security & Compliance) | Sensitivity Label Reader, View-Only DLP Compliance Management, View-Only Retention Management | Read-only | Read labels, label policies, DLP and retention policies and rules |

Rejected for Part 2: **Mail Recipients** as-is (can change almost any mailbox setting), **Audit Logs** (includes organisation-wide audit settings no recipient scope limits), **Compliance Administrator** and **Exchange Administrator** Entra roles (tenant-wide).

## Part 3 additions (Entra ID and Exchange Online)

| Where | Grant | Scope | What the app can do |
| --- | --- | --- | --- |
| Entra ID | User Administrator | Administrative unit `KRS-SecOps Pilot Containment` (3 pilot users) | Block sign-in and revoke sessions for those users. Graph refuses the same calls for anyone else, and the role cannot act on administrators. |
| Exchange (custom role) | `Disable-InboxRule`, `Enable-InboxRule` added to KRS-SecOps Mailbox Hardening | KRS-SecOps Pilot Mailboxes (tagged mailboxes only) | Switch a forwarding rule off (containment) or back on (explicit recovery). No `Remove-InboxRule`: rules are evidence. The role now has 8 commands. |
| Exchange (role group) | View-Only Audit Logs | Read-only | `Search-UnifiedAuditLog`: who created or changed inbox rules and forwarding, when and from where |

Rejected for Part 3: **User.EnableDisableAccount.All** and **User.RevokeSessions.All** (narrow, but tenant-wide and unscopable), **User Administrator** tenant-wide, **IdentityRiskEvent.Read.All** (the user's risk level is enough), and **Remove-InboxRule** (deleting a planted rule destroys evidence; a person does it after review).

Accepted trade-off: within the administrative unit, User Administrator could also reset passwords or edit profiles of the three pilot users. That is broader than block and revoke, but bounded to three test accounts by the platform, which no tenant-wide permission could offer.

## Deliberately not used

| Permission | Why not |
| --- | --- |
| Directory.Read.All | Typed endpoints cover every lookup with narrower permissions. |
| Any Graph write permission (*.ReadWrite.All and narrower) | Part 1 is read-only. Part 2 writes go through Exchange RBAC with a scope; Part 3 writes through a role scoped to an administrative unit. |
| Client secrets | Certificate only. The private key is non-exportable. |
