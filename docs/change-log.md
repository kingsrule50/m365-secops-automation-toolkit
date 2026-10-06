# Change log: shared tenant changes

The lab runs in a shared Microsoft 365 developer tenant owned by someone else. Every change to the
tenant is recorded here, with the owner's approval, the same way a production change would be.

| Date | Change | Scope | Approved by | Rollback |
| --- | --- | --- | --- | --- |
| 2026-10-04 | Create app registration `app-krs-secops-automation` with certificate credential (thumbprint 8EFC3C81…) | Tenant (app object) | Tenant owner (mentor): general lab approval | Delete the app registration |
| 2026-10-04 | Admin consent: 6 Part 1 read-only Graph permissions (see permission-matrix.md) | Tenant (read) | Tenant owner (mentor): general lab approval | Remove the app role assignments |
| 2026-10-04 | Create 5 pilot users and `SG-KRS-SecOps-Pilot` (c3a43abe…); SPE_E5 for amara.okafor, marcus.bennett, sofia.laurent | @m365.kingsruleusa.com only | Tenant owner (mentor): general lab approval | Remove licences; delete the users and group |
| 2026-10-04 | Seeded test findings: `app-krs-demo-legacy` (secret expires 2026-10-11); User Administrator active-permanent for daniel.reyes; Security Reader eligible for priya.shah | Pilot users and one demo app | Tenant owner (mentor): general lab approval | Delete the app; remove both role assignments |
| 2026-10-05 | Admin consent: Office 365 Exchange Online `Exchange.ManageAsApp` for `app-krs-secops-automation` (Part 2). Grants nothing on its own; no Entra role assigned | Tenant (app permission) | Tenant owner (mentor): general lab approval | Remove the app role assignment |
| 2026-10-05 | Tag pilot mailboxes amara.okafor, marcus.bennett, sofia.laurent with `CustomAttribute15 = KRS-SecOps-Pilot` | 3 pilot mailboxes | Tenant owner (mentor): general lab approval | `Set-Mailbox <upn> -CustomAttribute15 $null` |
| 2026-10-05 | Exchange RBAC: management scope `KRS-SecOps Pilot Mailboxes` (CustomAttribute15 tag), custom role `KRS-SecOps Mailbox Hardening` (6 cmdlets; forwarding and POP/IMAP/SMTP AUTH parameters only), role group `KRS-SecOps Pilot Mailbox Automation` (+ View-Only Configuration), app service principal registered as its only member | Exchange Online; writes limited to the 3 tagged mailboxes | Tenant owner (mentor): general lab approval | `Remove-RoleGroup`, `Remove-ManagementRole`, `Remove-ManagementScope`, `Remove-ServicePrincipal` |
| 2026-10-05 | Security & Compliance RBAC: role group `KRS-SecOps Purview Baseline Reader` (Sensitivity Label Reader, View-Only DLP Compliance Management, View-Only Retention Management), app service principal registered as its only member | Purview (read-only) | Tenant owner (mentor): general lab approval | `Remove-RoleGroup`, `Remove-ServicePrincipal` (Security & Compliance PowerShell) |
