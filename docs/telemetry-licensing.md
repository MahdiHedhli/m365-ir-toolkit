# Telemetry & licensing map

A hunt only works if the tenant actually collects the data. This maps each log these scripts touch to the Microsoft license that unlocks it, how this toolkit reaches it, and the retention you get — so an empty result tells you *clean* vs *blind*.

> SKUs, retention windows, and product names change. Confirm against current Microsoft docs for a specific tenant.

## Where PowerShell reaches

This toolkit pulls from two surfaces, no SIEM required:

- **Microsoft Graph** (`Invoke-MgGraphRequest`) → sign-in logs (interactive + non-interactive) and directory audit logs.
- **Exchange Online** (`Search-UnifiedAuditLog`) → the Unified Audit Log, spanning every workload, with the client IP per record.

If you instead have **Microsoft Sentinel** or **Defender XDR Advanced Hunting**, those same signals (plus `Device*`, `Identity*`, `Email*`, `CloudAppEvents`) are queryable in KQL with longer retention — use the [Cloud Threat Hunting Playbook](https://github.com/MahdiHedhli/cloud-threat-hunting-playbook).

## Telemetry → license → retention

| Telemetry | Unlocked by | How this toolkit reads it | Retention |
| --- | --- | --- | --- |
| Interactive sign-ins | Entra ID Free generates; **P1** for full reports | Graph `auditLogs/signIns` | 7 d (Free), 30 d (P1/P2) |
| Non-interactive sign-ins | Entra ID **P1** | Graph beta `signInEventTypes` filter | 30 d |
| Directory audit (consent, role adds, MFA reg) | Entra Free+ | Graph `auditLogs/directoryAudits` | 7 d (Free), 30 d (P1/P2) |
| **Unified Audit Log** (all workloads, has client IP) | Purview Audit **Standard** (most M365) | Exchange `Search-UnifiedAuditLog` | **~180 d** (Standard) |
| Risk signals (`RiskState`, `RiskLevelDuringSignIn`, risky users) | Entra ID **P2** (Identity Protection) | — (not populated at P1) | n/a at P1 |
| `MailItemsAccessed` (which mail was read) | **E5 / Audit Premium** | — (not present at BP) | n/a at BP |

## What you can pull, by tier

| Tier | With these scripts |
| --- | --- |
| **Entra Free** (base Business Basic/Standard) | UAL (~180 d) + 7-day sign-ins; no risk; no Device/Identity/Email tables anywhere |
| **Business Premium** (Entra P1, Defender for Business, MDO P1) | UAL (~180 d) + 30-day sign-ins incl. non-interactive + directory audit. **No** risk scoring (P2), **no** `MailItemsAccessed` (E5) |
| **+ Defender Suite / E5 Security**, or **E5** | All of the above **plus** Entra P2 risk and the full Defender XDR KQL surface → switch to the [KQL playbook](https://github.com/MahdiHedhli/cloud-threat-hunting-playbook) |

## Reading an empty result

Four causes, ruled out in order:

1. **The license doesn't generate it** (this page) — e.g. risk columns at P1.
2. **Past the retention window** — sign-ins ~30 d; UAL ~180 d.
3. **Auditing/diagnostic export off** — confirm `UnifiedAuditLogIngestionEnabled`.
4. **Nothing happened.**

Only the fourth is clean. The first three are blind spots.
