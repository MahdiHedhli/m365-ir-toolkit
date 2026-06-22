# m365-ir-toolkit

Read-only PowerShell for Microsoft 365 / Entra incident response — collect logs, trace an IP, and build a timeline in tenants that **don't have a SIEM**.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Read-only](https://img.shields.io/badge/Operations-read--only-brightgreen)

## Why this exists

Most Microsoft 365 threat-hunting material assumes you can write KQL against Microsoft Sentinel or Defender XDR Advanced Hunting. That assumption quietly excludes a huge population of tenants: small and mid-sized businesses on **Microsoft 365 Business Premium**. At that tier you get Entra ID P1 and Defender for Business — and **no KQL surface at all**. No Advanced Hunting in the portal, no Log Analytics workspace, and sign-in/audit logs retained for only ~30 days.

So when one of those tenants has a compromised account, you can't "run a hunt." You have to pull the logs yourself, straight from the APIs, before they age out — and you have to know which log still holds the answer. That's this toolkit: read-only PowerShell that collects everything a Business Premium tenant exposes (the Unified Audit Log via Exchange Online; sign-in and directory logs via Microsoft Graph), traces a suspect IP across all of it, and assembles a timeline.

It's the reactive, incident-time counterpart to a query library — built for the tenant that doesn't have the premium telemetry stack.

## Have a SIEM or E5? You want KQL instead

If the tenant has **Microsoft Sentinel** or **Defender XDR Advanced Hunting** — i.e. Microsoft 365 E5, E5 Security, the Defender Suite add-on, or standalone Entra ID P2 with the Defender products — you have a proper KQL hunting surface and longer retention. Use the companion repo:

➡️ **[Cloud Threat Hunting Playbook](https://github.com/MahdiHedhli/cloud-threat-hunting-playbook)** — reusable KQL hunting queries for Entra, Azure, and Defender XDR.

Which one fits:

| Tenant has… | KQL surface? | Use |
| --- | --- | --- |
| Microsoft Sentinel / Log Analytics | Yes | [Cloud Threat Hunting Playbook](https://github.com/MahdiHedhli/cloud-threat-hunting-playbook) (KQL) |
| Defender XDR Advanced Hunting (E5 / E5 Security / Defender Suite) | Yes | [Cloud Threat Hunting Playbook](https://github.com/MahdiHedhli/cloud-threat-hunting-playbook) (KQL) |
| **Business Premium / Entra P1, no SIEM** | **No** | **This repo (PowerShell)** |
| Entra Free (base Business Basic/Standard) | No | This repo — but note 7-day log retention |

Full license → telemetry → retention map: [docs/telemetry-licensing.md](docs/telemetry-licensing.md).

## What's in here

Three read-only scripts in [`scripts/`](scripts/):

- **`Trace-CompromiseTimeline.ps1`** — given a suspect IP and a user, pulls every accessible log and builds one chronological timeline of the account's activity.
- **`Find-OrgAccessFromIP.ps1`** — given one or more IPs, hunts the whole tenant for which accounts that IP set *accessed* vs. merely *attempted* — the blast-radius / "is it isolated?" question. It also runs a `MailItemsAccessed` pass (pulled by operation org-wide, then filtered to the suspect IPs) so **read-only / recon-only** access is caught too — not just sign-ins, sends, rules, and deletes — because `Search-UnifiedAuditLog -IPAddresses` doesn't return `MailItemsAccessed`.
- **`Get-AccountIPReport.ps1`** — given one or more users, reports every IP that touched those accounts, enriched with ASN / company / geo / hosting flags, with cross-account correlation and an ASN rollup that exposes IP rotation.

All three are **read-only**: they collect, they never change the tenant.

## Prerequisites

```powershell
Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
```

Runs on **PowerShell 5.1 or 7**. The Exchange Online module must be **V3** (`ExchangeOnlineManagement` v3+) — the session-reuse guard uses `Get-ConnectionInformation`, which is V3-only.

Roles on the account you run these with:

- Entra **Security Reader** or **Reports Reader** (sign-in logs require Entra P1, which Business Premium includes)
- Exchange/Purview **View-Only Audit Logs** (for the Unified Audit Log)

Full setup, Graph scopes, and gotchas: [docs/getting-started.md](docs/getting-started.md).

## Step-by-step: investigating a compromised account

The scripts chain into a workflow. Set the dates to bracket the suspected period through today — and read the retention note below before trusting any empty result.

> **Sign-in tip.** If `Connect-ExchangeOnline` prompts for an email at the console, add `-AdminUpn admin@tenant.com` to go straight to browser auth. `-AdminUpn` is the admin account you authenticate *as* — distinct from `-UserPrincipalName`, which is the account being *investigated*. If you've already run `Connect-MgGraph` / `Connect-ExchangeOnline` in the session, the scripts reuse those sessions and won't prompt.

**1 — Build the timeline for the known-compromised account.**

```powershell
.\scripts\Trace-CompromiseTimeline.ps1 -SuspectIP 185.174.101.58 -UserPrincipalName jdoe@client.com -StartDate '2026-05-01' -EndDate '2026-06-22'
```

Produces `TIMELINE_full.csv` (everything, chronological), `TIMELINE_suspect_IP_only.csv` (just the attacker's actions), inbox-rule and MFA snapshots, and raw evidence. The console flags any *other* users that IP signed into.

**2 — Scope the blast radius: is it isolated?**

```powershell
.\scripts\Find-OrgAccessFromIP.ps1 -SuspectIP 185.174.101.58 -StartDate '2026-05-01' -EndDate '2026-06-22'
```

Sweeps the whole tenant for that IP and rules each account **ACCESSED** (successful sign-in, audit-log activity, **or mail reads**) vs. **attempted** (failed only). `ORG_IP_ACCESSED_users.txt` is your response list.

Because `Search-UnifiedAuditLog -IPAddresses` does **not** return `MailItemsAccessed`, the sweep adds a second pass that pulls `MailItemsAccessed` by operation org-wide and filters it to the suspect IPs — so it catches an actor whose only IP-tagged footprint is **reading mail** (token-replay / quiet recon the IP-only pass would miss). Such accounts are flagged **read-only / recon**, and the read evidence (incl. `Subject` / `InternetMessageId`) lands in `ORG_IP_mailreads_RAW.csv`. The pass relies on `MailItemsAccessed` being in the mailbox audit set — the same Audit (Standard) capability that makes read-evidence available at Business Premium ([telemetry-licensing map](docs/telemetry-licensing.md)) — and is high-volume on large tenants, so narrow the window if it caps.

**3 — Characterize the IPs and catch rotation.**

```powershell
.\scripts\Get-AccountIPReport.ps1 -UserPrincipalName jdoe@client.com,asmith@client.com -StartDate '2026-05-01' -EndDate '2026-06-22'
```

Every IP that touched those accounts, enriched with ASN / company / geo and hosting/proxy flags. `shared_IP_rollup.csv` shows IPs that hit **multiple** accounts (spread); `account_ASN_rollup.csv` shows multiple IPs in **one hosting AS** (rotation).

**4 — Pivot on the AS and re-sweep.**

Take the hosting-AS sibling IPs the rollup reveals and run the org-wide sweep again across the whole set:

```powershell
.\scripts\Find-OrgAccessFromIP.ps1 -SuspectIP 185.174.101.58,185.174.101.91,185.174.102.7 -StartDate '2026-05-01' -EndDate '2026-06-22'
```

That turns "which accounts did this *IP* touch" into "which accounts did this *actor* touch."

Full decision tree: [docs/account-compromise.md](docs/account-compromise.md). Step-by-step containment runbook: [docs/containment-checklist.md](docs/containment-checklist.md).

## The retention trap (read this)

At Business Premium / Entra P1, **Entra sign-in and audit logs are retained only ~30 days.** The **Unified Audit Log** (Exchange/Purview) retains **~180 days**, spans every workload, and carries the client IP on each record. So for a compromise from a month or more ago, the sign-in logs are likely **already gone**, and the UAL is your primary source. An empty sign-in result for that period means *expired*, not *clean*. Every script leans on the UAL for exactly this reason and says so in its output.

## What you can and can't prove at Business Premium

Two licensing points to keep straight (not bugs):

- **Risk scoring** (`RiskState`, `RiskLevelDuringSignIn`, risky-user reports) is Entra **P2** / Identity Protection — blank at P1.
- **Which mail was actually read** (`MailItemsAccessed`) was historically E5 / Purview Audit (Premium) only — but Microsoft moved the formerly-Premium audit events, `MailItemsAccessed` among them, into Purview Audit (**Standard**). Rollout to Audit (Standard) license holders landed during 2024 (preview ~June 2024), and as of May 2024 the expanded logs were made available to all worldwide commercial customers (E3/G3 and above auto-enabled). Audit (Standard) is what Business Premium ships with, so `MailItemsAccessed` is **typically available** at Business Premium via `Search-UnifiedAuditLog` — including folder-bind records carrying `InternetMessageId` and `Subject` — and this toolkit relies on it. Caveats: it must be in the mailbox's audit set (auto-enabled unless a custom mailbox audit configuration was applied, in which case re-apply the default set), and it is **never retroactive** — you cannot backfill it for a period before it was being generated. Field confusion persists and some SKUs (e.g. Business Basic) are described as lacking it, so **verify against your tenant**.

So you can see *that* an IP signed in, *what* it did (rules, sends, deletes, file touches), and — where `MailItemsAccessed` is present — *which mail items it read*, while never assuming whole-mailbox access beyond what the logs show. Their absence is a licensing/config gap or a pre-logging period, never proof that nothing happened.

## Safety & scope

- **Read-only.** These scripts collect; they make no changes. Containment — revoking sessions, resetting credentials, removing attacker MFA/rules, Conditional Access — is deliberately *not* automated. Do it through your own admin process — see the [containment checklist](docs/containment-checklist.md).
- **Enrichment uses a third party.** `Get-AccountIPReport.ps1` sends observed IPs — including users' own — to ip-api.com for ASN/geo. Use `-SkipEnrichment` for privacy-sensitive or regulated tenants, or swap in an offline GeoIP database.
- **Output contains client data.** Generated CSV folders are git-ignored by default. Keep raw `*_RAW.csv` evidence untouched and analyze on copies.
- **Verify against your environment.** Microsoft renames products and changes retention; confirm specifics for the tenant you're working.

## License

MIT — see [LICENSE](LICENSE). For defensive incident response on tenants you are authorized to investigate.
