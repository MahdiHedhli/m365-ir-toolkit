# Playbook: compromised M365 account (no SIEM)

End-to-end response for a Business Premium tenant, chaining the three scripts. Read-only collection; containment is a hand-off to your admin process (last section).

## 0 — Frame it

Gather: the **suspect IP** (from the alert, a suspicious sign-in, a BEC report), the **affected user(s)**, and a **date window**. Set `-StartDate` to bracket the suspected period — but remember sign-ins only reach ~30 days, so the Unified Audit Log carries anything older. When in doubt, start the window wider (up to ~180 days back).

## 1 — Timeline the known account

```powershell
.\scripts\Trace-CompromiseTimeline.ps1 -SuspectIP <ip> -UserPrincipalName <user> -StartDate <start> -EndDate <end>
```

Read `TIMELINE_full.csv` to find the **pivot** — where the user's normal pattern stops and the suspect IP takes over. Then check:

- **Inbox rules** (`inbox_rules_current.csv` + `New-InboxRule`/`Set-InboxRule` in the timeline) — auto-forward/auto-delete is classic BEC persistence. A rule the attacker later deleted won't show in the snapshot, but the UAL event will.
- **MFA methods** (`mfa_methods_current.csv`) — an unfamiliar phone or authenticator is how they survive a password reset.
- The console line listing **other users the IP signed into** — your first hint of spread.

## 2 — Scope the blast radius

```powershell
.\scripts\Find-OrgAccessFromIP.ps1 -SuspectIP <ip> -StartDate <start> -EndDate <end>
```

`ORG_IP_user_summary.csv` ranks every account the IP touched: **ACCESSED** (successful sign-in or UAL activity) vs. **attempted** (failed only). `ORG_IP_ACCESSED_users.txt` is your action list. A wide spread of *attempted*-only accounts is password spray, not 50 breaches — but check whether any later flipped to ACCESSED.

## 3 — Characterize & correlate

```powershell
.\scripts\Get-AccountIPReport.ps1 -UserPrincipalName <user1>,<user2>,... -StartDate <start> -EndDate <end>
```

- `shared_IP_rollup.csv` — the **same IP across multiple accounts** = one actor, spread compromise.
- `account_ASN_rollup.csv` — **multiple IPs in one hosting AS** = the attacker rotating addresses.

The signal that means *attacker*: hosting/proxy + foreign-or-wrong-geo + clustered in time. A residential ISP in the user's own city reappearing over months is just the user.

## 4 — Pivot on the AS, re-sweep

Feed the hosting-AS sibling IPs from step 3 back into the org-wide sweep as a set:

```powershell
.\scripts\Find-OrgAccessFromIP.ps1 -SuspectIP <ip1>,<ip2>,<ip3> -StartDate <start> -EndDate <end>
```

This catches accounts hit from *other* addresses in the same rented infrastructure that a single-IP sweep misses.

## 5 — Contain (your admin process — not automated here)

Full step-by-step runbook: **[containment-checklist.md](containment-checklist.md)** — block sign-in, then work the survives-a-reset persistence list (MFA, OAuth, forwarding, rules, delegation), then verify it held. The essentials, for each confirmed-accessed account:

- Revoke sign-in sessions / refresh tokens.
- Reset the password.
- Review and remove attacker-registered MFA methods.
- Remove malicious inbox rules and forwarding.

At the tenant level, consider a Conditional Access policy that blocks the hosting ASN or geo-fences sign-ins to expected locations. Blocking a single IP alone is weak — they rotate.

## Evidence handling

Keep the `*_RAW.csv` files (full `AuditData` JSON) untouched as your source of record. Do analysis on copies. These folders are git-ignored so client data never lands in the repo.

## Limits to state in the report

No risk scoring (Entra P2) and no `MailItemsAccessed` (E5) at Business Premium. You can establish *that* each account was accessed and *what* was done — not every message read. Say so explicitly rather than implying full visibility.
