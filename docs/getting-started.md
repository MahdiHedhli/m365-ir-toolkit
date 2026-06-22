# Getting started

Setup before you run anything. Everything here is read-only.

## 1. Install the modules

```powershell
Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
```

Only `Microsoft.Graph.Authentication` is needed (the scripts call Graph through `Invoke-MgGraphRequest`, not the full typed SDK), plus `ExchangeOnlineManagement` for the Unified Audit Log.

## 2. Roles

Assign the account you'll run with the **least privilege** that works:

- **Entra**: `Security Reader` or `Reports Reader` — required to read sign-in and directory logs. Sign-in logs also require the tenant to have **Entra ID P1** (Business Premium includes it).
- **Exchange / Purview**: `View-Only Audit Logs` (or `Audit Logs`) — required for `Search-UnifiedAuditLog`. Often assigned via a Purview/Exchange role group.

## 3. Graph scopes

The scripts request these delegated scopes on `Connect-MgGraph` (consent once):

- `AuditLog.Read.All` — sign-in and directory audit logs
- `Directory.Read.All` — directory objects
- `UserAuthenticationMethod.Read.All` — registered MFA methods (timeline script only)

## 4. Connecting

Each script connects interactively — expect **two sign-in prompts** (Graph, then Exchange Online):

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All" -NoWelcome
Connect-ExchangeOnline -ShowBanner:$false
```

You don't run these yourself — the scripts do — but you'll authenticate when prompted.

## 5. Confirm auditing is on

If unified audit logging is disabled, every UAL search silently returns nothing. The scripts check and warn, but to verify manually:

```powershell
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
```

## 6. Dates and retention

- Pass `-StartDate` / `-EndDate` as `'yyyy-MM-dd'`. The scripts treat the window in UTC and the merged timelines are UTC.
- **Retention is the thing that bites.** At Entra P1, sign-in/audit logs reach ~30 days; the Unified Audit Log reaches ~180 days. Set `-StartDate` to cover your suspected period, but know that anything older than ~30 days will come only from the UAL pull. See [telemetry-licensing.md](telemetry-licensing.md).

## 7. Running

Run from the repo root so the `.\scripts\…` paths resolve, e.g.:

```powershell
.\scripts\Get-AccountIPReport.ps1 -UserPrincipalName jdoe@client.com -StartDate '2026-05-01' -EndDate '2026-06-22'
```

## Troubleshooting

- **"Neither tenant is B2C or tenant doesn't have premium license"** on sign-ins → the tenant lacks Entra P1, or your account can't read reports. Confirm P1 and the Security/Reports Reader role.
- **UAL returns nothing** → auditing disabled (step 5), the window is past retention, or the account lacks the audit role.
- **Sign-in pull is empty for older dates but UAL has data** → expected; sign-in logs aged out. Not a clean result.
- **Enrichment errors / rate limited** → ip-api.com free tier is 45 req/min over HTTP; the report batches and paces, but you can re-run with `-SkipEnrichment` to fall back to Microsoft-resolved ASN/geo.
