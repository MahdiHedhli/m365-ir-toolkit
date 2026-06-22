# Changelog

## v0.2.0 — 2026-06-22

- **Corrected `MailItemsAccessed` availability.** It is part of Purview Audit (**Standard**) — the tier Business Premium ships — not E5 / Audit (Premium) only as previously documented. Microsoft moved the formerly-Premium audit events into Audit (Standard) (rolled out during 2024; available to all worldwide commercial customers as of May 2024), so the toolkit can rely on it at Business Premium. Updated README and the telemetry-licensing map; added not-retroactive / verify-per-tenant caveats and sources.
- **`Find-OrgAccessFromIP.ps1`: added a `MailItemsAccessed` detection pass — closes a read-only blind spot.** The org sweep filtered the UAL with `-IPAddresses`, which does **not** return `MailItemsAccessed`; an actor whose only IP-tagged footprint was *reading* mail (token-replay / quiet recon that never re-emits a sign-in from that IP) could be missed entirely. The sweep now also pulls `MailItemsAccessed` by operation org-wide and filters it to the suspect IPs, folds matches into the per-account verdict (mail reads now count as ACCESS), flags accounts seen *only* via reads as **read-only / recon**, reports the read scope, and writes `ORG_IP_mailreads_RAW.csv`. Still read-only; depends on `MailItemsAccessed` being in the mailbox audit set, and is high-volume on large tenants (narrow the window if it caps).
- **Renamed the admin auth parameter to `-AdminUpn`** (was `-ConnectAs`) across all three scripts. Pass `-AdminUpn admin@tenant.com` to skip the Exchange Online console email prompt; scripts reuse an existing Microsoft Graph / Exchange Online session and tear down only what they opened.
- **README / prerequisites:** clarified `-AdminUpn` (admin you authenticate as) vs `-UserPrincipalName` (account investigated), documented the new `MailItemsAccessed` pass in the `Find-OrgAccessFromIP.ps1` description, and noted PowerShell 5.1/7 plus the Exchange Online **V3** module requirement (`Get-ConnectionInformation`).

## v0.1.0 — 2026-06-22

Initial release.

- `Trace-CompromiseTimeline.ps1` — suspect-IP + user timeline across UAL and Entra sign-ins, with inbox-rule and MFA snapshots.
- `Find-OrgAccessFromIP.ps1` — org-wide hunt for accounts accessed vs. attempted from an IP set; accepts multiple IPs for AS-rotation sweeps.
- `Get-AccountIPReport.ps1` — per-account IP report enriched with ASN/geo/company and hosting flags; multi-user with cross-account correlation and ASN rollup.
- All three scripts reuse an existing Microsoft Graph / Exchange Online session when one is already open, and accept `-ConnectAs <admin-upn>` to skip the Exchange Online console email prompt.
- Docs: getting-started, telemetry-licensing map, compromised-account playbook, account-containment checklist.
