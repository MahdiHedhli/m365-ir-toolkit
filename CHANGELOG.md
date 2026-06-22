# Changelog

## v0.1.0 — 2026-06-22

Initial release.

- `Trace-CompromiseTimeline.ps1` — suspect-IP + user timeline across UAL and Entra sign-ins, with inbox-rule and MFA snapshots.
- `Find-OrgAccessFromIP.ps1` — org-wide hunt for accounts accessed vs. attempted from an IP set; accepts multiple IPs for AS-rotation sweeps.
- `Get-AccountIPReport.ps1` — per-account IP report enriched with ASN/geo/company and hosting flags; multi-user with cross-account correlation and ASN rollup.
- All three scripts reuse an existing Microsoft Graph / Exchange Online session when one is already open, and accept `-ConnectAs <admin-upn>` to skip the Exchange Online console email prompt.
- Docs: getting-started, telemetry-licensing map, compromised-account playbook, account-containment checklist.
