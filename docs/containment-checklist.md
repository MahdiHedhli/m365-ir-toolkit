# Account Containment Checklist (BEC / compromised M365 account)

A field runbook for locking a threat actor out of a compromised Microsoft 365 account and
keeping them out. Written for Business Premium / Entra P1 tenants (no Sentinel, no P2 risk
data), but the steps apply to any M365 tenant.

> **The one thing to internalize:** resetting the password and revoking tokens is **necessary
> but not sufficient.** An attacker's foothold almost never lives in the password. It lives in
> the things a reset doesn't touch — registered MFA methods, OAuth grants, forwarding, inbox
> rules, and delegation. Two of those (a rogue **MFA method** and a consented **OAuth app**) let
> the attacker walk the password reset right back or keep a live token. Work the whole list, in
> order, and verify it held.

All commands are PowerShell (`Microsoft.Graph` + `ExchangeOnlineManagement`). Replace
`<user@tenant.com>` throughout. Most steps are read-then-act — read first, confirm what's
unexpected, then remove it.

---

## Phase 0 — Decide and preserve (before you touch anything)

- [ ] **Put the mailbox on hold first if there's any chance of investigation, dispute, or
      breach notification.** The attacker is likely deleting as you work; single-item recovery
      has a short default window. Litigation hold / eDiscovery hold preserves Recoverable Items
      even for already-deleted mail.
      ```powershell
      Set-Mailbox <user@tenant.com> -LitigationHoldEnabled $true
      ```
- [ ] **Decide whether to tip the attacker off.** Disabling sign-in is loud (the attacker
      notices immediately and may burn what they have). With active fraud / money moving, loud-
      and-fast is the right call. If you're still scoping quietly, you may sequence differently —
      but never leave a money-moving compromise live to preserve stealth.
- [ ] **Capture evidence before you delete it.** Snapshot current inbox rules, forwarding, MFA
      methods, and OAuth grants to CSV *before* removing them (the toolkit's
      `Trace-CompromiseTimeline.ps1` does the rules + MFA snapshot for you).

## Phase 1 — Close the residual window

Token revocation invalidates **refresh** tokens, but already-issued **access** tokens can stay
valid up to ~1 hour. With live access, don't wait that gap out — block sign-in outright.

- [ ] **Block sign-in** (locks the legitimate user out too; re-enable once clean):
      ```powershell
      Update-MgUser -UserId <user@tenant.com> -AccountEnabled:$false
      ```
- [ ] **Revoke all sessions** (run it even if the helpdesk already did — re-run after Phase 2 too):
      ```powershell
      Revoke-MgUserSignInSession -UserId <user@tenant.com>
      ```

## Phase 2 — Kill persistence (the survives-a-reset list)

Order matters: MFA and OAuth first, because those are the vectors that can undo your reset.

- [ ] **MFA / authentication methods — the most likely backdoor.** A method the attacker
      registered keeps them in and lets them self-service-reset the password right back. Review
      and remove anything unrecognized, then have the user re-register fresh from a trusted device.
      ```powershell
      Get-MgUserAuthenticationMethod -UserId <user@tenant.com>
      # remove unknown methods (Entra admin center → user → Authentication methods is fastest)
      ```
- [ ] **OAuth app consents.** AiTM/token-theft BEC frequently drops a consented mail app
      (lookalike "Mail" clients, sync/migration tools, archivers) that holds its **own** refresh
      token — surviving both the password reset and the token revoke. Revoke anything unfamiliar.
      ```powershell
      Get-MgUserOauth2PermissionGrant -UserId <user-objectId>
      # Entra → user → Applications, and Enterprise apps → recently consented
      ```
- [ ] **Mailbox forwarding** (separate from inbox rules, and easy to miss):
      ```powershell
      Get-Mailbox <user@tenant.com> | fl ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
      Set-Mailbox <user@tenant.com> -ForwardingAddress $null -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false
      ```
- [ ] **Inbox rules.** Remove the malicious one(s) and audit the rest — attackers usually leave
      more than one, and name them to blend in (e.g. a generic-looking `Microsoft …` name, a
      single character, or a blank name). Watch for rules that delete, redirect, mark-as-read, or
      move a specific sender's mail to an obscure folder (the classic "hide the counterparty" rule).
      ```powershell
      Get-InboxRule -Mailbox <user@tenant.com> | fl Name,Enabled,From,ForwardTo,RedirectTo,DeleteMessage,MarkAsRead,MoveToFolder,StopProcessingRules
      Remove-InboxRule -Mailbox <user@tenant.com> -Identity "<rule name>"
      ```
- [ ] **Mailbox delegation, SendAs, SendOnBehalf.** The attacker may have granted another account
      (theirs, or another compromised user) standing access so they keep reach after you clean
      this mailbox.
      ```powershell
      Get-MailboxPermission <user@tenant.com>   | ? { $_.User -notlike 'NT AUTHORITY*' }
      Get-RecipientPermission <user@tenant.com>                       # SendAs
      Get-Mailbox <user@tenant.com> | fl GrantSendOnBehalfTo
      ```
- [ ] **Registered / joined devices.** Remove devices the attacker registered to satisfy a
      device-compliance Conditional Access policy (Entra → user → Devices).
- [ ] **Legacy auth & app passwords.** A stolen password can be replayed over IMAP/POP/SMTP AUTH,
      bypassing MFA entirely. Confirm legacy auth is off for the mailbox and revoke any app passwords.
      ```powershell
      Get-CASMailbox <user@tenant.com> | fl ImapEnabled,PopEnabled,SmtpClientAuthenticationDisabled
      ```
- [ ] **Mailbox folder permissions & sharing.** Less common, but check for anonymous/external
      sharing the attacker added (calendar or folder publishing).
      ```powershell
      Get-MailboxFolderPermission '<user@tenant.com>:\Inbox'
      ```

## Phase 3 — Re-establish trust

- [ ] Set a new strong password (not reused). Re-register MFA **from a clean device**.
- [ ] Re-enable sign-in (`Update-MgUser -UserId <user@tenant.com> -AccountEnabled:$true`).
- [ ] **Rotate credentials that passed through the mailbox.** If the attacker read mail (check
      `MailItemsAccessed`), assume any password-reset links, shared secrets, or vendor/banking
      credentials sitting in that inbox are burned. Rotate them.

## Phase 4 — Verify it held (do not skip)

An attacker with a still-valid token or a missed vector will re-add a rule or forwarding within
**minutes** of being kicked. If anything below reappears, you missed a persistence path — almost
always a second MFA method or an OAuth grant.

- [ ] Re-check inbox rules, forwarding, and MFA methods at **~30–60 minutes**.
- [ ] Re-check again the **next day**.
- [ ] Re-run `Revoke-MgUserSignInSession` after Phase 2 cleanup.
- [ ] Re-run the toolkit's `Trace-CompromiseTimeline.ps1` for this user over the last few days and
      confirm **no new** activity from the attacker IPs/ASNs.

---

## Tenant-side, in parallel (don't clean one account in isolation)

- [ ] **Block the attacker infrastructure** in Conditional Access — the specific IPs **and their
      ASNs** (attackers rotate IPs within the same hosting/VPN AS). Geo-fence sign-in to the
      countries you actually operate in.
- [ ] **Tighten consent** so a stolen session can't silently grant a new app:
      Entra → Enterprise apps → Consent and permissions → set user consent to off (or
      verified-publishers, low-risk only), and enable the admin consent workflow with named reviewers.
- [ ] **Scope the blast radius.** Run the toolkit's `Find-OrgAccessFromIP.ps1` against the **whole
      attacker IP/ASN set** to find every other account the same infrastructure touched. BEC rarely
      stops at one mailbox — finance/AP and exec mailboxes are the usual second targets.
      ```powershell
      .\Find-OrgAccessFromIP.ps1 -SuspectIP <ip1>,<ip2>,<ip3> -StartDate '<yyyy-MM-dd>' -EndDate '<yyyy-MM-dd>'
      ```
- [ ] If the fraud involved redirected payments, drive the **out-of-band** action that the audit
      log can't do for you: have finance **phone-verify** (not email) any payment instruction or
      banking-detail change in the exposure window, and contact the bank about recall while the
      window is still open.

---

### Why these and not just "reset the password"

| Vector | Survives password reset? | Survives token revoke? | What it gives the attacker |
|---|---|---|---|
| Rogue **MFA method** | yes | yes | re-auth + ability to SSPR a new password |
| **OAuth** app consent | yes | yes (independent token) | persistent mailbox access with no user present |
| **Forwarding** / **inbox rule** | yes | yes | continued exfiltration + "hide the counterparty" |
| **Delegation / SendAs** | yes | yes | reach into the mailbox from another account |
| **Legacy auth / app password** | password-dependent | n/a | MFA-bypassing replay of a stolen password |
| Stolen **password** | no | n/a | the part a reset actually fixes |

The reset fixes the bottom row. Everything above it is why this checklist exists.
