<#
.SYNOPSIS
    Org-wide hunt for any access from a single suspect IP, to determine whether a
    compromise is isolated to one user or has spread. Read-only.

.WHAT IT ANSWERS
    "Which accounts did this IP touch, and which did it actually get into?"
    - Successful sign-in OR unified-audit-log activity from the IP  => ACCESSED
    - Only failed sign-ins from the IP                              => ATTEMPTED (possible spray)

.WHY THIS SHAPE (Business Premium / Entra P1)
    Entra sign-in logs retain ~30 days; the Unified Audit Log retains ~180 days
    and spans all workloads. A user hit in early May but not since will appear
    ONLY in the UAL, so the org-wide blast radius comes from the UAL pull.
    `Search-UnifiedAuditLog -IPAddresses` is already tenant-wide (no -UserIds).

.PREREQUISITES
    Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
    Roles: Entra "Security Reader"/"Reports Reader"; Exchange/Purview "View-Only Audit Logs".

.EXAMPLE
    # Single IP:
    .\Find-OrgAccessFromIP.ps1 -SuspectIP 185.174.101.58 -StartDate '2026-05-01' -EndDate '2026-06-22'
    # Whole AS-sibling set from Get-AccountIPReport.ps1's ASN rollup (catches rotation):
    .\Find-OrgAccessFromIP.ps1 -SuspectIP 185.174.101.58,185.174.101.91,185.174.102.7 -StartDate '2026-05-01' -EndDate '2026-06-22'

.NOTE ON SIGN-IN
    If Connect-ExchangeOnline keeps prompting for an email at the console, pass -AdminUpn
    admin@tenant.com to go straight to browser auth. If you've already run Connect-MgGraph /
    Connect-ExchangeOnline in this session, the script reuses those sessions and won't prompt at all.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$SuspectIP,   # one or many - pass the whole AS-sibling set to catch rotation
    [datetime]$StartDate = (Get-Date).AddDays(-180),
    [datetime]$EndDate   = (Get-Date),
    [string]$AdminUpn,   # admin UPN to authenticate as; skips Connect-ExchangeOnline's console email prompt
    [string]$OutputFolder
)

$ErrorActionPreference = 'Stop'
if (-not $OutputFolder) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $OutputFolder = Join-Path (Get-Location) "IR_orgIP_${stamp}"
}
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
function Write-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

function Normalize-IP([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip)) { return $null }
    $ip = $ip.Trim()
    if ($ip -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $Matches[1] }
    return $ip
}
$IPs = @($SuspectIP | ForEach-Object { Normalize-IP $_ } | Where-Object { $_ } | Select-Object -Unique)

# --- Connect (reuse existing sessions; -AdminUpn skips EXO's console email prompt) ---
Write-Section "Connecting"
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$weOpenedGraph = $false; $weOpenedExo = $false
if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All" -NoWelcome
    $weOpenedGraph = $true
} else { Write-Host "  Reusing Graph session: $((Get-MgContext).Account)" }
$exoConn = $null; try { $exoConn = Get-ConnectionInformation -ErrorAction SilentlyContinue } catch {}
if (-not $exoConn) {
    if ($AdminUpn) { Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false }
    else           { Connect-ExchangeOnline -ShowBanner:$false }
    $weOpenedExo = $true
} else { Write-Host "  Reusing Exchange Online session: $($exoConn.UserPrincipalName)" }
try {
    if (-not (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled) {
        Write-Warning "Unified audit log ingestion is DISABLED — historical data may be missing."
    }
} catch { Write-Warning "Could not confirm audit config: $($_.Exception.Message)" }
Write-Host "Suspect IP(s): $($IPs -join ', ')"
Write-Host "Window     : $($StartDate.ToString('u')) -> $($EndDate.ToString('u'))"
$siFloor = (Get-Date).AddDays(-30)
if ($StartDate -lt $siFloor) {
    Write-Warning ("Sign-in logs only reach ~{0:yyyy-MM-dd}. Earlier access shows up only in the UAL pull." -f $siFloor)
}

# --- Per-user aggregation scaffolding -------------------------------------
$agg = @{}
function Get-Bucket($user) {
    if ([string]::IsNullOrWhiteSpace($user)) { $user = '(unknown)' }
    $k = $user.ToLower()
    if (-not $agg.ContainsKey($k)) {
        $agg[$k] = [pscustomobject]@{
            User = $user; FirstSeen = $null; LastSeen = $null
            SuccessSignIns = 0; FailedSignIns = 0; UALEvents = 0; MailReadEvents = 0
            Workloads  = New-Object 'System.Collections.Generic.HashSet[string]'
            Operations = New-Object 'System.Collections.Generic.HashSet[string]'
        }
    }
    return $agg[$k]
}
function Bump-Time($b, $t) {
    if ($t) {
        if (-not $b.FirstSeen -or $t -lt $b.FirstSeen) { $b.FirstSeen = $t }
        if (-not $b.LastSeen  -or $t -gt $b.LastSeen ) { $b.LastSeen  = $t }
    }
}
$allEvents = New-Object System.Collections.Generic.List[object]

# --- 1) Unified Audit Log, org-wide, by IP --------------------------------
Write-Section "Unified Audit Log (org-wide, by IP)"
$sid = [guid]::NewGuid().ToString()
$ualRaw = New-Object System.Collections.Generic.List[object]
$page = 0; $maxPages = 25
do {
    $page++
    $batch = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -IPAddresses $IPs `
                -SessionId $sid -SessionCommand ReturnLargeSet -ResultSize 5000
    $n = ($batch | Measure-Object).Count
    if ($n -gt 0) { foreach ($r in $batch) { $ualRaw.Add($r) } }
    Write-Host ("  page {0}: +{1} (raw {2})" -f $page, $n, $ualRaw.Count)
} while ($n -gt 0 -and $page -lt $maxPages)
if ($page -ge $maxPages) { Write-Warning "Hit page cap (>50k). Narrow the window or use the Graph AuditLogQuery API." }
$ualRaw = $ualRaw | Sort-Object Identity -Unique
$ualRaw | Select-Object CreationDate,UserIds,Operations,RecordType,AuditData |
    Export-Csv (Join-Path $OutputFolder 'ORG_IP_ual_RAW.csv') -NoTypeInformation

foreach ($r in $ualRaw) {
    $a = $null; try { $a = $r.AuditData | ConvertFrom-Json } catch { }
    if (-not $a) { continue }
    $t = [datetime]$a.CreationTime
    $b = Get-Bucket $a.UserId
    $b.UALEvents++
    if ($a.Workload)  { [void]$b.Workloads.Add($a.Workload) }
    if ($a.Operation) { [void]$b.Operations.Add($a.Operation) }
    Bump-Time $b $t
    $allEvents.Add([pscustomobject]@{ TimestampUTC=$t; Source='UAL'; User=$a.UserId
        Workload=$a.Workload; Operation=$a.Operation; Result='' })
}

# --- 1b) MailItemsAccessed org-wide BY OPERATION, filtered to suspect IPs in post ---
# -IPAddresses does NOT return MailItemsAccessed, so pull by operation and match ClientIP here.
Write-Section "MailItemsAccessed (org-wide by operation, filtered to suspect IPs)"
$sidM = [guid]::NewGuid().ToString()
$miaRaw = New-Object System.Collections.Generic.List[object]
$pageM = 0
do {
    $pageM++
    $batchM = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations MailItemsAccessed `
                -SessionId $sidM -SessionCommand ReturnLargeSet -ResultSize 5000
    $nM = ($batchM | Measure-Object).Count
    foreach ($r in $batchM) {
        $a = $null; try { $a = $r.AuditData | ConvertFrom-Json } catch { }
        if (-not $a) { continue }
        $cipRaw = $a.ClientIPAddress; if (-not $cipRaw) { $cipRaw = $a.ClientIP }
        if ($IPs -contains (Normalize-IP $cipRaw)) { $miaRaw.Add($r) }
    }
    Write-Host ("  page {0}: scanned +{1}, kept-from-suspect-IP {2}" -f $pageM, $nM, $miaRaw.Count)
} while ($nM -gt 0 -and $pageM -lt $maxPages)
if ($pageM -ge $maxPages) { Write-Warning "MailItemsAccessed pull hit the page cap (>50k scanned). Narrow the window." }
$miaRaw = $miaRaw | Sort-Object Identity -Unique
$miaRaw | Select-Object CreationDate,UserIds,Operations,RecordType,AuditData |
    Export-Csv (Join-Path $OutputFolder 'ORG_IP_mailreads_RAW.csv') -NoTypeInformation

foreach ($r in $miaRaw) {
    $a = $null; try { $a = $r.AuditData | ConvertFrom-Json } catch { }
    if (-not $a) { continue }
    $t = [datetime]$a.CreationTime
    $b = Get-Bucket $a.UserId
    $b.MailReadEvents++
    [void]$b.Workloads.Add('Exchange')
    [void]$b.Operations.Add('MailItemsAccessed')
    Bump-Time $b $t
    $allEvents.Add([pscustomobject]@{ TimestampUTC=$t; Source='UAL-MailRead'; User=$a.UserId
        Workload='Exchange'; Operation='MailItemsAccessed'; Result='' })
}

# --- 2) Entra sign-ins, org-wide, by IP (interactive + non-interactive) ---
Write-Section "Entra Sign-ins (org-wide, by IP, last ~30d)"
$startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$siRaw = New-Object System.Collections.Generic.List[object]
$ipClause = '(' + (($IPs | ForEach-Object { "ipAddress eq '$_'" }) -join ' or ') + ')'
foreach ($t in @('interactiveUser','nonInteractiveUser')) {
    $f = "$ipClause and createdDateTime ge $startZ and signInEventTypes/any(x: x eq '$t')"
    $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($f))&`$top=200"
    do {
        try { $resp = Invoke-MgGraphRequest -Method GET -Uri $uri }
        catch { Write-Warning "Sign-in query failed ($t): $($_.Exception.Message)"; break }
        foreach ($v in $resp.value) { $siRaw.Add($v) }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
}
Write-Host ("  sign-in events from IP: {0}" -f $siRaw.Count)
$siRaw | ForEach-Object {
    [pscustomobject]@{ createdDateTime=$_.createdDateTime; userPrincipalName=$_.userPrincipalName
        errorCode=$_.status.errorCode; appDisplayName=$_.appDisplayName; clientAppUsed=$_.clientAppUsed
        isInteractive=$_.isInteractive; city=$_.location.city; country=$_.location.countryOrRegion
        asn=$_.autonomousSystemNumber }
} | Export-Csv (Join-Path $OutputFolder 'ORG_IP_signins_RAW.csv') -NoTypeInformation

foreach ($s in $siRaw) {
    $t = [datetime]$s.createdDateTime
    $b = Get-Bucket $s.userPrincipalName
    $err = $s.status.errorCode
    $ok = ($err -eq 0)
    if ($ok) { $b.SuccessSignIns++ } else { $b.FailedSignIns++ }
    Bump-Time $b $t
    $op = if ($s.isInteractive) { 'Interactive sign-in' } else { 'Non-interactive sign-in' }
    $allEvents.Add([pscustomobject]@{ TimestampUTC=$t; Source='EntraSignIn'; User=$s.userPrincipalName
        Workload='AzureAD'; Operation="$op ($($s.appDisplayName))"; Result=$(if($ok){'success'}else{"fail $err"}) })
}

# --- 3) Build per-user summary --------------------------------------------
Write-Section "Scoping the blast radius"
$summary = foreach ($b in $agg.Values) {
    $accessed = ($b.SuccessSignIns -gt 0) -or ($b.UALEvents -gt 0) -or ($b.MailReadEvents -gt 0)
    [pscustomobject]@{
        User           = $b.User
        Verdict        = if ($accessed) { 'ACCESSED' } elseif ($b.FailedSignIns -gt 0) { 'attempted' } else { 'seen' }
        FirstSeenUTC   = $b.FirstSeen
        LastSeenUTC    = $b.LastSeen
        SuccessSignIns = $b.SuccessSignIns
        FailedSignIns  = $b.FailedSignIns
        UALEvents      = $b.UALEvents
        MailReadEvents = $b.MailReadEvents
        Workloads      = ($b.Workloads  -join ', ')
        Operations     = (($b.Operations | Select-Object -First 8) -join ', ')
    }
}
$summary = $summary | Sort-Object @{e='Verdict';Descending=$false}, `
    @{e={$_.SuccessSignIns + $_.UALEvents};Descending=$true}, FailedSignIns -Descending
$summary | Export-Csv (Join-Path $OutputFolder 'ORG_IP_user_summary.csv') -NoTypeInformation
$allEvents | Sort-Object TimestampUTC |
    Export-Csv (Join-Path $OutputFolder 'ORG_IP_all_events.csv') -NoTypeInformation

$accessedUsers = $summary | Where-Object { $_.Verdict -eq 'ACCESSED' -and $_.User -like '*@*' }
$attemptUsers  = $summary | Where-Object { $_.Verdict -eq 'attempted' -and $_.User -like '*@*' }
$readOnlyUsers = $accessedUsers | Where-Object { $_.SuccessSignIns -eq 0 -and $_.UALEvents -eq 0 -and $_.MailReadEvents -gt 0 }
$accessedUsers.User | Set-Content (Join-Path $OutputFolder 'ORG_IP_ACCESSED_users.txt')

# --- 4) Verdict ------------------------------------------------------------
Write-Section "Verdict"
Write-Host ("Distinct accounts touched by the IP set [{0}]: {1}" -f ($IPs -join ', '), (@($summary | Where-Object { $_.User -like '*@*' }).Count))
Write-Host ("  Confirmed ACCESS (sign-in success, UAL activity, or mail reads): {0}" -f @($accessedUsers).Count) -ForegroundColor Yellow
Write-Host ("  Failed attempts only:                                           {0}" -f @($attemptUsers).Count)

if (@($accessedUsers).Count -eq 0 -and @($attemptUsers).Count -gt 0) {
    Write-Host "`n>> No confirmed access. Pattern is attempts-only — possible spray that did not succeed." -ForegroundColor Green
} elseif (@($accessedUsers).Count -eq 1) {
    Write-Host ("`n>> Appears ISOLATED to: {0}" -f $accessedUsers.User) -ForegroundColor Green
} else {
    Write-Host ("`n>> NOT ISOLATED — {0} accounts were accessed from this IP:" -f @($accessedUsers).Count) -ForegroundColor Red
    $accessedUsers | Select-Object User,FirstSeenUTC,LastSeenUTC,SuccessSignIns,UALEvents,MailReadEvents | Format-Table -AutoSize
}
if (@($readOnlyUsers).Count -gt 0) {
    Write-Host ("`n>> READ-ONLY / RECON — {0} account(s) accessed from this IP show ONLY mail reads (no sign-in or other UAL activity from the IP):" -f @($readOnlyUsers).Count) -ForegroundColor Red
    Write-Host "   The IP-only sweep would have missed these — MailItemsAccessed isn't returned by -IPAddresses. Consistent with token replay / quiet recon." -ForegroundColor DarkYellow
    $readOnlyUsers | Select-Object User,FirstSeenUTC,LastSeenUTC,MailReadEvents | Format-Table -AutoSize
}
if (@($attemptUsers).Count -ge 10) {
    Write-Host ("Note: {0} accounts saw failed attempts from this IP — consistent with password spray." -f @($attemptUsers).Count) -ForegroundColor DarkYellow
}

Write-Host "`nFiles written to: $OutputFolder"
Write-Host "  ORG_IP_user_summary.csv   <- per-account: accessed vs attempted (start here)"
Write-Host "  ORG_IP_ACCESSED_users.txt <- the accounts to respond on now"
Write-Host "  ORG_IP_all_events.csv     <- every event from the IP, all users, chronological"
Write-Host "  ORG_IP_ual_RAW.csv / ORG_IP_signins_RAW.csv  <- evidence (full detail)"
Write-Host "  ORG_IP_mailreads_RAW.csv  <- MailItemsAccessed from the suspect IP(s) — what the actor read (incl. Subject / InternetMessageId in AuditData)"
Write-Host "`nReminder: sign-ins cover only ~30 days; the UAL pull is what reveals May-era access across the org." -ForegroundColor DarkYellow
Write-Host "Note: the MailItemsAccessed pass depends on MailItemsAccessed being in each mailbox's audit set (see docs/telemetry-licensing.md), and is high-volume on large tenants — narrow the window if it caps." -ForegroundColor DarkYellow

if ($weOpenedExo)   { Disconnect-ExchangeOnline -Confirm:$false | Out-Null }
if ($weOpenedGraph) { Disconnect-MgGraph | Out-Null }
