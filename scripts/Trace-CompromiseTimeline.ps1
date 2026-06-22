<#
.SYNOPSIS
    Traces a suspect IP and a compromised user across every log surface a
    Microsoft 365 Business Premium (Entra ID P1) tenant exposes, and assembles a
    single chronological timeline. Read-only — it collects, it never changes
    anything in the tenant.

.WHY THIS SHAPE
    At P1, Entra sign-in and audit logs are retained only ~30 days. For a
    compromise in May discovered in late June, those sign-in logs are largely
    GONE. The Unified Audit Log (Exchange/Purview) retains ~180 days, spans all
    workloads, and carries the client IP on each record — so it is the PRIMARY
    source for the May trail. Entra sign-ins are pulled too, but only corroborate
    the last ~30 days.

.PREREQUISITES
    Modules:  Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
    Roles:    Entra "Security Reader" or "Reports Reader" (sign-in logs need P1, which BP has)
              Exchange/Purview "View-Only Audit Logs" or "Audit Logs" role (for Search-UnifiedAuditLog)
    Auditing: Unified audit logging must be on (the script checks this).

.LICENSING LIMITS TO EXPECT (Business Premium)
    - Risk columns (RiskState / RiskLevelDuringSignIn) are P2-only — expect blanks.
    - MailItemsAccessed (which mail was actually read) is Audit Premium / E5 — absent here.
    Their absence is a license gap, NOT evidence of "nothing happened."

.EXAMPLE
    .\Trace-CompromiseTimeline.ps1 -SuspectIP 203.0.113.45 -UserPrincipalName jdoe@client.com `
        -StartDate '2026-05-01' -EndDate '2026-06-22'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SuspectIP,
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [datetime]$StartDate = (Get-Date).AddDays(-180),   # UAL retention ceiling at Standard
    [datetime]$EndDate   = (Get-Date),
    [string]$ConnectAs,           # admin UPN to sign in as; skips Connect-ExchangeOnline's console email prompt
    [string]$OutputFolder
)

$ErrorActionPreference = 'Stop'
if (-not $OutputFolder) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $safeUser = ($UserPrincipalName -replace '[^\w.-]', '_')
    $OutputFolder = Join-Path (Get-Location) "IR_${safeUser}_${stamp}"
}
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

function Write-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

function Normalize-IP([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip)) { return $null }
    $ip = $ip.Trim()
    if ($ip -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $Matches[1] }  # strip IPv4:port
    return $ip
}
$SuspectIPNorm = Normalize-IP $SuspectIP

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
Write-Section "Connecting"
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$gScopes = @("AuditLog.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All")
$weOpenedGraph = $false; $weOpenedExo = $false
$ctx = Get-MgContext
if (-not $ctx) {
    Connect-MgGraph -Scopes $gScopes -NoWelcome
    $weOpenedGraph = $true
} elseif (@($gScopes | Where-Object { $_ -notin $ctx.Scopes }).Count -gt 0) {
    Connect-MgGraph -Scopes $gScopes -NoWelcome   # top up missing scopes (e.g. MFA read) on an existing session
} else { Write-Host "  Reusing Graph session: $($ctx.Account)" }
$exoConn = $null; try { $exoConn = Get-ConnectionInformation -ErrorAction SilentlyContinue } catch {}
if (-not $exoConn) {
    if ($ConnectAs) { Connect-ExchangeOnline -UserPrincipalName $ConnectAs -ShowBanner:$false }
    else                    { Connect-ExchangeOnline -ShowBanner:$false }
    $weOpenedExo = $true
} else { Write-Host "  Reusing Exchange Online session: $($exoConn.UserPrincipalName)" }

# Confirm auditing is actually on, or every UAL search silently returns nothing.
try {
    $cfg = Get-AdminAuditLogConfig
    if (-not $cfg.UnifiedAuditLogIngestionEnabled) {
        Write-Warning "Unified audit log ingestion is DISABLED in this tenant. Historical UAL data may be unavailable."
    }
} catch { Write-Warning "Could not confirm audit config: $($_.Exception.Message)" }

Write-Host "Suspect IP : $SuspectIPNorm"
Write-Host "User       : $UserPrincipalName"
Write-Host "Window     : $($StartDate.ToString('u')) -> $($EndDate.ToString('u'))"
Write-Host "Output     : $OutputFolder"
$signInFloor = (Get-Date).AddDays(-30)
if ($StartDate -lt $signInFloor) {
    Write-Warning ("Entra sign-in logs only go back ~30 days (to {0:yyyy-MM-dd}). The May trail will come from the Unified Audit Log." -f $signInFloor)
}

# ---------------------------------------------------------------------------
# Unified Audit Log search (ReturnLargeSet paging + dedupe)
# ---------------------------------------------------------------------------
function Search-UAL {
    param([string[]]$IPAddresses, [string[]]$UserIds, [string]$Label)
    Write-Host ("  UAL search [{0}]..." -f $Label)
    $sid = [guid]::NewGuid().ToString()
    $all = New-Object System.Collections.Generic.List[object]
    $page = 0; $maxPages = 25   # 25 * 5000 = 125k, well past the 50k hard ceiling
    do {
        $page++
        $p = @{ StartDate = $StartDate; EndDate = $EndDate; SessionId = $sid;
                SessionCommand = 'ReturnLargeSet'; ResultSize = 5000 }
        if ($IPAddresses) { $p.IPAddresses = $IPAddresses }
        if ($UserIds)     { $p.UserIds     = $UserIds }
        $batch = Search-UnifiedAuditLog @p
        $n = ($batch | Measure-Object).Count
        if ($n -gt 0) { foreach ($r in $batch) { $all.Add($r) } }
        Write-Host ("    page {0}: +{1} (raw total {2})" -f $page, $n, $all.Count)
    } while ($n -gt 0 -and $page -lt $maxPages)

    if ($page -ge $maxPages) {
        Write-Warning "Hit the page cap — result set may exceed Search-UnifiedAuditLog's 50k limit. Narrow the date window or use the Graph AuditLogQuery API."
    }
    # ReturnLargeSet returns duplicates; Identity is the unique record id.
    return ($all | Sort-Object Identity -Unique)
}

function ConvertFrom-UAL {
    param($Records)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Records) {
        $a = $null
        try { $a = $r.AuditData | ConvertFrom-Json } catch { }
        if (-not $a) { continue }
        $ip = Normalize-IP ($a.ClientIP, $a.ClientIPAddress, $a.ActorIpAddress | Where-Object { $_ } | Select-Object -First 1)
        $out.Add([pscustomobject]@{
            TimestampUTC = [datetime]$a.CreationTime
            Source       = 'UAL'
            Workload     = $a.Workload
            Operation    = $a.Operation
            User         = $a.UserId
            IP           = $ip
            Location     = ''
            Detail       = ($a.ObjectId, $a.ResultStatus | Where-Object { $_ }) -join ' | '
            IPMatch      = ($ip -and $ip -eq $SuspectIPNorm)
            RecordId     = $r.Identity
        })
    }
    return $out
}

Write-Section "Unified Audit Log"
$ualByIp   = Search-UAL -IPAddresses $SuspectIPNorm -Label "by suspect IP"
$ualByUser = Search-UAL -UserIds $UserPrincipalName -Label "by compromised user"

# Preserve the raw records (with full AuditData JSON) as evidence.
$ualByIp   | Select-Object CreationDate,UserIds,Operations,RecordType,AuditData |
    Export-Csv (Join-Path $OutputFolder 'ual_by_ip_RAW.csv') -NoTypeInformation
$ualByUser | Select-Object CreationDate,UserIds,Operations,RecordType,AuditData |
    Export-Csv (Join-Path $OutputFolder 'ual_by_user_RAW.csv') -NoTypeInformation

$normUal = New-Object System.Collections.Generic.List[object]
(ConvertFrom-UAL $ualByIp)   | ForEach-Object { $normUal.Add($_) }
(ConvertFrom-UAL $ualByUser) | ForEach-Object { $normUal.Add($_) }

# ---------------------------------------------------------------------------
# Entra sign-in logs (beta; interactive + non-interactive). ~30 days only.
# ---------------------------------------------------------------------------
function Get-SignIns {
    param([string]$BaseFilter)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in @('interactiveUser','nonInteractiveUser')) {
        $f = "$BaseFilter and signInEventTypes/any(x: x eq '$t')"
        $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($f))&`$top=200"
        do {
            try { $resp = Invoke-MgGraphRequest -Method GET -Uri $uri }
            catch { Write-Warning "Sign-in query failed ($t): $($_.Exception.Message)"; break }
            foreach ($v in $resp.value) { $out.Add($v) }
            $uri = $resp.'@odata.nextLink'
        } while ($uri)
    }
    return $out
}

function ConvertFrom-SignIn {
    param($SignIns)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in $SignIns) {
        $ip  = Normalize-IP $s.ipAddress
        $loc = @($s.location.city, $s.location.countryOrRegion | Where-Object { $_ }) -join ', '
        if ($s.autonomousSystemNumber) { $loc = "$loc (ASN $($s.autonomousSystemNumber))" }
        $op = if ($s.isInteractive) { 'Interactive sign-in' } else { 'Non-interactive sign-in' }
        $out.Add([pscustomobject]@{
            TimestampUTC = [datetime]$s.createdDateTime
            Source       = 'EntraSignIn'
            Workload     = 'AzureAD'
            Operation    = $op
            User         = $s.userPrincipalName
            IP           = $ip
            Location     = $loc
            Detail       = "app=$($s.appDisplayName); client=$($s.clientAppUsed); err=$($s.status.errorCode); CA=$($s.conditionalAccessStatus); os=$($s.deviceDetail.operatingSystem); risk=$($s.riskState)"
            IPMatch      = ($ip -and $ip -eq $SuspectIPNorm)
            RecordId     = $s.id
        })
    }
    return $out
}

Write-Section "Entra Sign-in Logs (last ~30 days)"
$startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$siByUser = Get-SignIns -BaseFilter "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startZ"
$siByIp   = Get-SignIns -BaseFilter "ipAddress eq '$SuspectIPNorm' and createdDateTime ge $startZ"
Write-Host ("  sign-ins by user: {0}   by IP: {1}" -f $siByUser.Count, $siByIp.Count)

$normSi = New-Object System.Collections.Generic.List[object]
(ConvertFrom-SignIn $siByUser) | ForEach-Object { $normSi.Add($_) }
(ConvertFrom-SignIn $siByIp)   | ForEach-Object { $normSi.Add($_) }

# The IP-by-sign-in pass can reveal OTHER users the same IP hit.
$otherUsers = $normSi | Where-Object { $_.Source -eq 'EntraSignIn' -and $_.IPMatch } |
    Select-Object -ExpandProperty User -Unique | Where-Object { $_ -and $_ -ne $UserPrincipalName }

# ---------------------------------------------------------------------------
# State snapshots: inbox rules + registered MFA methods (current, not historical)
# ---------------------------------------------------------------------------
Write-Section "Persistence snapshots"
try {
    Get-InboxRule -Mailbox $UserPrincipalName |
        Select-Object Name,Enabled,Priority,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder,From,SubjectContainsWords,BodyContainsWords |
        Export-Csv (Join-Path $OutputFolder 'inbox_rules_current.csv') -NoTypeInformation
    Write-Host "  inbox rules exported (review forward/redirect/delete rules)"
} catch { Write-Warning "Inbox rules: $($_.Exception.Message)" }

try {
    $mfa = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserPrincipalName/authentication/methods").value
    $mfa | ForEach-Object {
        [pscustomobject]@{ Type = $_.'@odata.type'; Id = $_.id; Detail = ($_.phoneNumber, $_.displayName, $_.emailAddress | Where-Object { $_ }) -join ' ' }
    } | Export-Csv (Join-Path $OutputFolder 'mfa_methods_current.csv') -NoTypeInformation
    Write-Host "  MFA methods exported (look for an unfamiliar phone/authenticator the attacker added)"
} catch { Write-Warning "MFA methods: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# Merge -> one chronological timeline
# ---------------------------------------------------------------------------
Write-Section "Building timeline"
$timeline = @()
$timeline += $normUal
$timeline += $normSi
$timeline = $timeline |
    Sort-Object TimestampUTC, Source -Unique |   # de-dupes identical rows
    Sort-Object TimestampUTC

$timeline | Export-Csv (Join-Path $OutputFolder 'TIMELINE_full.csv') -NoTypeInformation
$timeline | Where-Object IPMatch |
    Export-Csv (Join-Path $OutputFolder 'TIMELINE_suspect_IP_only.csv') -NoTypeInformation

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section "Summary"
$ipHits = $timeline | Where-Object IPMatch | Sort-Object TimestampUTC
if ($ipHits) {
    Write-Host ("Suspect IP {0}: {1} events, {2:u} -> {3:u}" -f $SuspectIPNorm, $ipHits.Count, $ipHits[0].TimestampUTC, $ipHits[-1].TimestampUTC) -ForegroundColor Yellow
    Write-Host "Operations from that IP:"
    $ipHits | Group-Object Operation | Sort-Object Count -Descending |
        ForEach-Object { Write-Host ("  {0,-40} {1}" -f $_.Name, $_.Count) }
} else {
    Write-Host "No events matched the suspect IP. Check the IP, widen the window, or confirm auditing was on for the period." -ForegroundColor Yellow
}
if ($otherUsers) {
    Write-Host "`nOther users this IP signed into (last 30d) — possible additional victims:" -ForegroundColor Yellow
    $otherUsers | ForEach-Object { Write-Host "  $_" }
}
Write-Host ("`nTotal timeline events: {0}  (UAL {1}, sign-ins {2})" -f $timeline.Count, $normUal.Count, $normSi.Count)
Write-Host "`nFiles written to: $OutputFolder"
Write-Host "  TIMELINE_full.csv              <- everything, chronological"
Write-Host "  TIMELINE_suspect_IP_only.csv   <- just the suspect IP's activity"
Write-Host "  ual_by_ip_RAW.csv / ual_by_user_RAW.csv  <- full AuditData JSON (evidence)"
Write-Host "  inbox_rules_current.csv / mfa_methods_current.csv"
Write-Host "`nReminder: empty sign-in results before ~30 days = expired logs, not a clean period. The UAL pull is your May source." -ForegroundColor DarkYellow

if ($weOpenedExo)   { Disconnect-ExchangeOnline -Confirm:$false | Out-Null }
if ($weOpenedGraph) { Disconnect-MgGraph | Out-Null }
