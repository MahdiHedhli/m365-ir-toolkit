<#
.SYNOPSIS
    Reports every IP that accessed one or more accounts across all Business
    Premium-accessible Microsoft 365 logs (Unified Audit Log + Entra sign-ins),
    enriched with ASN, company/ISP, geolocation, and hosting/proxy flags. Read-only.

.WHY THIS SHAPE
    Surfaces IP rotation (several IPs in one hosting AS hitting an account) and,
    when multiple users are supplied, cross-account correlation: the SAME IP
    touching several accounts is the signature of a spread compromise. The UAL
    covers ~180 days (the May trail); Entra sign-ins cover ~30 days.

.ENRICHMENT
    Uses ip-api.com (free, no API key, HTTP only, 45 requests/min, up to 100 IPs per
    batch). NOTE: every observed IP - including users' own home/office IPs - is sent
    to that third party. For a privacy-sensitive or regulated client use
    -SkipEnrichment (the report then falls back to the ASN/geo Microsoft already
    resolved on sign-in records), or swap in an offline MaxMind GeoIP database.

.PREREQUISITES
    Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
    Roles: Entra "Security Reader"/"Reports Reader"; Exchange/Purview "View-Only Audit Logs".

.EXAMPLE
    # One account:
    .\Get-AccountIPReport.ps1 -UserPrincipalName jdoe@client.com -StartDate '2026-05-01' -EndDate '2026-06-22'
    # Several accounts at once (cross-account IP correlation):
    .\Get-AccountIPReport.ps1 -UserPrincipalName jdoe@client.com,asmith@client.com -StartDate '2026-05-01' -EndDate '2026-06-22'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$UserPrincipalName,   # one or many UPNs
    [datetime]$StartDate = (Get-Date).AddDays(-180),
    [datetime]$EndDate   = (Get-Date),
    [switch]$SkipEnrichment,
    [string]$ConnectAs,           # admin UPN to sign in as; skips Connect-ExchangeOnline's console email prompt
    [string]$OutputFolder
)

$ErrorActionPreference = 'Stop'
$Users = @($UserPrincipalName | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ } | Select-Object -Unique)
if ($Users.Count -eq 0) { throw "No valid UserPrincipalName supplied." }

if (-not $OutputFolder) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $safe  = if ($Users.Count -eq 1) { ($Users[0] -replace '[^\w.-]', '_') } else { "multi_$($Users.Count)users" }
    $OutputFolder = Join-Path (Get-Location) "IP_report_${safe}_${stamp}"
}
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
function Write-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

function Normalize-IP([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip)) { return $null }
    $ip = $ip.Trim()
    if ($ip -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $Matches[1] }   # strip IPv4:port
    return $ip
}

# --- Connect ---------------------------------------------------------------
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
    if ($ConnectAs) { Connect-ExchangeOnline -UserPrincipalName $ConnectAs -ShowBanner:$false }
    else                    { Connect-ExchangeOnline -ShowBanner:$false }
    $weOpenedExo = $true
} else { Write-Host "  Reusing Exchange Online session: $($exoConn.UserPrincipalName)" }
try {
    if (-not (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled) {
        Write-Warning "Unified audit log ingestion is DISABLED - historical data may be missing."
    }
} catch { Write-Warning "Could not confirm audit config: $($_.Exception.Message)" }
Write-Host ("Accounts : {0}" -f ($Users -join ', '))
Write-Host ("Window   : {0} -> {1}" -f $StartDate.ToString('u'), $EndDate.ToString('u'))
if ($StartDate -lt (Get-Date).AddDays(-30)) {
    Write-Warning "Sign-ins only reach ~30 days; older IPs come from the UAL pull only."
}

# Per-(user,IP) aggregation buckets
$buckets = @{}
function Get-Bucket($user, $ip) {
    if ([string]::IsNullOrWhiteSpace($user)) { $user = '(unknown)' } else { $user = $user.ToLower() }
    $k = "$user|$ip"
    if (-not $buckets.ContainsKey($k)) {
        $buckets[$k] = [pscustomobject]@{
            User = $user; IP = $ip; FirstSeen = $null; LastSeen = $null
            SuccessSignIns = 0; FailedSignIns = 0; UALEvents = 0
            Workloads  = New-Object 'System.Collections.Generic.HashSet[string]'
            Operations = New-Object 'System.Collections.Generic.HashSet[string]'
            MsAsn = $null; MsCity = $null; MsCountry = $null
        }
    }
    return $buckets[$k]
}
function Bump($b, $t) {
    if ($t) {
        if (-not $b.FirstSeen -or $t -lt $b.FirstSeen) { $b.FirstSeen = $t }
        if (-not $b.LastSeen  -or $t -gt $b.LastSeen ) { $b.LastSeen  = $t }
    }
}

# --- 1) Unified Audit Log, by user(s) -------------------------------------
Write-Section "Unified Audit Log (by account)"
$sid = [guid]::NewGuid().ToString(); $ual = New-Object System.Collections.Generic.List[object]
$page = 0
do {
    $page++
    $batch = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $Users `
                -SessionId $sid -SessionCommand ReturnLargeSet -ResultSize 5000
    $n = ($batch | Measure-Object).Count
    if ($n -gt 0) { foreach ($r in $batch) { $ual.Add($r) } }
    Write-Host ("  page {0}: +{1}" -f $page, $n)
} while ($n -gt 0 -and $page -lt 25)
$ual = $ual | Sort-Object Identity -Unique
foreach ($r in $ual) {
    $a = $null; try { $a = $r.AuditData | ConvertFrom-Json } catch { }
    if (-not $a) { continue }
    $ip = Normalize-IP (($a.ClientIP, $a.ClientIPAddress, $a.ActorIpAddress | Where-Object { $_ }) | Select-Object -First 1)
    if (-not $ip) { continue }
    $b = Get-Bucket $a.UserId $ip
    $b.UALEvents++
    if ($a.Workload)  { [void]$b.Workloads.Add($a.Workload) }
    if ($a.Operation) { [void]$b.Operations.Add($a.Operation) }
    Bump $b ([datetime]$a.CreationTime)
}

# --- 2) Entra sign-ins, by user(s) (interactive + non-interactive) --------
Write-Section "Entra sign-ins (by account, last ~30d)"
$startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$userClause = '(' + (($Users | ForEach-Object { "userPrincipalName eq '$_'" }) -join ' or ') + ')'
$signins = New-Object System.Collections.Generic.List[object]
foreach ($t in @('interactiveUser','nonInteractiveUser')) {
    $f = "$userClause and createdDateTime ge $startZ and signInEventTypes/any(x: x eq '$t')"
    $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($f))&`$top=200"
    do {
        try { $resp = Invoke-MgGraphRequest -Method GET -Uri $uri }
        catch { Write-Warning "Sign-in query failed ($t): $($_.Exception.Message)"; break }
        foreach ($v in $resp.value) { $signins.Add($v) }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
}
Write-Host ("  sign-in events: {0}" -f $signins.Count)
foreach ($s in $signins) {
    $ip = Normalize-IP $s.ipAddress
    if (-not $ip) { continue }
    $b = Get-Bucket $s.userPrincipalName $ip
    if ($s.status.errorCode -eq 0) { $b.SuccessSignIns++ } else { $b.FailedSignIns++ }
    if (-not $b.MsAsn -and $s.autonomousSystemNumber) { $b.MsAsn = $s.autonomousSystemNumber }
    if (-not $b.MsCity)    { $b.MsCity    = $s.location.city }
    if (-not $b.MsCountry) { $b.MsCountry = $s.location.countryOrRegion }
    Bump $b ([datetime]$s.createdDateTime)
}

# --- 3) Enrich distinct IPs (ip-api.com batch) ----------------------------
function Get-IPEnrichment {
    param([string[]]$IPList)
    $map = @{}
    if ($SkipEnrichment -or -not $IPList) { return $map }
    $fields = 'status,query,as,asname,isp,org,city,regionName,country,countryCode,proxy,hosting,mobile'
    for ($i = 0; $i -lt $IPList.Count; $i += 100) {
        $chunk = $IPList[$i..([math]::Min($i + 99, $IPList.Count - 1))]
        $body  = '["' + ($chunk -join '","') + '"]'
        try {
            $resp = Invoke-RestMethod -Method Post -Uri "http://ip-api.com/batch?fields=$fields" `
                        -Body $body -ContentType 'application/json' -TimeoutSec 30
            foreach ($r in $resp) { if ($r.query) { $map[$r.query] = $r } }
        } catch { Write-Warning "Enrichment batch failed: $($_.Exception.Message)" }
        if ($IPList.Count -gt 100) { Start-Sleep -Seconds 2 }
    }
    return $map
}
Write-Section "Enriching IPs"
$distinct = @($buckets.Values | Select-Object -ExpandProperty IP -Unique)
Write-Host ("  distinct IPs: {0}{1}" -f $distinct.Count, $(if($SkipEnrichment){' (enrichment skipped)'}else{''}))
$enr = Get-IPEnrichment -IPList $distinct

# --- 4) Build the per-(account,IP) report ---------------------------------
$report = foreach ($b in $buckets.Values) {
    $e = $enr[$b.IP]
    $asn     = if ($e -and $e.status -eq 'success') { $e.as }         elseif ($b.MsAsn) { "AS$($b.MsAsn)" } else { '' }
    $company = if ($e -and $e.status -eq 'success') { $e.isp }        else { '' }
    $org     = if ($e -and $e.status -eq 'success') { $e.org }        else { '' }
    $city    = if ($e -and $e.status -eq 'success') { $e.city }       elseif ($b.MsCity)    { $b.MsCity }    else { '' }
    $region  = if ($e -and $e.status -eq 'success') { $e.regionName } else { '' }
    $country = if ($e -and $e.status -eq 'success') { $e.country }    elseif ($b.MsCountry) { $b.MsCountry } else { '' }
    $flags = @()
    if ($e.hosting) { $flags += 'HOSTING' }
    if ($e.proxy)   { $flags += 'PROXY' }
    if ($e.mobile)  { $flags += 'mobile' }
    [pscustomobject]@{
        User           = $b.User
        IP             = $b.IP
        Flag           = ($flags -join ',')
        ASN            = $asn
        Company_ISP    = $company
        Org            = $org
        City           = $city
        Region         = $region
        Country        = $country
        FirstSeenUTC   = $b.FirstSeen
        LastSeenUTC    = $b.LastSeen
        Events         = ($b.SuccessSignIns + $b.FailedSignIns + $b.UALEvents)
        SuccessSignIns = $b.SuccessSignIns
        FailedSignIns  = $b.FailedSignIns
        UALEvents      = $b.UALEvents
        Workloads      = ($b.Workloads -join ', ')
        TopOperations  = (($b.Operations | Select-Object -First 8) -join ', ')
    }
}
# Flagged (hosting/proxy) first, then by volume.
$report = $report | Sort-Object @{e={[string]::IsNullOrEmpty($_.Flag)}}, @{e='Events';Descending=$true}
$report | Export-Csv (Join-Path $OutputFolder 'account_IP_report.csv') -NoTypeInformation

# Cross-account IP rollup - the SAME IP across multiple users = spread compromise
$ipRollup = $report | Group-Object IP | ForEach-Object {
    $g = $_.Group
    $u = @($g.User | Select-Object -Unique)
    [pscustomobject]@{
        IP          = $_.Name
        Accounts    = $u.Count
        AccountList = ($u -join ', ')
        Flag        = (($g.Flag | Where-Object { $_ }) | Select-Object -First 1)
        ASN         = $g[0].ASN
        Company_ISP = $g[0].Company_ISP
        Country     = $g[0].Country
        TotalEvents = ($g | Measure-Object Events -Sum).Sum
        FirstSeenUTC= ($g.FirstSeenUTC | Measure-Object -Minimum).Minimum
        LastSeenUTC = ($g.LastSeenUTC  | Measure-Object -Maximum).Maximum
    }
} | Sort-Object @{e='Accounts';Descending=$true}, @{e='TotalEvents';Descending=$true}
$ipRollup | Export-Csv (Join-Path $OutputFolder 'shared_IP_rollup.csv') -NoTypeInformation

# ASN rollup - rotation shows here
$asnRollup = $report | Where-Object { $_.ASN } | Group-Object ASN | ForEach-Object {
    $g = $_.Group
    [pscustomobject]@{
        ASN        = $_.Name
        IPCount    = (@($g.IP | Select-Object -Unique)).Count
        Accounts   = (@($g.User | Select-Object -Unique)).Count
        TotalEvents= ($g | Measure-Object Events -Sum).Sum
        Hosting    = [bool]($g | Where-Object { $_.Flag -match 'HOSTING|PROXY' })
        Countries  = ((@($g.Country | Select-Object -Unique)) -join ', ')
        SampleIPs  = ((@($g.IP | Select-Object -Unique) | Select-Object -First 5) -join ', ')
    }
} | Sort-Object @{e='TotalEvents';Descending=$true}
$asnRollup | Export-Csv (Join-Path $OutputFolder 'account_ASN_rollup.csv') -NoTypeInformation

# --- 5) Console summary ----------------------------------------------------
Write-Section "Report"
Write-Host ("Accounts queried: {0}   distinct IPs: {1}" -f $Users.Count, (@($report.IP | Select-Object -Unique)).Count) -ForegroundColor Yellow
$shared = $ipRollup | Where-Object { $_.Accounts -gt 1 }
if ($shared) {
    Write-Host "`n>> IPs that touched MULTIPLE accounts (cross-account correlation - spread compromise):" -ForegroundColor Red
    $shared | Format-Table IP,Accounts,AccountList,Flag,ASN,Country,TotalEvents -AutoSize
} else {
    Write-Host "`n>> No IP touched more than one account - no cross-account overlap in this set." -ForegroundColor Green
}
$flagged = $report | Where-Object { $_.Flag }
if ($flagged) { Write-Host ("Flagged hosting/proxy/mobile rows: {0}" -f @($flagged).Count) -ForegroundColor Yellow }

Write-Host "`nASN rollup (rotation: multiple IPs in one hosting AS):"
$asnRollup | Format-Table ASN,IPCount,Accounts,TotalEvents,Hosting,Countries -AutoSize

Write-Host "Files written to: $OutputFolder"
Write-Host "  account_IP_report.csv    <- every (account, IP), enriched, hosting/proxy flagged"
Write-Host "  shared_IP_rollup.csv     <- IPs grouped by IP, showing how many accounts each touched"
Write-Host "  account_ASN_rollup.csv   <- IPs grouped by AS (the malicious AS + its sibling IPs)"
Write-Host "`nNext: take hosting-AS sibling IPs from the rollup and sweep org-wide:" -ForegroundColor DarkYellow
Write-Host "  .\Find-OrgAccessFromIP.ps1 -SuspectIP <ip1>,<ip2>,... -StartDate '$($StartDate.ToString('yyyy-MM-dd'))' -EndDate '$($EndDate.ToString('yyyy-MM-dd'))'" -ForegroundColor DarkYellow

if ($weOpenedExo)   { Disconnect-ExchangeOnline -Confirm:$false | Out-Null }
if ($weOpenedGraph) { Disconnect-MgGraph | Out-Null }
