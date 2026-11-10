#Requires -Version 5.1
<#
.SYNOPSIS
    SteamPin - keeps Steam hostnames pinned in the Windows hosts file to the fastest
    server that actually works from your connection, and switches automatically when
    that server stops working.

.DESCRIPTION
    Every run (by default every 30 minutes, at startup, on network connect and on
    resume from sleep, via the "SteamPin" scheduled task):

      1. Collects candidate server IPs for each configured hostname: the current pin,
         servers that worked before, fresh DNS answers from several resolvers
         (optionally filtered to your ISP's networks), and seed IPs from config.json.
      2. Probes each candidate over HTTPS with the real hostname (SNI), a valid
         certificate and a host-specific check (status code, body or redirect).
      3. Keeps the current pin while it is healthy. Switches immediately when it
         fails, or when another server is clearly faster on two runs in a row.
         Removes the pin (back to normal DNS) only after two failed runs with no
         working replacement. Does nothing at all while the PC is offline.
      4. Rewrites only its own marked block in the hosts file, atomically, and only
         when something changed, then flushes the DNS cache.

.PARAMETER DryRun
    Do everything except write the hosts file, state or log. Prints what would change.
.PARAMETER Test
    Probe every candidate for every hostname and print a table. Changes nothing.
.PARAMETER Status
    Show the last check, the current pins and the recent log.
.PARAMETER Unpin
    Remove SteamPin's block from the hosts file (used by the uninstaller).
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run')]    [switch]$DryRun,
    [Parameter(ParameterSetName = 'Test')]   [switch]$Test,
    [Parameter(ParameterSetName = 'Status')] [switch]$Status,
    [Parameter(ParameterSetName = 'Unpin')]  [switch]$Unpin,
    [string]$ConfigPath = '',   # default: config.json next to this script
    [string]$HostsPath  = (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'),
    [string]$StateDir   = (Join-Path $env:ProgramData 'SteamPin')
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'config.json' }

$script:Version     = '2.0.0'
$script:BeginPrefix = '# BEGIN SteamPin'
$script:BeginMark   = '# BEGIN SteamPin - managed automatically, edits inside this block are overwritten'
$script:EndMark     = '# END SteamPin'
$script:LegacyTag   = '# local VN Steam cache node - pinned; delete this line to undo'   # SteamPin v1 lines
$script:Curl        = Join-Path $env:SystemRoot 'System32\curl.exe'
$script:Inv         = [Globalization.CultureInfo]::InvariantCulture
$script:TimeFmt     = 'yyyy-MM-ddTHH:mm:ss'
$script:Utf8NoBom   = New-Object Text.UTF8Encoding $false

# ---------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------

function Get-Now { Get-Date }
function Format-Time([datetime]$t) { $t.ToString($script:TimeFmt, $script:Inv) }
function ConvertFrom-Time([string]$s) {
    if (-not $s) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParseExact($s, $script:TimeFmt, $script:Inv, 'None', [ref]$d)) { return $d }
    return $null
}

function Write-Log([string]$Message, [string]$Level = 'INFO') {
    $line = '{0}  {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if (-not $script:WriteEnabled) { return }
    try {
        $log = Join-Path $StateDir 'log.txt'
        Add-Content -LiteralPath $log -Value $line -Encoding UTF8
        if ((Get-Item -LiteralPath $log).Length -gt 256KB) {
            $keep = Get-Content -LiteralPath $log -Encoding UTF8 | Select-Object -Last 1000
            Set-Content -LiteralPath $log -Value $keep -Encoding UTF8
        }
    } catch { }
}

# Recursively turns ConvertFrom-Json output (PSCustomObject) into hashtables/arrays.
function ConvertTo-HashtableDeep($o) {
    if ($null -eq $o) { return $null }
    if ($o -is [Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-HashtableDeep $p.Value }
        return $h
    }
    if ($o -is [Collections.IEnumerable] -and $o -isnot [string]) {
        $list = @(foreach ($x in $o) { ConvertTo-HashtableDeep $x })
        return , $list
    }
    return $o
}

# ---------------------------------------------------------------------------------
# IP validation (everything that can end up in the hosts file passes through here)
# ---------------------------------------------------------------------------------

function ConvertTo-IpNumber([string]$ip) {
    $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes()
    return ([uint64]$b[0] -shl 24) + ([uint64]$b[1] -shl 16) + ([uint64]$b[2] -shl 8) + [uint64]$b[3]
}

# True only for a canonical dotted IPv4 address that is publicly routable.
function Test-PublicIPv4([string]$s) {
    if (-not $s -or $s -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($s, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -ne $s) { return $false }
    foreach ($bad in '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
                     '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
                     '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3') {
        if (Test-InCidr $s $bad) { return $false }
    }
    return $true
}

function Test-InCidr([string]$ip, [string]$cidr) {
    if ($cidr -notmatch '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$') { return $false }
    $len = [int]$Matches[3]
    if ($len -gt 32) { return $false }
    $full = [uint64]4294967295
    $mask = if ($len -eq 0) { [uint64]0 } else { ($full -shl (32 - $len)) -band $full }
    return ((ConvertTo-IpNumber $ip) -band $mask) -eq ((ConvertTo-IpNumber $Matches[1]) -band $mask)
}

function Test-AllowedNetwork([string]$ip, $networks) {
    if (-not $networks -or @($networks).Count -eq 0) { return $true }
    foreach ($n in $networks) { if (Test-InCidr $ip $n) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------------

function Read-Config([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Config not found: $path" }
    $c = ConvertTo-HashtableDeep (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json)
    $defaults = @{
        seeds = @(); resolvers = @(); dohUrls = @(); allowedNetworks = @()
        samples = 3; probeTimeoutSec = 6; connectTimeoutSec = 3; maxCandidatesPerName = 16
        switchMinGainPct = 20; switchMinGainMs = 15; switchConfirmRuns = 2; removeAfterFailedRuns = 2
        forgetAfterDays = 14; runBudgetSec = 480
        connectivityUrl = 'http://www.msftconnecttest.com/connecttest.txt'; connectivityExpect = 'Microsoft Connect Test'
    }
    foreach ($k in $defaults.Keys) { if (-not $c.ContainsKey($k) -or $null -eq $c[$k]) { $c[$k] = $defaults[$k] } }

    if (-not $c.ContainsKey('targets') -or @($c.targets).Count -eq 0) { throw 'Config has no targets.' }
    $seen = @{}
    foreach ($t in @($c.targets)) {
        if (-not ($t -is [hashtable]) -or -not $t.name) { throw 'Every target needs a name.' }
        $t.name = ([string]$t.name).ToLowerInvariant()
        if ($t.name -notmatch '^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { throw "Bad target name: $($t.name)" }
        if ($seen[$t.name]) { throw "Duplicate target: $($t.name)" }
        $seen[$t.name] = $true
        if (-not $t.path) { $t.path = '/' }
        if ([string]$t.path -notmatch '^/[A-Za-z0-9/._~%?=&+-]*$') { throw "Bad path for $($t.name): $($t.path)" }
        if (-not $t.expectStatus) { $t.expectStatus = @(200) }
        $t.expectStatus = @($t.expectStatus | ForEach-Object { [int]$_ })
        foreach ($k in 'expectBody', 'expectRedirect') { if (-not $t.ContainsKey($k)) { $t[$k] = $null } }
        if (-not $t.ContainsKey('seeds') -or $null -eq $t.seeds) { $t.seeds = @() }
    }
    foreach ($ip in @($c.seeds) + @($c.targets | ForEach-Object { $_.seeds })) {
        if ($ip -and -not (Test-PublicIPv4 $ip)) { throw "Bad seed IP in config: $ip" }
    }
    foreach ($n in @($c.allowedNetworks)) { if ($n -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { throw "Bad network in allowedNetworks: $n" } }
    foreach ($r in @($c.resolvers)) { if ($r -notmatch '^[A-Za-z0-9.-]+$') { throw "Bad resolver: $r" } }
    foreach ($u in @($c.dohUrls)) { if ($u -notmatch '^https://[A-Za-z0-9.-]+(/[A-Za-z0-9/._-]*)?$') { throw "Bad DoH URL: $u" } }
    return $c
}

# ---------------------------------------------------------------------------------
# State (what worked before, failure streaks, pending switches)
# ---------------------------------------------------------------------------------

function Read-State {
    $p = Join-Path $StateDir 'state.json'
    $s = $null
    if (Test-Path -LiteralPath $p) {
        try { $s = ConvertTo-HashtableDeep (Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json) }
        catch { Write-Log "state.json unreadable, starting fresh ($($_.Exception.Message))" 'WARN' }
    }
    if (-not ($s -is [hashtable])) { $s = @{} }
    if (-not ($s['targets'] -is [hashtable])) { $s['targets'] = @{} }
    return $s
}

function Get-TargetState($state, [string]$name) {
    if (-not ($state.targets[$name] -is [hashtable])) { $state.targets[$name] = @{} }
    $ts = $state.targets[$name]
    if (-not ($ts['ips'] -is [hashtable])) { $ts['ips'] = @{} }
    foreach ($k in 'challenger', 'challengerRuns', 'failedRuns') { if (-not $ts.ContainsKey($k)) { $ts[$k] = $null } }
    if ($null -eq $ts.challengerRuns) { $ts.challengerRuns = 0 }
    if ($null -eq $ts.failedRuns) { $ts.failedRuns = 0 }
    # Drop anything that is not a valid public IP (state is data, never trusted).
    foreach ($ip in @($ts.ips.Keys)) { if (-not (Test-PublicIPv4 $ip) -or -not ($ts.ips[$ip] -is [hashtable])) { $ts.ips.Remove($ip) } }
    return $ts
}

function Save-State($state) {
    $p = Join-Path $StateDir 'state.json'
    $tmp = "$p.tmp"
    [IO.File]::WriteAllText($tmp, ($state | ConvertTo-Json -Depth 8), $script:Utf8NoBom)
    Move-Item -LiteralPath $tmp -Destination $p -Force
}

# ---------------------------------------------------------------------------------
# Hosts file
# ---------------------------------------------------------------------------------

# Reads the hosts file as UTF-8 (BOM stripped); falls back to the ANSI code page if the
# file is not valid UTF-8, and remembers that so the file is written back the same way.
$script:HostsEncoding = $script:Utf8NoBom
function Get-HostsText {
    if (-not (Test-Path -LiteralPath $HostsPath)) { return '' }
    $bytes = [IO.File]::ReadAllBytes($HostsPath)
    $offset = if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { 3 } else { 0 }
    try {
        $script:HostsEncoding = $script:Utf8NoBom
        return (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes, $offset, $bytes.Length - $offset)
    } catch {
        $script:HostsEncoding = [Text.Encoding]::Default
        return [Text.Encoding]::Default.GetString($bytes)
    }
}

function Read-HostsLines {
    if (-not (Test-Path -LiteralPath $HostsPath)) { return , @() }
    $text = Get-HostsText
    $lines = $text -split "`r?`n"
    if ($lines.Count -gt 0 -and $lines[-1] -eq '') { $lines = $lines[0..($lines.Count - 2)] }
    if ($lines.Count -eq 1 -and $lines[0] -eq '') { $lines = @() }
    return , @($lines)
}

# Splits hosts lines into: other (untouched) lines, and SteamPin's pins (block + v1 legacy lines).
function Split-Hosts([string[]]$lines, [string[]]$names) {
    $other = New-Object Collections.Generic.List[string]
    $pins = [ordered]@{}
    $inBlock = $false; $sawBlock = $false
    foreach ($l in $lines) {
        if ($l.StartsWith($script:BeginPrefix)) { $inBlock = $true; $sawBlock = $true; continue }
        if ($inBlock -and $l -eq $script:EndMark) { $inBlock = $false; continue }
        $isLegacy = $l.Contains($script:LegacyTag)
        if ($inBlock -or $isLegacy) {
            if ($l -match '^\s*(\S+)\s+(\S+)') {
                $ip = $Matches[1]; $n = $Matches[2].ToLowerInvariant()
                if ((Test-PublicIPv4 $ip) -and ($names -contains $n) -and -not $pins.Contains($n)) { $pins[$n] = $ip }
            }
            continue
        }
        $other.Add($l)
    }
    return @{ Other = $other; Pins = $pins; SawBlock = $sawBlock; Unterminated = $inBlock }
}

# Names that also appear on an active line outside SteamPin's block (user's own entries).
function Get-ForeignEntries([Collections.Generic.List[string]]$other, [string[]]$names) {
    $found = @()
    foreach ($l in $other) {
        $body = ($l -split '#', 2)[0]
        $parts = @($body -split '\s+' | Where-Object { $_ })
        if ($parts.Count -ge 2) { foreach ($p in $parts[1..($parts.Count - 1)]) { if ($names -contains $p.ToLowerInvariant()) { $found += $p.ToLowerInvariant() } } }
    }
    return @($found | Select-Object -Unique)
}

function New-HostsText([Collections.Generic.List[string]]$other, $pins, [string[]]$order) {
    $out = New-Object Collections.Generic.List[string]
    foreach ($l in $other) { $out.Add($l) }
    while ($out.Count -gt 0 -and $out[$out.Count - 1].Trim() -eq '') { $out.RemoveAt($out.Count - 1) }
    $names = @($order | Where-Object { $pins[$_] })
    if ($names.Count -gt 0) {
        $out.Add('')
        $out.Add($script:BeginMark)
        foreach ($n in $names) { $out.Add("$($pins[$n])`t$n") }
        $out.Add($script:EndMark)
    }
    if ($out.Count -eq 0) { return '' }
    return (($out -join "`r`n") + "`r`n")
}

# Atomic replace (temp file in the same folder + File.Replace), with retries for locks.
function Write-HostsText([string]$text) {
    $dir = Split-Path -Parent $HostsPath
    $tmp = Join-Path $dir 'hosts.steampin.tmp'
    $bak = Join-Path $dir 'hosts.steampin.bak'
    [IO.File]::WriteAllText($tmp, $text, $script:HostsEncoding)
    $done = $false; $err = $null
    for ($i = 0; $i -lt 10 -and -not $done; $i++) {
        try {
            if (Test-Path -LiteralPath $HostsPath) { [IO.File]::Replace($tmp, $HostsPath, $bak) }
            else { [IO.File]::Move($tmp, $HostsPath) }
            $done = $true
        } catch { $err = $_; Start-Sleep -Milliseconds 500 }
    }
    if (-not $done) {
        # Fallback: in-place write (some security tools block File.Replace on hosts).
        for ($i = 0; $i -lt 10 -and -not $done; $i++) {
            try { [IO.File]::WriteAllText($HostsPath, $text, $script:HostsEncoding); $done = $true }
            catch { $err = $_; Start-Sleep -Milliseconds 500 }
        }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    if (-not $done) { throw "Could not write hosts file: $($err.Exception.Message)" }
    if ((Get-HostsText) -ne $text) { throw 'Hosts file did not read back as written (another program changed it?).' }
}

function Clear-Dns {
    if ($HostsPath -ne (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts')) { return }   # test runs
    try { Clear-DnsClientCache -ErrorAction Stop } catch { & ipconfig.exe /flushdns | Out-Null }
}

# ---------------------------------------------------------------------------------
# Discovery and probing
# ---------------------------------------------------------------------------------

function Invoke-Curl([string[]]$curlArgs) {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $script:Curl @curlArgs 2>$null; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $eap }
    return @{ Out = (@($out) -join "`n"); Exit = $code }
}

function Test-Online($cfg) {
    if (-not $cfg.connectivityUrl) { return $true }
    for ($i = 0; $i -lt 2; $i++) {
        $r = Invoke-Curl @('-4', '-s', '-m', '8', [string]$cfg.connectivityUrl)
        if ($r.Exit -eq 0 -and (-not $cfg.connectivityExpect -or $r.Out.Contains([string]$cfg.connectivityExpect))) { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}

function Get-DnsCandidates($cfg, [string]$name) {
    $found = New-Object Collections.Generic.List[string]
    foreach ($srv in @($cfg.resolvers)) {
        try {
            $ans = Resolve-DnsName -Name $name -Type A -Server $srv -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop
            foreach ($a in @($ans)) { if ($a.Type -eq 'A' -and $a.IPAddress) { $found.Add([string]$a.IPAddress) } }
        } catch { }
    }
    foreach ($u in @($cfg.dohUrls)) {
        $r = Invoke-Curl @('-s', '-m', '6', '-H', 'accept: application/dns-json', "$($u)?name=$name&type=A")
        if ($r.Exit -ne 0) { continue }
        try {
            $j = $r.Out | ConvertFrom-Json
            foreach ($a in @($j.Answer)) { if ($a -and $a.type -eq 1) { $found.Add([string]$a.data) } }
        } catch { }
    }
    return @($found | Where-Object { (Test-PublicIPv4 $_) -and (Test-AllowedNetwork $_ $cfg.allowedNetworks) } | Select-Object -Unique)
}

# One HTTPS request to $ip with SNI/Host = target name and full certificate validation.
function Invoke-Probe($cfg, $t, [string]$ip) {
    $marker = '@@SteamPin@@'
    $fmt = '\n' + $marker + '%{http_code}|%{time_appconnect}|%{time_starttransfer}|%{redirect_url}'
    $r = Invoke-Curl @('-4', '-s', '--max-time', [string]$cfg.probeTimeoutSec, '--connect-timeout', [string]$cfg.connectTimeoutSec,
                       '--max-filesize', '262144', '--resolve', "$($t.name):443:$ip", '-w', $fmt, "https://$($t.name)$($t.path)")
    $res = @{ Ok = $false; Ms = $null; Code = 0; Reason = '' }
    $i = $r.Out.LastIndexOf($marker)
    if ($i -lt 0) { $res.Reason = "curl exit $($r.Exit)"; return $res }
    $body = $r.Out.Substring(0, $i)
    $f = $r.Out.Substring($i + $marker.Length).Split('|')
    $res.Code = [int]$f[0]
    if ($r.Exit -ne 0) {
        $res.Reason = switch ($r.Exit) { 6 { 'DNS' } 7 { 'refused' } 28 { 'timeout' } 35 { 'TLS reset/failed' } 60 { 'certificate mismatch' } default { "curl exit $($r.Exit)" } }
        return $res
    }
    # Rank by TLS-handshake-complete time: it measures the path to the edge server.
    # Time-to-first-byte mostly measures Valve's origin behind the edge, so it is only informative.
    $ms = [double]::Parse($f[1], $script:Inv) * 1000
    if ($t.expectStatus -notcontains $res.Code) { $res.Reason = "HTTP $($res.Code)"; return $res }
    if ($t.expectBody -and $body -notmatch $t.expectBody) { $res.Reason = 'unexpected body'; return $res }
    if ($t.expectRedirect -and ($f.Count -lt 4 -or $f[3] -notmatch $t.expectRedirect)) { $res.Reason = 'unexpected redirect'; return $res }
    $res.Ok = $true; $res.Ms = [math]::Round($ms)
    return $res
}

# Probes an IP up to $samples times. With -FailFast, stops at the first failure.
function Measure-Candidate($cfg, $t, [string]$ip, [int]$samples, [switch]$FailFast) {
    $ok = New-Object Collections.Generic.List[double]
    $n = 0; $reason = ''
    for ($i = 0; $i -lt $samples; $i++) {
        if ($i -gt 0) { Start-Sleep -Milliseconds 250 }
        $p = Invoke-Probe $cfg $t $ip
        $n++
        if ($p.Ok) { $ok.Add($p.Ms) } else { $reason = $p.Reason; if ($FailFast) { break } }
    }
    $median = $null
    if ($ok.Count -gt 0) { $s = @($ok | Sort-Object); $median = $s[[int][math]::Floor(($s.Count - 1) / 2)] }
    return [pscustomobject]@{ Ip = $ip; Pass = $ok.Count; Total = $n; Ms = $median; Reason = $reason }
}

function Get-Candidates($cfg, $t, $ts, [string]$cur) {
    # Note: under StrictMode, reading a missing hashtable key with dot syntax throws, so use ['key'].
    $known = @($ts.ips.Keys | Where-Object { $ts.ips[$_]['lastOk'] } |
               Sort-Object { ConvertFrom-Time $ts.ips[$_]['lastOk'] } -Descending)
    $dns = @(Get-DnsCandidates $cfg $t.name)
    $now = Get-Now
    foreach ($ip in $dns) {
        if (-not $ts.ips.ContainsKey($ip)) { $ts.ips[$ip] = @{ firstSeen = (Format-Time $now) } }
        $ts.ips[$ip].lastSeenDns = Format-Time $now
    }
    $all = @(@($cur) + $known + $dns + @($t.seeds) + @($cfg.seeds) | Where-Object { $_ -and (Test-PublicIPv4 $_) } | Select-Object -Unique)
    return @{ All = @($all | Select-Object -First ([int]$cfg.maxCandidatesPerName)); Dns = $dns }
}

# Exponential backoff for IPs that keep failing: 30 min, 1 h, 2 h, ... capped at 6 h.
function Test-BackedOff($entry, [datetime]$now) {
    if (-not $entry -or -not $entry['failStreak'] -or [int]$entry.failStreak -lt 3) { return $false }
    $last = ConvertFrom-Time $entry['lastProbe']
    if (-not $last) { return $false }
    $mins = [math]::Min(360, 30 * [math]::Pow(2, [int]$entry.failStreak - 3))
    return ($now - $last).TotalMinutes -lt $mins
}

function Update-IpEntry($ts, [string]$ip, $m, [datetime]$now) {
    if (-not $ts.ips.ContainsKey($ip)) { $ts.ips[$ip] = @{ firstSeen = (Format-Time $now) } }
    $e = $ts.ips[$ip]
    $e.lastProbe = Format-Time $now
    if ($m.Pass -eq $m.Total) { $e.lastOk = Format-Time $now; $e.failStreak = 0; $e.lastMs = $m.Ms }
    elseif ($m.Pass -eq 0) { $e.failStreak = 1 + [int]$(if ($e['failStreak']) { $e.failStreak } else { 0 }); $e.lastFail = Format-Time $now; $e.lastReason = $m.Reason }
}

function Remove-StaleIps($cfg, $ts, [datetime]$now, [string[]]$keep) {
    foreach ($ip in @($ts.ips.Keys)) {
        if ($keep -contains $ip) { continue }
        $e = $ts.ips[$ip]
        $ref = ConvertFrom-Time $(if ($e['lastOk']) { $e.lastOk } elseif ($e['lastSeenDns']) { $e.lastSeenDns } else { $e['firstSeen'] })
        if (-not $ref -or ($now - $ref).TotalDays -gt [double]$cfg.forgetAfterDays) { $ts.ips.Remove($ip) }
    }
}

# ---------------------------------------------------------------------------------
# Decision for one hostname
# ---------------------------------------------------------------------------------

function Select-Pin($cfg, $t, $ts, [string]$cur, $results) {
    $samples = [int]$cfg.samples
    $curPin = if ($cur) { $cur } else { $null }   # [string] params turn $null into ''
    $curM = if ($cur) { $results[$cur] } else { $null }
    $curHealthy = $curM -and ($curM.Pass * 2 -gt $curM.Total)
    $best = @($results.Values | Where-Object { $_.Ip -ne $cur -and $_.Total -eq $samples -and $_.Pass -eq $_.Total } |
              Sort-Object Ms | Select-Object -First 1)
    $best = if ($best.Count) { $best[0] } else { $null }

    $d = @{ Pin = $curPin; Action = 'none'; Note = '' }
    if ($curHealthy) {
        $ts.failedRuns = 0
        $gainMs = if ($best) { $curM.Ms - $best.Ms } else { 0 }
        $clearlyBetter = $best -and $gainMs -ge [double]$cfg.switchMinGainMs -and
                         ($gainMs -ge $curM.Ms * [double]$cfg.switchMinGainPct / 100)
        if ($clearlyBetter) {
            if ($ts.challenger -eq $best.Ip) { $ts.challengerRuns = [int]$ts.challengerRuns + 1 } else { $ts.challenger = $best.Ip; $ts.challengerRuns = 1 }
            if ($ts.challengerRuns -ge [int]$cfg.switchConfirmRuns) {
                $d.Pin = $best.Ip; $d.Action = 'faster'
                $d.Note = "$($best.Ip) is faster ($($best.Ms) ms vs $($curM.Ms) ms on $($ts.challengerRuns) runs)"
                $ts.challenger = $null; $ts.challengerRuns = 0
            } else {
                $d.Note = "kept; $($best.Ip) is faster ($($best.Ms) vs $($curM.Ms) ms), switching if still faster next run"
            }
        } else { $ts.challenger = $null; $ts.challengerRuns = 0 }
        return $d
    }

    $ts.challenger = $null; $ts.challengerRuns = 0
    $why = if ($cur) { "$cur failed ($($curM.Reason))" } else { 'not pinned' }
    if ($best) {
        $ts.failedRuns = 0
        $d.Pin = $best.Ip; $d.Action = if ($cur) { 'replaced' } else { 'pinned' }
        $d.Note = "$why -> $($best.Ip) ($($best.Ms) ms)"
        return $d
    }
    if ($cur) {
        $ts.failedRuns = [int]$ts.failedRuns + 1
        if ($ts.failedRuns -ge [int]$cfg.removeAfterFailedRuns) {
            $d.Pin = $null; $d.Action = 'removed'
            $d.Note = "$why on $($ts.failedRuns) runs and no working server found -> pin removed (normal DNS)"
            $ts.failedRuns = 0
        } else {
            $d.Action = 'failing'
            $d.Note = "$why, no working replacement yet; keeping it until the next check"
        }
    }
    return $d
}

# ---------------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------------

function Invoke-Run($cfg) {
    $start = Get-Now
    $names = @($cfg.targets | ForEach-Object { $_.name })
    $state = Read-State
    $split = Split-Hosts (Read-HostsLines) $names
    $pins = $split.Pins

    if ($split.Unterminated) { Write-Log 'SteamPin block in hosts had no END line; it will be rewritten.' 'WARN' }
    $hadPins = $state['lastPins'] -is [hashtable] -and @($state.lastPins.Keys).Count -gt 0
    if ($hadPins -and -not $split.SawBlock -and $pins.Count -eq 0) {
        Write-Log 'SteamPin block disappeared from the hosts file (reset by another program, e.g. antivirus?). Re-pinning.' 'WARN'
    }
    foreach ($n in (Get-ForeignEntries $split.Other $names)) {
        Write-Log "hosts has your own entry for $n outside SteamPin's block; it may override SteamPin's pin." 'WARN'
    }

    if (-not (Test-Online $cfg)) {
        Write-Log 'offline (connectivity check failed) - nothing changed'
        Write-Summary @("offline - nothing changed") $start
        return 0
    }

    $now = Get-Now
    $deadline = $start.AddSeconds([int]$cfg.runBudgetSec)
    $newPins = [ordered]@{}
    $lines = @()
    foreach ($t in $cfg.targets) {
        $ts = Get-TargetState $state $t.name
        $cur = $pins[$t.name]
        $c = Get-Candidates $cfg $t $ts $cur
        $results = @{}
        foreach ($ip in $c.All) {
            if ((Get-Now) -gt $deadline -and $ip -ne $cur) { break }
            if ($ip -ne $cur -and (Test-BackedOff $ts.ips[$ip] $now)) { continue }
            $m = Measure-Candidate $cfg $t $ip ([int]$cfg.samples) -FailFast:($ip -ne $cur)
            $results[$ip] = $m
            Update-IpEntry $ts $ip $m $now
        }
        $d = Select-Pin $cfg $t $ts $cur $results
        $newPins[$t.name] = $d.Pin
        if ($d.Note) { Write-Log "$($t.name): $($d.Note)" $(if ($d.Action -in 'failing', 'removed') { 'WARN' } else { 'INFO' }) }
        Remove-StaleIps $cfg $ts $now @(@($d.Pin, $cur) + @($t.seeds) | Where-Object { $_ })

        $okCount = @($results.Values | Where-Object { $_.Pass -gt 0 }).Count
        $pinMs = if ($d.Pin -and $results.ContainsKey($d.Pin)) { $results[$d.Pin].Ms } else { $null }
        $lines += ('{0,-26} {1,-16} {2,7}  {3,-9} ({4} of {5} servers working, {6} from DNS)' -f $t.name,
                   $(if ($d.Pin) { $d.Pin } else { 'not pinned' }), $(if ($pinMs) { "$pinMs ms" } else { '' }),
                   $(if ($d.Action -eq 'none') { 'kept' } else { $d.Action }), $okCount, $results.Count, @($c.Dns).Count)
    }

    $order = $names
    $text = New-HostsText $split.Other $newPins $order
    $currentText = Get-HostsText
    $changed = $text -ne $currentText
    if ($changed) {
        if ($script:WriteEnabled) {
            Write-HostsText $text
            Clear-Dns
            Write-Log ('hosts updated: ' + (@($order | ForEach-Object { "$_=$(if ($newPins[$_]) { $newPins[$_] } else { '-' })" }) -join ' '))
        } else {
            Write-Host ''
            Write-Host 'Dry run - SteamPin block would become:'
            $block = @($text -split "`r`n" | Where-Object { $_ -match '^\d' -and $_ -match "`t" })
            if ($block.Count) { $block | ForEach-Object { Write-Host "   $_" } } else { Write-Host '   (no pins)' }
        }
    }

    $state.lastPins = @{}
    foreach ($n in $order) { if ($newPins[$n]) { $state.lastPins[$n] = $newPins[$n] } }
    $state.lastRun = Format-Time (Get-Now)
    $state.version = $script:Version
    if ($script:WriteEnabled) { Save-State $state }
    Write-Summary $lines $start
    return 0
}

function Write-Summary([string[]]$lines, [datetime]$start) {
    $secs = [math]::Round(((Get-Now) - $start).TotalSeconds)
    $head = "SteamPin $($script:Version) - last check $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (took $secs s)"
    $all = @($head) + $lines
    if ($script:WriteEnabled) {
        try { Set-Content -LiteralPath (Join-Path $StateDir 'last-check.txt') -Value $all -Encoding UTF8 } catch { }
    }
    if (-not $script:WriteEnabled -or $VerbosePreference -eq 'Continue') { $all | ForEach-Object { Write-Host $_ } }
}

function Invoke-Test($cfg) {
    $names = @($cfg.targets | ForEach-Object { $_.name })
    $pins = (Split-Hosts (Read-HostsLines) $names).Pins
    $state = Read-State
    if (-not (Test-Online $cfg)) { Write-Host 'Offline (connectivity check failed).' -ForegroundColor Yellow }
    foreach ($t in $cfg.targets) {
        $ts = Get-TargetState $state $t.name
        $c = Get-Candidates $cfg $t $ts $pins[$t.name]
        Write-Host ''
        Write-Host "$($t.name)  (pinned: $(if ($pins[$t.name]) { $pins[$t.name] } else { 'no' }); DNS gave: $(if ($c.Dns) { $c.Dns -join ', ' } else { 'nothing usable' }))" -ForegroundColor Cyan
        $rows = foreach ($ip in $c.All) {
            $m = Measure-Candidate $cfg $t $ip ([int]$cfg.samples)
            [pscustomobject]@{
                IP = $ip; Result = "$($m.Pass)/$($m.Total)"
                'Median ms' = $m.Ms; Note = $(if ($m.Pass -lt $m.Total) { $m.Reason } else { '' })
                Pinned = $(if ($ip -eq $pins[$t.name]) { '<- pinned' } else { '' })
            }
        }
        $table = $rows | Sort-Object @{ e = { if ($_.'Median ms') { $_.'Median ms' } else { [double]::MaxValue } } } | Format-Table -AutoSize | Out-String -Width 200
        Write-Host $table.Trim()
    }
    return 0
}

function Invoke-Status($cfg) {
    $names = @($cfg.targets | ForEach-Object { $_.name })
    $lc = Join-Path $StateDir 'last-check.txt'
    if (Test-Path -LiteralPath $lc) { Get-Content -LiteralPath $lc -Encoding UTF8 | Write-Host } else { Write-Host 'No check has run yet.' }
    Write-Host ''
    $pins = (Split-Hosts (Read-HostsLines) $names).Pins
    Write-Host 'Pins in hosts file now:' -ForegroundColor Cyan
    foreach ($n in $names) { Write-Host ('   {0,-26} {1}' -f $n, $(if ($pins[$n]) { $pins[$n] } else { '(not pinned - normal DNS)' })) }
    try {
        $info = Get-ScheduledTask -TaskName 'SteamPin' -ErrorAction Stop | Get-ScheduledTaskInfo
        Write-Host ''
        Write-Host "Scheduled task: last run $($info.LastRunTime), result $($info.LastTaskResult), next run $($info.NextRunTime)"
    } catch { }
    $log = Join-Path $StateDir 'log.txt'
    if (Test-Path -LiteralPath $log) {
        Write-Host ''
        Write-Host 'Recent log:' -ForegroundColor Cyan
        Get-Content -LiteralPath $log -Encoding UTF8 -Tail 15 | ForEach-Object { Write-Host "   $_" }
    }
    return 0
}

function Invoke-Unpin($cfg) {
    $names = @($cfg.targets | ForEach-Object { $_.name })
    $split = Split-Hosts (Read-HostsLines) $names
    $text = New-HostsText $split.Other @{} $names
    $current = Get-HostsText
    if ($text -ne $current) { Write-HostsText $text; Clear-Dns; Write-Log 'all pins removed (unpin)' }
    else { Write-Host 'Nothing to remove.' }
    return 0
}

# ---------------------------------------------------------------------------------
# Entry point (skipped when the file is dot-sourced by the tests)
# ---------------------------------------------------------------------------------

function Invoke-Main {
    $script:WriteEnabled = -not ($DryRun -or $Test -or $Status)
    if (-not (Test-Path -LiteralPath $script:Curl)) { Write-Host "curl.exe not found at $($script:Curl)"; return 2 }
    $cfg = Read-Config $ConfigPath
    if ($script:WriteEnabled) { New-Item -ItemType Directory -Force -Path $StateDir | Out-Null }

    $mutex = $null
    if ($script:WriteEnabled) {
        try {
            $mutex = New-Object Threading.Mutex($false, 'Global\SteamPinRun')
            $got = $false
            try { $got = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $got = $true }
            if (-not $got) { Write-Host 'Another SteamPin run is in progress.'; return 0 }
        } catch { $mutex = $null }
    }
    try {
        if ($Test) { return Invoke-Test $cfg }
        if ($Status) { return Invoke-Status $cfg }
        if ($Unpin) { return Invoke-Unpin $cfg }
        return Invoke-Run $cfg
    } catch {
        Write-Log "error: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" 'ERROR'
        return 1
    } finally {
        if ($mutex) { try { $mutex.ReleaseMutex() } catch { }; $mutex.Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-Main) }
