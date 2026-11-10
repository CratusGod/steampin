#Requires -Version 5.1
<#
.SYNOPSIS
    SteamPin test suite. No admin rights needed: it never touches the real hosts file.

    Unit tests     - IP validation, CIDR matching, config validation, hosts parsing/writing,
                     backoff, and the switch/keep/remove decision logic (no network).
    Scenario tests - run steampin.ps1 end to end against a temporary hosts file, state
                     folder and config. These need a network where the configured Steam
                     servers work (they were written for FPT Telecom, Vietnam).

    .\tests\Run-Tests.ps1              # everything
    .\tests\Run-Tests.ps1 -UnitOnly    # no network
#>
param([switch]$UnitOnly)

$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$script = Join-Path $root 'steampin.ps1'
$cfgSrc = Join-Path $root 'config.json'
$work   = Join-Path ([IO.Path]::GetTempPath()) ("steampin-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null

$script:pass = 0; $script:fail = 0; $script:failures = @()
function Assert([bool]$cond, [string]$msg) {
    if ($cond) { $script:pass++; Write-Host "  ok   $msg" -ForegroundColor Green }
    else { $script:fail++; $script:failures += $msg; Write-Host "  FAIL $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ''; Write-Host "== $name" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------------
# Unit tests (dot-source the script: its entry point is skipped)
# ---------------------------------------------------------------------------------
. $script -ConfigPath $cfgSrc -HostsPath (Join-Path $work 'unused-hosts') -StateDir (Join-Path $work 'unused-state')
$script:WriteEnabled = $false
$ErrorActionPreference = 'Stop'

Section 'IP validation'
foreach ($ok in '42.119.186.138', '118.69.17.16', '8.8.8.8', '1.1.1.1') { Assert (Test-PublicIPv4 $ok) "accepts $ok" }
foreach ($bad in '10.0.0.1', '127.0.0.1', '192.168.1.1', '172.16.5.4', '100.64.0.1', '169.254.1.1', '0.0.0.0',
                 '224.0.0.1', '255.255.255.255', '203.0.113.113', '256.1.1.1', '01.2.3.4', '1.2.3', '1.2.3.4.5',
                 '1.2.3.4; calc', '1.2.3.4 evil.com', '::1', '', 'abc') {
    Assert (-not (Test-PublicIPv4 $bad)) "rejects '$bad'"
}

Section 'CIDR matching'
Assert (Test-InCidr '42.119.186.138' '42.118.0.0/15') '42.119.186.138 in 42.118.0.0/15'
Assert (Test-InCidr '42.118.0.1' '42.118.0.0/15') '42.118.0.1 in 42.118.0.0/15'
Assert (-not (Test-InCidr '42.120.0.1' '42.118.0.0/15')) '42.120.0.1 not in 42.118.0.0/15'
Assert (Test-InCidr '183.81.255.255' '183.80.0.0/15') '183.81.255.255 in 183.80.0.0/15'
Assert (Test-InCidr '9.9.9.9' '0.0.0.0/0') 'anything in /0'
Assert (Test-InCidr '1.2.3.4' '1.2.3.4/32') 'exact /32'
Assert (-not (Test-InCidr '1.2.3.5' '1.2.3.4/32')) 'neighbour not in /32'
Assert (-not (Test-InCidr '1.2.3.4' '1.2.3.0/33')) 'invalid prefix length rejected'
Assert (Test-AllowedNetwork '23.53.33.1' @()) 'empty allow-list allows everything'
Assert (-not (Test-AllowedNetwork '23.53.33.1' @('42.118.0.0/15', '118.68.0.0/15'))) 'foreign Akamai IP filtered out'

Section 'Config validation'
$cfg = Read-Config $cfgSrc
Assert (@($cfg.targets).Count -eq 3) 'shipped config has 3 targets'
Assert ($cfg.samples -eq 3) 'defaults/values loaded'
function Test-BadConfig([string]$label, [scriptblock]$mutate) {
    $j = Get-Content $cfgSrc -Raw | ConvertFrom-Json
    & $mutate $j
    $p = Join-Path $work 'bad-config.json'
    $j | ConvertTo-Json -Depth 6 | Set-Content $p -Encoding UTF8
    $threw = $false; try { Read-Config $p | Out-Null } catch { $threw = $true }
    Assert $threw "rejects config with $label"
}
Test-BadConfig 'private seed IP'        { param($j) $j.seeds = @('192.168.1.10') }
Test-BadConfig 'injected seed'          { param($j) $j.seeds = @('1.2.3.4 evil.com') }
Test-BadConfig 'bad target name'        { param($j) $j.targets[0].name = 'store steampowered.com' }
Test-BadConfig 'bad path'               { param($j) $j.targets[0].path = '/"; calc' }
Test-BadConfig 'duplicate target'       { param($j) $j.targets[1].name = $j.targets[0].name }
Test-BadConfig 'bad network'            { param($j) $j.allowedNetworks = @('42.118.0.0') }
Test-BadConfig 'bad resolver'           { param($j) $j.resolvers = @('8.8.8.8 & calc') }
Test-BadConfig 'non-https DoH URL'      { param($j) $j.dohUrls = @('http://dns.google/resolve') }
Test-BadConfig 'no targets'             { param($j) $j.targets = @() }

Section 'Hosts parsing and writing'
$names = @($cfg.targets | ForEach-Object { $_.name })
$sample = @(
    '# Copyright (c) Microsoft Corp.',
    '# ghi chú tiếng Việt',
    '127.0.0.1       localhost-test',
    "42.119.186.138`tstore.steampowered.com`t$($script:LegacyTag)",
    '',
    '# BEGIN SteamPin - managed automatically, edits inside this block are overwritten',
    "118.69.17.16`tapi.steampowered.com",
    "10.0.0.1`tlogin.steampowered.com",
    "1.2.3.4`tevil.example.com",
    '# END SteamPin',
    '0.0.0.0 ads.example.com'
)
$s = Split-Hosts $sample $names
Assert ($s.Pins['store.steampowered.com'] -eq '42.119.186.138') 'reads v1 legacy pin'
Assert ($s.Pins['api.steampowered.com'] -eq '118.69.17.16') 'reads pin from block'
Assert (-not $s.Pins.Contains('login.steampowered.com')) 'ignores private IP inside block'
Assert (-not $s.Pins.Contains('evil.example.com')) 'ignores non-target names inside block'
Assert ($s.Other.Count -eq 5) 'keeps the 5 unrelated lines (incl. blank)'
Assert ($s.Other -contains '# ghi chú tiếng Việt') 'keeps non-ASCII comment'
Assert ($s.Other -contains '0.0.0.0 ads.example.com') 'keeps lines after the block'
Assert ($s.SawBlock -and -not $s.Unterminated) 'block detected and terminated'
$u = Split-Hosts @('# BEGIN SteamPin', "1.1.1.1`tstore.steampowered.com", 'x y') $names
Assert $u.Unterminated 'detects unterminated block'

$pins = [ordered]@{ 'store.steampowered.com' = '42.119.186.138'; 'api.steampowered.com' = $null; 'login.steampowered.com' = '118.69.17.204' }
$text = New-HostsText $s.Other $pins $names
Assert ($text.EndsWith("# END SteamPin`r`n")) 'block appended at end with CRLF'
Assert ($text -notmatch "(?<!`r)`n") 'all line endings are CRLF'
Assert ($text -match "42\.119\.186\.138`tstore\.steampowered\.com") 'store pin written'
Assert ($text -notmatch 'api\.steampowered\.com') 'null pin not written'
Assert ($text -notmatch [regex]::Escape($script:LegacyTag)) 'legacy lines removed'
$empty = New-HostsText $s.Other ([ordered]@{}) $names
Assert ($empty -notmatch 'SteamPin') 'no pins -> no block at all'
$fe = @(Get-ForeignEntries ([Collections.Generic.List[string]]@('1.2.3.4 store.steampowered.com # mine', '# 1.2.3.4 api.steampowered.com')) $names)
Assert ($fe.Count -eq 1 -and $fe[0] -eq 'store.steampowered.com') 'detects user-owned entry, ignores commented one'

# Round trip through the real writer on a temp file
$HostsPath = Join-Path $work 'unit-hosts'
[IO.File]::WriteAllText($HostsPath, ($sample -join "`r`n") + "`r`n", (New-Object Text.UTF8Encoding $true))   # with BOM
$s2 = Split-Hosts (Read-HostsLines) $names
Assert ($s2.Other[0] -eq '# Copyright (c) Microsoft Corp.') 'BOM stripped when reading'
Write-HostsText (New-HostsText $s2.Other $pins $names)
$bytes = [IO.File]::ReadAllBytes($HostsPath)
Assert (-not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB)) 'written without BOM'
Assert ([IO.File]::ReadAllText($HostsPath, [Text.Encoding]::UTF8) -match 'ghi chú tiếng Việt') 'non-ASCII comment survives (UTF-8)'
Assert (Test-Path (Join-Path $work 'hosts.steampin.bak')) 'backup of previous hosts kept'
Assert (-not (Test-Path (Join-Path $work 'hosts.steampin.tmp'))) 'temp file cleaned up'

# Hosts file saved in the legacy ANSI code page (not valid UTF-8) must be written back unchanged.
$ansi = [Text.Encoding]::Default
$ansiLine = '# caf' + [char]0xE9 + ' r' + [char]0xE9 + 'sum' + [char]0xE9
[IO.File]::WriteAllBytes($HostsPath, $ansi.GetBytes("$ansiLine`r`n127.0.0.1 a`r`n"))
$s3 = Split-Hosts (Read-HostsLines) $names
Assert ($s3.Other[0] -eq $ansiLine) 'ANSI hosts file decoded correctly'
Write-HostsText (New-HostsText $s3.Other $pins $names)
$back = [IO.File]::ReadAllBytes($HostsPath)
$prefix = $ansi.GetBytes("$ansiLine`r`n127.0.0.1 a`r`n")
Assert ((Compare-Object $back[0..($prefix.Length - 1)] $prefix -SyncWindow 0) -eq $null) 'ANSI bytes preserved exactly on rewrite'

Section 'Backoff'
$now = Get-Date
Assert (-not (Test-BackedOff @{ failStreak = 2; lastProbe = (Format-Time $now) } $now)) 'no backoff below 3 failures'
Assert (Test-BackedOff @{ failStreak = 3; lastProbe = (Format-Time $now.AddMinutes(-10)) } $now) '3 failures: skipped for 30 min'
Assert (-not (Test-BackedOff @{ failStreak = 3; lastProbe = (Format-Time $now.AddMinutes(-31)) } $now)) '3 failures: retried after 30 min'
Assert (Test-BackedOff @{ failStreak = 5; lastProbe = (Format-Time $now.AddMinutes(-100)) } $now) '5 failures: skipped for 2 h'
Assert (-not (Test-BackedOff @{ failStreak = 20; lastProbe = (Format-Time $now.AddMinutes(-361)) } $now)) 'backoff capped at 6 h'

Section 'Decision logic (mocked probe results)'
function Res($ip, $pass, $ms, $total = 3) { [pscustomobject]@{ Ip = $ip; Pass = $pass; Total = $total; Ms = $ms; Reason = $(if ($pass -lt $total) { 'TLS reset/failed' } else { '' }) } }
$t = $cfg.targets[0]
function NewTs { @{ ips = @{}; challenger = $null; challengerRuns = 0; failedRuns = 0 } }

$ts = NewTs
$d = Select-Pin $cfg $t $ts 'A' @{ 'A' = (Res 'A' 3 20); 'B' = (Res 'B' 3 18) }
Assert ($d.Action -eq 'none' -and $d.Pin -eq 'A') 'keeps healthy pin when others are only slightly faster'

$ts = NewTs
$res = @{ 'A' = (Res 'A' 3 100); 'B' = (Res 'B' 3 40) }
$d = Select-Pin $cfg $t $ts 'A' $res
Assert ($d.Pin -eq 'A' -and $ts.challengerRuns -eq 1) 'clearly faster server: waits one run (hysteresis)'
$d = Select-Pin $cfg $t $ts 'A' $res
Assert ($d.Pin -eq 'B' -and $d.Action -eq 'faster') 'clearly faster on 2nd run: switches'

$ts = NewTs
Select-Pin $cfg $t $ts 'A' @{ 'A' = (Res 'A' 3 100); 'B' = (Res 'B' 3 40) } | Out-Null
$d = Select-Pin $cfg $t $ts 'A' @{ 'A' = (Res 'A' 3 100); 'B' = (Res 'B' 3 95) }
Assert ($d.Pin -eq 'A' -and $ts.challengerRuns -eq 0) 'challenger resets when it stops being clearly faster'

$ts = NewTs
$d = Select-Pin $cfg $t $ts 'A' @{ 'A' = (Res 'A' 2 30); 'B' = (Res 'B' 3 10) }
Assert ($d.Pin -eq 'A') 'pin with 2/3 passing counts as healthy'

$ts = NewTs
$d = Select-Pin $cfg $t $ts 'A' @{ 'A' = (Res 'A' 1 30); 'B' = (Res 'B' 3 50); 'C' = (Res 'C' 3 25) }
Assert ($d.Pin -eq 'C' -and $d.Action -eq 'replaced') 'failing pin replaced immediately by fastest healthy'

$ts = NewTs
$d = Select-Pin $cfg $t $ts 'A' @{ 'A' = (Res 'A' 0 $null); 'B' = (Res 'B' 1 10 1) }
Assert ($d.Pin -eq 'A' -and $d.Action -eq 'failing') 'candidate probed only once (fail-fast) is not eligible; dead pin kept on 1st failed run'
$d = Select-Pin $cfg $t $ts 'A' @{ 'A' = (Res 'A' 0 $null) }
Assert ($d.Pin -eq $null -and $d.Action -eq 'removed') 'dead pin removed on 2nd failed run with no replacement'

$ts = NewTs
$d = Select-Pin $cfg $t $ts $null @{ 'B' = (Res 'B' 3 40); 'C' = (Res 'C' 2 10) }
Assert ($d.Pin -eq 'B' -and $d.Action -eq 'pinned') 'unpinned name gets pinned; flaky candidate (2/3) not chosen'

$ts = NewTs
$d = Select-Pin $cfg $t $ts $null @{ 'B' = (Res 'B' 0 $null) }
Assert ($d.Pin -eq $null -and $d.Action -eq 'none') 'nothing works and nothing pinned: no change'

# ---------------------------------------------------------------------------------
# Scenario tests (real network, temp hosts/state/config)
# ---------------------------------------------------------------------------------
if (-not $UnitOnly) {
    function Invoke-SteamPin([string]$dir, [string[]]$extra = @()) {
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script, '-ConfigPath', (Join-Path $dir 'config.json'),
               '-HostsPath', (Join-Path $dir 'hosts'), '-StateDir', (Join-Path $dir 'state')) + $extra
        $out = & powershell.exe @a 2>&1 | Out-String
        return @{ Exit = $LASTEXITCODE; Out = $out }
    }
    function New-Case([string]$name, [string[]]$hostsLines, [scriptblock]$mutateConfig = $null) {
        $dir = Join-Path $work $name
        New-Item -ItemType Directory -Path $dir | Out-Null
        $j = Get-Content $cfgSrc -Raw | ConvertFrom-Json
        if ($mutateConfig) { & $mutateConfig $j }
        $j | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $dir 'config.json') -Encoding UTF8
        [IO.File]::WriteAllText((Join-Path $dir 'hosts'), (($hostsLines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding $false))
        return $dir
    }
    function Get-Pins([string]$dir) {
        $HostsPath = Join-Path $dir 'hosts'
        return (Split-Hosts (Read-HostsLines) $names).Pins
    }
    $base = @('# Copyright (c) Microsoft Corp.', '# ghi chú', '127.0.0.1 localhost-test')
    $storeOk = '^(42\.119\.186\.138|42\.119\.184\.231|118\.68\.82\.144|42\.11[89]\.\d+\.\d+|118\.6[89]\.\d+\.\d+|183\.8[01]\.\d+\.\d+)$'

    Section 'Scenario: fresh hosts file, nothing pinned'
    $d1 = New-Case 'fresh' $base
    $r = Invoke-SteamPin $d1
    $p = Get-Pins $d1
    Assert ($r.Exit -eq 0) "exit code 0 ($($r.Exit))"
    Assert (@($p.Keys).Count -eq 3) "all 3 names pinned ($(@($p.Keys) -join ', '))"
    foreach ($n in $names) { Assert ($p[$n] -match $storeOk) "$n pinned to a local server ($($p[$n]))" }
    $txt = [IO.File]::ReadAllText((Join-Path $d1 'hosts'), [Text.Encoding]::UTF8)
    Assert ($txt.StartsWith("# Copyright (c) Microsoft Corp.`r`n# ghi chú`r`n127.0.0.1 localhost-test`r`n")) 'existing lines untouched'
    Assert (Test-Path (Join-Path $d1 'state\state.json')) 'state.json written'
    Assert ((Get-Content (Join-Path $d1 'state\last-check.txt') -Raw) -match 'last check') 'last-check.txt written'
    Assert ((Get-Content (Join-Path $d1 'state\log.txt') -Raw) -match 'hosts updated') 'change logged'

    Section 'Scenario: second run with healthy pins changes nothing'
    $before = (Get-Item (Join-Path $d1 'hosts')).LastWriteTimeUtc
    $hashBefore = (Get-FileHash (Join-Path $d1 'hosts')).Hash
    Start-Sleep -Seconds 1
    $r = Invoke-SteamPin $d1
    Assert ($r.Exit -eq 0) 'exit code 0'
    Assert ((Get-FileHash (Join-Path $d1 'hosts')).Hash -eq $hashBefore) 'hosts content unchanged'
    Assert ((Get-Item (Join-Path $d1 'hosts')).LastWriteTimeUtc -eq $before) 'hosts file not rewritten'

    Section 'Scenario: migrate SteamPin v1 lines'
    $d2 = New-Case 'legacy' ($base + @(
        "42.119.186.138`tstore.steampowered.com`t$($script:LegacyTag)",
        "118.69.17.16`tapi.steampowered.com`t$($script:LegacyTag)",
        "118.69.17.204`tlogin.steampowered.com`t$($script:LegacyTag)"))
    $r = Invoke-SteamPin $d2
    $txt = [IO.File]::ReadAllText((Join-Path $d2 'hosts'))
    $p = Get-Pins $d2
    Assert ($txt -notmatch [regex]::Escape($script:LegacyTag)) 'v1 lines removed'
    Assert ($txt -match '# BEGIN SteamPin') 'block written'
    Assert ($p['store.steampowered.com'] -eq '42.119.186.138') 'healthy v1 store pin kept'
    Assert ($p['api.steampowered.com'] -eq '118.69.17.16') 'healthy v1 api pin kept'

    Section 'Scenario: dead pin is replaced in the same run'
    $d3 = New-Case 'dead-pin' ($base + @('', $script:BeginMark, "118.69.17.16`tstore.steampowered.com", $script:EndMark))
    $r = Invoke-SteamPin $d3
    $p = Get-Pins $d3
    Assert ($p['store.steampowered.com'] -and $p['store.steampowered.com'] -ne '118.69.17.16') "wrong-pool store pin replaced (now $($p['store.steampowered.com']))"
    Assert ((Get-Content (Join-Path $d3 'state\log.txt') -Raw) -match 'store\.steampowered\.com: 118\.69\.17\.16 failed') 'replacement logged with reason'

    Section 'Scenario: no working server anywhere'
    $d4 = New-Case 'no-server' ($base + @('', $script:BeginMark, "1.0.0.1`tstore.steampowered.com", $script:EndMark)) {
        param($j) $j.targets = @($j.targets[0]); $j.seeds = @('1.1.1.1'); $j.resolvers = @(); $j.dohUrls = @() }
    $r = Invoke-SteamPin $d4
    Assert ((Get-Pins $d4)['store.steampowered.com'] -eq '1.0.0.1') 'run 1: dead pin kept (could be a blip)'
    $r = Invoke-SteamPin $d4
    $txt = [IO.File]::ReadAllText((Join-Path $d4 'hosts'))
    Assert (-not (Get-Pins $d4).Contains('store.steampowered.com')) 'run 2: dead pin removed -> normal DNS'
    Assert ($txt -notmatch 'SteamPin') 'empty block removed entirely'
    Assert ($txt -match 'localhost-test') 'other lines kept'

    Section 'Scenario: offline -> nothing touched'
    $d5 = New-Case 'offline' ($base + @('', $script:BeginMark, "118.69.17.16`tstore.steampowered.com", $script:EndMark)) {
        param($j) $j.connectivityUrl = 'http://192.0.2.1/' }
    $hashBefore = (Get-FileHash (Join-Path $d5 'hosts')).Hash
    $r = Invoke-SteamPin $d5
    Assert ($r.Exit -eq 0) 'exit code 0'
    Assert ((Get-FileHash (Join-Path $d5 'hosts')).Hash -eq $hashBefore) 'hosts untouched while offline (even with a bad pin)'
    Assert ((Get-Content (Join-Path $d5 'state\last-check.txt') -Raw) -match 'offline') 'last-check says offline'

    Section 'Scenario: dry run writes nothing'
    $d6 = New-Case 'dry-run' $base
    $hashBefore = (Get-FileHash (Join-Path $d6 'hosts')).Hash
    $r = Invoke-SteamPin $d6 @('-DryRun')
    Assert ((Get-FileHash (Join-Path $d6 'hosts')).Hash -eq $hashBefore) 'hosts unchanged'
    Assert (-not (Test-Path (Join-Path $d6 'state'))) 'no state folder created'
    Assert ($r.Out -match 'would become') 'prints what would change'

    Section 'Scenario: corrupt state, unterminated block, user entry, block wiped by antivirus'
    $d7 = New-Case 'messy' ($base + @('1.2.3.4 api.steampowered.com', '', '# BEGIN SteamPin', "42.119.186.138`tstore.steampowered.com"))
    New-Item -ItemType Directory (Join-Path $d7 'state') | Out-Null
    Set-Content (Join-Path $d7 'state\state.json') '{ this is not json' -Encoding UTF8
    $r = Invoke-SteamPin $d7
    $log = Get-Content (Join-Path $d7 'state\log.txt') -Raw
    Assert ($r.Exit -eq 0) 'survives corrupt state.json'
    Assert ($log -match 'state.json unreadable') 'corrupt state logged'
    Assert ($log -match 'no END line') 'unterminated block logged'
    Assert ($log -match 'your own entry for api\.steampowered\.com') 'user-owned entry warned about'
    $txt = [IO.File]::ReadAllText((Join-Path $d7 'hosts'))
    Assert (([regex]::Matches($txt, '# END SteamPin')).Count -eq 1) 'block repaired'
    Assert ($txt -match '1\.2\.3\.4 api\.steampowered\.com') "user's own line left alone"
    [IO.File]::WriteAllText((Join-Path $d7 'hosts'), (($base -join "`r`n") + "`r`n"))
    $r = Invoke-SteamPin $d7
    Assert ((Get-Content (Join-Path $d7 'state\log.txt') -Raw) -match 'block disappeared') 'wiped block detected'
    Assert ((Get-Pins $d7).Contains('store.steampowered.com')) 're-pinned after wipe'

    Section 'Scenario: -Unpin removes only the block'
    $r = Invoke-SteamPin $d1 @('-Unpin')
    $txt = [IO.File]::ReadAllText((Join-Path $d1 'hosts'), [Text.Encoding]::UTF8)
    Assert ($txt -notmatch 'SteamPin' -and $txt -notmatch 'steampowered') 'all pins removed'
    Assert ($txt -eq "# Copyright (c) Microsoft Corp.`r`n# ghi chú`r`n127.0.0.1 localhost-test`r`n") 'file back to exactly the original'

    Section 'Scenario: -Status and -Test run read-only'
    $hashBefore = (Get-FileHash (Join-Path $d2 'hosts')).Hash
    $r = Invoke-SteamPin $d2 @('-Status')
    Assert ($r.Exit -eq 0 -and $r.Out -match 'Pins in hosts file now') '-Status prints pins'
    $r = Invoke-SteamPin $d2 @('-Test')
    Assert ($r.Exit -eq 0 -and $r.Out -match '3/3') '-Test prints probe table'
    Assert ((Get-FileHash (Join-Path $d2 'hosts')).Hash -eq $hashBefore) 'hosts unchanged by -Status/-Test'
}

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host ''
if ($script:fail -eq 0) { Write-Host "ALL $($script:pass) TESTS PASSED" -ForegroundColor Green; exit 0 }
Write-Host "$($script:fail) FAILED, $($script:pass) passed:" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
exit 1
