#Requires -RunAsAdministrator
# End-to-end drills against the INSTALLED RustyDPI (run as admin, after installing).
# Checks the install, then breaks things on purpose and checks that RustyDPI repairs them:
#   1 install state   2 diagnosis   3 strategy test   4 winws killed   4b full check keeps winws running
#   5 hosts block wiped   5b winws.exe removed (antivirus) -> driverless relay -> repair   6 uninstall + reinstall
# Writes a report to test-results\ (site names masked). Takes about 10-12 minutes.
param([switch]$SkipReinstall, [string]$Installer = (Join-Path $PSScriptRoot '..\target\release\rustydpi.exe'))

$ErrorActionPreference = 'Stop'
$exe = 'C:\Program Files\RustyDPI\RustyDPI.exe'
$data = 'C:\ProgramData\RustyDPI'
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$outDir = Join-Path $PSScriptRoot '..\test-results'
New-Item -ItemType Directory -Force $outDir | Out-Null
$report = Join-Path $outDir ("e2e-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
$script:pass = 0; $script:fail = 0

function Say($m) { $l = "{0:HH:mm:ss} {1}" -f (Get-Date), $m; Write-Host $l; Add-Content $report $l }
function Check([bool]$ok, [string]$what) { if ($ok) { $script:pass++; Say "PASS  $what" } else { $script:fail++; Say "FAIL  $what" } }
function Invoke-SP([string[]]$a) { $o = & $exe @a 2>&1 | Out-String; return $o.Trim() }
function Status { try { Get-Content "$data\status.json" -Raw | ConvertFrom-Json } catch { $null } }
# The user's own sites never appear in the report: first letter and top-level domain only.
$userSites = try { @((Get-Content "$data\settings.json" -Raw | ConvertFrom-Json).extraSites) } catch { @() }
function Mask([string]$n) { if ($userSites -contains $n) { $n.Substring(0, 1) + '****.' + $n.Split('.')[-1] } else { $n } }
function Ours { Get-CimInstance Win32_Process -Filter "Name='winws.exe'" | Where-Object { $_.ExecutablePath -like 'C:\Program Files\RustyDPI\*' } }
function WaitFor([scriptblock]$cond, [int]$sec, [string]$what) {
    $t = [Diagnostics.Stopwatch]::StartNew()
    while ($t.Elapsed.TotalSeconds -lt $sec) { if (& $cond) { Say "      ($what after $([int]$t.Elapsed.TotalSeconds) s)"; return $true }; Start-Sleep 3 }
    Say "      (${what}: gave up after $sec s)"; return $false
}
function WaitIdle([int]$sec = 300) {
    WaitFor { $s = (Invoke-SP '--status'); -not ($s -match 'Busy:') } $sec 'service idle' | Out-Null
}

Say "RustyDPI end-to-end drills on $env:COMPUTERNAME, Windows $([Environment]::OSVersion.Version)"

# 1 ---------------------------------------------------------------------------
Say '--- 1. install state'
$svc = Get-Service RustyDPI -ErrorAction SilentlyContinue
Check ($svc -and $svc.Status -eq 'Running') 'service RustyDPI is running'
Check ((Get-CimInstance Win32_Service -Filter "Name='RustyDPI'").StartName -eq 'LocalSystem') 'service runs as LocalSystem'
Check (-not (Get-ScheduledTask -TaskName SteamPin -ErrorAction SilentlyContinue)) 'old SteamPin v2 scheduled task removed'
Check (-not (Get-Service SteamPin -ErrorAction SilentlyContinue) -and -not (Test-Path 'C:\Program Files\SteamPin')) 'old SteamPin 3 service and folder removed'
$qc = sc.exe qc RustyDPI | Out-String
Check ($qc -match 'AUTO_START' -and $qc -notmatch 'DELAYED') 'service starts with Windows (not delayed)'
Check (Test-Path 'C:\Program Files\RustyDPI\zapret\winws.exe') 'zapret files extracted'
WaitIdle
$s = Status
Check ($s -and $s.version -like '4.*') "status.json written by v4 ($($s.version))"
$h = Get-Content $hosts -Raw
Check ($h -notmatch 'local VN Steam cache node') 'no v1 legacy lines left in hosts'
Check ($h -match '# BEGIN RustyDPI') 'managed block present in hosts'
$acl = (Get-Acl $data).Access | Where-Object { $_.IdentityReference -match 'Users' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }
Check (-not $acl) 'normal users cannot write to ProgramData\RustyDPI'
Say (Invoke-SP '--status')

# 1b --------------------------------------------------------------------------
Say '--- 1b. close other DPI-bypass tools (CDPI UI etc.) so RustyDPI does the bypass itself'
& $exe --stop-other-bypass | Out-Null
Start-Sleep 2
$others = Get-Process winws, winws2, CDPIUI, CDPIUI_TrayIcon, goodbyedpi -ErrorAction SilentlyContinue | Where-Object { $_.Path -notlike 'C:\Program Files\RustyDPI\*' }
Check (-not $others) 'no other DPI-bypass tool running'
Say '      full check now that RustyDPI is alone on the traffic'
Invoke-SP '--check', '--full' | Out-Null
Start-Sleep 5
WaitIdle 400
Say (Invoke-SP '--status')

# 2 ---------------------------------------------------------------------------
Say '--- 2. diagnosis'
$d = Invoke-SP '--diagnose'
Say $d
Check ($d -match '\[OK  \] RustyDPI service') 'diagnosis reaches the service'
Check ($d -notmatch '\[FAIL\] Bypass files') 'bypass files intact'

# 3 ---------------------------------------------------------------------------
Say '--- 3. strategy test (forced)'
Invoke-SP '--retest' | Out-Null
Start-Sleep 5
WaitIdle 400
$s = Status
Say ("      bypass hosts: {0}; strategy: {1}; running: {2}; error: {3}" -f (($s.bypass.hosts | ForEach-Object { Mask $_ }) -join ', '), $s.bypass.strategyName, $s.bypass.running, $s.bypass.error)
if ($s.bypass.scores) { $s.bypass.scores.PSObject.Properties | ForEach-Object { Say ("      {0,-16} {1}" -f $_.Name, $_.Value) } }
$bad = @($s.rows | Where-Object { -not $_.ok })
Check ($bad.Count -eq 0) ("every Steam host works after a full check" + $(if ($bad) { ': failing ' + (($bad | ForEach-Object { Mask $_.name }) -join ', ') } else { '' }))

# 4 ---------------------------------------------------------------------------
Say '--- 4. winws killed'
$w = Ours
if ($w) {
    $w | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Check (WaitFor { Ours } 150 'winws back') 'service restarts winws after it is killed'
    Start-Sleep 3
    WaitIdle   # let the repair check finish, or it rewrites the block during drill 5
} else { Say '      skipped: the bypass is not needed on this network right now' }

# 4b --------------------------------------------------------------------------
Say '--- 4b. a full check keeps the bypass running'
$w = Ours
if ($w) {
    Invoke-SP '--check', '--full' | Out-Null
    Start-Sleep 5
    WaitIdle
    $w2 = Ours
    Check ($w2 -and $w2.ProcessId -eq $w.ProcessId) "winws kept running through the full check (pid $($w.ProcessId) -> $($w2.ProcessId))"
    $s = Status
    $direct = @($s.rows | Where-Object { $_.route -in 'bypass', 'pinnedBypass' -and -not $_.directProblem })
    Check ($direct.Count -eq 0) 'checks without the bypass saw the real block for every bypassed host (TTL marker works)'
} else { Say '      skipped: the bypass is not needed on this network right now' }

# 5 ---------------------------------------------------------------------------
Say '--- 5. hosts block wiped (like antivirus does)'
$lines = Get-Content $hosts
$in = $false
$kept = foreach ($l in $lines) { if ($l -like '# BEGIN RustyDPI*') { $in = $true; continue }; if ($in -and $l -eq '# END RustyDPI') { $in = $false; continue }; if (-not $in) { $l } }
[IO.File]::WriteAllLines($hosts, [string[]]$kept)
Check (WaitFor { (Get-Content $hosts -Raw) -match '# BEGIN RustyDPI' } 150 'block back') 'service restores the hosts block'
WaitIdle
Check ((Get-Content "$data\log.txt" -Tail 50 | Out-String) -match 'disappeared') 'the reset is logged as a warning'

# 5b --------------------------------------------------------------------------
Say '--- 5b. winws.exe removed (like antivirus does): the driverless relay takes over'
$w = Ours
if ($w) {
    $ws = 'C:\Program Files\RustyDPI\zapret\winws.exe'
    $w | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Start-Sleep 1
    Rename-Item $ws "$ws.away"
    try {
        Check (WaitFor { (Status).rows | Where-Object { $_.route -eq 'relay' -and $_.ok } } 150 'relay in use') 'sites move to the driverless relay'
        $r = (Status).rows | Where-Object { $_.route -eq 'relay' } | Select-Object -First 1
        if ($r) {
            Check ((Get-Content $hosts -Raw) -match "127\.77\.\d+\.\d+\s+$([regex]::Escape($r.name))") 'hosts file points the site at its relay address'
            $code = & curl.exe -s -o NUL -m 15 -w '%{http_code}' "https://$($r.name)/"
            Check ($code -match '^[1-5]\d\d$') "the site loads through the relay via the real hosts file (HTTP $code)"
        }
    } finally { if (Test-Path "$ws.away") { Rename-Item "$ws.away" $ws } }
    & $exe --repair | Out-Null
    Invoke-SP '--check', '--full' | Out-Null
    Start-Sleep 5
    WaitIdle 400
    Check (@((Status).rows | Where-Object { $_.route -eq 'relay' }).Count -eq 0 -and (Ours)) 'after repair, the next full check goes back to winws'
} else { Say '      skipped: the bypass is not needed on this network right now' }

# 6 ---------------------------------------------------------------------------
if (-not $SkipReinstall) {
    Say '--- 6. uninstall and reinstall'
    # Uninstall deletes ProgramData\RustyDPI, settings included: keep the user's settings and put them back after.
    $saved = if (Test-Path "$data\settings.json") { [IO.File]::ReadAllBytes("$data\settings.json") } else { $null }
    & $exe --uninstall | Out-Null
    Start-Sleep 6
    Check (-not (Get-Service RustyDPI -ErrorAction SilentlyContinue)) 'uninstall removes the service'
    Check (-not (Ours)) 'uninstall stops winws'
    Check ((Get-Content $hosts -Raw) -notmatch 'RustyDPI') 'uninstall removes the hosts block'
    Check (-not (Test-Path $data)) 'uninstall removes ProgramData\RustyDPI'
    Check (-not (Test-Path 'C:\Program Files\RustyDPI')) 'uninstall removes Program Files\RustyDPI'
    Check (-not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name RustyDPI -ErrorAction SilentlyContinue)) 'uninstall removes the tray autostart'
    $drv = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDivert' -ErrorAction SilentlyContinue).ImagePath
    Check (-not $drv -or $drv -notlike '*Program Files\RustyDPI*') 'uninstall removes our WinDivert driver service'
    Say "      reinstalling from $Installer"
    & $Installer --install | Out-Null
    if ($saved) {
        Stop-Service RustyDPI; [IO.File]::WriteAllBytes("$data\settings.json", $saved); Start-Service RustyDPI
        Check (@((Get-Content "$data\settings.json" -Raw | ConvertFrom-Json).extraSites).Count -eq $userSites.Count) 'reinstall: your settings and sites are put back'
    }
    Check ((Get-Service RustyDPI -ErrorAction SilentlyContinue).Status -eq 'Running') 'reinstall: service running'
    Start-Sleep 10
    WaitIdle 400
    $s = Status
    Check ($s -and @($s.rows | Where-Object { -not $_.ok }).Count -eq 0) 'reinstall: every Steam host works'
}

Say "--- done: $script:pass passed, $script:fail failed. Report: $report"
