#Requires -RunAsAdministrator
# End-to-end drills against the INSTALLED SteamPin (run as admin, after installing).
# Checks the install, then breaks things on purpose and checks that SteamPin repairs them:
#   1 install state   2 diagnosis   3 strategy test   4 winws killed   5 hosts block wiped   6 uninstall + reinstall
# Writes a report to test-results\. Takes about 8-10 minutes.
param([switch]$SkipReinstall, [string]$Installer = (Join-Path $PSScriptRoot '..\target\release\steampin.exe'))

$ErrorActionPreference = 'Stop'
$exe = 'C:\Program Files\SteamPin\SteamPin.exe'
$data = 'C:\ProgramData\SteamPin'
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$outDir = Join-Path $PSScriptRoot '..\test-results'
New-Item -ItemType Directory -Force $outDir | Out-Null
$report = Join-Path $outDir ("e2e-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
$script:pass = 0; $script:fail = 0

function Say($m) { $l = "{0:HH:mm:ss} {1}" -f (Get-Date), $m; Write-Host $l; Add-Content $report $l }
function Check([bool]$ok, [string]$what) { if ($ok) { $script:pass++; Say "PASS  $what" } else { $script:fail++; Say "FAIL  $what" } }
function Invoke-SP([string[]]$a) { $o = & $exe @a 2>&1 | Out-String; return $o.Trim() }
function Status { try { Get-Content "$data\status.json" -Raw | ConvertFrom-Json } catch { $null } }
function Ours { Get-CimInstance Win32_Process -Filter "Name='winws.exe'" | Where-Object { $_.ExecutablePath -like 'C:\Program Files\SteamPin\*' } }
function WaitFor([scriptblock]$cond, [int]$sec, [string]$what) {
    $t = [Diagnostics.Stopwatch]::StartNew()
    while ($t.Elapsed.TotalSeconds -lt $sec) { if (& $cond) { Say "      ($what after $([int]$t.Elapsed.TotalSeconds) s)"; return $true }; Start-Sleep 3 }
    Say "      (${what}: gave up after $sec s)"; return $false
}
function WaitIdle([int]$sec = 300) {
    WaitFor { $s = (Invoke-SP '--status'); -not ($s -match 'Busy:') } $sec 'service idle' | Out-Null
}

Say "SteamPin end-to-end drills on $env:COMPUTERNAME, Windows $([Environment]::OSVersion.Version)"

# 1 ---------------------------------------------------------------------------
Say '--- 1. install state'
$svc = Get-Service SteamPin -ErrorAction SilentlyContinue
Check ($svc -and $svc.Status -eq 'Running') 'service SteamPin is running'
Check ((Get-CimInstance Win32_Service -Filter "Name='SteamPin'").StartName -eq 'LocalSystem') 'service runs as LocalSystem'
Check (-not (Get-ScheduledTask -TaskName SteamPin -ErrorAction SilentlyContinue)) 'old v2 scheduled task removed'
Check (-not (Test-Path 'C:\Program Files\SteamPin\steampin.ps1') -and -not (Test-Path 'C:\Program Files\SteamPin\steam-pin.ps1')) 'old v1/v2 scripts removed'
Check (Test-Path 'C:\Program Files\SteamPin\zapret\winws.exe') 'zapret files extracted'
WaitIdle
$s = Status
Check ($s -and $s.version -like '3.*') "status.json written by v3 ($($s.version))"
$h = Get-Content $hosts -Raw
Check ($h -notmatch 'local VN Steam cache node') 'no v1 legacy lines left in hosts'
Check ($h -match '# BEGIN SteamPin') 'managed block present in hosts'
$acl = (Get-Acl $data).Access | Where-Object { $_.IdentityReference -match 'Users' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }
Check (-not $acl) 'normal users cannot write to ProgramData\SteamPin'
Say (Invoke-SP '--status')

# 1b --------------------------------------------------------------------------
Say '--- 1b. close other DPI-bypass tools (CDPI UI etc.) so SteamPin does the bypass itself'
& $exe --stop-other-bypass | Out-Null
Start-Sleep 2
$others = Get-Process winws, winws2, CDPIUI, CDPIUI_TrayIcon, goodbyedpi -ErrorAction SilentlyContinue | Where-Object { $_.Path -notlike 'C:\Program Files\SteamPin\*' }
Check (-not $others) 'no other DPI-bypass tool running'
Say '      full check now that SteamPin is alone on the traffic'
Invoke-SP '--check', '--full' | Out-Null
Start-Sleep 5
WaitIdle 400
Say (Invoke-SP '--status')

# 2 ---------------------------------------------------------------------------
Say '--- 2. diagnosis'
$d = Invoke-SP '--diagnose'
Say $d
Check ($d -match '\[OK  \] SteamPin service') 'diagnosis reaches the service'
Check ($d -notmatch '\[FAIL\] Bypass files') 'bypass files intact'

# 3 ---------------------------------------------------------------------------
Say '--- 3. strategy test (forced)'
Invoke-SP '--retest' | Out-Null
Start-Sleep 5
WaitIdle 400
$s = Status
Say ("      bypass hosts: {0}; strategy: {1}; running: {2}; error: {3}" -f (($s.bypass.hosts) -join ', '), $s.bypass.strategyName, $s.bypass.running, $s.bypass.error)
if ($s.bypass.scores) { $s.bypass.scores.PSObject.Properties | ForEach-Object { Say ("      {0,-16} {1}" -f $_.Name, $_.Value) } }
$bad = @($s.rows | Where-Object { -not $_.ok })
Check ($bad.Count -eq 0) ("every Steam host works after a full check" + $(if ($bad) { ': failing ' + (($bad | ForEach-Object name) -join ', ') } else { '' }))

# 4 ---------------------------------------------------------------------------
Say '--- 4. winws killed'
$w = Ours
if ($w) {
    $w | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Check (WaitFor { Ours } 150 'winws back') 'service restarts winws after it is killed'
    Start-Sleep 3
    WaitIdle   # let the repair check finish, or it rewrites the block during drill 5
} else { Say '      skipped: the bypass is not needed on this network right now' }

# 5 ---------------------------------------------------------------------------
Say '--- 5. hosts block wiped (like antivirus does)'
$lines = Get-Content $hosts
$in = $false
$kept = foreach ($l in $lines) { if ($l -like '# BEGIN SteamPin*') { $in = $true; continue }; if ($in -and $l -eq '# END SteamPin') { $in = $false; continue }; if (-not $in) { $l } }
[IO.File]::WriteAllLines($hosts, [string[]]$kept)
Check (WaitFor { (Get-Content $hosts -Raw) -match '# BEGIN SteamPin' } 150 'block back') 'service restores the hosts block'
WaitIdle
Check ((Get-Content "$data\log.txt" -Tail 50 | Out-String) -match 'disappeared') 'the reset is logged as a warning'

# 6 ---------------------------------------------------------------------------
if (-not $SkipReinstall) {
    Say '--- 6. uninstall and reinstall'
    & $exe --uninstall | Out-Null
    Start-Sleep 6
    Check (-not (Get-Service SteamPin -ErrorAction SilentlyContinue)) 'uninstall removes the service'
    Check (-not (Ours)) 'uninstall stops winws'
    Check ((Get-Content $hosts -Raw) -notmatch 'SteamPin') 'uninstall removes the hosts block'
    Check (-not (Test-Path $data)) 'uninstall removes ProgramData\SteamPin'
    Check (-not (Test-Path 'C:\Program Files\SteamPin')) 'uninstall removes Program Files\SteamPin'
    Check (-not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SteamPin -ErrorAction SilentlyContinue)) 'uninstall removes the tray autostart'
    $drv = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDivert' -ErrorAction SilentlyContinue).ImagePath
    Check (-not $drv -or $drv -notlike '*Program Files\SteamPin*') 'uninstall removes our WinDivert driver service'
    Say "      reinstalling from $Installer"
    & $Installer --install | Out-Null
    Check ((Get-Service SteamPin -ErrorAction SilentlyContinue).Status -eq 'Running') 'reinstall: service running'
    Start-Sleep 10
    WaitIdle 400
    $s = Status
    Check ($s -and @($s.rows | Where-Object { -not $_.ok }).Count -eq 0) 'reinstall: every Steam host works'
}

Say "--- done: $script:pass passed, $script:fail failed. Report: $report"
