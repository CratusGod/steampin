#Requires -Version 5.1
# Installs or upgrades SteamPin. Double-click install.cmd (or run this file) and accept the admin prompt.
param([switch]$ResetConfig)

$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($ResetConfig) { $argList += ' -ResetConfig' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

try {
    $src   = Split-Path -Parent $MyInvocation.MyCommand.Path
    $dir   = Join-Path $env:ProgramFiles 'SteamPin'
    $state = Join-Path $env:ProgramData 'SteamPin'

    Write-Host 'Installing SteamPin...' -ForegroundColor Cyan

    # 1. Program files (admin-only write access, inherited from Program Files)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item (Join-Path $src 'steampin.ps1') (Join-Path $dir 'steampin.ps1') -Force
    $cfgDst = Join-Path $dir 'config.json'
    if ((Test-Path $cfgDst) -and -not $ResetConfig) {
        Write-Host "   kept your existing config.json (run install with -ResetConfig to replace it)"
    } else {
        Copy-Item (Join-Path $src 'config.json') $cfgDst -Force
    }
    Remove-Item (Join-Path $dir 'steam-pin.ps1') -Force -ErrorAction SilentlyContinue   # v1 script

    # 2. State folder: SYSTEM and Administrators can write, users can only read.
    New-Item -ItemType Directory -Force -Path $state | Out-Null
    & icacls.exe $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host '   warning: could not set permissions on the state folder' -ForegroundColor Yellow }

    # 3. Scheduled task (XML so it can include event triggers)
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $script = Join-Path $dir 'steampin.ps1'
    $netQuery = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"><Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000)]]</Select></Query></QueryList>'
    $wakeQuery = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name=''Microsoft-Windows-Power-Troubleshooter''] and (EventID=1)]]</Select></Query></QueryList>'
    $esc = { param($s) [Security.SecurityElement]::Escape($s) }
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>SteamPin: keeps Steam hostnames pinned in the hosts file to the fastest working server. https://github.com/CratusGod/steampin</Description>
    <URI>\SteamPin</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></BootTrigger>
    <TimeTrigger>
      <Repetition><Interval>PT30M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>$((Get-Date).AddMinutes(30).ToString('yyyy-MM-ddTHH:mm:ss'))</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <EventTrigger><Enabled>true</Enabled><Delay>PT30S</Delay><Subscription>$(& $esc $netQuery)</Subscription></EventTrigger>
    <EventTrigger><Enabled>true</Enabled><Delay>PT1M</Delay><Subscription>$(& $esc $wakeQuery)</Subscription></EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$(& $esc $ps)</Command>
      <Arguments>$(& $esc "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`"")</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    Register-ScheduledTask -TaskName 'SteamPin' -Xml $xml -Force | Out-Null
    Write-Host '   scheduled task "SteamPin" registered (every 30 min, at startup, on network connect, after sleep)'

    # 4. First run now, and show the result
    Write-Host '   running the first check (takes up to a minute)...'
    $startedAt = Get-Date
    Start-ScheduledTask -TaskName 'SteamPin'
    $deadline = (Get-Date).AddMinutes(5)
    Start-Sleep -Seconds 3
    while ((Get-ScheduledTask -TaskName 'SteamPin').State -eq 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    $info = Get-ScheduledTaskInfo -TaskName 'SteamPin'
    Write-Host ''
    $lc = Join-Path $state 'last-check.txt'
    if ((Test-Path $lc) -and (Get-Item $lc).LastWriteTime -ge $startedAt.AddSeconds(-5)) {
        Get-Content $lc -Encoding UTF8 | Write-Host
        Write-Host ''
        Write-Host 'SteamPin installed and working.' -ForegroundColor Green
    } else {
        Write-Host "The first check did not finish yet (task result $($info.LastTaskResult)). Check later with status.cmd." -ForegroundColor Yellow
    }
    Write-Host "Log: $state\log.txt"
} catch {
    Write-Host "Install failed: $($_.Exception.Message)" -ForegroundColor Red
}
Read-Host 'Press Enter to close'
