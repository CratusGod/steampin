#Requires -Version 5.1
# Removes SteamPin: its hosts entries, the scheduled task, the program and its state/logs.
$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
try {
    $dir   = Join-Path $env:ProgramFiles 'SteamPin'
    $state = Join-Path $env:ProgramData 'SteamPin'
    Unregister-ScheduledTask -TaskName 'SteamPin' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host '   scheduled task removed'
    $installed = Join-Path $dir 'steampin.ps1'
    $here = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'steampin.ps1'
    $runner = if (Test-Path $installed) { $installed } else { $here }
    if (Test-Path $runner) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner -Unpin
        Write-Host '   hosts entries removed (Steam uses normal DNS again)'
    }
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $state -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'SteamPin removed.' -ForegroundColor Green
} catch {
    Write-Host "Uninstall failed: $($_.Exception.Message)" -ForegroundColor Red
}
Read-Host 'Press Enter to close'
