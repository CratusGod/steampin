@echo off
rem Shows SteamPin's last check, current pins and recent log. No admin needed.
set "SP=%ProgramFiles%\SteamPin\steampin.ps1"
if not exist "%SP%" set "SP=%~dp0steampin.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SP%" -Status
echo.
pause
