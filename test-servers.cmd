@echo off
rem Probes every known server for each Steam hostname and prints a speed table. Changes nothing.
set "SP=%ProgramFiles%\SteamPin\steampin.ps1"
if not exist "%SP%" set "SP=%~dp0steampin.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SP%" -Test
echo.
pause
