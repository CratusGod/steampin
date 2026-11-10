@echo off
echo Asking for admin rights to remove SteamPin...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0uninstall.ps1\"'"
if errorlevel 1 (
  echo Admin prompt was cancelled or failed.
  pause
)
