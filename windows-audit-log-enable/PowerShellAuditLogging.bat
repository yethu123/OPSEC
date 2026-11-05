@echo off
rem Runs PowerShellAuditLogging.ps1 from this folder. Right-click and choose "Run as administrator".
rem Extra arguments are passed on, for example:  PowerShellAuditLogging.bat -Method AuditPolicy
fltmc >nul 2>&1
if errorlevel 1 (
    echo This script must be run as Administrator.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PowerShellAuditLogging.ps1" %*
set RC=%ERRORLEVEL%
timeout /t 10
exit /b %RC%
