@echo off
REM Double-click bootstrap for the PrivateFirewall installer.
REM Runs Setup-PrivateFirewall.ps1, which self-elevates via UAC.
setlocal
set "HERE=%~dp0"
echo Launching PrivateFirewall installer...
echo A User Account Control prompt will appear - click Yes to continue.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%Setup-PrivateFirewall.ps1" -Install -Startup -Desktop %*
echo.
echo If the installer window closed immediately, it relaunched elevated in a new window.
pause
