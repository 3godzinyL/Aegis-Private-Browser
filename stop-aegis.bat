@echo off
REM Stop Aegis (daemon + desktop app).
taskkill /F /IM aegis-manager-ui.exe >nul 2>&1
taskkill /F /IM aegis-daemon.exe    >nul 2>&1
echo Aegis stopped.
timeout /t 2 >nul
