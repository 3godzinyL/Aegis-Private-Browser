@echo off
REM ==========================================================================
REM  Aegis Private Browser - one-click launcher (Windows, host-browser mode)
REM
REM  HOW TO USE: just double-click this file in Explorer.
REM  It builds the binaries, starts the daemon in its own window, and opens
REM  the desktop app. Close the app window, then run stop-aegis.bat to stop.
REM ==========================================================================
setlocal
cd /d "%~dp0"
title Aegis launcher

echo [Aegis] Stopping any previous instance...
taskkill /F /IM aegis-manager-ui.exe >nul 2>&1
taskkill /F /IM aegis-daemon.exe    >nul 2>&1

echo [Aegis] Building (first run is slow, then cached)...
cargo build --release -p aegis-daemon -p aegis-cli
if errorlevel 1 (
  echo.
  echo [Aegis] Build FAILED. Install Rust from https://rustup.rs and try again.
  pause
  exit /b 1
)

echo [Aegis] Preparing runtime folders...
if not exist ".demo\profiles" mkdir ".demo\profiles"
if not exist ".demo\run"      mkdir ".demo\run"
if not exist ".demo\log"      mkdir ".demo\log"
if not exist ".demo\images"   mkdir ".demo\images"
if not exist ".demo\ipc.token" echo aegis-local-dev-token-change-me>".demo\ipc.token"

REM Config is a committed file (.demo\config.toml) with relative paths. Recreate
REM it only if it is missing (e.g. a fresh clone).
if not exist ".demo\config.toml" (
  echo [Aegis] Writing default config...
  (
    echo default_protection = "balanced"
    echo network_prefix = "aegis"
    echo.
    echo [default_network]
    echo kind = "tor"
    echo.
    echo [enforcement]
    echo require_vm_isolation = false
    echo require_gateway = false
    echo allow_host_browser = true
    echo.
    echo [paths]
    echo profiles_dir = ".demo/profiles"
    echo images_dir = ".demo/images"
    echo runtime_dir = ".demo/run"
    echo audit_log = ".demo/log/audit.jsonl"
    echo daemon_socket = ".demo/run/daemon.sock"
  ) > ".demo\config.toml"
)

REM Host-browser mode routes through a SOCKS proxy. Tor Browser's built-in Tor
REM listens on 127.0.0.1:9150 (a standalone Tor Expert Bundle uses 9050). Open
REM Tor Browser before starting a host session, or override AEGIS_HOST_PROXY.
if not defined AEGIS_HOST_PROXY set "AEGIS_HOST_PROXY=socks5h://127.0.0.1:9150"

REM To use Firefox / Tor Browser as the session browser, point this at your
REM firefox.exe (Tor Browser: ...\Tor Browser\Browser\firefox.exe), e.g.:
REM   set "AEGIS_FIREFOX_BIN=C:\path\to\Tor Browser\Browser\firefox.exe"

echo [Aegis] Starting the daemon in a new window...
start "Aegis Daemon" cmd /k "set AEGIS_HOST_PROXY=%AEGIS_HOST_PROXY%& set AEGIS_FIREFOX_BIN=%AEGIS_FIREFOX_BIN%& target\release\aegis-daemon --config .demo\config.toml --dev-port 7690 --dev-token .demo\ipc.token"

echo [Aegis] Waiting for the daemon...
timeout /t 3 >nul

echo [Aegis] Launching the desktop app (close its window to finish)...
set "AEGIS_IPC_ADDR=127.0.0.1:7690"
set "AEGIS_IPC_TOKEN_FILE=%CD%\.demo\ipc.token"
cd "apps\manager-ui\src-tauri"
cargo run

echo.
echo [Aegis] App closed. Run stop-aegis.bat to stop the daemon window.
pause
