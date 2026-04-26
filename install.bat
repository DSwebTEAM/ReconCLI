@echo off
:: ─────────────────────────────────────────────────────
::  ReconCLI v3 — Windows Installer
::  DSwebTEAM | github.com/DSwebTEAM/ReconCLI
:: ─────────────────────────────────────────────────────
title ReconCLI v3 Installer
chcp 65001 >nul 2>&1

echo.
echo   ____                      _____ _     ___
echo  ^|  _ \ ___  ___ ___  _ __ / ____^| ^|   ^|_ _^|
echo  ^| ^|_^) / _ \/ __/ _ \^| '_ \ ^|    ^| ^|    ^| ^|
echo  ^|  _ ^<  __/ (_^| (_) ^| ^|_) ^| ^|___^| ^|___ ^| ^|
echo  ^|_^| \_\___^|\___\___/^|_.__/ \____^|_____^|___^|
echo.
echo   ────────────────────────────────────────────────
echo   v3.0.0  ^|  DSwebTEAM  ^|  Windows Installer
echo   ────────────────────────────────────────────────
echo.

:: ── Python check ─────────────────────────────────────
echo   [*] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
  echo   [!] Python not found.
  echo   [!] Download: https://python.org/downloads
  echo   [!] Check "Add Python to PATH" during install.
  pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do (
  echo   [+] Found: %%v
)

:: Python version >= 3.8 check
python -c "import sys; exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
  echo   [!] Python 3.8+ required.
  pause & exit /b 1
)

:: ── pip check ────────────────────────────────────────
echo   [*] Checking pip...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
  echo   [*] Installing pip...
  python -m ensurepip --upgrade
)
echo   [+] pip ready

:: ── pyreadline3 for tab completion ───────────────────
echo   [*] Installing pyreadline3 (Windows tab-completion)...
python -m pip install pyreadline3 --quiet

:: ── Install ReconCLI ─────────────────────────────────
echo   [*] Installing ReconCLI...
python -m pip install -e . --quiet
if %errorlevel% neq 0 (
  echo   [!] Install failed — try running as Administrator.
  pause & exit /b 1
)
echo   [+] ReconCLI installed

:: ── PATH notice ──────────────────────────────────────
echo   [*] Checking reconcli command...
where reconcli >nul 2>&1
if %errorlevel% neq 0 (
  echo   [!] reconcli not in PATH yet.
  echo   [!] You may need to restart your terminal or add Python Scripts to PATH.
  for /f "tokens=*" %%p in ('python -c "import sysconfig; print(sysconfig.get_path(\"scripts\"))"') do (
    echo   [!] Scripts dir: %%p
  )
) else (
  echo   [+] reconcli is ready
)

:: ── Done ─────────────────────────────────────────────
echo.
echo   ────────────────────────────────────────────────
echo   ReconCLI v3 installed!
echo   ────────────────────────────────────────────────
echo.
echo   Usage:
echo     reconcli                                  - interactive shell
echo     reconcli recon/subdomain -t hibiki.app   - direct mode
echo     reconcli --list                           - all modules
echo.
echo   ! Authorized use on your own systems only.
echo.
pause
