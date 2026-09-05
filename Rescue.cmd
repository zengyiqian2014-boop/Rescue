@echo off
setlocal enabledelayedexpansion
title Rescue - anti-ransomware / anti-malware toolkit

rem --- self-elevate to Administrator (all tools need it) ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

rem --- pick the binary folder for this CPU ---
set ARCH=x86_64
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set ARCH=arm64
set BIN=%~dp0%ARCH%
if not exist "%BIN%\scanner.exe" (
    echo Could not find the Rescue binaries under "%BIN%".
    echo Make sure this launcher sits next to the x86_64\ and arm64\ folders.
    pause & exit /b 1
)

:menu
cls
echo ============================================================
echo   RESCUE   ^(%ARCH%^)   - defensive anti-ransomware toolkit
echo ============================================================
echo.
echo   SCAN / CLEAN
echo     1  Quick scan (Downloads, Desktop, Temp, startup...)
echo     2  Full scan (all fixed drives)
echo     3  Autostart (ASEP) scan - flag unsigned autostarts
echo.
echo   UNLOCK
echo     4  Lockdown Breaker - SCAN (report only)
echo     5  Lockdown Breaker - FIX (unlock, kill overlays/effects)
echo.
echo   REAL-TIME PROTECTION
echo     6  Start Anti-Ransomware Guard (+ disk write shield)
echo     7  Install Watchdog service (keeps the guard alive)
echo.
echo   BACKUP / RECOVERY  (Time Machine)
echo     8  Back up my data now  (asks for a backup drive)
echo     9  Schedule automatic backups
echo    10  Restore from a backup
echo.
echo     0  Exit
echo.
set /p choice=Choose an option:

if "%choice%"=="1" ( "%BIN%\scanner.exe" & pause & goto menu )
if "%choice%"=="2" ( "%BIN%\scanner.exe" --full & pause & goto menu )
if "%choice%"=="3" ( "%BIN%\asep_cleaner.exe" & pause & goto menu )
if "%choice%"=="4" ( "%BIN%\lockdown_breaker.exe" & pause & goto menu )
if "%choice%"=="5" ( "%BIN%\lockdown_breaker.exe" --fix --kill-overlays --kill-effects & pause & goto menu )
if "%choice%"=="6" ( echo Starting guard. Leave the window open. Ctrl+C to stop.& "%BIN%\ransom_guard.exe" --shield & pause & goto menu )
if "%choice%"=="7" ( "%BIN%\watchdog.exe" --install & pause & goto menu )
if "%choice%"=="8" (
    set /p bdrive=Backup drive letter (e.g. E): 
    "%BIN%\backup.exe" --snapshot "!bdrive!" --keep 10
    pause & goto menu
)
if "%choice%"=="9" (
    echo Presets: monthly ^| every5days ^| daily ^| hourly
    set /p preset=Schedule: 
    set /p bdrive=Backup drive letter (e.g. E): 
    "%BIN%\backup.exe" --schedule "!preset!" --disk "!bdrive!" --keep 14
    pause & goto menu
)
if "%choice%"=="10" (
    set /p rbk=Path to .rbk backup file: 
    set /p dest=Restore into which folder: 
    "%BIN%\backup.exe" --restore "!rbk!" --to "!dest!"
    pause & goto menu
)
if "%choice%"=="0" exit /b 0
goto menu
