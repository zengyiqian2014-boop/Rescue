@echo off
setlocal EnableDelayedExpansion
:: ===========================================================================
:: Rescue - Offline WinPE Rescue (bare-batch fallback)
::
:: Use this when your WinPE boot media does NOT include PowerShell. It does the
:: essential offline cleanup with only reg.exe / del / copy, which exist in
:: every WinPE:
::   * back up + delete dropped WDAC / Code-Integrity policy files
::   * clear machine-wide restriction policies + Winlogon shell hijack
::     (offline SOFTWARE hive)
::
:: DRY-RUN BY DEFAULT. Pass /FIX to actually change anything.
::   rescue-offline.cmd                 scan/report (auto-detect Windows volume)
::   rescue-offline.cmd /FIX            apply
::   rescue-offline.cmd D: /FIX         target volume D:, apply
::   rescue-offline.cmd D: S: /FIX      also clean EFI copy on S:
:: ===========================================================================

set "FIX=0"
set "VOL="
set "EFI="
for %%A in (%*) do (
    if /I "%%~A"=="/FIX" (set "FIX=1") else (
        echo %%~A| findstr /R "^[A-Za-z]:$" >nul && (
            if not defined VOL (set "VOL=%%~A") else (set "EFI=%%~A")
        )
    )
)

:: --- auto-detect the offline Windows volume --------------------------------
if not defined VOL (
    for %%D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
        if exist "%%D:\Windows\System32\config\SOFTWARE" if not defined VOL set "VOL=%%D:"
    )
)
if not defined VOL (
    echo No offline Windows installation found on any drive. Aborting.
    exit /b 1
)
set "BK=%VOL%\RescueBackup"

echo =====================================================
if "%FIX%"=="1" (echo   Rescue - Offline Rescue [FIX MODE]) else (echo   Rescue - Offline Rescue [scan only])
echo =====================================================
echo   Target Windows volume: %VOL%
echo   Backups go to:         %BK%
if "%FIX%"=="1" if not exist "%BK%" mkdir "%BK%" >nul 2>&1

set /a FIND=0

:: --- 1. WDAC / Code-Integrity policy files ---------------------------------
echo.
echo == Dropped WDAC / Code-Integrity policy ==
call :killfile "%VOL%\Windows\System32\CodeIntegrity\SiPolicy.p7b"
call :killglob "%VOL%\Windows\System32\CodeIntegrity\CiPolicies\Active" "*.cip"
if defined EFI call :killglob "%EFI%\EFI\Microsoft\Boot\CiPolicies\Active" "*.cip"
if not defined EFI (
    for %%D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
        if exist "%%D:\EFI\Microsoft\Boot\CiPolicies\Active" call :killglob "%%D:\EFI\Microsoft\Boot\CiPolicies\Active" "*.cip"
    )
)

:: --- 2. machine policies + shell hijack (offline SOFTWARE hive) -------------
echo.
echo == Machine restriction policies + shell hijack (offline SOFTWARE) ==
reg load HKLM\RESCUE_SW "%VOL%\Windows\System32\config\SOFTWARE" >nul 2>&1
if errorlevel 1 (
    echo   could not load SOFTWARE hive
) else (
    call :delval "HKLM\RESCUE_SW\Microsoft\Windows\CurrentVersion\Policies\System"   "DisableTaskMgr"       "Task Manager disabled"
    call :delval "HKLM\RESCUE_SW\Microsoft\Windows\CurrentVersion\Policies\System"   "DisableRegistryTools" "regedit disabled"
    call :delval "HKLM\RESCUE_SW\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRun"                "Run box removed"
    call :delval "HKLM\RESCUE_SW\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDesktop"            "Desktop icons hidden"
    call :delval "HKLM\RESCUE_SW\Microsoft\Windows\CurrentVersion\Policies\Explorer" "RestrictRun"          "Only whitelisted apps may run"
    call :delval "HKLM\RESCUE_SW\Policies\Microsoft\Windows\System"                  "DisableCMD"           "Command Prompt disabled"
    call :fixshell "HKLM\RESCUE_SW\Microsoft\Windows NT\CurrentVersion\Winlogon"
    reg unload HKLM\RESCUE_SW >nul 2>&1
)

echo.
echo -----------------------------------------------------
if "%FIND%"=="0" (
    echo   No lockdown levers found on %VOL%. Looks clean.
) else if "%FIX%"=="1" (
    echo   Findings: %FIND%  -^> cleared. Reboot the offline system normally.
) else (
    echo   Findings: %FIND%  ^(scan only^). Re-run with /FIX to apply.
)
echo -----------------------------------------------------
endlocal
exit /b 0

:: ---------------------------------------------------------------------------
:killfile
if exist "%~1" (
    echo   [!] policy file: %~1
    set /a FIND+=1
    if "%FIX%"=="1" (
        copy /Y "%~1" "%BK%\" >nul 2>&1
        del /F /Q "%~1" >nul 2>&1 && (echo       -^> backed up and removed) || (echo       -^> could NOT remove ^(enforced? try again / check EFI copy^))
    )
)
exit /b 0

:killglob
if exist "%~1\%~2" (
    for %%F in ("%~1\%~2") do (
        echo   [!] policy file: %%F
        set /a FIND+=1
        if "%FIX%"=="1" (
            copy /Y "%%F" "%BK%\" >nul 2>&1
            del /F /Q "%%F" >nul 2>&1 && (echo       -^> backed up and removed) || (echo       -^> could NOT remove)
        )
    )
)
exit /b 0

:delval
reg query "%~1" /v "%~2" >nul 2>&1
if not errorlevel 1 (
    echo   [!] %~3
    set /a FIND+=1
    if "%FIX%"=="1" reg delete "%~1" /v "%~2" /f >nul 2>&1 && echo       -^> cleared
)
exit /b 0

:fixshell
for /f "tokens=2,*" %%A in ('reg query "%~1" /v Shell 2^>nul ^| findstr /I "Shell"') do set "SH=%%B"
if defined SH if /I not "%SH%"=="explorer.exe" (
    echo   [!] Shell hijacked to: %SH%
    set /a FIND+=1
    if "%FIX%"=="1" reg add "%~1" /v Shell /t REG_SZ /d "explorer.exe" /f >nul 2>&1 && echo       -^> restored to explorer.exe
)
set "SH="
exit /b 0
