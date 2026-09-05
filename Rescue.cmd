@echo off
rem Rescue launcher - opens the GUI app. The GUI requests admin itself (UAC).
setlocal
set ARCH=x86_64
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set ARCH=arm64
set GUI=%~dp0%ARCH%\rescue_gui.exe
if exist "%GUI%" ( start "" "%GUI%" & exit /b )
echo Could not find "%GUI%".
echo Make sure this launcher sits next to the x86_64\ and arm64\ folders.
pause
