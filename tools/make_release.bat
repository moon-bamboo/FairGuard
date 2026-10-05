@echo off
rem ================================================================
rem  FairGuard release packer
rem
rem  Builds a zip containing ONLY what a player needs:
rem     FairGuard.dll / .inj / .ini / FairGuardReport.exe
rem  plus the docs worth shipping:
rem     README.md / DISCLAIMER.md / LICENSE / CHANGELOG.md
rem
rem  NOTE: this script does NOT compile anything.
rem        Run src\build.bat first (it also runs the self-tests).
rem
rem  THIS FILE MUST STAY PURE ASCII -- see the header of src\build.bat
rem  for why (cmd.exe parses .bat with the local ANSI code page).
rem ================================================================
setlocal
cd /d "%~dp0.."

rem ---- version: keep in sync with src\FairGuard.c GUARD_VERSION and CHANGELOG.md ----
set "VER=1.3"
set "OUT=FairGuard-%VER%.zip"

if not exist "FairGuard.dll"       ( echo [ERROR] FairGuard.dll not found -- run src\build.bat first. & goto :fail )
if not exist "FairGuard.dll.inj"   ( echo [ERROR] FairGuard.dll.inj not found. & goto :fail )
if not exist "FairGuard.ini"       ( echo [ERROR] FairGuard.ini not found. & goto :fail )
if not exist "FairGuardReport.exe" ( echo [ERROR] FairGuardReport.exe not found -- run src\build.bat first. & goto :fail )

echo Packing %OUT% ...
if exist "%OUT%" del /q "%OUT%"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$items=@('FairGuard.dll','FairGuard.dll.inj','FairGuard.ini','FairGuardReport.exe','README.md','DISCLAIMER.md','LICENSE','CHANGELOG.md');" ^
  "foreach($i in $items){ if(-not (Test-Path $i)){ throw ('missing: ' + $i) } };" ^
  "Compress-Archive -Path $items -DestinationPath '%OUT%' -Force;"
if errorlevel 1 ( echo [ERROR] packing failed. & goto :fail )

echo.
echo ================================================
echo  RELEASE OK
echo ================================================
for %%F in ("%OUT%") do echo    %%~nxF  %%~zF bytes
echo.
echo Contents (a player only needs the first four):
echo     FairGuard.dll          the plugin
echo     FairGuard.dll.inj      hook declaration (name must match the DLL exactly)
echo     FairGuard.ini          config
echo     FairGuardReport.exe    log reader + hash-chain verifier
echo     README.md  DISCLAIMER.md  LICENSE  CHANGELOG.md
echo.
echo Next: upload this zip to the GitHub Release for tag v%VER%
echo.
pause
goto :eof

:fail
echo.
pause
exit /b 1
