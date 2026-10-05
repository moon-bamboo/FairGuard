@echo off
rem ================================================================
rem  FairGuard - opponent anomaly detection
rem  Authors: BaiYueQingZhu, DeepSeek-V4.1-Flash (AI collaboration)
rem  License: GPL-3.0 (see LICENSE in the repo root)
rem ================================================================
rem
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ================================================================
rem  FairGuard.dll build script   (32-bit mingw, -nostdlib)
rem
rem  ****************************************************************
rem  THIS FILE MUST STAY PURE ASCII -- do NOT add Chinese comments.
rem
rem  cmd.exe parses .bat files using the local ANSI code page (GBK on
rem  Chinese Windows). A UTF-8 file with Chinese comments gets mis-parsed:
rem  the bytes of a comment line can swallow the *next* command, and you
rem  end up with errors like
rem      '"D:\...\FairGuard\src\src"' is not recognized as an internal
rem      or external command
rem  on a line that looks perfectly fine when you open the file.
rem  (Cost us a real debugging round -- see the dev docs, item 17.)
rem  ****************************************************************
rem
rem  Layout this script assumes:
rem     <workspace>\ToolsChain\w64devkit                        <- toolchain
rem     <workspace>\<project>\FairGuard\src\build.bat            <- this file
rem
rem  Set EP_NOPAUSE=1 to build without the final "pause" (for scripts).
rem ================================================================

echo ================================================
echo  FairGuard.dll build  (32-bit, -nostdlib)
echo ================================================
echo.

rem ---------------------------------------------------------------
rem  [1/5] Locate the toolchain.
rem  NOTE: %~dp0 already ends with a backslash, so "%~dp0..\.."
rem  climbs from src\ up to the WORKSPACE root (the parent of this repo).
rem  exactly what made the old version of this script never work.
rem ---------------------------------------------------------------
set "TC=%~dp0..\..\ToolsChain\w64devkit"
if not exist "%TC%\bin\g++.exe" set "TC=%~dp0..\..\NoCopyProtect\tools\w64devkit"
if not exist "%TC%\bin\g++.exe" set "TC=%~dp0toolchain"
if not exist "%TC%\bin\g++.exe" (
    echo [ERROR] toolchain not found. Tried:
    echo         %~dp0..\..\ToolsChain\w64devkit
    echo         %~dp0..\..\NoCopyProtect\tools\w64devkit
    echo         %~dp0toolchain
    goto :fail
)
echo [1/5] toolchain: %TC%

for /f "tokens=*" %%v in ('"%TC%\bin\g++.exe" -dumpmachine') do set "TRIPLE=%%v"
echo       target: !TRIPLE!
echo !TRIPLE! | findstr /i "i686 mingw32" >nul
if errorlevel 1 (
    echo [ERROR] toolchain is not 32-bit. gamemd.exe is a 32-bit process.
    goto :fail
)

rem ---------------------------------------------------------------
rem  [2/5] Decide where to build.
rem
rem  Default: stage toolchain + source into %TEMP% (pure ASCII), build
rem  there, then copy the DLL back.
rem
rem  Reason: 32-bit gcc locates its own files through ANSI APIs. A path
rem  containing non-ASCII characters (this project's folder name is
rem  Chinese) loses them and gcc then reports:
rem      ld.exe: cannot find -lkernel32
rem
rem  If your copy lives on a pure-ASCII path and you want a faster in-place
rem  build, set EP_INPLACE=1.
rem
rem  NOTE: we do NOT auto-detect "is this path ASCII?" by piping the path
rem  through findstr. GBK trail bytes can be 0x7C ('|'), so cmd would see a
rem  pipe in the middle of the path and die with
rem      ... was unexpected at this time.
rem  (Cost us a round -- see the dev docs, item 17.)
rem ---------------------------------------------------------------
set "SRCDIR=%~dp0."

if "%EP_INPLACE%"=="1" (
    echo [2/5] EP_INPLACE=1 - building in place
    set "SRC=%SRCDIR%"
    set "TOOLDIR=%~dp0..\tools"
    set "BUILD=%~dp0..\_build"
    if not exist "!BUILD!" mkdir "!BUILD!"
) else (
    echo [2/5] staging to %%TEMP%% for build - pure ASCII path
    set "WORK=%TEMP%\fairguard_build"
    if exist "!WORK!" rmdir /s /q "!WORK!"
    mkdir "!WORK!" 2>nul
    echo       copying toolchain - about 250MB, please wait...
    robocopy "%TC%" "!WORK!\toolchain" /E /XD share src /NFL /NDL /NJH /NJS /NP /R:0 /W:0 >nul
    echo       copying source...
    robocopy "!SRCDIR!" "!WORK!\src" /E /NFL /NDL /NJH /NJS /NP /R:0 /W:0 >nul
    echo       copying tools...
    robocopy "%~dp0..\tools" "!WORK!\tools" /E /NFL /NDL /NJH /NJS /NP /R:0 /W:0 >nul
    set "TC=!WORK!\toolchain"
    set "SRC=!WORK!\src"
    set "TOOLDIR=!WORK!\tools"
    set "BUILD=!WORK!\out"
    mkdir "!BUILD!" 2>nul
)

rem ---------------------------------------------------------------
rem  [3/5] Compile the plugin.
rem
rem  -fno-exceptions -fno-rtti      no exception / RTTI machinery
rem  -nostdlib                      no CRT, no libstdc++ (code uses no STL)
rem  -Wl,--no-insert-timestamp      reproducible output (same bytes each run)
rem
rem  Charset: the on-screen alert uses Chinese wide strings and mingw's
rem  wchar_t is 16-bit, so wide-exec-charset MUST be pinned to UTF-16LE.
rem  Otherwise the game shows garbage. Log text is plain ASCII, so
rem  exec-charset can stay at its default.
rem ---------------------------------------------------------------
echo [3/5] compiling...
set "PATH=%TC%\bin;%PATH%"

"%TC%\bin\g++.exe" -Wall -O2 -shared -fno-exceptions -fno-rtti ^
    -finput-charset=UTF-8 -fwide-exec-charset=UTF-16LE ^
    -I"%SRC%" ^
    -o "%BUILD%\FairGuard.dll" "%SRC%\FairGuard.c" ^
    -nostdlib -lkernel32 -lgcc ^
    -Wl,--enable-stdcall-fixup -Wl,--no-insert-timestamp -Wl,--entry,_DllMain@12
if errorlevel 1 (
    echo [ERROR] build failed.
    goto :fail
)
echo       ok - no warnings expected above

rem ---------------------------------------------------------------
rem  [4/5] Run the offline self-tests.
rem  They need no game and no network. All of them must print
rem  "failures: 0".  See the detector usage doc, section 9.
rem ---------------------------------------------------------------
echo [4/5] running self-tests...

echo       - test_detector (judgement core, 63 checks)
"%TC%\bin\gcc.exe" -O2 -Wall -o "%BUILD%\test_detector.exe" "%~dp0..\test\test_detector.c" -I"%SRC%"
if errorlevel 1 ( echo [ERROR] test_detector failed to compile. & goto :fail )
"%BUILD%\test_detector.exe" | findstr /c:"failures: 0" >nul
if errorlevel 1 ( echo [ERROR] test_detector FAILED. & goto :fail )

echo       - test_abi (MessageListClass::AddMessage calling convention, 5 checks)
"%TC%\bin\gcc.exe" -O2 -Wall -o "%BUILD%\test_abi.exe" "%~dp0..\test\test_abi.c"
if errorlevel 1 ( echo [ERROR] test_abi failed to compile. & goto :fail )
"%BUILD%\test_abi.exe" | findstr /c:"failures: 0" >nul
if errorlevel 1 ( echo [ERROR] test_abi FAILED. & goto :fail )

echo       - test_load (DLL load / exports / Syringe handshake)
"%TC%\bin\gcc.exe" -O2 -o "%BUILD%\test_load.exe" "%~dp0..\test\test_load.c" -lkernel32
if errorlevel 1 ( echo [ERROR] test_load failed to compile. & goto :fail )
copy /y "%BUILD%\FairGuard.dll" "%BUILD%\FairGuard.dll" >nul
pushd "%BUILD%"
test_load.exe | findstr /c:"failures: 0" >nul
set "LOADRC=!errorlevel!"
popd
if not "!LOADRC!"=="0" ( echo [ERROR] test_load FAILED. & goto :fail )

echo       - FairGuardReport (log reader + hash-chain verifier)
rem  Charset note for the report tool:
rem    - narrow strings stay UTF-8  -> the HTML report is written as UTF-8
rem    - wide strings (L"...") MUST be UTF-16LE, otherwise MessageBoxW
rem      on a GBK system shows garbage
rem    - console text is plain English on purpose: the console code page is
rem      GBK by default, so printing UTF-8 Chinese there comes out garbled
rem      (see the header comment in tools\FairGuardReport.c)
"%TC%\bin\gcc.exe" -O2 -Wall ^
    -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE ^
    -o "%BUILD%\FairGuardReport.exe" "%TOOLDIR%\FairGuardReport.c"
if errorlevel 1 ( echo [ERROR] FairGuardReport failed to compile. & goto :fail )
"%BUILD%\FairGuardReport.exe" --selftest | findstr /c:"failures: 0" >nul
if errorlevel 1 ( echo [ERROR] FairGuardReport --selftest FAILED. & goto :fail )

rem ---------------------------------------------------------------
rem  [5/5] Collect the artifact.
rem  Target is the PROJECT ROOT (one level up from src\), not src\ itself.
rem ---------------------------------------------------------------
echo [5/5] collecting output...
copy /y "%BUILD%\FairGuard.dll" "%~dp0..\FairGuard.dll" >nul
if errorlevel 1 (
    echo [ERROR] could not copy FairGuard.dll back.
    goto :fail
)
copy /y "%BUILD%\FairGuardReport.exe" "%~dp0..\FairGuardReport.exe" >nul
if errorlevel 1 (
    echo [ERROR] could not copy FairGuardReport.exe back.
    goto :fail
)

echo.
echo ================================================
echo  BUILD OK
echo ================================================
for %%F in ("%~dp0..\FairGuard.dll") do echo    %%~nxF  %%~zF bytes
echo.
echo Deploy to the game folder (where gamemd.exe lives):
echo     FairGuard.dll          ^<- the plugin
echo     FairGuard.dll.inj      ^<- hook declaration (name must match exactly)
echo     FairGuard.ini          ^<- config, optional
echo.
echo Log: ^<game folder^>\MsgLog\FairGuard_YYYY-MM-DD_HH-MM-SS.log
echo.
echo Optional: FairGuardReport.exe reads a log and writes a readable HTML
echo           report + verifies the hash chain. Double-click it.
echo.
if not "%EP_NOPAUSE%"=="" goto :eof
pause
goto :eof

:fail
echo.
echo BUILD FAILED.
if not "%EP_NOPAUSE%"=="" exit /b 1
pause
exit /b 1
