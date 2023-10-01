@echo off
rem 32-bit version of SDIO works BOTH on 32-bit and 64-bit Windows.
rem 64-bit version of SDIO works ONLY on 64-bit Windows.
rem EXECEPTION: 32-bit version of SDIO cannot run on Windows PE x64.
rem 64-bit version is faster and doesn't have the 2GB RAM per process limitation.

title=Start Snappy Driver Installer Origin

IF %PROCESSOR_ARCHITECTURE% == x86 (IF NOT DEFINED PROCESSOR_ARCHITEW6432 goto bit32)
goto bit64
:bit32
echo 32-bit
set xOS="R"
goto cont
:bit64
echo 64-bit
set xOS="x64_R"
:cont

for /f "tokens=*" %%a in ('dir /b /od "%~dp0SDIO_%xOS%*.exe"') do set "SDIOEXE=%%a"
if exist "%~dp0%SDIOEXE%" (
 start "Snappy Driver Installer Origin" /d"%~dp0" "%~dp0%SDIOEXE%" %1 %2 %3 %4 %5 %6 %7 %8 %9
 goto ex
) else (
 echo.
 echo  Not found 'Snappy Driver Installer Origin'!
 echo.
 timeout 6
)
:ex