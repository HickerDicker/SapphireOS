rem
rem Extracts all driver packs and scans the contents for malware.
rem This is calling my copy of Emsisoft Emergency Kit (EEK).
rem You should insert your scanner software of choice.
rem You may also need to adjust the errorlevel tests.
rem Copy this to the directory with the SDIO exe files.
rem It uses the SDIO command line to extract the driver packs
rem in the drivers directory.

@echo off
cls
for /f "tokens=*" %%a in ('dir /b /od "%~dp0SDIO_R*.exe"') do set "SDIOEXE=%%a"
echo %SDIOEXE%
for /F %%i in ('dir /b drivers\*.7z') do call :scanpack %%i %%~ni
goto end

:scanpack
%SDIOEXE% -7z x drivers\%1 -y -odrivers\%2
rem insert your own scanner software here
"C:\EEK\bin64\a2cmd.exe" /files=drivers\%2
if errorlevel 2 goto :error
if errorlevel 1 goto :found
if exist drivers\%2\. rmdir /s /q drivers\%2
goto :eof

:error
echo Error: drivers\%2
goto :end

:found
echo FOUND: drivers\%2
goto :end

:end
