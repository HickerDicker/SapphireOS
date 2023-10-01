@echo off
for /f "tokens=*" %%a in ('dir /b /od "%~dp0SDIO_R*.exe"') do set "SDIOEXE=%%a"
echo %SDIOEXE%
for /F %%i in ('dir /b drivers\*.7z') do %SDIOEXE% -7z x drivers\%%i -y -odrivers\%%~ni
del indexes\SDI\unpacked.bin
echo -keepunpackedindex >> sdi.cfg
