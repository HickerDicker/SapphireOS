@ECHO OFF
::***********************************************************************************
::
:: Keep SDIO.exe updated with the latest drivers and version of SDIO_Rnnn.exe
::
:: Place this batch file in the same directory as the SDIO_*.exe files
::
::***********************************************************************************
::
::SET SDIOPath to location of batch file
SET SDIOPath=%~dp0
PUSHD %SDIOPath%
::Get the newest SDIO_Rnnn.exe file
FOR /F "delims=|" %%I IN ('DIR "SDIO_R*.exe" /B /O:D') DO SET NewestSDIO=%%I
:: Run SDIO update
CALL %NewestSDIO% /autoupdate /autoclose
::Make sure we still have most current executables in case one was just downloaded
FOR /F "delims=|" %%I IN ('DIR "SDIO_R*.exe" /B /O:D') DO SET NewestSDIO=%%I
::Copy current version to SDIO.exe
COPY %NewestSDIO% SDIO.exe /Y
::Same for x64 version
FOR /F "delims=|" %%I IN ('DIR "SDIO_x64_R*.exe" /B /O:D') DO SET NewestSDIO=%%I
::Copy current version to SDIO.exe
COPY %NewestSDIO% SDIO_x64.exe /Y
POPD