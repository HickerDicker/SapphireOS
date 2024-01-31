@echo off
%~d0
CD %~dp0

echo.
echo DirectX Redistributable 1-Click Installer by W1zzard @ TechPowerUp
echo https://www.techpowerup.com/download/directx-redistributable-runtime/
echo.
echo Installing runtime packages...

echo Installing DirectX Runtimes

start /wait dxsetup.exe /silent
