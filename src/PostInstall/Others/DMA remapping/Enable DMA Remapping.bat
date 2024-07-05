@echo off
Echo "Disabling DMA Remapping"
for %%a in (DmaRemappingCompatible) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "1" /f >nul 2>&1
cls
Echo "DMA Remapping is enabled"
Echo "A reboot is required"
Echo "Press any key to reboot"
pause
shutdown -r -t 01
exit