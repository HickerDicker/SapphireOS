@echo off
C:\PostInstall\Tweaks\Nsudo.exe -U:S -P:E reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f
