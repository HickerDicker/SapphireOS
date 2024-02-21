@echo off
Echo "Reverting Network Tweaks"
:: using minsudo because of SapphireTool
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh winsock reset"
cls
Echo "Network Tweaks are Reverted"
Echo "A reboot is required"
Echo "Press any key to reboot"
pause
shutdown -r -t 01
exit