@echo off
Echo "Reverting Network Tweaks"
:: using minsudo because of SapphireTool
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set global dca=enabled"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set global netdma=enabled"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh interface isatap set state disabled"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set global timestamps=disabled"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set global rss=enabled"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set global nonsackrttresiliency=disabled"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set global initialRto=2000"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set supplemental template=custom icw=10"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh interface ip set interface ethernet currenthoplimit=64"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int ip set global taskoffload=enabled"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "netsh int tcp set global rss=enabled"
cls
Echo "Network Tweaks are Reapplied"
Echo "A reboot is required"
Echo "Press any key to reboot"
pause
shutdown -r -t 01
exit