@Echo off 
Title SapphireOS 
setlocal EnableDelayedExpansion

Echo Setting "Execution Policy To Unrestricted"
powershell set-executionpolicy unrestricted -force >nul 2>&1
cls

Echo "Disabling Process Mitigations"
::  Thanks AMIT
call %WINDIR%\TEMP\disable-process-mitigations.bat >nul 2>&1
cls

Echo "Disabling Write Cache Buffer"
	for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg.exe add "%%a\Device Parameters\Disk" /v "CacheIsPowerProtected" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
	for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg.exe add "%%a\Device Parameters\Disk" /v "UserWriteCacheSetting" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
)
cls

Echo "Editing Bcdedit"
label C: SapphireOS
bcdedit /set {current} description "SapphireOS Server"
bcdedit /set {current} nx AlwaysOff
bcdedit /set disabledynamictick yes
bcdedit /deletevalue useplatformclock
bcdedit /set bootmenupolicy legacy
bcdedit /set integrityservices disable
bcdedit /set isolatedcontext No
bcdedit /timeout 3
cls

Echo "Disabling power throttling and setting the powerplan to SapphireOS Powerplan on desktops and enabling it along with setting the balanced powerplan on laptops"

for /f "delims=:{}" %%a in ('wmic path Win32_SystemEnclosure get ChassisTypes ^| findstr [0-9]') do set "CHASSIS=%%a"
set "DEVICE_TYPE=PC"
for %%a in (8 9 10 11 12 13 14 18 21 30 31 32) do if "%CHASSIS%" == "%%a" (set "DEVICE_TYPE=LAPTOP")

if "%DEVICE_TYPE%" == "LAPTOP" (
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serenum" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serial" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiacpi" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f >nul 2>&1
    powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e >nul 2>&1
	cls
)
) else (
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiacpi" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
    cls
)

Echo "Disabling network adapters"
powershell -NoProfile -Command "Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6, ms_msclient, ms_server, ms_rspndr, ms_lltdio, ms_implat, ms_lldp" >nul 2>&1
cls

Echo "Disabling NetBIOS over TCP/IP"
for /f "delims=" %%u in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr "HKEY"') do (
    reg add "%%u" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
)
cls

Echo "Disabling Exclusive Mode On Audio Devices"
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo "Reset Firewall Rules"
reg delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f && reg add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
cls

Echo "Removing leftover devices"
C:\PostInstall\Tweaks\DeviceCleanupCmd.exe * -s >nul 2>&1
cls

Echo "Renaming Microcode Updates"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "ren mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.old" >nul 2>&1
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "ren mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.old" >nul 2>&1

Echo "Network Tweaks"
netsh int tcp set heuristics disabled >nul 2>&1
netsh int tcp set supplemental Internet congestionprovider=ctcp >nul 2>&1
netsh int tcp set global timestamps=disabled >nul 2>&1
netsh int tcp set global rsc=disabled >nul 2>&1
netsh int ip set global taskoffload=enabled >nul 2>&1
netsh int tcp set global rss=enabled >nul 2>&1
cls

Echo "Disabling Device Manager Devices"
C:\PostInstall\Tweaks\DevManView.exe /disable "Microsoft Device Association Root Enumerator" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "High precision event timer" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "System Speaker" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Microsoft Radio Device Enumeration Bus" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "PCI Encryption/Decryption Controller" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "AMD PSP" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Intel SMBus" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Intel Management Engine" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "PCI Memory Controller" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "PCI standard RAM Controller" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "System Timer" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (IKEv2)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (IP)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (IPv6)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (L2TP)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (Network Monitor)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (PPPOE)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (PPTP)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "WAN Miniport (SSTP)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Programmable Interrupt Controller" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Numeric Data Processor" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Communications Port (COM1)" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Microsoft RRAS Root Enumerator" > NUL 2>&1
C:\PostInstall\Tweaks\DevManView.exe /disable "Micosoft GS Wavetable Synth" > NUL 2>&1
cls

Echo "Changing fsutil behaviors"
fsutil behavior set disable8dot3 1 > NUL 2>&1
fsutil behavior set disablelastaccess 1 > NUL 2>&1
Fsutil behavior set memoryusage 2 > NUL 2>&1
cls

Echo "Disable Driver PowerSaving"
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"
cls

Echo "Enabling MSI mode & set to undefined"
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
cls

Echo "Disabling DMA Remapping"
for %%a in (DmaRemappingCompatible) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo "Disable Background apps"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t Reg_DWORD /d "0" /f >nul 2>&1
cls

Echo "fixing languages if needed"
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 0 /f > NUL 2>&1
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /t REG_DWORD /d 0 /f > NUL 2>&1

Echo "Set svchost to ffffffff works best for all RAM size"
Reg add HKLM\SYSTEM\CurrentControlSet\Control /t REG_DWORD /v SvcHostSplitThresholdInKB /d 0xffffffff /f >nul 2>&1
cls

Echo "Attempting To Disable MemoryCompression"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "PowerShell Get-MMAgent"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "PowerShell Disable-MMAgent -MemoryCompression"
cls

del /q/f/s %TEMP%\* >nul 2>&1

shutdown -r -t 60 
msg * your pc will restart in 60 seconds from now you can run shutdown -a to cancel it if you have to install any drivers or want to set up your pc BUT DO NOT FORGET TO RESTART

del /q/f/s %WINDIR%\TEMP\* >nul 2>&1

start /b "" cmd /c del "%~f0"&exit /b

Exit