@Echo off 
Title SapphireOS 
setlocal EnableDelayedExpansion

Echo Setting "Execution Policy To Unrestricted"
powershell set-executionpolicy unrestricted -force >nul 2>&1
cls

Echo "Opting Out Of PowerShell Telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1 >nul 2>&1
cls

Echo "Disabling Process Mitigations"
::  Thanks AMIT
call %WINDIR%\Modules\disable-process-mitigations.bat >nul 2>&1
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
bcdedit /set hypervisorlaunchtype off
bcdedit /set integrityservices disable
bcdedit /set isolatedcontext No
bcdedit /set loadoptions DISABLE-LSA-ISO,DISABLE-VBS
bcdedit /set vsmlaunchtype Off
bcdedit /set vm no
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
	Echo "Disabling powersaving features"
	for %%a in (
	EnhancedPowerManagementEnabled
	AllowIdleIrpInD3
	EnableSelectiveSuspend
	DeviceSelectiveSuspended
	SelectiveSuspendEnabled
	SelectiveSuspendOn
	WaitWakeEnabled
	D3ColdSupported
	WdfDirectedPowerTransitionEnable
	EnableIdlePowerManagement
	IdleInWorkingState
	) do for /f "delims=" %%b in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f > NUL 2>&1
    cls
)

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
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "ren C:\Windows\System32\mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.old" >nul 2>&1
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "ren C:\Windows\System32\mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.old" >nul 2>&1
cls

Echo "Network Tweaks"
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh interface isatap set state disabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global rss=enabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global initialRto=2000
netsh int tcp set supplemental template=custom icw=10
netsh interface ip set interface ethernet currenthoplimit=64
netsh int ip set global taskoffload=enabled
cls

Echo "Tweak NIC"
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "*SpeedDuplex" /s ^| findstr "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "*DeviceSleepOnDisconnect" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*FlowControl" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*IPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*InterruptModeration" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*InterruptModeration" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*LsoV2IPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*LsoV2IPv4" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*LsoV2IPv6" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*LsoV2IPv6" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*NumRssQueues" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*NumRssQueues" /t REG_SZ /d "2" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*PMARPOffload" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*PMARPOffload" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*PMNSOffload" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*PMNSOffload" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*PriorityVLANTag" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*PriorityVLANTag" /t REG_SZ /d "1" /f >nul 2>&1  
    )
    for /f %%i in ('reg query "%%a" /v "*RSS" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*RSS" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnMagicPacket" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnPattern" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*ReceiveBuffers" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*ReceiveBuffers" /t REG_SZ /d "2048" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*TransmitBuffers" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*TransmitBuffers" /t REG_SZ /d "2048" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "DMACoalescing" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "DMACoalescing" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EEELinkAdvertisement" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "EeePhyEnable" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EeePhyEnable" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ITR" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ITR" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "PowerDownPll" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PowerDownPll" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WaitAutoNegComplete" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WaitAutoNegComplete" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnLink" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnLink" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "WakeOnSlot" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnSlot" /t REG_SZ /d "0" /f >nul 2>&1
    )
	    for /f %%i in ('reg query "%%a" /v "WakeUpModeCap" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeUpModeCap" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "AdvancedEEE" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "AdvancedEEE" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "GigaLite" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "PnPCapabilities" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PnPCapabilities" /t REG_DWORD /d "24" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PowerSavingMode" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "S5WakeOnLan" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "SavePowerNowEnabled" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "SavePowerNowEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
	    for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ULPMode" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WolShutdownLinkSpeed" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "LogLinkStateEvent" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "LogLinkStateEvent" /t REG_SZ /d "16" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnMagicPacketFromS5" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnMagicPacketFromS5" /t REG_SZ /d "0" /f >nul 2>&1   
	)
	for /f %%i in ('reg query "%%a" /v "Ultra Low Power Mode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Ultra Low Power Mode" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "System Idle Power Saver" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "System Idle Power Saver" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "Selective Suspend" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Selective Suspend" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "Selective Suspend Idle Timeout" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Selective Suspend Idle Timeout" /t REG_SZ /d "60" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "Link Speed Battery Saver" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Link Speed Battery Saver" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*SelectiveSuspend" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*SelectiveSuspend" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnablePME" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "TxIntDelay" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "TxIntDelay" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "TxDelay" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "TxDelay" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnableModernStandby" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableModernStandby" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*ModernStandbyWoLMagicPacket" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnableLLI" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableLLI" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*SSIdleTimeout" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*SSIdleTimeout" /t REG_SZ /d "60" /f >nul 2>&1   
    )
) >nul 2>&1
cls
powershell disable-netadapterbinding -name "*" -componentid vmware_bridge, ms_lldp, ms_lltdio, ms_implat, ms_tcpip6, ms_rspndr, ms_server, ms_msclient
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
:: Fix VMware
wmic computersystem get manufacturer /format:value | findstr /i /C:VMWare && (
    for /f %%a in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
        reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "2"  /f > nul 2>nul
    )
)
cls

Echo "Disabling DMA Remapping"
for %%a in (DmaRemappingCompatible) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo Disabling HIPM, DIPM and HDDParking
for %%a in (EnableHIPM EnableDIPM EnableHDDParking) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo Disabling StorPort Idle
for /f "tokens=*" %%s in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" ^| findstr /e "StorPort"') do Reg.exe add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo "Disable Background apps"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t Reg_DWORD /d "0" /f >nul 2>&1
cls

Echo "fixing languages if needed"
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 0 /f > NUL 2>&1
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /t REG_DWORD /d 0 /f > NUL 2>&1
cls

Echo "Attempting To Disable MemoryCompression"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "PowerShell Get-MMAgent"
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "PowerShell Disable-MMAgent -MemoryCompression"
cls

shutdown -r -t 60 
msg * your pc will restart in 60 seconds from now you can run shutdown -a to cancel it if you have to install any drivers or want to set up your pc BUT DO NOT FORGET TO RESTART

Echo "Cleanup"

del /q /f /s %WINDIR%\TEMP\* >nul 2>&1
del /q /f /s %TEMP%\* >nul 2>&1
del /q /f /s %WINDIR%\MODULES\* >nul 2>&1

start /b "" cmd /c del "%~f0"&exit /b

Exit