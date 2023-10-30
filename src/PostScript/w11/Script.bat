@Echo off 
Title SapphireOS 
setlocal EnableDelayedExpansion

Echo Setting "Execution Policy To Unrestricted"
powershell set-executionpolicy unrestricted -force >nul 2>&1
cls

Echo "Installing LowAudioLatency"
start /b /wait "" "%WINDIR%\Temp\LowAudioLatency_2.0.0.0.msi" /passive >nul 2>&1
cls

Echo Configuring "Keyboard and Mouse Settings"
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul 2>&1
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

Echo "Visual Effects"
Reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Blur" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Animations" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMA_TRANSITTIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f > NUL 2>&1
cls

Echo "Editing Bcdedit"
bcdedit /set {current} nx optin
label C: SapphireOS 11
bcdedit /set {current} description "SapphireOS 11"
bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
bcdedit /deletevalue useplatformclock
bcdedit /set bootux disabled
bcdedit /set bootmenupolicy legacy
bcdedit /set hypervisorlaunchtype off
bcdedit /set quietboot yes
bcdedit /set debug No
bcdedit /set ems No
bcdedit /set bootems No
bcdedit /set vm No
bcdedit /set sos No
bcdedit /set integrityservices disable
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000068 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {current} recoveryenabled no
bcdedit /timeout 10
cls

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
reg delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f && reg add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f
cls

Echo "editing POW & power tweaks"
: : thanks to Amit
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg /delete a1841308-3541-4fab-bc81-f71556f20b4a
powercfg -import "%WINDIR%\Temp\SapphireOS.pow" 00000000-0000-0000-0000-000000000000
powercfg /setactive 00000000-0000-0000-0000-000000000000
powercfg -h off
powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /setacvalueindex scheme_current 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg /setactive scheme_current
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t Reg_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t Reg_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t Reg_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t Reg_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t Reg_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowHibernateOption" /t Reg_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t Reg_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t Reg_DWORD /d "0" /f
wevtutil set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false
wevtutil set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false
wevtutil set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false
cls

Echo "Disabling Device Manager Devices"
devmanview /disable "Microsoft Device Association Root Enumerator" > NUL 2>&1
devmanview /disable "High precision event timer" > NUL 2>&1
devmanview /disable "System Speaker" > NUL 2>&1
devmanview /disable "Microsoft Radio Device Enumeration Bus" > NUL 2>&1
devmanview /disable "PCI Encryption/Decryption Controller" > NUL 2>&1
devmanview /disable "AMD PSP" > NUL 2>&1
devmanview /disable "Intel SMBus" > NUL 2>&1
devmanview /disable "Intel Management Engine" > NUL 2>&1
devmanview /disable "PCI Memory Controller" > NUL 2>&1
devmanview /disable "PCI standard RAM Controller" > NUL 2>&1
devmanview /disable "System Timer" > NUL 2>&1
devmanview /disable "WAN Miniport (IKEv2)" > NUL 2>&1
devmanview /disable "WAN Miniport (IP)" > NUL 2>&1
devmanview /disable "WAN Miniport (IPv6)" > NUL 2>&1
devmanview /disable "WAN Miniport (L2TP)" > NUL 2>&1
devmanview /disable "WAN Miniport (Network Monitor)" > NUL 2>&1
devmanview /disable "WAN Miniport (PPPOE)" > NUL 2>&1
devmanview /disable "WAN Miniport (PPTP)" > NUL 2>&1
devmanview /disable "WAN Miniport (SSTP)" > NUL 2>&1
devmanview /disable "Programmable Interrupt Controller" > NUL 2>&1
devmanview /disable "Numeric Data Processor" > NUL 2>&1
devmanview /disable "Communications Port (COM1)" > NUL 2>&1
devmanview /disable "Microsoft RRAS Root Enumerator" > NUL 2>&1
devmanview /disable "Micosoft GS Wavetable Synth" > NUL 2>&1
cls

Echo "Changing fsutil behaviors"
:: Thanks to AMITXV
fsutil behavior set allowextchar 0 > NUL 2>&1
fsutil behavior set Bugcheckoncorrupt 0 > NUL 2>&1
fsutil repair set C: 0 > NUL 2>&1
fsutil behavior set disable8dot3 1 > NUL 2>&1
fsutil behavior set disablecompression 1 > NUL 2>&1
fsutil behavior set disableencryption 1 > NUL 2>&1
fsutil behavior set disablelastaccess 1 > NUL 2>&1
fsutil behavior set disablespotcorruptionhandling 1 > NUL 2>&1
fsutil behavior set encryptpagingfile 0 > NUL 2>&1
fsutil behavior set quotanotify 86400 > NUL 2>&1
fsutil behavior set symlinkevaluation L2L:1 > NUL 2>&1
fsutil behavior set disabledeletenotify 0 > NUL 2>&1
cls

Echo "Disable Driver PowerSaving"
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"
cls

Echo "Set svchost to ffffffff works best for all RAM size"
Reg add HKLM\SYSTEM\CurrentControlSet\Control /t REG_DWORD /v SvcHostSplitThresholdInKB /d 0xffffffff /f
cls

Echo "Enabling MSI mode & set to undefined"
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
:: Probably will be reset by installing GPU driver
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
cls

Echo "Remove Share from context menu"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f > nul
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f > nul
cls

Echo "Remove Restore Previous Versions from context menu"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{596AB062-B4D2-4215-9F74-E9109B0A8153}" /t REG_SZ /d "" /f >nul 2>&1
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{596AB062-B4D2-4215-9F74-E9109B0A8153}" /t REG_SZ /d "" /f >nul 2>&1
cls

Echo "Disabling DMA Remapping"
for %%a in (DmaRemappingCompatible) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo "Disabling HIPM, DIPM and HDDParking"
for %%a in (EnableHIPM EnableDIPM EnableHDDParking) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo "Disabling StorPort Idle"
for /f "tokens=*" %%s in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" ^| findstr /e "StorPort"') do Reg.exe add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo "Remove Troubleshoot Compability from context menu"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f > nul
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f > nul
cls

Echo "Disable Background apps"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t Reg_DWORD /d "0" /f >nul 2>&1
cls

Echo "Enabling FSE"
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f >nul 2>&1
cls

Echo "RW Fix for w11"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
cls

Echo "Disabling Drivers and Services"
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v "InactivityShutdownDelay" /t REG_DWORD /d "4294967295" /f
for %%z in (
	AppVClient
	AJRouter
	AppIDSvc
	DiagTrack
      DsmSvc
	DialogBlockingService
	Diagsvc
      autotimesvc
      W32Time
	diagnosticshub.standardcollector.service
	DPS
      DsSvc
	DusmSvc
	FontCache
	FontCache3.0.0.0
	MsKeyboardFilter
      icssvc
      IKEEXT
	PcaSvc
	ShellHWDetection
	SysMain
	Themes
	TrkWks
	tzautoupdate
	OneSyncSvc
	WdiSystemHost
	WdiServiceHost
	SensorDataService
	SensrSvc
      SensorService
	Beep
	cdfs
	cdrom
      acpiex
      acpipagr
      acpipmi
      acpitime
	cnghwassist
	GpuEnergyDrv
	Telemetry
	VerifierExt
	udfs
	MsLldp
	lltdio
	NdisVirtualBus
	NDU
      luafv
      UsoSvc
      cbdhsvc
      BcastDVRUserService
	rdyboost
      rdpbus
      umbus
      vdrvroot
      Vid
      CompositeBus
	rspndr
	NdisCap
	NetBIOS
	NetBT
	KSecPkg
	spaceport
      VaultSvc
      EventSystem
	storqosflt
	bam
	bowser
      WarpJITSvc
      Wecsvc
      dmwappushservice
      GraphicsPerfSvc
      WMPNetworkSvc
      TermService
      UmRdpService
      UnistoreSvc
      PimIndexMaintenanceSvc
      UserDataSvc
      3ware
      arcsas
      buttonconverter
      cdfs
      circlass
      Dfsc
      ErrDev
      mrxsmb
      mrxsmb20
      PEAUTH
      QWAVEdrv
      srv
      SiSRaid2
      SiSRaid4
      Tcpip6
      tcpipreg
      vsmraid
      VSTXRAID
      wcnfs
      WindowsTrustedRTProxy
      SstpSvc
      SSDPSRV
      SmsRouter
	CldFlt
      DisplayEnhancementService
	iphlpsvc
      IpxlatCfgSvc
      NetTcpPortSharing
      KtmRm
	lmhosts
      MSDTC
      QWAVE
	RmSvc
	RFCOMM
	BthEnum
	bthleenum
	BTHMODEM
	BthA2dp
	microsoft_bluetooth_avrcptransport
	BthHFEnum
	BTAGService
	bthserv
	BluetoothUserService
	BthAvctpSvc
	vmickvpexchange
	vmicguestinterface
	vmicshutdown
	vmicheartbeat
	vmicvmsession
      vpci
      TsUsbFlt
      tsusbhub
      storflt
      RDPDR
      RdpVideominiport
      bttflt
      HidBth
      BthMini
      BTHPORT
      BTHUSB
	vmicrdv
	vmictimesync
	vmicvss
	hyperkbd
	hypervideo
	gencounter
	vmgid
	storflt
	hvservice
	hvcrash
	HvHost
	lfsvc
) do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%z" /v "Start" /t REG_DWORD /d "4" /f
)
cls

Echo "Disabling Intel Drivers on Amd Systems And Vice Versa
for /F "tokens=* skip=1" %%n in ('wmic cpu get Manufacturer ^| findstr "."') do set CPUManufacturer=%%n
if %CPUManufacturer% EQU AuthenticAMD (
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iagpio" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iai2c" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_GPIO2" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_GPIO2_BXT_P" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_I2C" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaLPSS2i_I2C_BXT_P" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaLPSSi_GPIO" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaLPSSi_I2C" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaStorAVC" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\iaStorV" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\intelide" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\intelpep" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\intelppm" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
)

if %CPUManufacturer% EQU GenuineIntel (
	  reg.exe add "HKLM\System\CurrentControlSet\Services\AmdK8" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\AmdPPM" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\amdsata" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\amdsbs" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
	  reg.exe add "HKLM\System\CurrentControlSet\Services\amdxata" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
)
cls

Echo "Fix explorer white bar bug"
cmd /c "start C:\Windows\explorer.exe"
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
cmd /c "start C:\Windows\explorer.exe"
cls

REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 0 /f

REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm" /v "Start" /t REG_DWORD /d "2" /f

Echo "Attempting To Disable MemoryCompression"

PowerShell Get-MMAgent

PowerShell Disable-MMAgent -MemoryCompression

del /q/f/s %TEMP%\*

echo "We love Rax and everyone credited in the discord (This script is mostly taken from RaxOS [also the credits are stolen from RaxOS too lol])"

shutdown -r -t 05

del /q/f/s %WINDIR%\TEMP\*

start /b "" cmd /c del "%~f0"&exit /b

Exit