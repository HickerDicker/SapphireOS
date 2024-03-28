@Echo off 
Title SapphireOS
setlocal EnableDelayedExpansion

Echo Setting "Execution Policy To Unrestricted"
powershell set-executionpolicy unrestricted -force >nul 2>&1
cls

Echo Configuring "Keyboard and Mouse Settings"
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul 2>&1
cls

Echo "Editing Bcdedit"
label C: SapphireOS
bcdedit /set {current} description "SapphireOS 10"
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

Echo "editing POW & power tweaks"
powercfg -import "C:\PostInstall\PreInstall\SapphireOS.pow" 00000000-0000-0000-0000-000000000000 >nul 2>&1
powercfg /setactive 00000000-0000-0000-0000-000000000000 >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowHibernateOption" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t Reg_DWORD /d "0" /f >nul 2>&1
powercfg /hibernate off >nul 2>&1
powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318584 100 >nul 2>&1
wevtutil set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false >nul 2>&1
wevtutil set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false >nul 2>&1
wevtutil set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false >nul 2>&1
cls

echo "Setting legacy photo viewer as default"
:: Credits to Zusier
for %%a in (tif tiff bmp dib gif jfif jpe jpeg jpg jxr png) do (
    %currentuser% reg add "HKCU\SOFTWARE\Classes\.%%~a" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
)

Echo "Disable Sticky Keys"
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1
cls

Echo "Changing fsutil behaviors"
fsutil behavior set disable8dot3 1 > NUL 2>&1
fsutil behavior set disablelastaccess 1 > NUL 2>&1
Fsutil behavior set memoryusage 2 
cls

Echo "Disable Driver PowerSaving"
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"
cls

Echo "Set svchost to ffffffff works best for all RAM size"
Reg add HKLM\SYSTEM\CurrentControlSet\Control /t REG_DWORD /v SvcHostSplitThresholdInKB /d 0xffffffff /f >nul 2>&1
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
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v "InactivityShutdownDelay" /t REG_DWORD /d "4294967295" /f
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
        fvevol
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
        LanmanWorkstation
	LanmanServer
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

Echo "fixing languages if needed"
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /t REG_DWORD /d 0 /f >nul 2>&1
cls

del /q/f/s %TEMP%\*

echo "We love Rax and everyone credited in the discord (This script is mostly taken from RaxOS [also the credits are stolen from RaxOS too lol])"

del /q/f/s %WINDIR%\TEMP\*

Exit