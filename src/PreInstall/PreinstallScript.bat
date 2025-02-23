@Echo off 
Title SapphireOS
setlocal EnableDelayedExpansion

Echo "Execution Policy To Unrestricted"
powershell set-executionpolicy unrestricted -force >nul 2>&1
cls

Echo "Configuring "Keyboard and Mouse Settings"
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul 2>&1
cls

Echo "Reset Firewall Rules"
reg delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f && reg add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
cls

Echo "Editing POW & power tweaks"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowHibernateOption" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t Reg_DWORD /d "0" /f >nul 2>&1
powercfg -h off >nul 2>&1
wevtutil set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false >nul 2>&1
wevtutil set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false >nul 2>&1
wevtutil set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false >nul 2>&1
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

Echo "RW Fix for w11"
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
cls

Echo "Disable Sticky Keys"
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1

Echo "Disabling Process Mitigations For VM"
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -SYSTEM -Disable $v.ToString() -ErrorAction SilentlyContinue}"
for /f "tokens=3 skip=2" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do (
    set "mitigation_mask=%%a"
)
echo info: current mask - %mitigation_mask%
for /L %%a in (0,1,9) do (
    set "mitigation_mask=!mitigation_mask:%%a=2!"
)
echo info: modified mask - %mitigation_mask%
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul 2>&1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul 2>&1
for %%d in (
	fontdrvhost.exe
	dwm.exe
	lsass.exe
	svchost.exe
	WmiPrvSE.exe
	winlogon.exe
	csrss.exe
	audiodg.exe
	ntoskrnl.exe
	services.exe
) do (
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%d" /v "MitigationOptions" /t REG_BINARY /d "%mitigation_mask%" /f > NUL 2>&1
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%d" /v "MitigationAuditOptions" /t REG_BINARY /d "%mitigation_mask%" /f > NUL 2>&1
)
Echo "Backing up Services"
set BACKUP="C:\PostInstall\Services\Windows-Default-services.reg"
echo Windows Registry Editor Version 5.00 >>%BACKUP%

for /f "delims=" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services"') do (
    for /f "tokens=3" %%b in ('reg query "%%~a" /v "Start" 2^>nul') do (
        for /l %%c in (0,1,4) do (
            if "%%b"=="0x%%c" (
                echo. >>%BACKUP%
                echo [%%~a] >>%BACKUP%
                echo "Start"=dword:0000000%%c >>%BACKUP%
            ) 
        ) 
    ) 
) >nul 2>&1
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
      AxInstSV
      AarSvc
      cloudidsvc
      CldFlt
      defragsvc
      dispbrokerdesktopsvc
      diagsvc
      diagnosticshub.standardcollector.service
      dam
      ehstorclass
      ehstortcgdrv
      embeddedmode
      FontCache
      FontCache3.0.0.0
      IpxlatCfgSvc
      lfsvc
      lltdio
      luafv
      lmhosts
      MSiSCSI
      MessagingService
      mslldp
      MixedRealityOpenXRSvc
      microsoft_bluetooth_avrcptransport
      MapsBroker
      Ndu
      NetBIOS
      NetBT
      NetTcpPortSharing
      OneSyncSvc
      UsoSvc
      PcaSvc
      PimIndexMaintenanceSvc
      printworkflowusersvc
      PenService
      P9RdrService
      PNRPsvc
      p2psvc
      p2pimsvc
      PhoneSvc
      perceptionsimulation
      PeerDistSvc
      QWAVE
      QWAVEdrv
      rspndr
      rdyboost
      rdpbus
      RasAuto
      RasAcd
      RDPDR
      RdpVideominiport
      RmSvc
      RFCOMM
      SharedAccess
      SysMain
      ShellHWDetection
      SCardSvr
      ScDeviceEnum
      SCPolicySvc
      scfilter
      spectrum
      SharedRealitySvc
      spooler
      SEMgrSvc
      SSDPSRV
      storflt
      SmsRouter
      spaceport
      Themes
      TrkWks
      tzautoupdate
      troubleshootingsvc
      TapiSrv
      terminpt
      TsUsbGD
      TermService
      tcpipreg
      TsUsbFlt
      tsusbhub
      UserDataSvc
      UnistoreSvc
      udfs
      UmRdpService
      VacSvc
      Vid
      vmickvpexchange
      vmicguestinterface
      vmicshutdown
      vmicheartbeat
      vmicvmsession
      vpci
      vmicrdv
      vmictimesync
      vmicvss
      vmgid
      VSS
      W32Time
      WaaSMedicSvc
      WalletService
      wbengine
      WpnService
      WbioSrvc
      WEPHOSTSVC
      WerSvc
      wercplsupport
      WSearch
      WPDBusEnum
      wdiservicehost
      wdisystemhost
      WMPNetworkSvc
      WpcMonSvc
) do (
C:\PostInstall\Tweaks\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%z" /v "Start" /t REG_DWORD /d "4" /f"
)
pause
cls
Echo "backup again"
set BACKUP="C:\PostInstall\SapphireOS-Default-services.reg"
echo Windows Registry Editor Version 5.00 >>%BACKUP%

for /f "delims=" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services"') do (
    for /f "tokens=3" %%b in ('reg query "%%~a" /v "Start" 2^>nul') do (
        for /l %%c in (0,1,4) do (
            if "%%b"=="0x%%c" (
                echo. >>%BACKUP%
                echo [%%~a] >>%BACKUP%
                echo "Start"=dword:0000000%%c >>%BACKUP%
            ) 
        ) 
    ) 
) >nul 2>&1
cls
echo "Setting legacy photo viewer as default"
:: Credits to Zusier
for %%a in (tif tiff bmp dib gif jfif jpe jpeg jpg jxr png) do (
    %currentuser% reg add "HKCU\SOFTWARE\Classes\.%%~a" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
)

Echo "Disable Background apps"
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t Reg_DWORD /d "0" /f >nul 2>&1
cls
Echo "Optimizing Scheduled Tasks"
schtasks.exe /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Autochk\Proxy" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Diagnosis\Scheduled"
schtasks.exe /change /disable /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\DiskFootprint\StorageSense" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\International\Synchronize Language Settings" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
schtasks.exe /change /disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\UPnP\UPnPHostConfig" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Clip\License Validation" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\InstallService\SmartRetry" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Registry\RegIdleBackup" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Security\Pwdless\IntelligentPwdlessTask" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\WDI\ResolutionHost" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" 
schtasks.exe /change /disable /TN "\Microsoft\Windows\Wininet\CacheTask" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\TaskScheduler" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\WaaSMedic" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\WindowsUpdate" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Report policies" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work" 
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work"

Echo "fixing languages if needed"
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 0 /f
REG ADD HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /t REG_DWORD /d 0 /f

del /q/f/s %TEMP%\*

echo "We love Rax and everyone credited in the discord (This script is mostly taken from RaxOS [also the credits are stolen from RaxOS too lol])"

del /q/f/s %WINDIR%\TEMP\*