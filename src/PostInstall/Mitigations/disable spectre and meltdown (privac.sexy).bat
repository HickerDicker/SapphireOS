@echo off
:: https://privacy.sexy — v0.11.4 — Fri, 21 Jul 2023 08:04:42 GMT
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)


:: ----------------------------------------------------------
:: -----Spectre variant 2 and meltdown (own OS) (revert)-----
:: ----------------------------------------------------------
echo --- Spectre variant 2 and meltdown (own OS) (revert)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Spectre variant 2 and meltdown (HyperV) (revert)-----
:: ----------------------------------------------------------
echo --- Spectre variant 2 and meltdown (HyperV) (revert)
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /f
:: ----------------------------------------------------------


pause
exit /b 0