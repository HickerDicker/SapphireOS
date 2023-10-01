@echo off
title SapphireTool

if not exist "C:\SapphireTool\Downloads" mkdir "C:\SapphireTool\Downloads"

:menu
cls
echo [1] Firefox
echo [2] Chrome
echo [3] Brave
echo [4] OperaGX
echo [5] Opera
echo [6] Steam
echo [7] Discord
echo [8] Vencord(installer)
echo [9] Exit
echo leave suggestions in the discord for what I should add in the next version of this

set /p choice=Enter your choice: 

if "%choice%"=="1" (
    echo You selected Firefox
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US', 'C:\SapphireTool\Downloads\Firefox.exe')"
    C:\SapphireTool\Downloads\Firefox.exe
    start "" "C:\Program Files (x86)\Mozilla Maintenance Service\Uninstall.exe" >nul 2>&1
    :: wmic product where name="Mozilla Maintenance Service" call uninstall /nointeractive >nul 2>&1
    del "C:\Program Files\Mozilla Firefox\crashreporter.exe" /f /q >nul 2>&1
    del "C:\Program Files\Mozilla Firefox\crashreporter.ini" /f /q >nul 2>&1
    del "C:\Program Files\Mozilla Firefox\maintenanceservice.exe" /f /q >nul 2>&1
    del "C:\Program Files\Mozilla Firefox\maintenanceservice_installer.exe" /f /q >nul 2>&1
    del "C:\Program Files\Mozilla Firefox\minidump-analyzer.exe" /f /q >nul 2>&1
    del "C:\Program Files\Mozilla Firefox\pingsender.exe" /f /q >nul 2>&1
    del "C:\Program Files\Mozilla Firefox\updater.exe" /f /q >nul 2>&1
) else if "%choice%"=="2" (
    echo You selected Chrome
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://dl.google.com/chrome/install/chrome_installer.exe', 'C:\SapphireTool\Downloads\Chrome.exe')"
    C:\SapphireTool\Downloads\Chrome.exe
    taskkill /f /im "GoogleUpdateSetup.exe" >nul 2>&1
    taskkill /f /im "GoogleCrashHandler.exe" >nul 2>&1
    taskkill /f /im "GoogleCrashHandler64.exe" >nul 2>&1
    taskkill /f /im "GoogleUpdateBroker.exe" >nul 2>&1
    taskkill /f /im "GoogleUpdateCore.exe" >nul 2>&1
    taskkill /f /im "GoogleUpdateOnDemand.exe" >nul 2>&1
    taskkill /f /im "GoogleUpdateComRegisterShell64.exe" >nul 2>&1
    sc delete gupdate >nul 2>&1
    sc delete gupdatem >nul 2>&1
    sc delete googlechromeelevationservice >nul 2>&1
    rmdir /s /q "C:\Program Files (x86)\Google\Update" >nul 2>&1
    rmdir /s /q "C:\Program Files\Google\GoogleUpdater" >nul 2>&1
) else if "%choice%"=="3" (
    echo You selected Brave
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://laptop-updates.brave.com/latest/winx64', 'C:\SapphireTool\Downloads\Brave.exe')"
    C:\SapphireTool\Downloads\Brave.exe
    taskkill /f /im "BraveUpdate.exe" >nul 2>&1
    taskkill /f /im "brave_installer-x64.exe" >nul 2>&1
    taskkill /f /im "BraveCrashHandler.exe" >nul 2>&1
    taskkill /f /im "BraveCrashHandler64.exe" >nul 2>&1
    taskkill /f /im "BraveCrashHandlerArm64.exe" >nul 2>&1
    taskkill /f /im "BraveUpdateBroker.exe" >nul 2>&1
    taskkill /f /im "BraveUpdateCore.exe" >nul 2>&1
    taskkill /f /im "BraveUpdateOnDemand.exe" >nul 2>&1
    taskkill /f /im "BraveUpdateSetup.exe" >nul 2>&1
    taskkill /f /im "BraveUpdateComRegisterShell64" >nul 2>&1
    taskkill /f /im "BraveUpdateComRegisterShellArm64" >nul 2>&1
    sc delete brave >nul 2>&1
    sc delete bravem >nul 2>&1
    sc delete BraveElevationService >nul 2>&1
    sc delete BraveVpnService >nul 2>&1
    rmdir /s /q "C:\Program Files (x86)\BraveSoftware\Update" >nul 2>&1
) else if "%choice%"=="4" (
    echo You selected OperaGX
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://net.geo.opera.com/opera_gx/stable/windows?utm_tryagain=yes&utm_source=google&utm_medium=ose&utm_campaign=(none)&http_referrer=https%3A%2F%2Fwww.google.com%2F&utm_site=opera_com&&utm_lastpage=opera.com/', 'C:\SapphireTool\Downloads\OperaGX.exe')"
    C:\SapphireTool\Downloads\OperaGX.exe
) else if "%choice%"=="5" (
    echo You selected Opera
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://net.geo.opera.com/opera/stable/windows?utm_tryagain=yes&utm_source=google&utm_medium=ose&utm_campaign=(none)&http_referrer=https%3A%2F%2Fwww.google.com%2F&utm_site=opera_com&&utm_lastpage=opera.com/', 'C:\SapphireTool\Downloads\Opera.exe')"
    C:\SapphireTool\Downloads\Opera.exe
) else if "%choice%"=="6" (
    echo You selected Steam
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe', 'C:\SapphireTool\Downloads\SteamSetup.exe')"
    C:\SapphireTool\Downloads\SteamSetup.exe
) else if "%choice%"=="7" (
    echo You selected Discord
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x86', 'C:\SapphireTool\Downloads\DiscordSetup.exe')"
    C:\SapphireTool\Downloads\DiscordSetup.exe
) else if "%choice%"=="8" (
    echo You selected Vencord
    powershell -Command ""C:\PostInstall\Browsers\Vencord.ps1""
) else if "%choice%"=="9" (
    echo Exiting...
    goto :eof
) else (
    echo Invalid choice. Please select a valid option.
    pause
    goto menu
)
goto menu

:end