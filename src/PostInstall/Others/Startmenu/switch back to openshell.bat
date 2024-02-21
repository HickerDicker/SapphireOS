@echo off
taskkill /f /im explorer.exe
:: uncomment these if you want to disable startmenu small issue is it may or may not cause issues
#C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren %WINDIR%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe StartMenuExperienceHost.old
#C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren %WINDIR%\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe SearchApp.old
start /b /wait "" "C:\PostInstall\Others\Startmenu\OpenShellSetup_4_4_191.exe" >nul 2>&1
start explorer