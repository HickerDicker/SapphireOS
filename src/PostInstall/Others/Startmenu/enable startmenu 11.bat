@echo off
taskkill /f /im explorer.exe
C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren %WINDIR%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.old StartMenuExperienceHost.exe
C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren %WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.old SearchHost.exe
start explorer