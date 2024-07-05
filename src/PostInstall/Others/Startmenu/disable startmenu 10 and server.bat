@echo off
taskkill /f /im explorer.exe
C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren %WINDIR%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe StartMenuExperienceHost.old
C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren %WINDIR%\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe SearchApp.old
start explorer