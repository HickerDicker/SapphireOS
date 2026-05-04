@echo off
taskkill /f /im ctfmon.exe
C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren "%WINDIR%\System32\ctfmon.exee" "ctfmon.exe"
taskkill /f /im TextInputHost.exe
C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exee" "TextInputHost.exe"
taskkill /f /im backgroundTaskHost.exe
C:\PostInstall\Tweaks\NSudo.exe -U:S -P:E cmd.exe /c ren "%WINDIR%\System32\backgroundTaskHost.exee" "backgroundTaskHost.exe"