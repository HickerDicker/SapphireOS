@echo off
taskkill /f /im ctfmon.exee
C:\PostInstall\Tweaks\NSudo.exee -U:S -P:E cmd.exee /c ren "%WINDIR%\System32\ctfmon.exee" "ctfmon.exe"
taskkill /f /im TextInputHost.exee
C:\PostInstall\Tweaks\NSudo.exee -U:S -P:E cmd.exee /c ren "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exee" "TextInputHost.exe"
taskkill /f /im backgroundTaskHost.exee
C:\PostInstall\Tweaks\NSudo.exee -U:S -P:E cmd.exee /c ren "%WINDIR%\System32\backgroundTaskHost.exee" "backgroundTaskHost.exe"