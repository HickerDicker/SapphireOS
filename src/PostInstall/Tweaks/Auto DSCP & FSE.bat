<# :
@echo off
setlocal

:START
cls
echo RUN THIS SCRIPT AFTER YOU HAVE INSTALLED YOUR GAMES.

:SETPROFILENAME
echo.
echo Example: Fortnite, Valorant, CSGO, COD, Overwatch, Rocket league,
echo.
set /p PROFILENAME="Enter a profile name for the QoS policy : "

echo %PROFILENAME%|findstr /r "[^0-9]" > nul
if errorlevel 1 cls & goto SETAPPLICATIONPATH
echo %PROFILENAME%|findstr /r "[^a-zA-Z]" > nul
if errorlevel 1 cls & goto SETAPPLICATIONPATH
echo %PROFILENAME%|findstr /r "[^0-9a-zA-Z]" > nul
if errorlevel 1 (actionZ) else goto badappname 

:badappname
cls
echo Invalid input. Only alphanumeric characters can be accepted.
goto SETPROFILENAME

:SETAPPLICATIONPATH
echo Select the main game exe you would like to assign to the profile : %PROFILENAME%
for /f "delims=" %%I in ('powershell -noprofile "iex (${%~f0} | out-string)"') do set application=%%I

for %%a in (%application%) do if /i "%%~xa"==".exe" goto DSCP
for %%a in (%application%) do if /i not "%%~xa"==".exe" goto invalid

:invalid
cls
echo Invalid input. Make sure the application name ends in .exe
goto SETAPPLICATIONPATH

:DSCP
cls
echo Setting DSCP to 46 for a game exe will allow packets of the application to
echo be prioritized over other packets on your network or even apps running on your own PC.
echo.
echo Are you sure you want to prioritize packets for:
echo.
echo 	%application%? 
echo.
echo [1] Yes
echo. 
echo [2] No 
echo.
echo [3] Choose exe again
echo.
choice /c:123 /n > NUL 2>&1
if errorlevel 3 cls & goto SETAPPLICATIONPATH
if errorlevel 2 cls & goto FSE
if errorlevel 1 cls & goto DSCPYES

:DSCPYES
cls
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Version" /t REG_SZ /d "1.0" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Application Name" /t REG_SZ /d "%application%" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Protocol" /t REG_SZ /d "*" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Local Port" /t REG_SZ /d "*" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Local IP" /t REG_SZ /d "*" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Remote Port" /t REG_SZ /d "*" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Remote IP" /t REG_SZ /d "*" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "DSCP Value" /t REG_SZ /d "46" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%PROFILENAME%" /v "Throttle Rate" /t REG_SZ /d "-1" /f > NUL 2>&1
cls

:FSE
cls
echo Would you like to enable exclusive fullscreen for:
echo.
echo 	%application%?
echo.
echo [1] Yes (recommended)
echo. 
echo [2] No 
echo.
choice /c:12 /n > NUL 2>&1
if errorlevel 2 goto FSENO
if errorlevel 1 goto FSEYES

:FSEYES
cls
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%application%" /t REG_SZ /d "~ DISABLEDXMAXIMIZEDWINDOWEDMODE HIGHDPIAWARE" /f > NUL 2>&1
cls

:FSENO
cls
:: DOES NOT AFFECT DESKTOP PERFORMANCE, HERE FOR LAPTOPS BUT IT DOES NOT HURT TO ADD IT TO DESKTOP SYSTEMS
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "%application%" /t REG_SZ /d "GpuPreference=2;" /f > NUL 2>&1
cls
echo Would you like to add another game exe?
echo.
echo [1] Yes
echo. 
echo [2] No 
echo.
choice /c:12 /n > NUL 2>&1
if errorlevel 2 goto EXIT
if errorlevel 1 goto START

:EXIT
cls
echo You can add another game later if you keep this script safe.
pause
exit /b

goto :EOF
PS #>

Add-Type -AssemblyName System.Windows.Forms
$f = new-object Windows.Forms.OpenFileDialog
$f.InitialDirectory = pwd
$f.Filter = "Image Files (*.exe)|*.exe|All Files (*.*)|*.*"
$f.ShowHelp = $true
$f.Multiselect = $true
[void]$f.ShowDialog()
if ($f.Multiselect) { $f.FileNames } else { $f.FileName }