@echo off
bcdedit /set {current} nx optin
echo "DEP/NX has been set to optin press any key to reboot or close the tab to reboot later"
pause
shutdown -r -t 00