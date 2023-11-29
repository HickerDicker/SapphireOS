@echo off
bcdedit /set {current} nx AlwaysOff
echo "DEP/NX has been disabled press any key to reboot or close the tab to reboot later"
pause
shutdown -r -t 00