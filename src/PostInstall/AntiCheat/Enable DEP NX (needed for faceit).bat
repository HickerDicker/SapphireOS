@echo off
bcdedit /deletevalue nx
echo "DEP/NX has been Enabled press any key to reboot or close the tab to reboot later"
pause
shutdown -r -t 00