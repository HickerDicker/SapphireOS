@echo off
Echo "Setting SvcHostSplitThresholdInKB to The Default Value"
Reg add HKLM\SYSTEM\CurrentControlSet\Control /t REG_DWORD /v SvcHostSplitThresholdInKB /d 0xffffffff /f
cls
Echo "SvcHostSplitThresholdInKB has been set to The Default Value"
Echo "A Reboot May be Required"
Echo "Press any key to reboot"
pause
shutdown -r -t 01
exit