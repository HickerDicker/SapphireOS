@echo off
set /p newName=Enter a new name:
net user Administrator /fullname:"%newName%"