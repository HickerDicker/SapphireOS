rem simple batch file to run the install over a network
rem change the network path to your server
@echo off
net use u: "\\server\sdio"
u:
cd \
SDIO_RD.exe -script:scripts\install.txt
c:
net use u: /delete