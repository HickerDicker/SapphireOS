@echo off
Echo "Resyncing Time Don't Close This"
sc config w32time start= auto 2> nul
net start w32time 2> nul
w32tm /resync 2> nul
net stop w32time 2> nul
sc config w32time start= disabled 2> nul
exit /0