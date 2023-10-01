Prerequisites for 2kHz-8kHz:
Must be used on usb 3.x
Must be using the microsoft usb 3.x driver (this is the driver that comes with windows 8 / 8.1 / 10)
Must be running windows 8 / 8.1 / 10

2kHz-8kHz Procedure:
Run the 1kHz, 2kHz-4kHz, 4kHz-8kHz batch file in the driver directory.
Run setup, install service, restart computer.
Run setup, check box "filter on device", choose refreshrate (31 and 62 represent different things on each driver)
{
1kHz driver		31 = 31Hz	62 = 62Hz
2kHz-4kHz driver	31 = 2000Hz	62 = 4000Hz
4kHz-8kHz driver	31 = 4000Hz	62 = 8000Hz
}
Click restart.

If mouse stops working and disappears from the list:
Use tab and shift tab to highlight "mice only", press spacebar.
You will see your mouse again.
Use tab and shift tab to highlight your mouse.
Use tab and shift tab to highlight "filter on device", press spacebar.
Use tab and shift tab to highlight "restart", press spacebar.