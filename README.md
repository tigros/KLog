KLog -- Kernel Logger

KLog is used to log all processes started, it uses a driver to catch processes starting at the root rather than using a polling method, 
which means fast closing processes will not be missed. ETW or WMI methods don't miss anything but getting the command line arguments 
of fast closing processes is next to impossible using those methods, which is where KLog has an advantage. 

Once the driver is compiled the system will need to be in Test Mode because it is Test signed. Hopefully someday this will be rectified, if you are
willing to MS sign it with your credentials please let me know, it would be very much appreciated!

To put Windows in Test Mode run these 2 commands from an elevated cmd prompt:

	bcdedit.exe /set nointegritychecks on
	bcdedit /set testsigning on

Also, a minor change is required in ProcessHacker\main.c to bypass the .sig check. In main.c look for PhInitializeKph funtion then after the KphConnect2Ex call, bypass 
the .sig check with a goto or whatever method you prefer.

This program is based on the good work of the Battelle Memorial Institute team, see https://github.com/HoneProject for more information.


