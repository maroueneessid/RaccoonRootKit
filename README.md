# Raccoon Rootkit #

- Windows Driver with rootkit capabilities `ninjaRaccoon.sys`.
- Usermode interface. `ninjaRaccoonInterface.exe`
- Capabilities : 
	- Elevate any process to SYSTEM
	- Downgraed any process to MEDIUM/LOW Integrity 
	- Kill any process (one time kill).
	- Disables LSASS "Protected Process Light" protection for dumping. Doesn't do the actual dumping.

### Usage ###

```
Options:
  -e <pid>    Elevate privileges of the specified PID. If PID is 0 , elevates current process.
  -d <pid>    Downgrade privileges of the specified PID to match a low-integrity process (explorer.exe).
  -k <pid>    Kill the process with the given PID.
  -l          Unprotect LSASS (enables interaction or manipulation with LSASS).
  -credGuard  Disables Windows Credential Guard.

Examples:
  Program.exe -e 1234           Elevate process 1234
  Program.exe -d 5678           Downgrade process 5678
  Program.exe -k 4321           Kill process 4321
  Program.exe -l                Unprotect LSASS
```

- All options can be used simultaneously.

### Notes ###

- Ntoskrnl.exe dynamic structure offset resolution code , picked from https://github.com/wavestone-cdt/EDRSandblast
- To avoid , `Warning treated as Errors` during compilation of driver. Lower Warning Level from `W4` to `W3` . should be handled by solution file.

### To Do ### 

- Credential Guard.

### References ###

- https://github.com/wavestone-cdt/EDRSandblast
- https://www.exploit-db.com/exploits/37098
- https://www.vergiliusproject.com/



