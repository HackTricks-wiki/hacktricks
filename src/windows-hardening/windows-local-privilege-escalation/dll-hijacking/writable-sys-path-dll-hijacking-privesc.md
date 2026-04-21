# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Si tu as trouvé que tu peux **écrire dans un dossier du System Path** (note que cela ne fonctionnera pas si tu peux écrire dans un dossier du User Path), il est possible que tu puisses **escalader les privilèges** dans le système.

Pour cela, tu peux abuser d’un **Dll Hijacking** où tu vas **hijack** une library en cours de chargement par un service ou un process avec **plus de privilèges** que toi, et comme ce service charge un Dll qui n’existe probablement même pas sur tout le système, il va essayer de le charger depuis le System Path où tu peux écrire.

Pour plus d’infos sur **ce qu’est le Dll Hijackig** consulte :


{{#ref}}
./
{{#endref}}

## Privesc avec Dll Hijacking

### Trouver un Dll manquant

La première chose dont tu as besoin est d’**identifier un process** exécuté avec **plus de privilèges** que toi qui essaie de **charger un Dll depuis le System Path** dans lequel tu peux écrire.

Rappelle-toi que cette technique dépend d’une entrée **Machine/System PATH**, pas seulement de ton **User PATH**. Par conséquent, avant de passer du temps sur Procmon, il vaut la peine d’énumérer les entrées **Machine PATH** et de vérifier lesquelles sont inscriptibles :
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Le problème dans ce cas est que probablement ces processus sont déjà en cours d’exécution. Pour trouver quels Dlls manquent aux services, vous devez lancer procmon dès que possible (avant le chargement des processus). Donc, pour trouver les .dll manquants, faites :

- **Create** le dossier `C:\privesc_hijacking` et ajoutez le chemin `C:\privesc_hijacking` à la variable d’environnement **System Path**. Vous pouvez le faire **manually** ou avec **PS** :
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Lancez **`procmon`** et allez dans **`Options`** --> **`Enable boot logging`** puis cliquez sur **`OK`** dans l’invite.
- Ensuite, **redémarrez**. Lorsque l’ordinateur redémarre, **`procmon`** commencera à **enregistrer** les événements dès que possible.
- Une fois **Windows** **démarré, exécutez `procmon`** à nouveau ; il vous indiquera qu’il a été en cours d’exécution et vous **demandera si vous voulez stocker** les événements dans un fichier. Répondez **yes** et **stockez les événements dans un fichier**.
- **Après** la **génération** du **fichier**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier d’événements**.
- Ajoutez ces **filtres** et vous trouverez tous les Dlls que certains **processus ont tenté de charger** depuis le dossier writable System Path :

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is only required for services that start too early** to observe otherwise. If you can **trigger the target service/program on demand** (for example, by interacting with its COM interface, restarting the service, or relaunching a scheduled task), it is usually faster to keep a normal Procmon capture with filters such as **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, and **`Path begins with <writable_machine_path>`**.

### Missed Dlls

En exécutant cela sur une machine **Windows 11 virtuelle (vmware) gratuite**, j’ai obtenu ces résultats :

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, les .exe sont inutiles, donc ignorez-les ; les DLLs manquantes provenaient de :

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Après avoir trouvé cela, j’ai trouvé ce post de blog intéressant qui explique aussi comment [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). C’est ce que nous **allons faire maintenant**.

### Other candidates worth triaging

`WptsExtensions.dll` est un bon exemple, mais ce n’est pas le seul **phantom DLL** récurrent qui apparaît dans des services privilégiés. Les règles de hunting modernes et les catalogues publics de hijack suivent encore des noms tels que :

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidat **SYSTEM** classique sur les systèmes clients. Bon lorsque le répertoire writable se trouve dans le **Machine PATH** et que le service interroge la DLL au démarrage. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Intéressant sur les **server editions** car le service s’exécute en tant que **SYSTEM** et peut être **triggered on demand by a normal user** dans certaines versions, ce qui est mieux que les cas nécessitant uniquement un reboot. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Donne généralement d’abord **`NT AUTHORITY\LOCAL SERVICE`**. C’est souvent encore suffisant car le token a **`SeImpersonatePrivilege`**, donc vous pouvez enchaîner avec [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considérez ces noms comme des **indices de triage**, pas comme des victoires garanties : ils dépendent du **SKU/build**, et Microsoft peut changer le comportement entre les versions. L’idée importante est de chercher des **DLL manquantes dans des services privilégiés qui traversent le Machine PATH**, surtout si le service peut être **re-triggered sans redémarrage**.

### Exploitation

Donc, pour **élever les privilèges**, nous allons détourner la bibliothèque **WptsExtensions.dll**. En ayant le **chemin** et le **nom**, il nous suffit de **générer la DLL malveillante**.

Vous pouvez [**essayer d’utiliser l’un de ces exemples**](#creating-and-compiling-dlls). Vous pourriez exécuter des payloads tels que : obtenir un rev shell, ajouter un utilisateur, exécuter un beacon...

> [!WARNING]
> Notez que **tous les services ne s’exécutent pas** avec **`NT AUTHORITY\SYSTEM`** ; certains s’exécutent aussi avec **`NT AUTHORITY\LOCAL SERVICE`**, qui a **moins de privilèges** et vous **ne pourrez pas créer un nouvel utilisateur** pour abuse ses permissions.\
> Cependant, cet utilisateur a le privilège **`seImpersonate`**, donc vous pouvez utiliser la [**potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Donc, dans ce cas, un rev shell est une meilleure option que d’essayer de créer un utilisateur.

Au moment de l’écriture, le service **Task Scheduler** s’exécute avec **Nt AUTHORITY\SYSTEM**.

Une fois **la DLL malveillante générée** (_dans mon cas, j’ai utilisé un x64 rev shell et j’ai obtenu un shell, mais defender l’a tué parce qu’il provenait de msfvenom_), enregistrez-la dans le writable System Path avec le nom **WptsExtensions.dll** puis **redémarrez** l’ordinateur (ou redémarrez le service, ou faites ce qu’il faut pour relancer le service/programme concerné).

Lorsque le service est redémarré, la **dll devrait être chargée et exécutée** (vous pouvez **réutiliser** l’astuce **procmon** pour vérifier si la **bibliothèque a été chargée comme prévu**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
