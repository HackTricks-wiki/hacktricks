# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Si vous pouvez **écrire dans un répertoire du `PATH` à l’échelle du système** (et pas seulement dans le `PATH` de votre utilisateur), vous pouvez être en mesure d’**escalader les privilèges** sur le système.

Cela peut être exploité via le **DLL hijacking** lorsqu’un service ou processus disposant de privilèges plus élevés tente de charger une DLL qui n’existe pas dans ses emplacements de recherche précédents, puis finit par rechercher le répertoire du `PATH` système accessible en écriture.

Pour plus d’informations sur le **DLL hijacking**, consultez :


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a Missing DLL

Commencez par **identifier un processus** exécuté avec **davantage de privilèges** qui tente de **charger une DLL depuis un répertoire du `PATH` système accessible en écriture**.

N’oubliez pas que cette technique dépend d’une entrée du **Machine/System PATH**, et pas uniquement de votre **User PATH**. Par conséquent, avant de consacrer du temps à Procmon, il est utile d’énumérer les entrées du **Machine PATH** et de vérifier lesquelles sont accessibles en écriture :<sup>[[1]](#references)</sup>
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
Le problème dans ces cas est que ces processus sont probablement déjà en cours d'exécution. Pour identifier les DLL que les services tentent de charger sans succès, lancez Procmon le plus tôt possible (avant le démarrage des processus), puis :

- **Créez** le dossier `C:\privesc_hijacking` et ajoutez le chemin `C:\privesc_hijacking` à la **variable d'environnement System Path**. Vous pouvez le faire **manuellement** ou avec **PS** :
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
- Lancez **`procmon`**, allez dans **`Options`** --> **`Enable boot logging`**, puis appuyez sur **`OK`** dans l’invite.
- Ensuite, **redémarrez**. Lorsque l’ordinateur redémarrera, **`procmon`** commencera à **enregistrer** les événements dès que possible.
- Une fois **Windows** **démarré, exécutez à nouveau `procmon`**. Il vous indiquera qu’il était déjà en cours d’exécution et vous **demandera si vous souhaitez stocker** les événements dans un fichier. Répondez **oui** et **stockez les événements dans un fichier**.
- **Une fois que le fichier** est **généré**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier d’événements**.
- Ajoutez ces **filtres** pour trouver toutes les DLL qu’un **processus a essayé de charger** depuis le dossier System Path accessible en écriture :

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **La journalisation du démarrage est uniquement nécessaire pour les services qui démarrent trop tôt** pour être observés autrement. Si vous pouvez **déclencher le service/programme ciblé à la demande** (par exemple en interagissant avec son interface COM, en redémarrant le service ou en relançant une tâche planifiée), il est généralement plus rapide de conserver une capture Procmon normale avec des filtres tels que **`Path contains .dll`**, **`Result is NAME NOT FOUND`** et **`Path begins with <writable_machine_path>`**.

### DLL manquantes

En exécutant ceci dans une **machine Windows 11 virtuelle (vmware)** gratuite, j’ai obtenu les résultats suivants :

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, ignorez les résultats `.exe`. Les recherches de DLL manquantes provenaient de :

| Service                         | DLL                | Ligne CMD                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

L’exemple suivant utilise la technique décrite dans cet article concernant [**l’abus de `WptsExtensions.dll` pour l’escalade de privilèges**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Autres candidats qui méritent un triage

`WptsExtensions.dll` est un bon exemple, mais ce n’est pas la seule **phantom DLL** récurrente qui apparaît dans les services privilégiés. Les règles de hunting modernes et les catalogues publics de hijacking suivent encore des noms tels que :<sup>[[2]](#references)</sup>

| Service / Scénario | DLL manquante | Remarques |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidat classique **SYSTEM** sur les systèmes clients. Intéressant lorsque le répertoire accessible en écriture se trouve dans le **Machine PATH** et que le service recherche la DLL au démarrage. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Intéressant sur les **éditions serveur**, car le service s’exécute en tant que **SYSTEM** et peut être **déclenché à la demande par un utilisateur normal** dans certaines builds, ce qui le rend préférable aux cas nécessitant uniquement un redémarrage. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Renvoie généralement **`NT AUTHORITY\LOCAL SERVICE`** en premier. Cela suffit souvent, car le token possède **`SeImpersonatePrivilege`** ; vous pouvez donc l’enchaîner avec [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considérez ces noms comme des **indications de triage**, et non comme des réussites garanties : ils dépendent du **SKU/de la build**, et Microsoft peut modifier ce comportement entre les versions. L’idée importante est de rechercher les **DLL manquantes dans les services privilégiés qui parcourent le Machine PATH**, en particulier si le service peut être **redéclenché sans redémarrer**.

### Exploitation

Pour **escalader les privilèges**, détournez **`WptsExtensions.dll`**. Une fois le **chemin** et le **nom** connus, générez la DLL malveillante.

Vous pouvez [**essayer d’utiliser l’un de ces exemples**](#creating-and-compiling-dlls). Vous pourriez exécuter des payloads tels que : obtenir un rev shell, ajouter un utilisateur, exécuter un beacon...

> [!WARNING]
> Notez que **tous les services ne s’exécutent pas** en tant que **`NT AUTHORITY\SYSTEM`**. Certains s’exécutent en tant que **`NT AUTHORITY\LOCAL SERVICE`**, qui possède **moins de privilèges** ; l’abus de l’un de ces services peut donc ne pas vous permettre de créer un nouvel utilisateur.\
> Cependant, ce compte possède le droit utilisateur **`SeImpersonatePrivilege`**, vous pouvez donc utiliser la [**suite Potato pour escalader les privilèges**](../roguepotato-and-printspoofer.md). Dans ce cas, un reverse shell est une meilleure option que d’essayer de créer un utilisateur.

Au moment de la rédaction, le service **Task Scheduler** s’exécute avec **Nt AUTHORITY\SYSTEM**.

Après avoir **généré la DLL malveillante** (_dans mon cas, j’ai utilisé un rev shell x64 et j’ai obtenu un shell en retour, mais Defender l’a supprimé, car il provenait de msfvenom_), enregistrez-la dans le System Path accessible en écriture sous le nom **WptsExtensions.dll**, puis **redémarrez** l’ordinateur (ou redémarrez le service, ou faites tout ce qui est nécessaire pour réexécuter le service/programme concerné).

Lorsque le service redémarre, la **DLL devrait être chargée et exécutée** (vous pouvez **réutiliser l’astuce** de **procmon** pour vérifier si la **bibliothèque a été chargée comme prévu**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
