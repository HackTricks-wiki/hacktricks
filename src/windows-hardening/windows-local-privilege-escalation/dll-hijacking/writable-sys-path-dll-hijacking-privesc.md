# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Si vous avez découvert que vous pouvez **écrire dans un dossier du System Path** (notez que cela ne fonctionnera pas si vous pouvez écrire dans un dossier du User Path), il est possible que vous puissiez **escalate privileges** sur le système.

Pour cela, vous pouvez exploiter un **Dll Hijacking**, où vous allez **hijack une library en cours de chargement** par un service ou un processus disposant de **plus de privileges** que vous. Comme ce service charge une Dll qui n'existe probablement même pas sur l'ensemble du système, il va essayer de la charger depuis le System Path dans lequel vous pouvez écrire.

Pour plus d'informations sur **ce qu'est le Dll Hijackig**, consultez :


{{#ref}}
./
{{#endref}}

## Privesc avec Dll Hijacking

### Finding a missing Dll

La première chose dont vous avez besoin est d'**identifier un processus** exécuté avec **plus de privileges** que vous et qui tente de **charger une Dll depuis le System Path** dans lequel vous pouvez écrire.

Rappelez-vous que cette technique dépend d'une entrée **Machine/System PATH**, et pas uniquement de votre **User PATH**. Par conséquent, avant de consacrer du temps à Procmon, il est utile d'énumérer les entrées du **Machine PATH** et de vérifier lesquelles sont accessibles en écriture :<sup>[[1]](#references)</sup>
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
Le problème dans ces cas est que ces processus sont probablement déjà en cours d’exécution. Pour trouver les DLL manquantes des services, vous devez lancer procmon dès que possible (avant le chargement des processus). Ainsi, pour trouver les `.dll` manquantes :

- **Créez** le dossier `C:\privesc_hijacking` et ajoutez le chemin `C:\privesc_hijacking` à la **variable d’environnement System Path**. Vous pouvez le faire **manuellement** ou avec **PS** :
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
- Lancez **`procmon`**, puis allez dans **`Options`** --> **`Enable boot logging`** et appuyez sur **`OK`** dans la fenêtre de confirmation.
- Ensuite, **redémarrez**. Lorsque l’ordinateur redémarre, **`procmon`** commencera à **enregistrer** les événements dès que possible.
- Une fois **Windows** **démarré, exécutez à nouveau `procmon`**. Il vous indiquera qu’il était déjà en cours d’exécution et vous **demandera si vous souhaitez enregistrer** les événements dans un fichier. Répondez **oui** et **enregistrez les événements dans un fichier**.
- **Une fois** le **fichier** **généré**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier d’événements**.
- Ajoutez ces **filtres** afin de trouver toutes les DLL qu’un **processus a tenté de charger** depuis le dossier System Path accessible en écriture :

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging est uniquement requis pour les services qui démarrent trop tôt** pour être observés autrement. Si vous pouvez **déclencher le service/programme cible à la demande** (par exemple en interagissant avec son interface COM, en redémarrant le service ou en relançant une tâche planifiée), il est généralement plus rapide de conserver une capture Procmon normale avec des filtres tels que **`Path contains .dll`**, **`Result is NAME NOT FOUND`** et **`Path begins with <writable_machine_path>`**.

### DLL manquées

En exécutant ceci sur une machine **virtuelle (vmware) Windows 11 gratuite**, j’ai obtenu les résultats suivants :

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, les fichiers .exe sont inutiles, ignorez-les. Les DLL manquantes provenaient de :

| Service                         | DLL                | Ligne CMD                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Après cette découverte, j’ai trouvé cet article de blog intéressant qui explique également comment [**abuser de WptsExtensions.dll pour effectuer une privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). C’est ce que nous **allons faire maintenant**.<sup>[[3]](#references)</sup>

### Autres candidats à examiner

`WptsExtensions.dll` est un bon exemple, mais ce n’est pas la seule **phantom DLL** récurrente apparaissant dans des services privilégiés. Les règles de hunting modernes et les catalogues publics de hijacking suivent encore des noms tels que :<sup>[[2]](#references)</sup>

| Service / Scénario | DLL manquante | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidat classique **SYSTEM** sur les systèmes clients. Intéressant lorsque le répertoire accessible en écriture se trouve dans le **Machine PATH** et que le service recherche la DLL lors de son démarrage. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Intéressant sur les **éditions serveur**, car le service s’exécute avec les privilèges **SYSTEM** et peut être **déclenché à la demande par un utilisateur normal** sur certaines builds, ce qui le rend préférable aux cas nécessitant uniquement un redémarrage. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Produit généralement d’abord **`NT AUTHORITY\LOCAL SERVICE`**. Cela est souvent suffisant, car le token possède **`SeImpersonatePrivilege`** ; vous pouvez donc l’enchaîner avec [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considérez ces noms comme des **indices de triage**, et non comme des réussites garanties : ils dépendent du **SKU/de la build**, et Microsoft peut modifier ce comportement entre les différentes versions. L’élément important à retenir est de rechercher les **DLL manquantes dans des services privilégiés qui parcourent le Machine PATH**, en particulier si le service peut être **déclenché à nouveau sans redémarrage**.

### Exploitation

Ainsi, pour **escalader les privilèges**, nous allons hijacker la library **WptsExtensions.dll**. Avec le **chemin** et le **nom**, il nous suffit de **générer la DLL malveillante**.

Vous pouvez [**essayer d’utiliser l’un de ces exemples**](#creating-and-compiling-dlls). Vous pourriez exécuter des payloads tels que : obtenir un rev shell, ajouter un utilisateur, exécuter un beacon...

> [!WARNING]
> Notez que **tous les services ne s’exécutent pas** avec **`NT AUTHORITY\SYSTEM`** ; certains s’exécutent également avec **`NT AUTHORITY\LOCAL SERVICE`**, qui possède **moins de privilèges**, et vous **ne pourrez pas créer un nouvel utilisateur** ni abuser de ses permissions.\
> Cependant, cet utilisateur possède le privilège **`seImpersonate`** ; vous pouvez donc utiliser la[ **potato suite pour escalader les privilèges**](../roguepotato-and-printspoofer.md). Dans ce cas, un rev shell est une meilleure option que d’essayer de créer un utilisateur.

Au moment de la rédaction, le service **Task Scheduler** s’exécute avec **Nt AUTHORITY\SYSTEM**.

Après avoir **généré la DLL malveillante** (_dans mon cas, j’ai utilisé un rev shell x64 et j’ai obtenu un shell, mais Defender l’a tué car il provenait de msfvenom_), enregistrez-la dans le System Path accessible en écriture sous le nom **WptsExtensions.dll**, puis **redémarrez** l’ordinateur (ou redémarrez le service, ou faites tout ce qui est nécessaire pour relancer le service/programme concerné).

Lorsque le service redémarre, la **DLL devrait être chargée et exécutée** (vous pouvez **réutiliser** l’astuce **procmon** pour vérifier que la **library a été chargée comme prévu**).

## Références

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
