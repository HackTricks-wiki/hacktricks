# Élévation de privilèges par Writable System PATH + DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Si vous pouvez **écrire dans un répertoire du `PATH` à l’échelle du système** (et pas seulement dans le `PATH` de votre utilisateur), vous pourrez peut-être **élever vos privilèges** sur le système.

Cela peut être exploité via le **DLL hijacking** lorsqu’un service ou processus disposant de privilèges plus élevés tente de charger une DLL qui n’existe pas dans ses emplacements de recherche précédents et finit par rechercher cette DLL dans le répertoire inscriptible du `PATH` système.

Une entrée `PATH` Machine inscriptible n’est qu’une **primitive**, et ne constitue pas une preuve d’exécution de code. Pour une application non empaquetée utilisant l’ordre de recherche standard, le `PATH` est atteint après la redirection, les API sets, SxS, la liste des modules chargés, KnownDLLs, les répertoires de l’application et de Windows, ainsi que le répertoire courant. Un chemin complet ou une stratégie `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` peut complètement exclure le `PATH`.<sup>[[4]](#references)</sup>

Pour plus d’informations sur le **DLL hijacking**, consultez :

{{#ref}}
./
{{#endref}}

## Privesc avec DLL Hijacking

### Trouver une DLL manquante

Commencez par **identifier un processus** exécuté avec **davantage de privilèges** qui tente de **charger une DLL depuis un répertoire inscriptible du `PATH` système**.

N’oubliez pas que cette technique dépend d’une entrée du `PATH` Machine/Système, et pas uniquement de votre **User PATH**. Par conséquent, avant de consacrer du temps à Procmon, il est utile d’énumérer les entrées du **Machine PATH** et de vérifier lesquelles sont inscriptibles :<sup>[[1]](#references)</sup>
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
Le texte des ACL peut être trompeur, car l’appartenance à un groupe, les ACE de refus et les permissions héritées influencent le résultat. Lors d’un test autorisé, une vérification de création/suppression contrôle les accès effectifs du token actuel (elle est intrusive et peut générer des alertes) :<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Confirmer le `PATH` effectif de la cible

Le `PATH` Machine lu dans le registre constitue des données de configuration ; le loader utilise le bloc d'environnement du **processus cible**. Chaque processus possède un bloc d'environnement, et un processus enfant hérite normalement d'une copie de l'environnement de son parent. Par conséquent, un service de longue durée peut conserver une ancienne valeur, et un service lancé avec un environnement personnalisé peut différer de la valeur visible dans votre shell. Considérez une observation Procmon de la recherche du répertoire exact par le PID cible comme la référence absolue ; après avoir modifié le `PATH` dans un lab, redémarrez l'arborescence de processus concernée ou la machine avant de conclure que la recherche n'a pas lieu.<sup>[[5]](#references)</sup>

Le problème dans ces cas est que ces processus sont probablement déjà en cours d'exécution. Pour identifier les DLL que les services tentent de charger sans succès, lancez Procmon le plus tôt possible (avant le démarrage des processus), puis :

> [!WARNING]
> Ajouter un répertoire accessible en écriture par un utilisateur au `PATH` Machine **crée la condition vulnérable**. Faites-le uniquement dans une VM de recherche isolée afin de déterminer quels processus privilégiés parcourent le `PATH` ; sur un hôte évalué, surveillez l'entrée accessible en écriture existante sans modifier la configuration du système.<sup>[[1]](#references)</sup>

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
- Lancez **`procmon`**, puis allez dans **`Options`** --> **`Enable boot logging`** et appuyez sur **`OK`** dans l'invite.
- Ensuite, **redémarrez**. Lorsque l'ordinateur redémarrera, **`procmon`** commencera à **enregistrer** les événements dès que possible.
- Une fois **Windows** **démarré, exécutez à nouveau `procmon`**. Il vous indiquera qu'il était en cours d'exécution et vous **demandera si vous souhaitez stocker** les événements dans un fichier. Répondez **oui** et **stockez les événements dans un fichier**.
- **Après** la **génération du fichier**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier d'événements**.
- Ajoutez ces **filtres** pour trouver toutes les DLL qu'un **processus a tenté de charger** depuis le dossier writable System Path :

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** est uniquement requis pour les services qui démarrent **trop tôt** pour être observés autrement. Si vous pouvez **déclencher le service/programme cible à la demande** (par exemple, en interagissant avec son interface COM, en redémarrant le service ou en relançant une scheduled task), il est généralement plus rapide de conserver une capture Procmon normale avec des filtres tels que **`Path contains .dll`**, **`Result is NAME NOT FOUND`** et **`Path begins with <writable_machine_path>`**.

### DLL manquantes

En exécutant ceci sur une **machine Windows 11 virtuelle (vmware) gratuite**, j'ai obtenu les résultats suivants :

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, ignorez les résultats `.exe`. Les recherches de DLL manquantes provenaient de :

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

L'exemple suivant utilise la technique décrite dans cet article concernant [**l'abus de `WptsExtensions.dll` pour l'escalade de privilèges**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Autres candidats méritant un triage

`WptsExtensions.dll` est un bon exemple, mais ce n'est pas la seule **phantom DLL** récurrente apparaissant dans les services privilégiés. Les règles de hunting modernes et les catalogues publics de hijacking suivent encore des noms tels que :<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidat **SYSTEM** classique sur les systèmes clients. Intéressant lorsque le répertoire writable se trouve dans le **Machine PATH** et que le service recherche la DLL au démarrage. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Intéressant sur les **éditions serveur**, car le service s'exécute en tant que **SYSTEM** et peut être **déclenché à la demande par un utilisateur normal** dans certaines builds, ce qui le rend préférable aux cas nécessitant uniquement un redémarrage. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Produit généralement **`NT AUTHORITY\LOCAL SERVICE`** en premier. Cela suffit souvent, car le token dispose de **`SeImpersonatePrivilege`** ; vous pouvez donc l'enchaîner avec [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considérez ces noms comme des **indices de triage**, et non comme des réussites garanties : ils dépendent de la **SKU/build**, et Microsoft peut modifier ce comportement entre les versions. L'essentiel est de rechercher les **DLL manquantes dans les services privilégiés qui parcourent le Machine PATH**, en particulier si le service peut être **redéclenché sans redémarrage**.

### Valider un candidat avant de l'utiliser

Un événement `NAME NOT FOUND` ne suffit pas à lui seul. Avant de placer un payload, vérifiez la chaîne complète :<sup>[[1]](#references)[[4]](#references)</sup>

1. L'événement concerne le **PID, la ligne de commande, le compte de service et le niveau d'intégrité** attendus, et le chemin manquant correspond exactement au répertoire writable du `PATH` Machine.
2. Pour le même basename de DLL, aucun répertoire précédent ne renvoie `SUCCESS`, et le module n'est pas satisfait par la liste des modules chargés, KnownDLLs, la redirection ou un manifeste SxS.
3. La recherche se répète lorsqu'un utilisateur disposant de faibles privilèges invoque le trigger prévu. Une recherche limitée au démarrage est exploitable, mais bien moins pratique qu'une recherche à la demande.
4. L'architecture du payload correspond à celle du processus. Si l'application résout ensuite des exports, faites office de proxy pour la DLL légitime ou exportez les symboles attendus ; consultez [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Utilisez d'abord une DLL canary inoffensive qui enregistre le PID, l'identité et l'horodatage. Dans Procmon, exigez un **`Load Image`** réussi depuis le chemin utilisé, plutôt que de supposer qu'une recherche de fichier précédente a provoqué l'exécution.

### Exploitation

Pour **escalader les privilèges**, détournez **`WptsExtensions.dll`**. Une fois le **chemin** et le **nom** connus, générez la DLL malveillante.

Vous pouvez [**essayer d'utiliser l'un de ces exemples**](README.md#creating-and-compiling-dlls). Vous pouvez exécuter des payloads tels que : obtenir un rev shell, ajouter un utilisateur, exécuter un beacon...

> [!WARNING]
> Notez que **tous les services ne s'exécutent pas** en tant que **`NT AUTHORITY\SYSTEM`**. Certains s'exécutent en tant que **`NT AUTHORITY\LOCAL SERVICE`**, qui dispose de **moins de privilèges** ; l'abus de l'un de ces services peut donc ne pas vous permettre de créer un nouvel utilisateur.\
> Cependant, ce compte dispose du droit utilisateur **`SeImpersonatePrivilege`**, vous pouvez donc utiliser la [**Potato suite pour escalader les privilèges**](../roguepotato-and-printspoofer.md). Dans ce cas, un reverse shell constitue une meilleure option que d'essayer de créer un utilisateur.

Le service **Task Scheduler** s'exécute normalement en tant que **`NT AUTHORITY\SYSTEM`**, mais vérifiez le déploiement réel et ne déduisez pas l'identité d'exécution uniquement à partir du nom du service :<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Après avoir **généré la DLL malveillante** (_dans mon cas, j’ai utilisé un x64 rev shell et obtenu un shell, mais Defender l’a tué car il provenait de msfvenom_), enregistrez-la dans le System Path accessible en écriture sous le nom **WptsExtensions.dll**, puis **redémarrez** l’ordinateur (ou redémarrez le service, ou faites le nécessaire pour relancer le service/programme concerné).

Lorsque le service est redémarré, la **DLL devrait être chargée et exécutée** (vous pouvez **réutiliser** l’astuce **Procmon** pour vérifier que la **bibliothèque a été chargée comme prévu**).

> [!NOTE]
> Prévoyez le nettoyage avant le déclenchement. Un service peut conserver la DLL mappée et verrouiller le fichier jusqu’à son arrêt ; pour `WptsExtensions.dll`, l’arrêt de Task Scheduler nécessite des droits élevés. Après avoir obtenu le contexte souhaité, arrêtez la cible en toute sécurité, supprimez le payload et restaurez toute modification de `PATH` propre au lab.<sup>[[1]](#references)</sup>

### Remédiation / détection

Supprimez les autorisations d’écriture trop permissives de chaque répertoire du `PATH` Machine et supprimez les entrées obsolètes. Les développeurs doivent charger les bibliothèques approuvées avec leur chemin complet ou limiter la résolution à l’aide de `SetDefaultDllDirectories` / des indicateurs de recherche de `LoadLibraryEx`. Les équipes de défense peuvent corréler les modifications du `PATH` Machine avec le chargement de DLL par des processus privilégiés depuis des répertoires non système accessibles en écriture aux utilisateurs.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Détournement de DLL Windows (enfin) clarifié](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL suspecte chargée pour la persistance ou l’élévation de privilèges](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [Détournement de DLL – Élévation de privilèges Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Ordre de recherche des bibliothèques de liens dynamiques](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Variables d’environnement](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
