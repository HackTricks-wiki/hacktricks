# Abuso dei processi macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base sui processi

Un processo è un'istanza di un eseguibile in esecuzione; tuttavia, i processi non eseguono codice: lo fanno i thread. Pertanto, **i processi sono solo contenitori per thread in esecuzione** che forniscono memoria, descrittori, porte, permessi...

Tradizionalmente, i processi venivano avviati all'interno di altri processi (tranne il PID 1) chiamando **`fork`**, che creava una copia esatta del processo corrente. Il **processo figlio** chiamava quindi generalmente **`execve`** per caricare il nuovo eseguibile ed eseguirlo. In seguito è stato introdotto **`vfork`** per rendere questo processo più veloce, senza copiare la memoria.\
Poi è stato introdotto **`posix_spawn`**, che combina **`vfork`** e **`execve`** in una sola chiamata e accetta dei flag:

- `POSIX_SPAWN_RESETIDS`: Reimposta gli ID effettivi sugli ID reali
- `POSIX_SPAWN_SETPGROUP`: Imposta l'appartenenza al gruppo di processi
- `POSUX_SPAWN_SETSIGDEF`: Imposta il comportamento predefinito dei segnali
- `POSIX_SPAWN_SETSIGMASK`: Imposta la maschera dei segnali
- `POSIX_SPAWN_SETEXEC`: Esegue nello stesso processo (come `execve`, con più opzioni)
- `POSIX_SPAWN_START_SUSPENDED`: Avvia in stato sospeso
- `_POSIX_SPAWN_DISABLE_ASLR`: Avvia senza ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa l'allocatore Nano di libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Consente `rwx` nei segmenti dati
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Chiude per impostazione predefinita tutti i descrittori di file con exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizza i bit alti dello slide ASLR

Inoltre, `posix_spawn` accetta le impostazioni **`posix_spawnattr`**, che controllano aspetti del processo avviato, e le voci **`posix_spawn_file_actions`**, che modificano i descrittori di file.

Quando un processo termina, invia il **codice di ritorno al processo padre** (se il padre è terminato, il nuovo padre è il PID 1) con il segnale `SIGCHLD`. Il padre deve ottenere questo valore chiamando `wait4()` o `waitid()`; fino ad allora, il processo figlio rimane in stato zombie: è ancora elencato, ma non consuma risorse.

### PID

I PID, ovvero gli identificatori di processo, identificano un processo univoco. In XNU, i **PID** sono di **64 bit**, aumentano monotonamente e **non tornano mai a zero** (per evitare abusi).

### Gruppi di processi, sessioni e coalizioni

I **processi** possono essere inseriti in **gruppi** per facilitarne la gestione. Per esempio, i comandi in uno script shell fanno parte dello stesso gruppo di processi, quindi è possibile **inviare loro segnali tutti insieme**, ad esempio usando kill.\
È anche possibile **raggruppare i processi in sessioni**. Quando un processo avvia una sessione (`setsid(2)`), i processi figli vengono inseriti nella sessione, a meno che non ne avviino una propria.

La coalizione è un altro modo per raggruppare i processi in Darwin. Un processo che entra a far parte di una coalizione può accedere alle risorse del pool, condividere un ledger o essere soggetto a Jetsam. Le coalizioni hanno ruoli diversi: Leader, servizio XPC, Extension.

### Credenziali e personae

Ogni processo possiede **credenziali** che **identificano i suoi privilegi** nel sistema. Ogni processo ha un `uid` primario e un `gid` primario (anche se può appartenere a più gruppi).\
È anche possibile modificare l'ID utente e gruppo se il binario ha il bit `setuid/setgid`.\
Esistono diverse funzioni per **impostare nuovi uid/gid**.

La syscall **`persona`** fornisce un insieme **alternativo** di **credenziali**. Adottare una persona implica assumere simultaneamente il suo uid, gid e le sue appartenenze ai gruppi. Nel [**codice sorgente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) è possibile trovare la struct:

```c
struct kpersona_info { uint32_t persona_info_version;
    uid_t    persona_id; /* overlaps with UID */
    int      persona_type;
    gid_t    persona_gid;
    uint32_t persona_ngroups;
    gid_t    persona_groups[NGROUPS];
    uid_t    persona_gmuid;
    char     persona_name[MAXLOGNAME + 1];

    /* TODO: MAC policies?! */
}
```

## Informazioni di base sui thread

1. **Thread POSIX (pthreads):** macOS supporta i thread POSIX (`pthreads`), che fanno parte di un'API standard per i thread in C/C++. L'implementazione di pthreads in macOS si trova in `/usr/lib/system/libsystem_pthread.dylib` e proviene dal progetto `libpthread`, disponibile pubblicamente. Questa libreria fornisce le funzioni necessarie per creare e gestire i thread.
2. **Creazione dei thread:** la funzione `pthread_create()` viene usata per creare nuovi thread. Internamente, questa funzione chiama `bsdthread_create()`, una chiamata di sistema di livello inferiore specifica del kernel XNU (il kernel su cui si basa macOS). Questa chiamata di sistema accetta vari flag derivati da `pthread_attr` (attributi) che specificano il comportamento del thread, incluse le policy di scheduling e la dimensione dello stack.
   - **Dimensione predefinita dello stack:** la dimensione predefinita dello stack per i nuovi thread è di 512 KB, sufficiente per le operazioni tipiche, ma modificabile tramite gli attributi del thread se serve più o meno spazio.
3. **Inizializzazione dei thread:** la funzione `__pthread_init()` è fondamentale durante la configurazione del thread; utilizza l'argomento `env[]` per analizzare le variabili d'ambiente, che possono includere dettagli sulla posizione e sulla dimensione dello stack.

#### Terminazione dei thread in macOS

1. **Uscita dai thread:** in genere, i thread vengono terminati chiamando `pthread_exit()`. Questa funzione consente a un thread di terminare correttamente, eseguendo le operazioni di pulizia necessarie e permettendogli di inviare un valore di ritorno a eventuali thread in attesa con `join`.
2. **Pulizia dei thread:** quando viene chiamata `pthread_exit()`, viene invocata la funzione `pthread_terminate()`, che gestisce la rimozione di tutte le strutture associate al thread. Dealloca le porte dei thread Mach (Mach è il sottosistema di comunicazione del kernel XNU) e chiama `bsdthread_terminate`, una syscall che rimuove le strutture del kernel associate al thread.

#### Meccanismi di sincronizzazione

Per gestire l'accesso alle risorse condivise ed evitare race condition, macOS fornisce diverse primitive di sincronizzazione. Sono fondamentali negli ambienti multi-thread per garantire l'integrità dei dati e la stabilità del sistema:

1. **Mutex:**
   - **Mutex regolare (firma: 0x4D555458):** mutex standard con un ingombro in memoria di 60 byte (56 byte per il mutex e 4 byte per la firma).
   - **Mutex veloce (firma: 0x4d55545A):** simile a un mutex regolare, ma ottimizzato per operazioni più rapide; anche questo è di 60 byte.
2. **Variabili di condizione:**
   - Usate per attendere il verificarsi di determinate condizioni; hanno una dimensione di 44 byte (40 byte più una firma di 4 byte).
   - **Attributi delle variabili di condizione (firma: 0x434e4441):** attributi di configurazione per le variabili di condizione, di 12 byte.
3. **Variabile Once (firma: 0x4f4e4345):**
   - Garantisce che una porzione di codice di inizializzazione venga eseguita una sola volta. Ha una dimensione di 12 byte.
4. **Lock di lettura-scrittura:**
   - Consente a più lettori o a un solo writer alla volta di accedere ai dati condivisi in modo efficiente.
   - **Lock di lettura-scrittura (firma: 0x52574c4b):** ha una dimensione di 196 byte.
   - **Attributi dei lock di lettura-scrittura (firma: 0x52574c41):** attributi per i lock di lettura-scrittura, di 20 byte.

> [!TIP]
> Gli ultimi 4 byte di questi oggetti servono a rilevare gli overflow.

### Variabili locali al thread (TLV)

Le **variabili locali al thread (TLV)** nei file Mach-O (il formato degli eseguibili in macOS) vengono usate per dichiarare variabili specifiche di **ciascun thread** in un'applicazione multi-thread. In questo modo, ogni thread dispone di una propria istanza separata della variabile, evitando conflitti e mantenendo l'integrità dei dati senza dover ricorrere a meccanismi di sincronizzazione espliciti come i mutex.

In C e nei linguaggi correlati, puoi dichiarare una variabile locale al thread usando la keyword **`__thread`**. Ecco come funziona nell'esempio:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Questo snippet definisce `tlv_var` come variabile locale al thread. Ogni thread che esegue questo codice avrà una propria `tlv_var` e le modifiche apportate da un thread a `tlv_var` non influiranno su `tlv_var` negli altri thread.

Nel binario Mach-O, i dati relativi alle variabili locali al thread sono organizzati in sezioni specifiche:

- **`__DATA.__thread_vars`**: questa sezione contiene i metadati delle variabili locali al thread, come i tipi e lo stato di inizializzazione.
- **`__DATA.__thread_bss`**: questa sezione viene usata per le variabili locali al thread non inizializzate esplicitamente. È una porzione di memoria riservata ai dati inizializzati a zero.

Mach-O fornisce anche un’API specifica, **`tlv_atexit`**, per gestire le variabili locali al thread quando un thread termina. Questa API consente di **registrare distruttori**, ovvero funzioni speciali che ripuliscono i dati locali al thread quando il thread termina.

### Priorità dei thread

Per comprendere le priorità dei thread bisogna considerare come il sistema operativo decide quali thread eseguire e quando. Questa decisione dipende dal livello di priorità assegnato a ciascun thread. In macOS e nei sistemi Unix-like, si usano concetti come `nice`, `renice` e le classi Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
   - Il valore `nice` di un processo è un numero che ne influenza la priorità. Ogni processo ha un valore `nice` compreso tra -20 (priorità più alta) e 19 (priorità più bassa). Quando un processo viene creato, il valore `nice` predefinito è in genere 0.
   - Un valore `nice` più basso (più vicino a -20) rende un processo più «egoista», assegnandogli più tempo di CPU rispetto ai processi con valori `nice` più alti.
2. **Renice:**
   - `renice` è un comando usato per modificare il valore `nice` di un processo già in esecuzione. Può servire a regolare dinamicamente la priorità dei processi, aumentando o diminuendo il tempo di CPU assegnato in base ai nuovi valori `nice`.
   - Ad esempio, se un processo ha temporaneamente bisogno di più risorse CPU, si può abbassarne il valore `nice` usando `renice`.

#### Classi Quality of Service (QoS)

Le classi QoS sono un approccio più moderno alla gestione delle priorità dei thread, in particolare nei sistemi come macOS che supportano **Grand Central Dispatch (GCD)**. Consentono agli sviluppatori di **classificare** il lavoro in diversi livelli in base all’importanza o all’urgenza. macOS gestisce automaticamente la priorità dei thread in base a queste classi QoS:

1. **User Interactive:**
   - Questa classe è destinata alle attività che interagiscono direttamente con l’utente o che richiedono risultati immediati per garantire una buona esperienza d’uso. A queste attività viene assegnata la priorità più alta per mantenere reattiva l’interfaccia (ad esempio, animazioni o gestione degli eventi).
2. **User Initiated:**
   - Attività avviate dall’utente per cui ci si aspetta un risultato immediato, come aprire un documento o fare clic su un pulsante che richiede calcoli. Hanno una priorità alta, ma inferiore a quella delle attività User Interactive.
3. **Utility:**
   - Queste attività durano a lungo e in genere mostrano un indicatore di avanzamento (ad esempio, il download di file o l’importazione di dati). Hanno una priorità inferiore rispetto alle attività avviate dall’utente e non devono terminare immediatamente.
4. **Background:**
   - Questa classe è destinata alle attività eseguite in background e non visibili all’utente, come l’indicizzazione, la sincronizzazione o i backup. Hanno la priorità più bassa e un impatto minimo sulle prestazioni del sistema.

Con le classi QoS, gli sviluppatori non devono gestire valori di priorità specifici, ma possono concentrarsi sulla natura dell’attività; il sistema ottimizza di conseguenza le risorse CPU.

Esistono inoltre diverse **politiche di scheduling dei thread**, che consentono ai flussi di specificare un insieme di parametri di scheduling che lo scheduler prenderà in considerazione. È possibile farlo usando `thread_policy_[set/get]`. Questo può essere utile negli attacchi basati su race condition.

## Abuso dei processi macOS

macOS offre molti meccanismi che consentono ai **processi di interagire, comunicare e condividere dati**. Sebbene questi meccanismi siano essenziali per il normale funzionamento del sistema, gli attaccanti possono abusarne per effettuare injection, eseguire codice o accedere ai dati.

### Library Injection

La Library Injection è una tecnica con cui un attaccante **costringe un processo a caricare una libreria malevola**. Una volta iniettata, la libreria viene eseguita nel contesto del processo bersaglio, garantendo all’attaccante gli stessi permessi e accessi del processo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Il Function Hooking consiste nell’**intercettare chiamate a funzioni** o messaggi all’interno del codice di un software. Collegando le funzioni, un attaccante può **modificare il comportamento** di un processo, osservare dati sensibili o persino assumere il controllo del flusso di esecuzione.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Questa pagina tratta i metadati di unwind di ARM64, i vincoli PAC di arm64e e le catene di chiamate sintetiche.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) si riferisce ai diversi metodi con cui processi separati **condividono e scambiano dati**. Sebbene l’IPC sia fondamentale per molte applicazioni legittime, può anche essere usato impropriamente per sovvertire l’isolamento dei processi, causare il leak di informazioni sensibili o compiere azioni non autorizzate.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Le applicazioni Electron eseguite con specifiche variabili d’ambiente potrebbero essere vulnerabili alla process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

È possibile usare i flag `--load-extension` e `--use-fake-ui-for-media-stream` per eseguire un **man in the browser attack**, che consente di rubare le digitazioni, il traffico e i cookie, iniettare script nelle pagine...


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

I file NIB **definiscono gli elementi dell’interfaccia utente (UI)** e le relative interazioni all’interno di un’applicazione. Tuttavia, possono **eseguire comandi arbitrari** e **Gatekeeper non impedisce** che un’applicazione già eseguita venga avviata di nuovo se un **file NIB è stato modificato**. Di conseguenza, possono essere usati per fare in modo che programmi arbitrari eseguano comandi arbitrari:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

È possibile iniettare opzioni JVM tramite **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`** e caricare un agente Java o nativo prima dell’avvio dell’applicazione.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** precarica JavaScript dell’attaccante tramite `--require` (file) o `--import data:text/javascript,…` (senza file, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carica un modulo in una REPL interattiva e **`ELECTRON_RUN_AS_NODE`** riabilita tutto questo nei binari Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

È possibile iniettare codice nelle applicazioni .NET tramite **`DOTNET_STARTUP_HOOKS`** prima di `Main`, oppure abusando delle funzionalità di debugging di .NET quando sono presenti i prerequisiti necessari.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interattivo legge **`BASH_ENV`**; le shell POSIX interattive leggono **`ENV`**; zsh legge **`$ZDOTDIR/.zshenv`**; fish legge i file di configurazione sotto **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Ognuna può eseguire un file di avvio controllato prima del comando previsto. Bash esegue anche una command substitution inserita in **`PS4`** ogni volta che xtrace è abilitato (ad esempio, tramite **`SHELLOPTS=xtrace`** ereditato):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Avviando `/bin/zsh -s`, la shell legge un programma dallo standard input. Di conseguenza, un downloader che copia un documento strutturato non attendibile nello stdin del processo figlio senza prima analizzarlo trasforma l’intero documento in codice sorgente della shell. Un loader osservato ha passato un file iCalendar pubblico attraverso una pipe anonima, una riga alla volta. I metadati del calendario non sono stati interpretati come comandi, ma zsh ha continuato fino a raggiungere le righe eseguibili inserite dopo `DESCRIPTION:`. Queste righe hanno scaricato e avviato il bundle dell’applicazione successivo. Il tipo di contenuto previsto e l’hosting attendibile del documento non lo rendevano sicuro: il confine pericoloso era il passaggio dei suoi byte a un interprete.<sup>[[5]](#references)</sup>

Le fasi correlate sono trattate in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) e [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** possono caricare configurazioni PHP controllate il cui **`auto_prepend_file`** viene eseguito prima dello script bersaglio.

[Iniezione all’avvio tramite configurazione PHP e `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

L’interprete Lua autonomo esegue codice o un `@file` da **`LUA_INIT`** (o dalla relativa variante specifica della versione) prima di elaborare lo script bersaglio.

[Iniezione all’avvio di Lua tramite `LUA_INIT` (file e codice inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** e **`R_PROFILE`** reindirizzano ai profili di avvio contenenti codice R. In alternativa, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, insieme a un percorso per la libreria R, possono caricare automaticamente un pacchetto installato.

[Profili di avvio e caricamento dei pacchetti R](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** reindirizza al depot il cui `config/startup.jl` viene eseguito automaticamente.

[Iniezione tramite `JULIA_DEPOT_PATH` e `startup.jl` di Julia](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** possono iniettare un’espressione Erlang VM **`-eval`** senza richiedere un file payload; i workload Elixir avviano comunemente la stessa VM.

[Iniezione dei flag VM di Erlang/Elixir](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** reindirizzano agli script di avvio di Octave.

[Iniezione tramite i file di avvio di GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` è un’app .NET multipiattaforma, quindi diverse variabili d’ambiente consentono l’esecuzione prima del comando: **`XDG_CONFIG_HOME`** reindirizza agli script di profilo eseguiti all’avvio, **`PSModulePath`** consente di dirottare il caricamento automatico dei moduli (un `.psm1` inserito ad arte viene eseguito all’importazione e può sostituire i cmdlet integrati) e le variabili .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** e **`DOTNET_STARTUP_HOOKS`** caricano codice dell’attaccante nel processo prima di `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Esamina le diverse opzioni per fare in modo che uno script Perl esegua codice arbitrario:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

È possibile anche abusare delle variabili d’ambiente di Ruby (**`RUBYOPT`**, **`RUBYLIB`**) per fare in modo che script arbitrari eseguano codice arbitrario:


[Opzioni di caricamento Ruby `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

La catena **`PYTHONWARNINGS`** e **`BROWSER`** della libreria standard può eseguire un comando durante l’analisi dei filtri degli avvisi. Un’alternativa basata su file consiste nel collocare `sitecustomize.py` in **`PYTHONPATH`**, in modo che la normale inizializzazione di `site` lo importi prima dello script bersaglio. **`PYTHONBREAKPOINT`** esegue una callable o un modulo scelto quando il codice raggiunge `breakpoint()`. Variabili valide solo in modalità interattiva, come **`PYTHONSTARTUP`**, hanno un’applicabilità più limitata.

Gli eseguibili compilati con **`pyinstaller`** non usano queste variabili d’ambiente, anche se vengono eseguiti con Python incorporato.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (e il fallback `EXINIT`) vengono eseguiti come comandi Ex durante un normale avvio; pertanto, `:!cmd` / `:call system(...)` consentono l’esecuzione di codice quando una vittima apre Vim/Neovim con un ambiente controllato:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Separatamente, Homebrew installa spesso Python sotto `/opt/homebrew`, dove i membri del gruppo locale `admin` potrebbero essere in grado di sostituire il launcher. Si tratta di un dirottamento di un binario scrivibile, non di un’injection tramite variabile d’ambiente; verificare proprietario e ACL prima di considerarlo sfruttabile.


## Rilevamento

### Shield

[**Shield**](https://github.com/theevilbit/Shield) è un’applicazione open source basata su **EndpointSecurity** che rileva e blocca la process injection. È un buon riferimento per capire quali segnali sono osservabili tramite Endpoint Security, poiché genera avvisi per:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variabili d’ambiente di injection** all’esecuzione di un processo: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chiamate a **`task_for_pid`**: un processo richiede la task port di un altro processo, prerequisito per iniettarvi codice.
- **Argomenti di debugging di Electron**: `--inspect`, `--inspect-brk` e `--remote-debugging-port`, che avviano un’app Electron in modalità debug e consentono a chiunque di collegarsi ed eseguire codice al suo interno.<sup>[[3]](#references)</sup>
- **Creazione di symlink/hardlink tra livelli di privilegi**: la classica primitiva «creare un link come utente normale e puntarlo a una posizione privilegiata». Si noti che **i symlink possono generare avvisi, ma non essere bloccati**: EndpointSecurity non espone la destinazione del link prima della sua creazione.

### Chiamate effettuate da altri processi

In [**questo post del blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) si spiega come sia possibile usare la funzione **`task_name_for_pid`** per ottenere informazioni su altri **processi che iniettano codice in un processo** e poi ottenere informazioni su quell’altro processo.<sup>[[4]](#references)</sup>

Per chiamare questa funzione è necessario avere lo **stesso uid** dell’utente che esegue il processo oppure essere **root** (la funzione restituisce informazioni sul processo, ma non offre un modo per iniettarvi codice).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — rilevamento open source della process injection in macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Perché le app Electron non possono conservare i tuoi segreti in modo riservato: l’opzione --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Rilevamento delle modifiche alle task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Una nuova versione del malware MacSync per macOS prende di mira gli appassionati di criptovalute e gli sviluppatori](https://securelist.com/macsync-new-version/121383/)
