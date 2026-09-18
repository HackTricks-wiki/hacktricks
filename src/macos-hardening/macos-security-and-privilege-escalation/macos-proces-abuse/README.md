# Abuso dei processi in macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base sui processi

Un processo è un'istanza di un eseguibile in esecuzione; tuttavia, i processi non eseguono codice: lo fanno i thread. Pertanto, **i processi sono semplicemente contenitori per i thread in esecuzione** che forniscono memoria, descrittori, porte, permessi...

Tradizionalmente, i processi venivano avviati all'interno di altri processi (eccetto PID 1) chiamando **`fork`**, che creava una copia esatta del processo corrente; quindi il **processo figlio** chiamava generalmente **`execve`** per caricare il nuovo eseguibile ed eseguirlo. In seguito è stato introdotto **`vfork`** per rendere questo processo più veloce senza copiare la memoria.\
Successivamente è stato introdotto **`posix_spawn`**, che combina **`vfork`** e **`execve`** in una sola chiamata e accetta dei flag:

- `POSIX_SPAWN_RESETIDS`: Reimposta gli ID effettivi sugli ID reali
- `POSIX_SPAWN_SETPGROUP`: Imposta l'affiliazione al gruppo di processi
- `POSUX_SPAWN_SETSIGDEF`: Imposta il comportamento predefinito dei segnali
- `POSIX_SPAWN_SETSIGMASK`: Imposta la maschera dei segnali
- `POSIX_SPAWN_SETEXEC`: Esegue nello stesso processo (come `execve`, con più opzioni)
- `POSIX_SPAWN_START_SUSPENDED`: Avvia in stato sospeso
- `_POSIX_SPAWN_DISABLE_ASLR`: Avvia senza ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa l'allocatore Nano di libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Consente `rwx` sui segmenti dati
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Chiude per impostazione predefinita tutti i descrittori di file su exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizza i bit alti dello slide di ASLR

Inoltre, `posix_spawn` accetta impostazioni **`posix_spawnattr`** che controllano vari aspetti del processo generato e voci **`posix_spawn_file_actions`** che modificano i descrittori di file.

Quando un processo termina, invia il **codice di ritorno al processo padre** (se il padre è terminato, il nuovo padre è PID 1) tramite il segnale `SIGCHLD`. Il padre deve ottenere questo valore chiamando `wait4()` o `waitid()` e, fino a quel momento, il figlio rimane in stato zombie: è ancora elencato, ma non consuma risorse.

### PID

I PID, ovvero gli identificatori dei processi, identificano un processo univoco. In XNU i **PID** sono a **64 bit**, aumentano monotonicamente e **non vanno mai in wraparound** (per evitare abusi).

### Gruppi di processi, sessioni e coalizioni

I **processi** possono essere inseriti in **gruppi** per semplificarne la gestione. Ad esempio, i comandi in uno shell script si trovano nello stesso gruppo di processi, quindi è possibile **inviare loro segnali contemporaneamente**, utilizzando ad esempio kill.\
È anche possibile **raggruppare i processi in sessioni**. Quando un processo avvia una sessione (`setsid(2)`), i processi figli vengono inseriti nella sessione, a meno che non avviino una sessione propria.

La coalizione è un altro modo per raggruppare i processi in Darwin. Un processo che entra in una coalizione può accedere alle risorse del pool, condividere un ledger o essere soggetto a Jetsam. Le coalizioni hanno ruoli diversi: Leader, servizio XPC, Extension.

### Credenziali e persona

Ogni processo possiede **credenziali** che **identificano i suoi privilegi** nel sistema. Ogni processo avrà un `uid` primario e un `gid` primario (anche se può appartenere a diversi gruppi).\
È anche possibile modificare l'ID utente e l'ID gruppo se il binario ha il bit `setuid/setgid`.\
Esistono diverse funzioni per **impostare nuovi uid/gid**.

La syscall **`persona`** fornisce un insieme **alternativo** di **credenziali**. L'adozione di una persona presuppone contemporaneamente il suo uid, gid e le sue appartenenze ai gruppi. Nel [**codice sorgente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) è possibile trovare la struct:
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

1. **POSIX Threads (pthreads):** macOS supporta i thread POSIX (`pthreads`), che fanno parte di una API standard per il threading in C/C++. L'implementazione di pthreads in macOS si trova in `/usr/lib/system/libsystem_pthread.dylib`, che deriva dal progetto `libpthread` disponibile pubblicamente. Questa libreria fornisce le funzioni necessarie per creare e gestire i thread.
2. **Creazione dei thread:** la funzione `pthread_create()` viene utilizzata per creare nuovi thread. Internamente, questa funzione chiama `bsdthread_create()`, una system call di livello inferiore specifica del kernel XNU (il kernel su cui si basa macOS). Questa system call accetta vari flag derivati da `pthread_attr` (attributi) che specificano il comportamento del thread, incluse le policy di scheduling e la dimensione dello stack.
- **Dimensione predefinita dello stack:** la dimensione predefinita dello stack per i nuovi thread è di 512 KB, sufficiente per le operazioni tipiche, ma può essere modificata tramite gli attributi del thread se è necessario più o meno spazio.
3. **Inizializzazione del thread:** la funzione `__pthread_init()` è fondamentale durante la configurazione del thread e utilizza l'argomento `env[]` per analizzare le variabili d'ambiente, che possono includere dettagli sulla posizione e sulla dimensione dello stack.

#### Terminazione dei thread in macOS

1. **Uscita dai thread:** i thread vengono generalmente terminati chiamando `pthread_exit()`. Questa funzione consente a un thread di uscire correttamente, eseguendo le operazioni di pulizia necessarie e permettendo al thread di inviare un valore di ritorno a eventuali thread in attesa tramite join.
2. **Pulizia del thread:** quando viene chiamata `pthread_exit()`, viene invocata la funzione `pthread_terminate()`, che gestisce la rimozione di tutte le strutture associate al thread. Dealloca le porte dei thread Mach (Mach è il sottosistema di comunicazione del kernel XNU) e chiama `bsdthread_terminate`, una syscall che rimuove le strutture a livello kernel associate al thread.

#### Meccanismi di sincronizzazione

Per gestire l'accesso alle risorse condivise ed evitare race condition, macOS fornisce diverse primitive di sincronizzazione. Queste sono fondamentali negli ambienti multi-threading per garantire l'integrità dei dati e la stabilità del sistema:

1. **Mutex:**
- **Mutex regolare (Signature: 0x4D555458):** mutex standard con un'occupazione di memoria di 60 byte (56 byte per il mutex e 4 byte per la signature).
- **Fast Mutex (Signature: 0x4d55545A):** simile a un mutex regolare, ma ottimizzato per operazioni più rapide; anche la sua dimensione è di 60 byte.
2. **Variabili di condizione:**
- Utilizzate per attendere il verificarsi di determinate condizioni, con una dimensione di 44 byte (40 byte più una signature di 4 byte).
- **Attributi delle variabili di condizione (Signature: 0x434e4441):** attributi di configurazione per le variabili di condizione, con una dimensione di 12 byte.
3. **Variabile Once (Signature: 0x4f4e4345):**
- Garantisce che una parte del codice di inizializzazione venga eseguita una sola volta. La sua dimensione è di 12 byte.
4. **Read-Write Locks:**
- Consentono più lettori o un solo writer alla volta, facilitando l'accesso efficiente ai dati condivisi.
- **Read Write Lock (Signature: 0x52574c4b):** ha una dimensione di 196 byte.
- **Attributi dei Read Write Lock (Signature: 0x52574c41):** attributi per i read-write lock, con una dimensione di 20 byte.

> [!TIP]
> Gli ultimi 4 byte di questi oggetti vengono utilizzati per rilevare gli overflow.

### Variabili locali dei thread (TLV)

Le **Thread Local Variables (TLV)** nel contesto dei file Mach-O (il formato degli eseguibili in macOS) vengono utilizzate per dichiarare variabili specifiche di **ogni thread** in un'applicazione multi-thread. Questo garantisce che ogni thread disponga di una propria istanza separata di una variabile, fornendo un modo per evitare conflitti e mantenere l'integrità dei dati senza dover ricorrere a meccanismi di sincronizzazione espliciti come i mutex.

In C e nei linguaggi correlati, è possibile dichiarare una variabile thread-local utilizzando la keyword **`__thread`**. Ecco come funziona nel tuo esempio:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Questo snippet definisce `tlv_var` come una variabile thread-local. Ogni thread che esegue questo codice avrà il proprio `tlv_var` e le modifiche apportate da un thread a `tlv_var` non influenzeranno `tlv_var` in un altro thread.

Nel binario Mach-O, i dati relativi alle variabili thread-local sono organizzati in sezioni specifiche:

- **`__DATA.__thread_vars`**: questa sezione contiene i metadati sulle variabili thread-local, come i relativi tipi e lo stato di inizializzazione.
- **`__DATA.__thread_bss`**: questa sezione viene utilizzata per le variabili thread-local non inizializzate esplicitamente. È una parte della memoria riservata ai dati inizializzati a zero.

Mach-O fornisce anche un'API specifica chiamata **`tlv_atexit`** per gestire le variabili thread-local quando un thread termina. Questa API consente di **registrare distruttori**, ovvero funzioni speciali che ripuliscono i dati thread-local quando un thread termina.

### Threading Priorities

Comprendere le priorità dei thread implica analizzare il modo in cui il sistema operativo decide quali thread eseguire e quando. Questa decisione è influenzata dal livello di priorità assegnato a ogni thread. Nei sistemi macOS e Unix-like, ciò viene gestito utilizzando concetti come `nice`, `renice` e le classi Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
- Il valore `nice` di un processo è un numero che influisce sulla sua priorità. Ogni processo ha un valore nice compreso tra -20 (priorità massima) e 19 (priorità minima). Il valore nice predefinito quando viene creato un processo è generalmente 0.
- Un valore nice più basso (più vicino a -20) rende un processo più "egoista", assegnandogli più tempo CPU rispetto ad altri processi con valori nice più alti.
2. **Renice:**
- `renice` è un comando utilizzato per modificare il valore nice di un processo già in esecuzione. Può essere utilizzato per regolare dinamicamente la priorità dei processi, aumentando o riducendo la quota di tempo CPU in base ai nuovi valori nice.
- Ad esempio, se un processo necessita temporaneamente di più risorse CPU, è possibile ridurre il suo valore nice utilizzando `renice`.

#### Quality of Service (QoS) Classes

Le classi QoS rappresentano un approccio più moderno alla gestione delle priorità dei thread, in particolare nei sistemi come macOS che supportano **Grand Central Dispatch (GCD)**. Le classi QoS consentono agli sviluppatori di **categorizzare** il lavoro in diversi livelli in base alla relativa importanza o urgenza. macOS gestisce automaticamente la priorità dei thread in base a queste classi QoS:

1. **User Interactive:**
- Questa classe è destinata alle attività che interagiscono attualmente con l'utente o che richiedono risultati immediati per garantire una buona esperienza utente. A queste attività viene assegnata la priorità massima per mantenere reattiva l'interfaccia (ad esempio, animazioni o gestione degli eventi).
2. **User Initiated:**
- Attività avviate dall'utente per le quali si attendono risultati immediati, come l'apertura di un documento o il clic su un pulsante che richiede elaborazioni. Hanno una priorità elevata, ma inferiore a quella di User Interactive.
3. **Utility:**
- Queste attività sono di lunga durata e in genere mostrano un indicatore di avanzamento (ad esempio, il download di file o l'importazione di dati). Hanno una priorità inferiore rispetto alle attività User Initiated e non devono terminare immediatamente.
4. **Background:**
- Questa classe è destinata alle attività eseguite in background e non visibili all'utente. Possono includere attività come indicizzazione, sincronizzazione o backup. Hanno la priorità più bassa e un impatto minimo sulle prestazioni del sistema.

Utilizzando le classi QoS, gli sviluppatori non devono gestire i numeri esatti delle priorità, ma possono concentrarsi sulla natura dell'attività, mentre il sistema ottimizza di conseguenza le risorse CPU.

Inoltre, esistono diverse **thread scheduling policies** che consentono di specificare un insieme di parametri di scheduling che lo scheduler prenderà in considerazione. Ciò può essere fatto utilizzando `thread_policy_[set/get]`. Questo può essere utile negli attacchi di race condition.

## macOS Process Abuse

macOS fornisce molti meccanismi che consentono ai **processi di interagire, comunicare e condividere dati**. Sebbene questi meccanismi siano essenziali per il normale funzionamento del sistema, gli attaccanti possono abusarne per eseguire injection, code execution o accedere ai dati.

### Library Injection

Library Injection è una tecnica in cui un attaccante **costringe un processo a caricare una libreria malevola**. Una volta effettuata l'injection, la libreria viene eseguita nel contesto del processo target, fornendo all'attaccante gli stessi permessi e lo stesso accesso del processo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste nell'**intercettare chiamate a funzioni** o messaggi all'interno del codice di un software. Effettuando hooking delle funzioni, un attaccante può **modificare il comportamento** di un processo, osservare dati sensibili o persino ottenere il controllo del flusso di esecuzione.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) si riferisce ai diversi metodi con cui processi separati **condividono e scambiano dati**. Sebbene l'IPC sia fondamentale per molte applicazioni legittime, può anche essere utilizzata impropriamente per eludere l'isolamento dei processi, causare il leak di informazioni sensibili o eseguire azioni non autorizzate.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Le applicazioni Electron eseguite con specifiche variabili env potrebbero essere vulnerabili alla process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

È possibile utilizzare i flag `--load-extension` e `--use-fake-ui-for-media-stream` per eseguire un **man in the browser attack**, consentendo di rubare keystroke, traffico e cookie, effettuare injection di script nelle pagine...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

I file NIB **definiscono gli elementi dell'interfaccia utente (UI)** e le relative interazioni all'interno di un'applicazione. Tuttavia, possono **eseguire comandi arbitrari** e **Gatekeeper non impedisce** a un'applicazione già eseguita di essere eseguita nuovamente se un **file NIB viene modificato**. Pertanto, potrebbero essere utilizzati per fare in modo che programmi arbitrari eseguano comandi arbitrari:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

È possibile effettuare injection di opzioni JVM tramite **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`** e caricare un agent Java o nativo prima dell'avvio dell'applicazione.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** precarica JavaScript dell'attaccante tramite `--require` (file) o `--import data:text/javascript,…` (fileless, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carica un modulo in una REPL interattiva e **`ELECTRON_RUN_AS_NODE`** riabilita tutto questo sui binari Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

È possibile effettuare code injection nelle applicazioni .NET tramite **`DOTNET_STARTUP_HOOKS`** prima di `Main` oppure abusando della funzionalità di debugging .NET quando sono presenti i relativi prerequisiti.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interattivo legge **`BASH_ENV`**; le shell POSIX interattive leggono **`ENV`**; zsh legge **`$ZDOTDIR/.zshenv`**; fish legge la configurazione sotto **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Ognuno di questi può eseguire un file di avvio controllato prima del comando previsto. Bash esegue inoltre una command substitution inserita in **`PS4`** ogni volta che xtrace è abilitato (ad esempio tramite **`SHELLOPTS=xtrace`** ereditato):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** possono caricare una configurazione PHP controllata, il cui **`auto_prepend_file`** viene eseguito prima dello script target.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

L'interprete Lua standalone esegue codice o un `@file` da **`LUA_INIT`** (o dalla variante specifica della versione) prima di elaborare lo script target.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** e **`R_PROFILE`** reindirizzano i profili di avvio contenenti codice R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, insieme a un percorso di libreria R, possono invece caricare automaticamente un package installato.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** reindirizza il depot il cui `config/startup.jl` viene eseguito automaticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** possono effettuare injection di un'espressione Erlang **`-eval`** senza richiedere un payload file; i workload Elixir avviano comunemente la stessa VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** reindirizzano gli script di avvio di Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` è un'app .NET multipiattaforma, quindi diverse variabili d'ambiente consentono l'esecuzione prima del comando: **`XDG_CONFIG_HOME`** reindirizza gli script dei profili eseguiti all'avvio, **`PSModulePath`** effettua l'hijacking del caricamento automatico dei moduli (un `.psm1` inserito ad arte viene eseguito al momento dell'import e può effettuare lo shadowing dei cmdlet integrati) e le variabili .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** e **`DOTNET_STARTUP_HOOKS`** caricano il codice dell'attaccante nel processo prima di `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Verificare le diverse opzioni per fare in modo che uno script Perl esegua codice arbitrario in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

È inoltre possibile abusare delle variabili env di Ruby (**`RUBYOPT`**, **`RUBYLIB`**) per fare in modo che script arbitrari eseguano codice arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

La chain della standard library **`PYTHONWARNINGS`** e **`BROWSER`** può eseguire un comando durante il parsing dei filtri degli avvisi. Un'alternativa basata su file inserisce `sitecustomize.py` in **`PYTHONPATH`**, in modo che la normale inizializzazione di `site` lo importi prima dello script target. **`PYTHONBREAKPOINT`** esegue una callable/modulo scelto quando il codice raggiunge `breakpoint()`. Le variabili esclusivamente interattive come **`PYTHONSTARTUP`** hanno un'applicabilità più limitata.

Si noti che gli eseguibili compilati con **`pyinstaller`** non utilizzeranno queste variabili d'ambiente, anche se vengono eseguiti tramite un Python embedded.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (e il relativo fallback **`EXINIT`**) viene eseguito come comandi Ex durante un normale avvio, quindi `:!cmd` / `:call system(...)` consentono la code execution quando una vittima apre Vim/Neovim con un ambiente controllato:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Separatamente, Homebrew installa comunemente Python sotto `/opt/homebrew`, dove i membri del gruppo locale `admin` potrebbero essere in grado di sostituire il launcher. Si tratta di un binary hijack scrivibile, non di una injection tramite variabili d'ambiente; verificare la proprietà e gli ACL prima di considerarlo sfruttabile.


## Rilevamento

### Shield

[**Shield**](https://github.com/theevilbit/Shield) è un'applicazione open source basata su **EndpointSecurity** che rileva e blocca la process injection. È un buon riferimento per capire quali segnali sono osservabili tramite Endpoint Security, poiché genera alert su:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variabili d'ambiente di injection** durante l'esecuzione del processo: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chiamate **`task_for_pid`** — un processo richiede il task port di un altro processo, prerequisito per effettuare injection al suo interno.
- **Argomenti di debugging Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, che avviano un'app Electron in modalità debug e consentono a chiunque di collegarsi ed eseguire codice al suo interno.<sup>[[3]](#references)</sup>
- **Creazione di symlink/hardlink tra diversi livelli di privilegio** — la classica primitiva "creare un link come utente normale e indirizzarlo a una posizione privilegiata". Si noti che è possibile generare alert sui **symlink, ma non bloccarli**: EndpointSecurity non espone la destinazione del link prima della creazione.

### Chiamate effettuate da altri processi

In [**questo blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) è possibile trovare informazioni su come utilizzare la funzione **`task_name_for_pid`** per ottenere informazioni su altri **processi che effettuano code injection in un processo** e quindi ottenere informazioni su quell'altro processo.<sup>[[4]](#references)</sup>

Si noti che per chiamare questa funzione è necessario avere **lo stesso uid** dell'utente che esegue il processo oppure essere **root** (e la funzione restituisce informazioni sul processo, non un modo per effettuare code injection).

## References

- [1] [Shield — rilevamento open source della process injection in macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Perché le app Electron non possono conservare i tuoi segreti in modo riservato: opzione --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Rilevamento delle modifiche ai task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
