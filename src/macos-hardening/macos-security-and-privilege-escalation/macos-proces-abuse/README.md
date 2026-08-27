# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base sui processi

Un processo è un'istanza di un eseguibile in esecuzione; tuttavia, i processi non eseguono codice: a farlo sono i thread. Pertanto, **i processi sono solo contenitori per i thread in esecuzione** che forniscono memoria, descrittori, porte, permessi...

Tradizionalmente, i processi venivano avviati all'interno di altri processi (tranne il PID 1) chiamando **`fork`**, che creava una copia esatta del processo corrente; quindi il **processo figlio** chiamava generalmente **`execve`** per caricare il nuovo eseguibile ed eseguirlo. In seguito è stato introdotto **`vfork`** per rendere questo processo più veloce senza copiare la memoria.\
Successivamente è stato introdotto **`posix_spawn`**, che combina **`vfork`** e **`execve`** in una singola chiamata e accetta dei flag:

- `POSIX_SPAWN_RESETIDS`: Reimposta gli id effettivi agli id reali
- `POSIX_SPAWN_SETPGROUP`: Imposta l'appartenenza al gruppo di processi
- `POSUX_SPAWN_SETSIGDEF`: Imposta il comportamento predefinito dei segnali
- `POSIX_SPAWN_SETSIGMASK`: Imposta la maschera dei segnali
- `POSIX_SPAWN_SETEXEC`: Esegue nello stesso processo (come `execve`, con più opzioni)
- `POSIX_SPAWN_START_SUSPENDED`: Avvia in modalità sospesa
- `_POSIX_SPAWN_DISABLE_ASLR`: Avvia senza ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa l'allocatore Nano di libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Consente `rwx` sui segmenti dati
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Chiude per impostazione predefinita tutte le descrizioni dei file su exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizza i bit alti dello slide di ASLR

Inoltre, `posix_spawn` accetta impostazioni **`posix_spawnattr`** che controllano alcuni aspetti del processo generato e voci **`posix_spawn_file_actions`** che modificano i descrittori dei file.

Quando un processo termina, invia il **codice di ritorno al processo padre** (se il padre è terminato, il nuovo padre è il PID 1) con il segnale `SIGCHLD`. Il padre deve ottenere questo valore chiamando `wait4()` o `waitid()`; fino a quel momento, il processo figlio rimane in uno stato zombie, in cui è ancora elencato ma non consuma risorse.

### PID

I PID, ovvero gli identificatori dei processi, identificano un processo univoco. In XNU i **PID** sono valori a **64 bit**, aumentano monotonicamente e **non effettuano mai il wrapping** (per evitare abusi).

### Gruppi di processi, sessioni e Coalitions

I **processi** possono essere inseriti in **gruppi** per facilitarne la gestione. Ad esempio, i comandi in uno shell script si trovano nello stesso gruppo di processi, quindi è possibile **inviare loro segnali insieme** utilizzando, per esempio, kill.\
È anche possibile **raggruppare i processi in sessioni**. Quando un processo avvia una sessione (`setsid(2)`), i processi figli vengono inseriti nella sessione, a meno che non avviino una sessione propria.

Coalition è un altro modo per raggruppare i processi in Darwin. L'ingresso di un processo in una Coalition gli consente di accedere a risorse condivise del pool, condividendo un ledger o subendo Jetsam. Le Coalition hanno ruoli diversi: Leader, XPC service, Extension.

### Credenziali e Personae

Ogni processo possiede **credenziali** che **identificano i suoi privilegi** nel sistema. Ogni processo ha un `uid` primario e un `gid` primario (anche se può appartenere a diversi gruppi).\
È anche possibile modificare l'id dell'utente e del gruppo se il binario ha il bit `setuid/setgid`.\
Esistono diverse funzioni per **impostare nuovi uid/gid**.

La syscall **`persona`** fornisce un insieme **alternativo** di **credenziali**. L'adozione di una persona assume contemporaneamente il relativo uid, gid e le appartenenze ai gruppi. Nel [**codice sorgente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) è possibile trovare la struct:
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

1. **POSIX Threads (pthreads):** macOS supporta i thread POSIX (`pthreads`), che fanno parte di un'API standard per il threading in C/C++. L'implementazione di pthreads in macOS si trova in `/usr/lib/system/libsystem_pthread.dylib`, che deriva dal progetto `libpthread` disponibile pubblicamente. Questa libreria fornisce le funzioni necessarie per creare e gestire i thread.
2. **Creazione dei thread:** la funzione `pthread_create()` viene utilizzata per creare nuovi thread. Internamente, questa funzione chiama `bsdthread_create()`, una system call di livello inferiore specifica del kernel XNU (il kernel su cui si basa macOS). Questa system call accetta vari flag derivati da `pthread_attr` (attributi) che specificano il comportamento del thread, incluse le policy di scheduling e la dimensione dello stack.
- **Dimensione predefinita dello stack:** la dimensione predefinita dello stack per i nuovi thread è di 512 KB, sufficiente per le operazioni tipiche, ma può essere modificata tramite gli attributi del thread se è necessario più o meno spazio.
3. **Inizializzazione dei thread:** la funzione `__pthread_init()` è fondamentale durante la configurazione del thread e utilizza l'argomento `env[]` per analizzare le variabili d'ambiente, che possono includere dettagli sulla posizione e sulla dimensione dello stack.

#### Terminazione dei thread in macOS

1. **Uscita dai thread:** i thread vengono generalmente terminati chiamando `pthread_exit()`. Questa funzione consente a un thread di terminare correttamente, eseguendo le operazioni di pulizia necessarie e permettendogli di inviare un valore di ritorno a eventuali thread che eseguono il join.
2. **Pulizia dei thread:** quando viene chiamata `pthread_exit()`, viene invocata la funzione `pthread_terminate()`, che gestisce la rimozione di tutte le strutture associate al thread. Dealloca le porte dei thread Mach (Mach è il sottosistema di comunicazione del kernel XNU) e chiama `bsdthread_terminate`, una syscall che rimuove le strutture a livello kernel associate al thread.

#### Meccanismi di sincronizzazione

Per gestire l'accesso alle risorse condivise ed evitare le race condition, macOS fornisce diverse primitive di sincronizzazione. Queste sono fondamentali negli ambienti multi-threading per garantire l'integrità dei dati e la stabilità del sistema:

1. **Mutex:**
- **Mutex regolare (Signature: 0x4D555458):** mutex standard con un'occupazione di memoria di 60 byte (56 byte per il mutex e 4 byte per la signature).
- **Fast Mutex (Signature: 0x4d55545A):** simile a un mutex regolare, ma ottimizzato per operazioni più rapide, anch'esso di 60 byte.
2. **Variabili di condizione:**
- Utilizzate per attendere il verificarsi di determinate condizioni, con una dimensione di 44 byte (40 byte più una signature di 4 byte).
- **Attributi delle variabili di condizione (Signature: 0x434e4441):** attributi di configurazione per le variabili di condizione, con una dimensione di 12 byte.
3. **Variabile Once (Signature: 0x4f4e4345):**
- Garantisce che una parte del codice di inizializzazione venga eseguita una sola volta. La sua dimensione è di 12 byte.
4. **Read-Write Locks:**
- Consentono più lettori o un solo writer alla volta, facilitando l'accesso efficiente ai dati condivisi.
- **Read Write Lock (Signature: 0x52574c4b):** con una dimensione di 196 byte.
- **Read Write Lock Attributes (Signature: 0x52574c41):** attributi per i read-write lock, con una dimensione di 20 byte.

> [!TIP]
> Gli ultimi 4 byte di questi oggetti vengono utilizzati per rilevare gli overflow.

### Thread Local Variables (TLV)

Le **Thread Local Variables (TLV)** nel contesto dei file Mach-O (il formato degli eseguibili in macOS) vengono utilizzate per dichiarare variabili specifiche per **ogni thread** in un'applicazione multi-thread. Questo garantisce che ogni thread disponga di una propria istanza separata di una variabile, offrendo un modo per evitare conflitti e mantenere l'integrità dei dati senza dover utilizzare meccanismi di sincronizzazione espliciti come i mutex.

In C e nei linguaggi correlati, è possibile dichiarare una variabile thread-local utilizzando la keyword **`__thread`**. Ecco come funziona nel tuo esempio:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Questo snippet definisce `tlv_var` come una variabile thread-local. Ogni thread che esegue questo codice avrà il proprio `tlv_var` e le modifiche apportate da un thread a `tlv_var` non influenzeranno il valore di `tlv_var` in un altro thread.

Nel binario Mach-O, i dati relativi alle variabili thread-local sono organizzati in sezioni specifiche:

- **`__DATA.__thread_vars`**: questa sezione contiene i metadati sulle variabili thread-local, come i relativi tipi e lo stato di inizializzazione.
- **`__DATA.__thread_bss`**: questa sezione viene utilizzata per le variabili thread-local non inizializzate esplicitamente. È una parte della memoria riservata ai dati inizializzati a zero.

Mach-O fornisce inoltre un'API specifica chiamata **`tlv_atexit`** per gestire le variabili thread-local quando un thread termina. Questa API consente di **registrare i distruttori** — funzioni speciali che puliscono i dati thread-local quando un thread termina.

### Threading Priorities

Comprendere le priorità dei thread richiede esaminare come il sistema operativo decide quali thread eseguire e quando. Questa decisione è influenzata dal livello di priorità assegnato a ciascun thread. In macOS e nei sistemi Unix-like, questo viene gestito tramite concetti come `nice`, `renice` e le classi Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
- Il valore `nice` di un processo è un numero che ne influenza la priorità. Ogni processo ha un valore nice compreso tra -20 (priorità più alta) e 19 (priorità più bassa). Il valore nice predefinito quando viene creato un processo è generalmente 0.
- Un valore nice più basso (più vicino a -20) rende un processo più "egoista", assegnandogli più tempo CPU rispetto ad altri processi con valori nice più alti.
2. **Renice:**
- `renice` è un comando utilizzato per modificare il valore nice di un processo già in esecuzione. Può essere utilizzato per regolare dinamicamente la priorità dei processi, aumentando o diminuendo la quantità di tempo CPU assegnata in base ai nuovi valori nice.
- Ad esempio, se un processo necessita temporaneamente di più risorse CPU, è possibile ridurne il valore nice utilizzando `renice`.

#### Classi Quality of Service (QoS)

Le classi QoS sono un approccio più moderno alla gestione delle priorità dei thread, in particolare nei sistemi come macOS che supportano **Grand Central Dispatch (GCD)**. Le classi QoS consentono agli sviluppatori di **classificare** il lavoro in diversi livelli in base alla relativa importanza o urgenza. macOS gestisce automaticamente la priorità dei thread in base a queste classi QoS:

1. **User Interactive:**
- Questa classe è destinata alle attività che interagiscono con l'utente o che richiedono risultati immediati per garantire una buona esperienza d'uso. A queste attività viene assegnata la priorità più alta per mantenere reattiva l'interfaccia (ad esempio, animazioni o gestione degli eventi).
2. **User Initiated:**
- Attività avviate dall'utente per le quali si attendono risultati immediati, come l'apertura di un documento o il clic su un pulsante che richiede l'esecuzione di calcoli. Hanno priorità alta, ma inferiore a User Interactive.
3. **Utility:**
- Queste attività sono di lunga durata e in genere mostrano un indicatore di avanzamento (ad esempio, download di file o importazione di dati). Hanno una priorità inferiore rispetto alle attività avviate dall'utente e non devono terminare immediatamente.
4. **Background:**
- Questa classe è destinata alle attività eseguite in background e non visibili all'utente. Può trattarsi di attività come indicizzazione, sincronizzazione o backup. Hanno la priorità più bassa e un impatto minimo sulle prestazioni del sistema.

Utilizzando le classi QoS, gli sviluppatori non devono gestire i valori numerici esatti delle priorità, ma possono concentrarsi sulla natura dell'attività; il sistema ottimizza di conseguenza le risorse CPU.

Inoltre, esistono diverse **thread scheduling policies** che consentono di specificare un insieme di parametri di scheduling che lo scheduler prenderà in considerazione. È possibile farlo utilizzando `thread_policy_[set/get]`. Questo può essere utile negli attacchi basati su race condition.

## macOS Process Abuse

macOS fornisce molti meccanismi che consentono ai **processi di interagire, comunicare e condividere dati**. Sebbene questi meccanismi siano essenziali per il normale funzionamento del sistema, gli attaccanti possono abusarne per eseguire injection, code execution o accedere ai dati.

### Library Injection

Library Injection è una tecnica con cui un attaccante **forza un processo a caricare una libreria malevola**. Una volta eseguita l'injection, la libreria viene eseguita nel contesto del processo target, fornendo all'attaccante gli stessi permessi e lo stesso accesso del processo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste nell'**intercettare chiamate a funzioni** o messaggi all'interno del codice software. Eseguendo hooking sulle funzioni, un attaccante può **modificare il comportamento** di un processo, osservare dati sensibili o persino ottenere il controllo del flusso di esecuzione.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) si riferisce ai diversi metodi con cui processi separati **condividono e scambiano dati**. Sebbene l'IPC sia fondamentale per molte applicazioni legittime, può anche essere utilizzato impropriamente per aggirare l'isolamento dei processi, effettuare leak di informazioni sensibili o eseguire azioni non autorizzate.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Le applicazioni Electron eseguite con specifiche variabili d'ambiente potrebbero essere vulnerabili a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

È possibile utilizzare i flag `--load-extension` e `--use-fake-ui-for-media-stream` per eseguire un **man in the browser attack**, consentendo di rubare keystroke, traffico e cookie, nonché di iniettare script nelle pagine...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

I file NIB **definiscono gli elementi dell'interfaccia utente (UI)** e le relative interazioni all'interno di un'applicazione. Tuttavia, possono **eseguire comandi arbitrari** e **Gatekeeper non impedisce** a un'applicazione già eseguita di essere eseguita nuovamente se un **file NIB viene modificato**. Pertanto, potrebbero essere utilizzati per fare in modo che programmi arbitrari eseguano comandi arbitrari:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

È possibile iniettare opzioni JVM tramite **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`** e caricare un agent Java o nativo prima dell'avvio dell'applicazione.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

È possibile iniettare codice nelle applicazioni .NET tramite **`DOTNET_STARTUP_HOOKS`** prima di `Main`, oppure abusando delle funzionalità di debugging di .NET quando i relativi prerequisiti sono presenti.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interattivo legge **`BASH_ENV`**; zsh legge **`$ZDOTDIR/.zshenv`**; fish legge la configurazione sotto **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Ognuno di questi può eseguire un file di startup controllato prima del comando previsto:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** possono caricare una configurazione PHP controllata il cui **`auto_prepend_file`** viene eseguito prima dello script target.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

L'interprete Lua standalone esegue codice o un `@file` da **`LUA_INIT`** (o dalla relativa variante specifica per versione) prima di elaborare lo script target.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** e **`R_PROFILE`** reindirizzano i profili di startup contenenti codice R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, insieme a un percorso per le librerie R, possono invece caricare automaticamente un package installato.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** reindirizza il depot il cui `config/startup.jl` viene eseguito automaticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** possono iniettare un'espressione Erlang **`-eval`** senza richiedere un payload file; i workload Elixir avviano comunemente la stessa VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** reindirizzano gli script di startup di Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

Su macOS e Linux, **`XDG_CONFIG_HOME`** può reindirizzare i profili utente di PowerShell, che vengono eseguiti all'avvio di `pwsh`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Verifica le diverse opzioni per fare in modo che uno script Perl esegua codice arbitrario in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

È anche possibile abusare delle variabili d'ambiente di ruby per fare in modo che script arbitrari eseguano codice arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

La catena della standard library composta da **`PYTHONWARNINGS`** e **`BROWSER`** può eseguire un comando durante il parsing dei filtri degli avvisi. Un'alternativa basata su file colloca `sitecustomize.py` in **`PYTHONPATH`**, in modo che la normale inizializzazione di `site` lo importi prima dello script target. Le variabili utilizzabili solo in modalità interattiva, come **`PYTHONSTARTUP`**, hanno un'applicabilità più limitata.

Nota che gli eseguibili compilati con **`pyinstaller`** non utilizzano queste variabili d'ambiente, anche se vengono eseguiti tramite Python embedded.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Separatamente, Homebrew installa comunemente Python sotto `/opt/homebrew`, dove i membri del gruppo locale `admin` potrebbero essere in grado di sostituire il launcher. Si tratta di un hijack di un binary scrivibile, non di environment-variable injection; verifica ownership e ACL prima di considerarlo sfruttabile.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) è un'applicazione open-source basata su **EndpointSecurity** che rileva e blocca la process injection. È un buon riferimento per comprendere quali segnali siano osservabili tramite Endpoint Security, poiché genera alert su:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variabili d'ambiente di injection** durante l'esecuzione del processo: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ed `ELECTRON_RUN_AS_NODE`.
- Chiamate **`task_for_pid`** — un processo richiede il task port di un altro processo, prerequisito per eseguire injection al suo interno.
- **Argomenti di debugging di Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, che avviano un'app Electron in modalità debug e consentono a chiunque di collegarsi ed eseguire codice al suo interno.<sup>[[3]](#references)</sup>
- **Creazione di symlink/hardlink tra diversi livelli di privilegio** — la classica primitiva "creare un link come utente normale e indirizzarlo a una posizione privilegiata". Nota che gli **symlink possono generare alert ma non essere bloccati**: EndpointSecurity non espone la destinazione del link prima della creazione.

### Calls made by other processes

In [**questo post del blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puoi trovare informazioni su come utilizzare la funzione **`task_name_for_pid`** per ottenere informazioni sugli altri **processi che iniettano codice in un processo** e quindi acquisire informazioni su quell'altro processo.<sup>[[4]](#references)</sup>

Nota che per chiamare questa funzione è necessario avere **lo stesso uid** dell'utente che esegue il processo oppure essere **root** (e la funzione restituisce informazioni sul processo, non un metodo per iniettare codice).

## References

- [1] [Shield — rilevamento open-source della process injection in macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Perché le app Electron non possono conservare i tuoi segreti in modo riservato: opzione --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Rilevamento delle modifiche ai task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
