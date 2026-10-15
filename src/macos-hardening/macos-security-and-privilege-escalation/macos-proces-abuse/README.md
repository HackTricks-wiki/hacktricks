# Abuso dei processi in macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base sui processi

Un processo è un'istanza di un eseguibile in esecuzione; tuttavia, i processi non eseguono codice: lo fanno i thread. Pertanto, **i processi sono solo contenitori per thread in esecuzione** che forniscono memoria, descrittori, porte, autorizzazioni...

Tradizionalmente, i processi venivano avviati all'interno di altri processi (tranne il PID 1) chiamando **`fork`**, che creava una copia esatta del processo corrente. Il **processo figlio** chiamava quindi generalmente **`execve`** per caricare il nuovo eseguibile ed eseguirlo. In seguito, è stato introdotto **`vfork`** per rendere più veloce questo processo, evitando di copiare la memoria.\
Poi è stato introdotto **`posix_spawn`**, che combina **`vfork`** ed **`execve`** in un'unica chiamata e accetta dei flag:

- `POSIX_SPAWN_RESETIDS`: Reimposta gli ID effettivi sugli ID reali
- `POSIX_SPAWN_SETPGROUP`: Imposta l'appartenenza al gruppo di processi
- `POSUX_SPAWN_SETSIGDEF`: Imposta il comportamento predefinito dei segnali
- `POSIX_SPAWN_SETSIGMASK`: Imposta la maschera dei segnali
- `POSIX_SPAWN_SETEXEC`: Esegue nello stesso processo (come `execve`, ma con più opzioni)
- `POSIX_SPAWN_START_SUSPENDED`: Avvia in stato sospeso
- `_POSIX_SPAWN_DISABLE_ASLR`: Avvia senza ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa l'allocatore Nano di libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Consente `rwx` nei segmenti di dati
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Chiude tutte le descrizioni di file per impostazione predefinita durante exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizza i bit più alti dello slide ASLR

Inoltre, `posix_spawn` accetta impostazioni **`posix_spawnattr`** che controllano vari aspetti del processo generato e voci **`posix_spawn_file_actions`** che modificano i descrittori di file.

Quando un processo termina, invia il **codice di ritorno al processo padre** (se il padre è terminato, il nuovo padre è il PID 1) con il segnale `SIGCHLD`. Il padre deve recuperare questo valore chiamando `wait4()` o `waitid()`; fino ad allora, il figlio rimane in stato zombie: è ancora elencato, ma non consuma risorse.

### PID

I PID, ovvero gli identificatori di processo, identificano un processo univoco. In XNU, i **PID** sono a **64 bit**, aumentano monotonamente e **non vanno mai in wraparound** (per evitare abusi).

### Gruppi di processi, sessioni e coalizioni

I **processi** possono essere inseriti in **gruppi** per facilitarne la gestione. Ad esempio, i comandi in uno script shell appartengono allo stesso gruppo di processi, quindi è possibile **inviare loro segnali tutti insieme**, ad esempio usando kill.\
È anche possibile **raggruppare i processi in sessioni**. Quando un processo avvia una sessione (`setsid(2)`), i processi figli vengono inseriti nella sessione, a meno che non avviino una sessione propria.

La coalizione è un altro modo di raggruppare i processi in Darwin. Un processo che entra a far parte di una coalizione può accedere alle risorse del pool, condividere un ledger o essere soggetto a Jetsam. Le coalizioni hanno ruoli diversi: Leader, servizio XPC, Extension.

### Credenziali e personae

Ogni processo detiene **credenziali** che **identificano i suoi privilegi** nel sistema. Ogni processo ha un `uid` primario e un `gid` primario (anche se può appartenere a più gruppi).\
È anche possibile cambiare l'ID utente e di gruppo se il binario ha il bit `setuid/setgid`.\
Esistono diverse funzioni per **impostare nuovi uid/gid**.

La syscall **`persona`** fornisce un insieme **alternativo** di **credenziali**. Adottare una persona significa assumere contemporaneamente il suo uid, gid e le sue appartenenze ai gruppi. Nel [**codice sorgente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) è possibile trovare la struct:

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

1. **POSIX Threads (pthreads):** macOS supporta i thread POSIX (`pthreads`), che fanno parte di un'API standard per i thread in C/C++. L'implementazione di pthreads in macOS si trova in `/usr/lib/system/libsystem_pthread.dylib` e deriva dal progetto `libpthread`, disponibile pubblicamente. Questa libreria fornisce le funzioni necessarie per creare e gestire i thread.
2. **Creazione dei thread:** La funzione `pthread_create()` viene usata per creare nuovi thread. Internamente, questa funzione richiama `bsdthread_create()`, una system call di livello inferiore specifica del kernel XNU (il kernel su cui si basa macOS). Questa system call accetta vari flag derivati da `pthread_attr` (attributi) che specificano il comportamento del thread, incluse le politiche di scheduling e la dimensione dello stack.
   - **Dimensione predefinita dello stack:** La dimensione predefinita dello stack per i nuovi thread è di 512 KB, sufficiente per le operazioni tipiche, ma può essere modificata tramite gli attributi del thread se serve più o meno spazio.
3. **Inizializzazione dei thread:** La funzione `__pthread_init()` è fondamentale durante la configurazione del thread e utilizza l'argomento `env[]` per analizzare le variabili d'ambiente, che possono includere informazioni sulla posizione e sulla dimensione dello stack.

#### Terminazione dei thread in macOS

1. **Uscita dai thread:** I thread vengono generalmente terminati chiamando `pthread_exit()`. Questa funzione consente a un thread di uscire correttamente, eseguendo le operazioni di pulizia necessarie e permettendogli di inviare un valore di ritorno a tutti i thread in attesa con `join`.
2. **Pulizia dei thread:** Quando viene chiamata `pthread_exit()`, viene invocata la funzione `pthread_terminate()`, che rimuove tutte le strutture associate al thread. Dealloca le porte del thread Mach (Mach è il sottosistema di comunicazione del kernel XNU) e richiama `bsdthread_terminate`, una syscall che rimuove le strutture a livello kernel associate al thread.

#### Meccanismi di sincronizzazione

Per gestire l'accesso alle risorse condivise ed evitare race condition, macOS offre diverse primitive di sincronizzazione. Sono essenziali negli ambienti multi-thread per garantire l'integrità dei dati e la stabilità del sistema:

1. **Mutex:**
   - **Mutex regolare (firma: 0x4D555458):** Mutex standard con un'impronta di memoria di 60 byte (56 byte per il mutex e 4 byte per la firma).
   - **Mutex rapido (firma: 0x4d55545A):** Simile a un mutex regolare, ma ottimizzato per operazioni più veloci; ha anch'esso una dimensione di 60 byte.
2. **Variabili condition:**
   - Usate per attendere il verificarsi di determinate condizioni; hanno una dimensione di 44 byte (40 byte più una firma di 4 byte).
   - **Attributi delle variabili condition (firma: 0x434e4441):** Attributi di configurazione per le variabili condition, di 12 byte.
3. **Variabile once (firma: 0x4f4e4345):**
   - Garantisce che un blocco di codice di inizializzazione venga eseguito una sola volta. Ha una dimensione di 12 byte.
4. **Lock di lettura-scrittura:**
   - Consentono più lettori o un solo scrittore alla volta, agevolando l'accesso efficiente ai dati condivisi.
   - **Lock di lettura-scrittura (firma: 0x52574c4b):** Ha una dimensione di 196 byte.
   - **Attributi del lock di lettura-scrittura (firma: 0x52574c41):** Attributi per i lock di lettura-scrittura, di 20 byte.

> [!TIP]
> Gli ultimi 4 byte di questi oggetti vengono usati per rilevare gli overflow.

### Variabili locali ai thread (TLV)

Le **variabili locali ai thread (TLV)** nei file Mach-O (il formato degli eseguibili in macOS) vengono usate per dichiarare variabili specifiche di **ciascun thread** in un'applicazione multi-thread. In questo modo ogni thread ha una propria istanza separata della variabile, evitando conflitti e preservando l'integrità dei dati senza dover ricorrere a meccanismi di sincronizzazione espliciti come i mutex.

In C e nei linguaggi correlati, è possibile dichiarare una variabile locale al thread usando la parola chiave **`__thread`**. Ecco come funziona nell'esempio:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Questo snippet definisce `tlv_var` come variabile locale al thread. Ogni thread che esegue questo codice avrà la propria `tlv_var` e le modifiche apportate da un thread a `tlv_var` non influiranno su quella degli altri thread.

Nel binario Mach-O, i dati relativi alle variabili locali al thread sono organizzati in sezioni specifiche:

- **`__DATA.__thread_vars`**: questa sezione contiene i metadati delle variabili locali al thread, come i tipi e lo stato di inizializzazione.
- **`__DATA.__thread_bss`**: questa sezione viene usata per le variabili locali al thread non inizializzate esplicitamente. È una parte della memoria riservata ai dati inizializzati a zero.

Mach-O fornisce anche un'API specifica, **`tlv_atexit`**, per gestire le variabili locali al thread quando un thread termina. Questa API consente di **registrare dei distruttori**: funzioni speciali che ripuliscono i dati locali al thread quando il thread termina.

### Priorità dei thread

Per comprendere le priorità dei thread, occorre considerare come il sistema operativo decide quali thread eseguire e quando. Questa decisione dipende dal livello di priorità assegnato a ogni thread. In macOS e nei sistemi Unix-like, si usano concetti come `nice`, `renice` e le classi Quality of Service (QoS).

#### Nice e renice

1. **Nice:**
   - Il valore `nice` di un processo è un numero che ne influenza la priorità. Ogni processo ha un valore `nice` compreso tra -20 (priorità massima) e 19 (priorità minima). Il valore `nice` predefinito alla creazione di un processo è in genere 0.
   - Un valore `nice` più basso (più vicino a -20) rende un processo più "egoista", assegnandogli più tempo CPU rispetto ai processi con valori `nice` più alti.
2. **Renice:**
   - `renice` è un comando usato per modificare il valore `nice` di un processo già in esecuzione. Consente di regolare dinamicamente la priorità dei processi, aumentando o diminuendo il tempo CPU assegnato in base ai nuovi valori `nice`.
   - Ad esempio, se un processo ha temporaneamente bisogno di più risorse CPU, si può abbassare il suo valore `nice` usando `renice`.

#### Classi Quality of Service (QoS)

Le classi QoS sono un approccio più moderno alla gestione delle priorità dei thread, in particolare nei sistemi come macOS che supportano **Grand Central Dispatch (GCD)**. Le classi QoS permettono agli sviluppatori di **classificare** le attività in base alla loro importanza o urgenza. macOS gestisce automaticamente la priorità dei thread in base a queste classi QoS:

1. **User Interactive:**
   - Questa classe è riservata alle attività che interagiscono con l'utente o richiedono risultati immediati per garantire una buona esperienza d'uso. A queste attività viene assegnata la priorità massima per mantenere reattiva l'interfaccia (ad esempio, animazioni o gestione degli eventi).
2. **User Initiated:**
   - Attività avviate dall'utente per cui sono attesi risultati immediati, come aprire un documento o fare clic su un pulsante che richiede calcoli. Hanno una priorità elevata, ma inferiore a quella di User Interactive.
3. **Utility:**
   - Attività di lunga durata che in genere mostrano un indicatore di avanzamento (ad esempio, scaricare file o importare dati). Hanno una priorità inferiore rispetto alle attività avviate dall'utente e non devono terminare immediatamente.
4. **Background:**
   - Questa classe è riservata alle attività in background, non visibili all'utente. Possono includere attività come indicizzazione, sincronizzazione o backup. Hanno la priorità più bassa e un impatto minimo sulle prestazioni del sistema.

Grazie alle classi QoS, gli sviluppatori non devono gestire i valori esatti delle priorità, ma possono concentrarsi sulla natura dell'attività; il sistema ottimizza di conseguenza le risorse CPU.

Inoltre, esistono diverse **politiche di scheduling dei thread** che specificano una serie di parametri di scheduling che lo scheduler prenderà in considerazione. È possibile configurarle usando `thread_policy_[set/get]`. Questo può essere utile negli attacchi basati su race condition.

## Abuso dei processi macOS

macOS fornisce molti meccanismi che consentono ai **processi di interagire, comunicare e condividere dati**. Sebbene siano essenziali per il normale funzionamento del sistema, gli attaccanti possono abusarne per injection, code execution o accesso ai dati.

### Library Injection

La Library Injection è una tecnica in cui un attaccante **costringe un processo a caricare una libreria malevola**. Una volta iniettata, la libreria viene eseguita nel contesto del processo bersaglio, garantendo all'attaccante gli stessi permessi e accessi del processo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Caricamento Mach-O riflessivo

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Il Function Hooking consiste nell'**intercettare le chiamate a funzioni** o i messaggi all'interno del codice di un programma. Agganciando le funzioni, un attaccante può **modificare il comportamento** di un processo, osservare dati sensibili o persino ottenere il controllo del flusso di esecuzione.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Spoofing dello stack di chiamate ARM64/ARM64e

Questa pagina tratta i metadati di unwind di ARM64, i vincoli PAC di arm64e e le catene di chiamate sintetiche.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Comunicazione tra processi

La comunicazione tra processi (IPC) comprende i diversi metodi con cui processi separati **condividono e scambiano dati**. Sebbene l'IPC sia fondamentale per molte applicazioni legittime, può anche essere usata impropriamente per eludere l'isolamento dei processi, sottrarre informazioni sensibili o eseguire azioni non autorizzate.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection nelle applicazioni Electron

Le applicazioni Electron eseguite con specifiche variabili d'ambiente possono essere vulnerabili alla process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection in Chromium

È possibile usare i flag `--load-extension` e `--use-fake-ui-for-media-stream` per eseguire un **attacco man in the browser**, che consente di rubare tasti digitati, traffico e cookie, e di iniettare script nelle pagine:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

I file NIB **definiscono gli elementi dell'interfaccia utente (UI)** e le relative interazioni all'interno di un'applicazione. Tuttavia, possono **eseguire comandi arbitrari** e **Gatekeeper non impedisce** di rieseguire un'applicazione già avviata se un **file NIB viene modificato**. Possono quindi essere usati per fare in modo che programmi arbitrari eseguano comandi arbitrari:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection nelle applicazioni Java

È possibile iniettare opzioni JVM tramite **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`** e caricare un agent Java o nativo prima dell'avvio dell'applicazione.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection in Node.js

**`NODE_OPTIONS`** precarica JavaScript controllato dall'attaccante tramite `--require` (file) o `--import data:text/javascript,…` (senza file, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carica un modulo in una REPL interattiva e **`ELECTRON_RUN_AS_NODE`** riattiva tutto questo nei binari Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection nelle applicazioni .Net

È possibile iniettare codice nelle applicazioni .NET tramite **`DOTNET_STARTUP_HOOKS`** prima di `Main`, oppure abusando delle funzionalità di debugging di .NET quando sono soddisfatti i prerequisiti.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interattiva legge **`BASH_ENV`**; le shell POSIX interattive leggono **`ENV`**; zsh legge **`$ZDOTDIR/.zshenv`**; fish legge la configurazione da **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Ognuna può eseguire un file di avvio controllato prima del comando previsto. Inoltre, Bash esegue una command substitution inserita in **`PS4`** ogni volta che xtrace è abilitato (ad esempio, tramite **`SHELLOPTS=xtrace`** ereditato):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Iniezione di comandi tramite stdin della shell

Avviare `/bin/zsh -s` fa sì che la shell legga un programma dallo standard input. Di conseguenza, se un downloader copia un documento strutturato non attendibile nello stdin del processo figlio senza prima analizzarlo, l'intero documento diventa codice sorgente della shell. Un loader osservato ha passato riga per riga un file iCalendar pubblico attraverso una pipe anonima. I metadati del calendario non sono stati interpretati come comandi, ma zsh ha continuato fino a raggiungere le righe eseguibili inserite dopo `DESCRIPTION:`. Queste righe hanno scaricato e avviato il bundle dell'applicazione successivo. Il tipo di contenuto previsto e l'hosting attendibile del contenuto trasportato non lo rendevano sicuro: il confine pericoloso era il passaggio dei suoi byte a un interprete.<sup>[[5]](#references)</sup>

Le fasi correlate sono trattate in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper e quarantine](../macos-security-protections/macos-gatekeeper.md) e [percorsi di auto-avvio di macOS](../../macos-auto-start-locations.md).

### Injection in PHP

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** possono caricare una configurazione PHP controllata il cui **`auto_prepend_file`** viene eseguito prima dello script bersaglio.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Injection in Lua

L'interprete Lua standalone esegue codice o un `@file` specificato tramite **`LUA_INIT`** (o la variante specifica della versione) prima di elaborare lo script bersaglio.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### Injection in R

**`R_PROFILE_USER`** e **`R_PROFILE`** reindirizzano ai profili di avvio contenenti codice R. In alternativa, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, insieme a un percorso per le librerie R, possono caricare automaticamente un pacchetto installato.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Injection in Julia

**`JULIA_DEPOT_PATH`** reindirizza al depot il cui `config/startup.jl` viene eseguito automaticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Injection in Erlang ed Elixir

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** possono iniettare un'espressione Erlang VM **`-eval`** senza richiedere un file payload; i carichi di lavoro Elixir avviano comunemente la stessa VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### Injection in GNU Octave

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** reindirizzano agli script di avvio di Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### Injection in PowerShell

`pwsh` è un'app .NET multipiattaforma, quindi diverse variabili d'ambiente consentono l'esecuzione prima del comando: **`XDG_CONFIG_HOME`** reindirizza agli script di profilo eseguiti all'avvio, **`PSModulePath`** consente di dirottare il caricamento automatico dei moduli (un file `.psm1` piazzato ad arte viene eseguito al momento dell'importazione e può sostituire i cmdlet integrati) e le variabili .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** e **`DOTNET_STARTUP_HOOKS`** caricano codice dell'attaccante nel processo prima di `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Injection in Perl

Verifica le diverse opzioni che consentono a uno script Perl di eseguire codice arbitrario in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Injection in Ruby

È anche possibile abusare delle variabili d'ambiente di ruby (**`RUBYOPT`**, **`RUBYLIB`**) per fare in modo che gli script eseguano codice arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Injection in Python

La catena **`PYTHONWARNINGS`** e **`BROWSER`** della standard library può eseguire un comando durante l'analisi dei filtri di warning. Un'alternativa basata su file consiste nel collocare `sitecustomize.py` in **`PYTHONPATH`**, in modo che la normale inizializzazione di `site` lo importi prima dello script bersaglio. **`PYTHONBREAKPOINT`** esegue una callable o un modulo scelto quando il codice raggiunge `breakpoint()`. Le variabili riservate all'uso interattivo, come **`PYTHONSTARTUP`**, hanno un'applicabilità più limitata.

Nota che gli eseguibili compilati con **`pyinstaller`** non usano queste variabili d'ambiente, anche se vengono eseguiti con un Python incorporato.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Injection in Vim/Neovim

**`VIMINIT`** (e il ripiego `EXINIT`) vengono eseguiti come comandi Ex durante un normale avvio; quindi, `:!cmd` / `:call system(...)` consentono la code execution quando una vittima apre Vim/Neovim in un ambiente controllato:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Separatamente, Homebrew installa spesso Python in `/opt/homebrew`, dove i membri del gruppo locale `admin` potrebbero essere in grado di sostituire il launcher. Si tratta di un hijack di un binario scrivibile, non di injection tramite variabile d'ambiente: verifica proprietario e ACL prima di considerarlo sfruttabile.


## Rilevamento

### Shield

[**Shield**](https://github.com/theevilbit/Shield) è un'applicazione open source basata su **EndpointSecurity** che rileva e blocca la process injection. È un buon riferimento per capire quali segnali sono osservabili tramite Endpoint Security, poiché genera avvisi per:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variabili d'ambiente per l'injection** all'avvio del processo: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chiamate a **`task_for_pid`**: un processo richiede la task port di un altro processo, un prerequisito per iniettarvi codice.
- **Argomenti di debugging di Electron**: `--inspect`, `--inspect-brk` e `--remote-debugging-port`, che avviano un'app Electron in modalità debug e consentono a chiunque di collegarsi ed eseguire codice al suo interno.<sup>[[3]](#references)</sup>
- **Creazione di symlink/hardlink tra livelli di privilegio**: la classica tecnica "crea un link come utente normale e puntalo a una posizione privilegiata". Nota che **è possibile generare avvisi sui symlink, ma non bloccarli**: EndpointSecurity non espone la destinazione del link prima della sua creazione.

### Chiamate effettuate da altri processi

In [**questo post del blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puoi scoprire come usare la funzione **`task_name_for_pid`** per ottenere informazioni su altri **processi che iniettano codice in un processo** e poi raccogliere informazioni su quel processo.<sup>[[4]](#references)</sup>

Nota che per chiamare questa funzione devi avere **lo stesso uid** del processo oppure essere **root** (e restituisce informazioni sul processo, non un metodo per iniettarvi codice).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — rilevamento open source della process injection in macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Perché le app Electron non possono conservare i tuoi segreti in modo riservato: opzione --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Rilevare le modifiche alle task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Una nuova versione del malware MacSync per macOS prende di mira gli appassionati di criptovalute e gli sviluppatori](https://securelist.com/macsync-new-version/121383/)
