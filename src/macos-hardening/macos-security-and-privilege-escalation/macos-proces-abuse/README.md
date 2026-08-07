# Abuso dei processi macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base sui processi

Un processo è un'istanza di un eseguibile in esecuzione; tuttavia, i processi non eseguono codice: lo fanno i thread. Pertanto, **i processi sono semplicemente contenitori per i thread in esecuzione** che forniscono memoria, descrittori, porte, permessi...

Tradizionalmente, i processi venivano avviati all'interno di altri processi (eccetto il PID 1) chiamando **`fork`**, che creava una copia esatta del processo corrente; quindi il **processo figlio** generalmente chiamava **`execve`** per caricare il nuovo eseguibile ed eseguirlo. Successivamente, è stato introdotto **`vfork`** per rendere questo processo più veloce senza alcuna copia della memoria.\
Poi è stato introdotto **`posix_spawn`**, che combina **`vfork`** e **`execve`** in una singola chiamata e accetta dei flag:

- `POSIX_SPAWN_RESETIDS`: Reimposta gli ID effettivi sugli ID reali
- `POSIX_SPAWN_SETPGROUP`: Imposta l'appartenenza al gruppo di processi
- `POSUX_SPAWN_SETSIGDEF`: Imposta il comportamento predefinito dei segnali
- `POSIX_SPAWN_SETSIGMASK`: Imposta la maschera dei segnali
- `POSIX_SPAWN_SETEXEC`: Esegue nello stesso processo (come `execve` con più opzioni)
- `POSIX_SPAWN_START_SUSPENDED`: Avvia in stato sospeso
- `_POSIX_SPAWN_DISABLE_ASLR`: Avvia senza ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa l'allocatore Nano di libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Consente `rwx` sui segmenti dati
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Chiude per impostazione predefinita tutte le descrizioni dei file su exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizza i bit alti dello slide ASLR

Inoltre, `posix_spawn` consente di specificare un array di **`posix_spawnattr`** che controlla alcuni aspetti del processo generato e **`posix_spawn_file_actions`** per modificare lo stato dei descrittori.

Quando un processo termina, invia il **codice di ritorno al processo padre** (se il padre è terminato, il nuovo padre è il PID 1) con il segnale `SIGCHLD`. Il padre deve ottenere questo valore chiamando `wait4()` o `waitid()` e, fino a quel momento, il processo figlio rimane in uno stato zombie, nel quale è ancora elencato ma non consuma risorse.

### PID

I PID, identificatori dei processi, identificano un processo univoco. In XNU, i **PID** sono di **64 bit**, aumentano monotonically e **non fanno mai wrap** (per evitare abusi).

### Gruppi di processi, sessioni e Coalations

I **processi** possono essere inseriti in **gruppi** per facilitarne la gestione. Ad esempio, i comandi in uno shell script si troveranno nello stesso gruppo di processi, quindi è possibile **inviare loro segnali insieme** usando, per esempio, kill.\
È anche possibile **raggruppare i processi in sessioni**. Quando un processo avvia una sessione (`setsid(2)`), i processi figli vengono inseriti nella sessione, a meno che non avviino una sessione propria.

Coalition è un altro modo per raggruppare i processi in Darwin. L'adesione di un processo a una Coalition gli consente di accedere a risorse del pool, condividendo un ledger o potendo essere soggetto a Jetsam. Le Coalition hanno ruoli diversi: Leader, XPC service, Extension.

### Credenziali e Personae

Ogni processo possiede **credenziali** che **identificano i suoi privilegi** nel sistema. Ogni processo avrà un `uid` primario e un `gid` primario (sebbene possa appartenere a diversi gruppi).\
È anche possibile modificare l'ID utente e l'ID gruppo se il binario ha il bit **`setuid/setgid`**.\
Esistono diverse funzioni per **impostare nuovi uid/gid**.

La syscall **`persona`** fornisce un insieme **alternativo** di **credenziali**. L'adozione di una persona assume contemporaneamente il suo uid, gid e le appartenenze ai gruppi. Nel [**codice sorgente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) è possibile trovare la struct:
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
2. **Creazione dei thread:** la funzione `pthread_create()` viene utilizzata per creare nuovi thread. Internamente, questa funzione chiama `bsdthread_create()`, una system call di livello inferiore specifica del kernel XNU (il kernel su cui si basa macOS). Questa system call accetta diversi flag derivati da `pthread_attr` (attributi), che specificano il comportamento del thread, incluse le policy di scheduling e la dimensione dello stack.
- **Dimensione predefinita dello stack:** la dimensione predefinita dello stack per i nuovi thread è di 512 KB, sufficiente per le operazioni tipiche, ma può essere modificata tramite gli attributi del thread se è necessario più o meno spazio.
3. **Inizializzazione del thread:** la funzione `__pthread_init()` è fondamentale durante la configurazione del thread e utilizza l'argomento `env[]` per analizzare le variabili d'ambiente, che possono includere informazioni sulla posizione e sulla dimensione dello stack.

#### Terminazione dei thread in macOS

1. **Uscita dei thread:** i thread vengono generalmente terminati chiamando `pthread_exit()`. Questa funzione consente a un thread di terminare correttamente, eseguendo la pulizia necessaria e permettendo al thread di inviare un valore di ritorno a eventuali thread in attesa tramite join.
2. **Pulizia del thread:** quando viene chiamata `pthread_exit()`, viene invocata la funzione `pthread_terminate()`, che gestisce la rimozione di tutte le strutture associate al thread. Dealloca le porte dei thread Mach (Mach è il sottosistema di comunicazione del kernel XNU) e chiama `bsdthread_terminate`, una syscall che rimuove le strutture a livello kernel associate al thread.

#### Meccanismi di sincronizzazione

Per gestire l'accesso alle risorse condivise ed evitare le race condition, macOS fornisce diverse primitive di sincronizzazione. Queste sono fondamentali negli ambienti multi-threading per garantire l'integrità dei dati e la stabilità del sistema:

1. **Mutex:**
- **Mutex regolare (Signature: 0x4D555458):** mutex standard con un'occupazione di memoria di 60 byte (56 byte per il mutex e 4 byte per la signature).
- **Fast Mutex (Signature: 0x4d55545A):** simile a un mutex regolare, ma ottimizzato per operazioni più rapide; anche la sua dimensione è di 60 byte.
2. **Variabili di condizione:**
- Utilizzate per attendere il verificarsi di determinate condizioni, con una dimensione di 44 byte (40 byte più una signature di 4 byte).
- **Attributi delle variabili di condizione (Signature: 0x434e4441):** attributi di configurazione per le variabili di condizione, con una dimensione di 12 byte.
3. **Variabile Once (Signature: 0x4f4e4345):**
- Garantisce che un blocco di codice di inizializzazione venga eseguito una sola volta. La sua dimensione è di 12 byte.
4. **Read-Write Locks:**
- Consentono più lettori o un solo writer alla volta, facilitando un accesso efficiente ai dati condivisi.
- **Read Write Lock (Signature: 0x52574c4b):** dimensione di 196 byte.
- **Read Write Lock Attributes (Signature: 0x52574c41):** attributi per i read-write lock, con una dimensione di 20 byte.

> [!TIP]
> Gli ultimi 4 byte di questi oggetti vengono utilizzati per rilevare gli overflow.

### Thread Local Variables (TLV)

Le **Thread Local Variables (TLV)** nel contesto dei file Mach-O (il formato degli eseguibili in macOS) vengono utilizzate per dichiarare variabili specifiche di **ciascun thread** in un'applicazione multi-thread. In questo modo ogni thread dispone di una propria istanza separata di una variabile, fornendo un metodo per evitare conflitti e mantenere l'integrità dei dati senza dover ricorrere a meccanismi di sincronizzazione espliciti come i mutex.

In C e nei linguaggi correlati, è possibile dichiarare una variabile thread-local utilizzando la parola chiave **`__thread`**. Ecco come funziona nel tuo esempio:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Questo frammento definisce `tlv_var` come una variabile thread-local. Ogni thread che esegue questo codice avrà la propria `tlv_var` e le modifiche apportate da un thread a `tlv_var` non influenzeranno `tlv_var` in un altro thread.

Nel binario Mach-O, i dati relativi alle variabili thread-local sono organizzati in sezioni specifiche:

- **`__DATA.__thread_vars`**: questa sezione contiene i metadati sulle variabili thread-local, come i relativi tipi e lo stato di inizializzazione.
- **`__DATA.__thread_bss`**: questa sezione viene utilizzata per le variabili thread-local non inizializzate esplicitamente. È una parte della memoria riservata ai dati inizializzati a zero.

Mach-O fornisce anche un'API specifica chiamata **`tlv_atexit`** per gestire le variabili thread-local quando un thread termina. Questa API consente di **registrare distruttori**—funzioni speciali che eseguono la pulizia dei dati thread-local quando un thread termina.

### Priorità dei thread

La comprensione delle priorità dei thread richiede di analizzare il modo in cui il sistema operativo decide quali thread eseguire e quando. Questa decisione è influenzata dal livello di priorità assegnato a ciascun thread. Nei sistemi macOS e Unix-like, questo viene gestito utilizzando concetti come `nice`, `renice` e le classi Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
- Il valore `nice` di un processo è un numero che influenza la sua priorità. Ogni processo ha un valore nice compreso tra -20 (priorità massima) e 19 (priorità minima). Il valore nice predefinito quando viene creato un processo è generalmente 0.
- Un valore nice più basso (più vicino a -20) rende un processo più "egoista", assegnandogli più tempo CPU rispetto ad altri processi con valori nice più alti.
2. **Renice:**
- `renice` è un comando utilizzato per modificare il valore nice di un processo già in esecuzione. Può essere utilizzato per regolare dinamicamente la priorità dei processi, aumentando o diminuendo l'allocazione del tempo CPU in base ai nuovi valori nice.
- Ad esempio, se un processo necessita temporaneamente di più risorse CPU, è possibile abbassare il suo valore nice utilizzando `renice`.

#### Classi Quality of Service (QoS)

Le classi QoS rappresentano un approccio più moderno alla gestione delle priorità dei thread, in particolare nei sistemi come macOS che supportano **Grand Central Dispatch (GCD)**. Le classi QoS consentono agli sviluppatori di **classificare** il lavoro in diversi livelli in base alla relativa importanza o urgenza. macOS gestisce automaticamente la prioritizzazione dei thread in base a queste classi QoS:

1. **User Interactive:**
- Questa classe è destinata alle attività che interagiscono direttamente con l'utente o richiedono risultati immediati per garantire una buona esperienza utente. Queste attività ricevono la priorità massima per mantenere reattiva l'interfaccia (ad esempio, animazioni o gestione degli eventi).
2. **User Initiated:**
- Attività avviate dall'utente per le quali si attendono risultati immediati, come l'apertura di un documento o il clic su un pulsante che richiede calcoli. Hanno una priorità alta, ma inferiore rispetto a User Interactive.
3. **Utility:**
- Queste attività sono di lunga durata e in genere mostrano un indicatore di avanzamento (ad esempio, il download di file o l'importazione di dati). Hanno una priorità inferiore rispetto alle attività avviate dall'utente e non devono terminare immediatamente.
4. **Background:**
- Questa classe è destinata alle attività eseguite in background e non visibili all'utente. Possono includere attività come indicizzazione, sincronizzazione o backup. Hanno la priorità più bassa e un impatto minimo sulle prestazioni del sistema.

Utilizzando le classi QoS, gli sviluppatori non devono gestire numeri di priorità specifici, ma possono concentrarsi sulla natura dell'attività; il sistema ottimizza di conseguenza le risorse CPU.

Inoltre, esistono diverse **politiche di scheduling dei thread** che consentono di specificare un insieme di parametri di scheduling che lo scheduler prenderà in considerazione. Questo può essere fatto utilizzando `thread_policy_[set/get]`. Ciò potrebbe essere utile negli attacchi di race condition.

## Abuso dei processi in MacOS

MacOS, come qualsiasi altro sistema operativo, fornisce diversi metodi e meccanismi che consentono ai **processi di interagire, comunicare e condividere dati**. Sebbene queste tecniche siano essenziali per il funzionamento efficiente del sistema, possono anche essere abusate dai threat actor per **eseguire attività malevole**.

### Library Injection

La Library Injection è una tecnica mediante la quale un attaccante **forza un processo a caricare una libreria malevola**. Una volta effettuata l'injection, la libreria viene eseguita nel contesto del processo target, fornendo all'attaccante gli stessi permessi e lo stesso accesso del processo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Il Function Hooking consiste nell'**intercettare le chiamate a funzioni** o i messaggi all'interno del codice di un software. Effettuando l'hooking delle funzioni, un attaccante può **modificare il comportamento** di un processo, osservare dati sensibili o persino ottenere il controllo del flusso di esecuzione.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

L'Inter Process Communication (IPC) si riferisce ai diversi metodi tramite i quali processi separati **condividono e scambiano dati**. Sebbene l'IPC sia fondamentale per molte applicazioni legittime, può anche essere utilizzata impropriamente per eludere l'isolamento dei processi, effettuare il leak di informazioni sensibili o eseguire azioni non autorizzate.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Le applicazioni Electron eseguite con specifiche variabili d'ambiente potrebbero essere vulnerabili alla process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

È possibile utilizzare i flag `--load-extension` e `--use-fake-ui-for-media-stream` per eseguire un **man in the browser attack**, che consente di rubare i keystroke, il traffico e i cookie, effettuare l'injection di script nelle pagine...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

I file NIB **definiscono gli elementi dell'interfaccia utente (UI)** e le relative interazioni all'interno di un'applicazione. Tuttavia, possono **eseguire comandi arbitrari** e **Gatekeeper non impedisce** a un'applicazione già eseguita di essere eseguita nuovamente se un **file NIB viene modificato**. Pertanto, potrebbero essere utilizzati per fare in modo che programmi arbitrari eseguano comandi arbitrari:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

È possibile abusare di alcune funzionalità di java (come la variabile d'ambiente **`_JAVA_OPTS`**) per fare in modo che un'applicazione java esegua **codice/comandi arbitrari**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

È possibile effettuare l'injection di codice nelle applicazioni .Net **abusando delle funzionalità di debugging di .Net** (non protette da misure di sicurezza di macOS come il runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Consulta diverse opzioni per fare in modo che uno script Perl esegua codice arbitrario in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

È anche possibile abusare delle variabili d'ambiente di ruby per fare in modo che script arbitrari eseguano codice arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Se la variabile d'ambiente **`PYTHONINSPECT`** è impostata, il processo python passerà a una CLI python al termine dell'esecuzione. È inoltre possibile utilizzare **`PYTHONSTARTUP`** per indicare uno script python da eseguire all'inizio di una sessione interattiva.\
Tuttavia, nota che lo script **`PYTHONSTARTUP`** non verrà eseguito quando **`PYTHONINSPECT`** crea la sessione interattiva.

Anche altre variabili d'ambiente come **`PYTHONPATH`** e **`PYTHONHOME`** potrebbero essere utili per fare in modo che un comando python esegua codice arbitrario.

Nota che gli eseguibili compilati con **`pyinstaller`** non utilizzeranno queste variabili d'ambiente, anche se vengono eseguiti utilizzando un python incorporato.

> [!CAUTION]
> Nel complesso, non sono riuscito a trovare un modo per fare in modo che python esegua codice arbitrario abusando delle variabili d'ambiente.\
> Tuttavia, la maggior parte delle persone installa pyhton utilizzando **Hombrew**, che installerà pyhton in una **posizione scrivibile** per l'utente admin predefinito. È possibile effettuare l'hijacking con qualcosa come:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Anche **root** eseguirà questo codice quando eseguirà python.


## Rilevamento

### Shield

[**Shield**](https://github.com/theevilbit/Shield) è un'applicazione open source basata su **EndpointSecurity** che rileva e blocca la process injection. È un buon riferimento per capire quali segnali siano effettivamente osservabili da ES, poiché genera alert per:<sup>[[1]](#references)[[2]](#references)</sup>

- **Variabili d'ambiente di injection** durante l'esecuzione di un processo: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chiamate **`task_for_pid`** — un processo richiede la task port di un altro processo, prerequisito per effettuare l'injection al suo interno.
- **Argomenti di debugging di Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, che avviano un'app Electron in modalità debug e consentono a chiunque di collegarsi ed eseguire codice al suo interno.<sup>[[3]](#references)</sup>
- **Creazione di symlink/hardlink tra diversi livelli di privilegio** — la classica primitiva "creare un link come utente normale e farlo puntare a una posizione privilegiata". Nota che i **symlink possono generare alert ma non essere bloccati**: EndpointSecurity non espone la destinazione del link prima della creazione.

### Chiamate effettuate da altri processi

In [**questo post del blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puoi trovare come sia possibile utilizzare la funzione **`task_name_for_pid`** per ottenere informazioni sugli altri **processi che effettuano code injection in un processo** e successivamente ottenere informazioni su tale altro processo.<sup>[[4]](#references)</sup>

Nota che per chiamare quella funzione devi avere **lo stesso uid** dell'utente che esegue il processo oppure essere **root** (e la funzione restituisce informazioni sul processo, non un metodo per effettuare code injection).

## Riferimenti

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
