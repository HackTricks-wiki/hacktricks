# App macOS - Ispezione, Debugging e Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Analisi statica

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (old jtool2)

Puoi [**scaricare disarm da qui**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Nota che **`disarm`** può funzionare anche con file IM4P compressi (come `kernelcache`) ed estrarre solo le parti necessarie o persino analizzare la parte richiesta senza estrarla.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** si trova in **macOS**, mentre **`ldid`** si trova in **iOS**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) è uno strumento utile per ispezionare i file **.pkg** (installer) e vedere cosa contengono prima di installarli.\
Questi installer includono script bash `preinstall` e `postinstall` che gli autori di malware sfruttano solitamente per **persist** **the** **malware**.

### hdiutil

Questo strumento **monta** i file immagine disco Apple (`.dmg`) per consentirne l’ispezione prima di eseguire qualsiasi cosa:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Verrà montato in `/Volumes`

### Binari packed

- Verifica l'entropia elevata
- Controlla le stringhe (se non ci sono quasi stringhe comprensibili, il binario è packed)
- Il packer UPX per macOS genera una sezione chiamata `__XHDR`.

## Analisi statica Objective-C

### Metadati

> [!CAUTION]
> Nota che i programmi scritti in Objective-C **mantengono** le dichiarazioni delle classi **quando vengono** **compilati** in [binari Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tali dichiarazioni delle classi **includono** il nome e il tipo di:

- Le interfacce definite
- I metodi delle interfacce
- Le variabili di istanza delle interfacce
- I protocolli definiti

Nota che questi nomi potrebbero essere offuscati per rendere più difficile il reverse engineering del binario.

### Chiamate di funzione

Quando viene chiamata una funzione in un binario che usa Objective-C, il codice compilato, invece di chiamare quella funzione, chiamerà **`objc_msgSend`**, che invocherà la funzione finale:

![Metadati - Chiamate di funzione: quando viene chiamata una funzione in un binario che usa Objective-C, il codice compilato, invece di chiamare quella funzione, chiamerà objc msgSend, che invocherà...](<../../../images/image (305).png>)

I parametri attesi da questa funzione sono:

- Il primo parametro (**self**) è "un puntatore che punta all'**istanza della classe che deve ricevere il messaggio**". In parole più semplici, è l'oggetto su cui viene invocato il metodo. Se il metodo è un metodo di classe, sarà un'istanza dell'oggetto classe (nel suo insieme); per un metodo di istanza, invece, self punterà a un'istanza della classe creata come oggetto.
- Il secondo parametro (**op**) è "il selettore del metodo che gestisce il messaggio". In parole più semplici, è semplicemente il **nome del metodo**.
- I parametri rimanenti sono gli eventuali **valori richiesti dal metodo** (op).

Vedi come **ottenere facilmente queste informazioni con `lldb` su ARM64** in questa pagina:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argomento**      | **Registro**                                                    | **(per) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1° argomento**  | **rdi**                                                         | **self: oggetto su cui viene invocato il metodo** |
| **2° argomento**  | **rsi**                                                         | **op: nome del metodo**                             |
| **3° argomento**  | **rdx**                                                         | **1° argomento del metodo**                         |
| **4° argomento**  | **rcx**                                                         | **2° argomento del metodo**                         |
| **5° argomento**  | **r8**                                                          | **3° argomento del metodo**                         |
| **6° argomento**  | **r9**                                                          | **4° argomento del metodo**                         |
| **7°+ argomento** | <p><strong>rsp+</strong><br><strong>(sullo stack)</strong></p> | **5°+ argomento del metodo**                        |

### Dump dei metadati Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) è uno strumento per eseguire il class-dump dei binari Objective-C. GitHub specifica le dylib, ma funziona anche con gli eseguibili.

```bash
./dynadump dump /path/to/bin
```

Al momento della stesura, questo è quello che funziona meglio.

#### Strumenti standard

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) è lo strumento originale per generare dichiarazioni delle classi, categorie e protocolli presenti nel codice formattato in Objective-C.

È vecchio e non più mantenuto, quindi probabilmente non funzionerà correttamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) è uno strumento moderno e multipiattaforma per il class dump di Objective-C. Rispetto agli strumenti esistenti, iCDump può funzionare indipendentemente dall'ecosistema Apple ed espone binding Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Analisi statica di Swift

Con i binari Swift, grazie alla compatibilità con Objective-C, a volte è possibile estrarre le dichiarazioni usando [class-dump](https://github.com/nygard/class-dump/), ma non sempre.

Con i comandi **`jtool -l`** o **`otool -l`** è possibile trovare diverse sezioni che iniziano con il prefisso **`__swift5`**:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Puoi trovare ulteriori informazioni sulle [**informazioni memorizzate in queste sezioni in questo post del blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Inoltre, **i binari Swift potrebbero contenere simboli** (per esempio, le librerie devono memorizzare i simboli affinché le relative funzioni possano essere chiamate). I **simboli di solito contengono informazioni sul nome della funzione** e sui suoi attributi, ma in un formato poco leggibile; perciò sono molto utili i **demanglers**, che possono recuperare il nome originale:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Analisi dinamica

> [!WARNING]
> **Non disabilitare SIP come passaggio predefinito per il debugging.** Le build di sviluppo con `com.apple.security.get-task-allow` possono essere sottoposte a debugging con SIP abilitato. Controlla il target con `codesign -d --entitlements :- /path/to/binary` prima di provare LLDB. Il solo entitlement del debugger non garantisce l'accesso ai target protetti da SIP.<sup>[[15]](#references)</sup>
>
> Un'app distribuita con hardened runtime di solito omette `get-task-allow` e blocca l'attach. Se possibile, usa una debug build fornita dallo sviluppatore; rifirmare una copia usa e getta può modificare il comportamento analizzato. Se per accedere a un target protetto è necessario disabilitare SIP, usa una macchina di test o una VM dedicata, anziché una macchina su cui fai affidamento.<sup>[[16]](#references)</sup>

> [!WARNING]
> Nota che per **strumentare i binari di sistema** (come `cloudconfigurationd`) su macOS, **SIP deve essere disabilitato** (rimuovere soltanto la firma non funziona).

### API

macOS espone alcune API interessanti che forniscono informazioni sui processi:

- `proc_info`: è la principale API e fornisce molte informazioni su ciascun processo. Per ottenere informazioni sugli altri processi devi essere root, ma non servono entitlement speciali né porte Mach.
- `libsysmon.dylib`: espone informazioni sui processi tramite funzioni XPC, ma chi le invoca deve avere l'entitlement `com.apple.sysmond.client`.

### Stackshot e microstackshot

Lo **stackshotting** è una tecnica usata per acquisire lo stato dei processi, inclusi gli stack delle chiamate di tutti i thread in esecuzione. È particolarmente utile per il debugging, l'analisi delle prestazioni e la comprensione del comportamento del sistema in un momento specifico. Su iOS e macOS, è possibile acquisire stackshot usando diversi strumenti e metodi, tra cui **`sample`** e **`spindump`**.

### Sysdiagnose

Questo strumento (`/usr/bini/ysdiagnose`) raccoglie fondamentalmente molte informazioni dal computer, eseguendo decine di comandi diversi come `ps`, `zprint`...

Deve essere eseguito come **root** e il daemon `/usr/libexec/sysdiagnosed` dispone di entitlement molto interessanti, come `com.apple.system-task-ports` e `get-task-allow`.

Il suo plist si trova in `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` e dichiara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: elimina i vecchi archivi in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: porta speciale 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: interfaccia in user mode tramite la classe Obj-C `Libsysdiagnose`. È possibile passare tre argomenti in un dict (`compress`, `display`, `run`)

### Unified Logs

macOS genera log dettagliati utili per analizzare il comportamento di un'applicazione.

Alcuni campi dei log contengono il tag `<private>` per nascondere informazioni che identificano l'utente o il dispositivo. Le istruzioni più datate a volte descrivono l'installazione di un certificato per rivelare questi campi; le indicazioni di debugging attuali usano invece un profilo di configurazione con ambito esplicito e `Enable-Private-Data`, oppure `OSLogPreferences` per applicazione. Il comportamento può variare in base al subsystem e alla versione di macOS. I riferimenti mantengono la discussione precedente su certificati e profili. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Pannello sinistro

Nel pannello sinistro di Hopper è possibile vedere i simboli (**Labels**) del binario, l'elenco delle procedure e delle funzioni (**Proc**) e le stringhe (**Str**). Non sono tutte le stringhe, ma quelle definite in varie parti del file Mac-O (come _cstring o `objc_methname`).

#### Pannello centrale

Nel pannello centrale è possibile vedere il **codice disassemblato**. È possibile visualizzarlo come disassemblato **grezzo**, come **grafo**, come **decompilato** o come **binario**, facendo clic sull'icona corrispondente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Facendo clic con il tasto destro su un oggetto di codice è possibile vedere i **riferimenti a/da quell'oggetto** o persino cambiarne il nome (questa funzione non è disponibile nel pseudocodice decompilato):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Inoltre, **nella parte inferiore del pannello centrale è possibile scrivere comandi Python**.

#### Pannello destro

Nel pannello destro è possibile vedere informazioni interessanti, come la **cronologia di navigazione** (per sapere come si è arrivati alla situazione corrente), il **grafo delle chiamate**, che mostra tutte le **funzioni che chiamano questa funzione** e tutte le funzioni **chiamate da questa funzione**, e le informazioni sulle **variabili locali**.

### dtrace

Consente agli utenti di accedere alle applicazioni a un **livello molto basso** e offre un modo per **tracciare** i **programmi** e persino modificarne il flusso di esecuzione. DTrace usa **probe** collocati in tutto il kernel, in posizioni come l'inizio e la fine delle chiamate di sistema.

DTrace usa la funzione **`dtrace_probe_create`** per creare un probe per ogni chiamata di sistema. Questi probe possono essere attivati nei **punti di ingresso e di uscita di ogni chiamata di sistema**. L'interazione con DTrace avviene tramite /dev/dtrace, disponibile solo per l'utente root.<sup>[[1]](#references)</sup>

> [!TIP]
> Per abilitare DTrace senza disabilitare completamente la protezione SIP, puoi eseguire in modalità Recovery: `csrutil enable --without dtrace`
>
> Puoi anche usare **`dtrace`** o **`dtruss`** sui binari che **hai compilato**.

È possibile ottenere i probe disponibili di dtrace con:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Il nome della probe è composto da quattro parti: provider, modulo, funzione e nome (`fbt:mach_kernel:ptrace:entry`). Se non si specifica una parte del nome, DTrace la considera un wildcard.

Per configurare DTrace in modo che attivi le probe e per specificare quali azioni eseguire quando vengono attivate, dovremo usare il linguaggio D.

Una spiegazione più dettagliata e altri esempi sono disponibili all’indirizzo [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Esempi

Esegui `man -k dtrace` per elencare gli **script DTrace disponibili**. Esempio: `sudo dtruss -n binary`

- In linea

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

È una funzionalità di tracing del kernel. I codici documentati si trovano in **`/usr/share/misc/trace.codes`**.

Strumenti come `latency`, `sc_usage`, `fs_usage` e `trace` la usano internamente.

Per interfacciarsi con `kdebug` si usa `sysctl` nello spazio dei nomi `kern.kdebug`; i MIB da usare si trovano in `sys/sysctl.h`, mentre le funzioni sono implementate in `bsd/kern/kdebug.c`.

Per interagire con kdebug usando un client personalizzato, in genere si seguono questi passaggi:

- Rimuovere le impostazioni esistenti con KERN_KDSETREMOVE
- Impostare il trace con KERN_KDSETBUF e KERN_KDSETUP
- Usare KERN_KDGETBUF per ottenere il numero di voci del buffer
- Recuperare il proprio client dal trace con KERN_KDPINDEX
- Abilitare il tracing con KERN_KDENABLE
- Leggere il buffer chiamando KERN_KDREADTR
- Per associare ogni thread al proprio processo, chiamare KERN_KDTHRMAP.

Per ottenere queste informazioni è possibile usare lo strumento Apple **`trace`** o lo strumento personalizzato [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Nota: Kdebug è disponibile per un solo client alla volta.** Quindi è possibile eseguire un solo strumento basato su k-debug alla volta.

### ktrace

Le API `ktrace_*` provengono da `libktrace.dylib`, che funge da wrapper per quelle di `Kdebug`. Un client può quindi chiamare `ktrace_session_create` e `ktrace_events_[single/class]` per impostare callback su codici specifici, quindi avviare il tracing con `ktrace_start`.

È possibile usare questo strumento anche con **SIP attivato**.

Come client si può usare l’utility `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Oppure `tailspin`.

### kperf

Viene utilizzato per eseguire il profiling a livello kernel ed è basato sulle callout di `Kdebug`.

In pratica, viene controllata la variabile globale `kernel_debug_active` e, se è impostata, viene chiamato `kperf_kdebug_handler` con il codice `Kdebug` e l'indirizzo del frame del kernel chiamante. Se il codice `Kdebug` corrisponde a uno di quelli selezionati, vengono eseguite le "azioni" configurate come bitmap (consulta `osfmk/kperf/action.h` per le opzioni).

Anche Kperf dispone di una tabella MIB sysctl: (come root) `sysctl kperf`. Questo codice si trova in `osfmk/kperf/kperfbsd.c`.

Inoltre, un sottoinsieme delle funzionalità di Kperf risiede in `kpc`, che fornisce informazioni sui performance counter della macchina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) è uno strumento molto utile per controllare le azioni relative ai processi eseguite da un processo (ad esempio, monitorare quali nuovi processi crea).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) è uno strumento che stampa le relazioni tra i processi.\
Devi monitorare il tuo Mac con un comando come **`sudo eslogger fork exec rename create > cap.json`** (il terminale da cui viene eseguito richiede FDA). Poi puoi caricare il file json in questo strumento per visualizzare tutte le relazioni:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) monitora eventi relativi ai file, come la creazione, la modifica e l'eliminazione.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) è uno strumento GUI con un aspetto e un'interfaccia che gli utenti Windows potrebbero riconoscere da _Procmon_ di Microsoft Sysinternals. Questo strumento consente di avviare e interrompere la registrazione di vari tipi di eventi, filtrare questi eventi per categorie come file, processi, rete, ecc. e salvare gli eventi registrati in formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fa parte degli strumenti per sviluppatori di Xcode e viene utilizzato per monitorare le prestazioni delle applicazioni, identificare i memory leak e tracciare l'attività del filesystem.

![Crescendo - Apple Instruments: Apple Instruments fa parte degli strumenti per sviluppatori di Xcode e viene utilizzato per monitorare le prestazioni delle applicazioni, identificare i memory leak e tracciare l'attività del filesystem](<../../../images/image (1138).png>)

### fs_usage

Consente di seguire le azioni eseguite dai processi:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) è utile per visualizzare le **librerie** usate da un binario, i **file** che utilizza e le connessioni di **rete**.\
Controlla inoltre i processi binari con **virustotal** e mostra informazioni sul binario.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**questo post del blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) trovi un esempio di come **eseguire il debug di un demone in esecuzione** che usava **`PT_DENY_ATTACH`** per impedire il debug anche quando SIP era disabilitato.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` è una richiesta `ptrace(2)` specifica di Darwin con valore **31** (`0x1f`); gli altri argomenti vengono ignorati. Un processo può invocarla direttamente, senza un fork, per impedire successivamente il tracing da parte del processo padre.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### Stato di XNU e ordine delle chiamate

Il risultato dipende da quale richiesta `ptrace` raggiunge per prima XNU:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB si collega per primo:** `debugserver` usa `PT_ATTACHEXC`; XNU la converte in `PT_ATTACH`, esegue l'autorizzazione `KAUTH_PROCESS_CANTRACE` e imposta `P_LTRACED` sul processo bersaglio. Una successiva `PT_DENY_ATTACH` rileva quel flag e termina il processo bersaglio con `W_EXITCODE(ENOTSUP, 0)`, normalmente mostrato da LLDB come stato **45** (`0x2d`).
- **Il processo bersaglio nega per primo:** XNU imposta `P_LNOATTACH`. Un successivo attach viene rifiutato dall'autorizzazione al tracciamento dei processi; il percorso di errore dell'attach rileva `P_LNOATTACH` e invia `SIGSEGV` al processo che esegue l'attach, il che può apparire in LLDB come una perdita della connessione a `debugserver`.

Per distinguere questi percorsi, abilita il logging di `debugserver` prima di avviare o collegarti al processo e controlla le sue richieste `ptrace`:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Identificazione statica e bypass su ARM64

Per un Mach-O ARM64 non offuscato, individua lo stub importato `_ptrace` ed esamina i punti in cui viene chiamato. Il primo argomento intero viene passato in `w0`, quindi questa sequenza rivela direttamente la richiesta anti-debug. L'assenza dell'importazione non è una prova definitiva, perché il codice può risolvere `ptrace` dinamicamente. Anche un `_sysctl` importato può indicare controlli anti-debug, sebbene anche questo possa essere risolto dinamicamente.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

Nel campione mostrato, modificare il valore immediato da `0x1f` a `0x0` cambia la richiesta in `PT_TRACE_ME` e consente al programma di continuare sotto LLDB. Si tratta di un **bypass specifico del campione**, non di un no-op generico: esamina i controlli sul valore di ritorno e il flusso di controllo del chiamante prima di scegliere se modificare la richiesta, saltare la chiamata o forzare un ritorno con esito positivo.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** è lo **strumento de facto** per il **debugging** dei binari **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Puoi impostare la sintassi Intel quando usi lldb creando un file chiamato **`.lldbinit`** nella tua cartella home con la seguente riga:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> All'interno di lldb, scarica un processo con `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Comando</strong></td><td><strong>Descrizione</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Avvia l'esecuzione, che continua fino al raggiungimento di un breakpoint o alla terminazione del processo.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Avvia l'esecuzione e si ferma al punto di ingresso.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Riprende l'esecuzione del processo sottoposto a debug.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Esegue l'istruzione successiva. Questo comando salta le chiamate di funzione.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Esegue l'istruzione successiva. A differenza del comando <code>nexti</code>, questo comando entra nelle chiamate di funzione.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Esegue le istruzioni rimanenti nella funzione corrente (frame), torna e si ferma.</td></tr>
<tr><td><strong>control + c</strong></td><td>Sospende l'esecuzione. Se il processo è stato avviato (<code>r</code>) o ripreso (<code>c</code>), il comando lo ferma nel punto in cui si trova.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Qualsiasi funzione chiamata main</p>
<p><code>b &lt;binname&gt;`main</code> # Funzione main del binario</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Funzione main del binario indicato</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Qualsiasi metodo NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Interrompi in tutte le funzioni di quella libreria</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Elenco dei breakpoint</p>
<p><code>br e/dis &lt;num&gt;</code> # Abilita/disabilita il breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Ottieni aiuto sul comando breakpoint</p>
<p><code>help memory write</code> # Ottieni aiuto per la scrittura in memoria</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Visualizza la memoria come stringa terminata da null.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Visualizza la memoria come istruzione assembly.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Visualizza la memoria come byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Stampa l'oggetto a cui fa riferimento il parametro.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
La maggior parte delle API o dei metodi Apple Objective-C restituisce oggetti, che andrebbero quindi visualizzati con il comando “print object” (<code>po</code>). Se <code>po</code> non produce un output significativo, usa <code>x/b</code>.
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Scrivi AAAA a quell'indirizzo<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Scrivi AAAA all'indirizzo
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassembla la funzione corrente</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassembla una funzione</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassembla una funzione<br>
<code>dis -c 6</code> # Disassembla sei righe<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassembla da un indirizzo all'altro<br>
<code>dis -p -c 4</code> # Inizia a disassemblare dall'indirizzo corrente</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Esamina un array di tre elementi nel registro <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Stampa una mappa della memoria del processo corrente.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Ottieni l'indirizzo di ogni simbolo di CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Quando chiami la funzione **`objc_sendMsg`**, il registro **rsi** contiene il **nome del metodo** come stringa terminata da null (“C”). Per stampare il nome tramite lldb, esegui:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-analisi dinamica

#### Rilevamento delle VM

- Il comando **`sysctl hw.model`** restituisce normalmente un identificatore del modello Mac su hardware fisico e può restituire un valore diverso in una VM.<sup>[[3]](#references)</sup>
- Modificando i valori di **`hw.logicalcpu`** e **`hw.physicalcpu`**, alcuni malware provano a rilevare se si trovano in una VM.<sup>[[4]](#references)</sup>
- Alcuni malware possono anche **rilevare** se la macchina è basata su **VMware** tramite l'indirizzo MAC (00:50:56).
- È anche possibile verificare **se un processo è sottoposto a debug** con del codice semplice, ad esempio:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Può anche invocare la system call **`ptrace`** con il flag **`PT_DENY_ATTACH`**. Consulta la [sezione PT_DENY_ATTACH](#page-title) per il comportamento di XNU dipendente dall'ordine, i log di `debugserver` e il flusso di patching ARM64.<sup>[[7]](#references)[[12]](#references)</sup>

- Può anche invocare la system call **`ptrace`** con il flag **`PT_DENY_ATTACH`**. Questo **impedisce** a un deb**u**gger di collegarsi al processo e tracciarlo.
  - Puoi verificare se la funzione **`sysctl`** o **`ptrace`** viene **importata** (ma il malware potrebbe importarla dinamicamente)
  - Come descritto in questo writeup, “[Sconfiggere le tecniche anti-debug: varianti di macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Il messaggio Process # exited with **status = 45 (0x0000002d)** è solitamente un chiaro indizio che il target di debug usa **PT_DENY_ATTACH**_”
#### Passaggio del processo tramite `fork()`

Un processo può eludere un debugger che rimane collegato al PID originale chiamando `fork()` all'avvio, terminando il processo padre (`fork()` restituisce un PID figlio positivo) e continuando la logica protetta solo nel processo figlio (`fork()` restituisce `0`). Risolvere `fork` con `dlsym(RTLD_DEFAULT, "fork")` rimuove anche il punto di chiamata diretto a `_fork`, ma questo è solo un ostacolo all'analisi: la stringa del nome del simbolo e il flusso di dati della risoluzione dinamica restano visibili nel binario Mach-O.<sup>[[13]](#references)[[14]](#references)</sup>

Su arm64, individua questo schema seguendo il flusso di dati anziché indirizzi fissi: i primi due argomenti di `dlsym` vengono passati in `x0` e `x1`, `RTLD_DEFAULT` può comparire come `-2` (ad esempio, `movn x0, #1`) e una coppia `adrp`/`add` costruisce spesso l'indirizzo della stringa `"fork"`. Dopo la `bl` allo stub di `dlsym`, segui il puntatore restituito da `x0` attraverso il controllo di null e la memorizzazione fino a una successiva `blr` indiretta. Poi segui il risultato di `fork()` in `w0`: zero seleziona la continuazione del processo figlio, mentre i valori positivi e `-1` selezionano il percorso del processo padre o di errore.<sup>[[13]](#references)[[14]](#references)</sup>

Un bypass statico consiste nel sopprimere la chiamata indiretta e forzare il controllo del risultato esistente a selezionare il percorso del processo figlio. Ad esempio, se il compilatore ha generato la sequenza mostrata sotto, applica una patch `nop` alla `blr` e all'istruzione che memorizza il risultato, fornisci un risultato sintetico pari a zero e mantieni la logica di confronto e di salto. L'applicazione prosegue quindi con il PID originale senza creare un processo figlio; i registri delle istruzioni e le destinazioni dei salti vanno adattati alla build analizzata.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

I core dump vengono creati se:

- Il sysctl `kern.coredump` è impostato su 1 (valore predefinito)
- Se il processo non è suid/sgid oppure `kern.sugid_coredump` è impostato su 1 (il valore predefinito è 0)
- Il limite `AS_CORE` consente l'operazione. È possibile impedire la creazione dei core dump chiamando `ulimit -c 0` e riabilitarla con `ulimit -c unlimited`.

In questi casi, i core dump vengono generati in base al sysctl `kern.corefile` e salvati solitamente in `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizza i processi che terminano in modo anomalo e salva un report di crash su disco**. Un report di crash contiene informazioni che possono **aiutare uno sviluppatore a diagnosticare** la causa del crash.\
Per le applicazioni e gli altri processi **in esecuzione nel contesto launchd del singolo utente**, ReportCrash viene eseguito come LaunchAgent e salva i report di crash in `~/Library/Logs/DiagnosticReports/` dell'utente.\
Per i daemon, gli altri processi **in esecuzione nel contesto launchd di sistema** e gli altri processi privilegiati, ReportCrash viene eseguito come LaunchDaemon e salva i report di crash in `/Library/Logs/DiagnosticReports` del sistema.

Se temi che i report di crash **vengano inviati ad Apple**, puoi disabilitarli. Altrimenti, i report di crash possono essere utili per **capire come è andato in crash un server**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Sospensione

Durante il fuzzing su macOS, impedisci al Mac di andare in stop:

- systemsetup -setsleep Never
- pmset, Preferenze di Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Disconnessione SSH

Se esegui il fuzzing tramite una connessione SSH, è importante assicurarsi che la sessione non termini. Modifica quindi il file sshd_config con:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Gestori interni

**Consulta la pagina seguente** per scoprire come individuare l’app responsabile della **gestione dello schema o del protocollo specificato:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerazione dei processi di rete

È utile per individuare i processi che gestiscono dati di rete:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Oppure usa `netstat` o `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzing stateful Mach IPC

I servizi Mach esposti dai daemon con privilegi sono target utili per il fuzzing quando un client non privilegiato o in sandbox può ottenere un send right. Parti dalla voce `MachServices` del daemon in launchd e usa il [workflow di analisi MIG](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) per associare gli ID dei messaggi ai relativi handler. Prima di modificare i byte, imposta un breakpoint sulla routine server MIG mentre un client normale usa il servizio e salva i messaggi di richiesta validi come input seed. Mantieni i campi obbligatori dell'header, le dimensioni dei messaggi e la disposizione dei descriptor, così le mutazioni raggiungono l'handler invece di essere rifiutate subito durante il dispatch.<sup>[[17]](#references)</sup>

Molti handler dipendono da chiamate precedenti. Fai inizializzare al harness lo stato del servizio, quindi usa ogni input di fuzzing come una sequenza di **operazioni e argomenti**: invia richieste di setup (come open o create), conserva gli identificatori restituiti e usali nelle richieste successive. In questo modo, il feedback sulla coverage può esplorare le transizioni di stato invece di imbattersi ripetutamente in un controllo su oggetti non inizializzati.<sup>[[17]](#references)</sup>

Per un target closed-source, un harness in-process che chiama la routine di dispatch MIG può essere strumentato con Jackalope/TinyInst. L'harness [CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) è un'implementazione concreta, non un harness pronto all'uso per altri servizi.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Verifica ogni crash attraverso il percorso IPC reale.** Un harness direct-dispatch salta la validazione dei messaggi Mach da parte del kernel e può produrre falsi positivi, soprattutto quando fornisce memoria out-of-line (OOL) o descriptor di porta non validi. Alloca memoria OOL di supporto valida nell'harness, quindi riproduci il testcase ridotto tramite `mach_msg` da un client con l'accesso originale al servizio e verifica che il daemon vada ancora in crash.<sup>[[17]](#references)</sup>

### Fuzzer

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funziona con gli strumenti CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

«**Funziona e basta**» con molti strumenti GUI per macOS. Alcune applicazioni hanno requisiti aggiuntivi, come nomi di file univoci, una determinata estensione o la lettura dei file dal proprio container sandbox (`~/Library/Containers/com.apple.Safari/Data`).

Alcuni esempi:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Altre informazioni sul fuzzing di macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)



## References

- [1] [Risposta agli incidenti OS X: scripting e analisi](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Estate del fuzzing: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [L'arte del malware per Mac, Volume I: analisi](https://taomm.org/)
- [4] [No Starch Press - L'arte del malware per Mac: guida all'analisi del software dannoso](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informazioni memorizzate in queste sezioni del post del blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging dei binari Apple che usano Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Come aggirare le tecniche anti-debug: varianti di ptrace su macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Log strutturati di Xcode e `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Visualizzare i dati privati nel log unificato di macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Definizioni delle richieste di `ptrace.h` di Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Implementazione di `ptrace` di Apple XNU in `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - Internals di ptrace: come impedisce l'aggancio del debugger](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - esempi di fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - Tecnica anti-debug che usa dlsym e fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Entitlement per gli strumenti di debugging](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Debugging di un'app di terze parti con protezione avanzata](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Superare la barriera del suono, parte I: fuzzing di CoreAudio con messaggi Mach](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - Harness di CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Fuzzer Jackalope](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
