# macOS Apps - Ispezione, debug e Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Analisi Statica

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
### jtool2 & Disarm

Puoi [**scaricare disarm da qui**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Puoi [**scaricare jtool2 qui**](http://www.newosxbook.com/tools/jtool.html) o installarlo con `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool è deprecato a favore di disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** si trova in **macOS** mentre **`ldid`** si trova in **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) è uno strumento utile per ispezionare i file **.pkg** (installer) e vedere cosa c'è dentro prima di installarli.\
Questi installer hanno script bash `preinstall` e `postinstall` che gli autori di malware di solito abusano per **persist** **il** **malware**.

### hdiutil

Questo strumento consente di **mount** le immagini disco Apple (**.dmg**) per ispezionarle prima di eseguire qualsiasi cosa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Sarà montato in `/Volumes`

### Binarie impacchettate

- Controlla l'alta entropia
- Controlla le stringhe (se ci sono quasi nessuna stringa comprensibile, impacchettato)
- Il pacchetto UPX per MacOS genera una sezione chiamata "\_\_XHDR"

## Analisi statica di Objective-C

### Metadati

> [!CAUTION]
> Nota che i programmi scritti in Objective-C **mantengono** le loro dichiarazioni di classe **quando** **compilati** in [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tali dichiarazioni di classe **includono** il nome e il tipo di:

- Le interfacce definite
- I metodi dell'interfaccia
- Le variabili di istanza dell'interfaccia
- I protocolli definiti

Nota che questi nomi potrebbero essere offuscati per rendere più difficile il reverse engineering del binario.

### Chiamata di funzione

Quando una funzione viene chiamata in un binario che utilizza Objective-C, il codice compilato invece di chiamare quella funzione, chiamerà **`objc_msgSend`**. Che chiamerà la funzione finale:

![](<../../../images/image (305).png>)

I parametri che questa funzione si aspetta sono:

- Il primo parametro (**self**) è "un puntatore che punta all'**istanza della classe che deve ricevere il messaggio**". In altre parole, è l'oggetto su cui viene invocato il metodo. Se il metodo è un metodo di classe, questo sarà un'istanza dell'oggetto classe (nel suo insieme), mentre per un metodo di istanza, self punterà a un'istanza instanziata della classe come oggetto.
- Il secondo parametro, (**op**), è "il selettore del metodo che gestisce il messaggio". Ancora una volta, in termini più semplici, questo è solo il **nome del metodo.**
- I parametri rimanenti sono eventuali **valori richiesti dal metodo** (op).

Vedi come **ottenere queste informazioni facilmente con `lldb` in ARM64** in questa pagina:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argomento**     | **Registro**                                                   | **(per) objc_msgSend**                                 |
| ----------------- | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1° argomento**  | **rdi**                                                        | **self: oggetto su cui viene invocato il metodo**     |
| **2° argomento**  | **rsi**                                                        | **op: nome del metodo**                                |
| **3° argomento**  | **rdx**                                                        | **1° argomento al metodo**                             |
| **4° argomento**  | **rcx**                                                        | **2° argomento al metodo**                             |
| **5° argomento**  | **r8**                                                         | **3° argomento al metodo**                             |
| **6° argomento**  | **r9**                                                         | **4° argomento al metodo**                             |
| **7°+ argomento** | <p><strong>rsp+</strong><br><strong>(sullo stack)</strong></p> | **5°+ argomento al metodo**                            |

### Dump dei metadati di ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) è uno strumento per il class-dump di binari Objective-C. Il github specifica dylibs ma funziona anche con eseguibili.
```bash
./dynadump dump /path/to/bin
```
Al momento della scrittura, questo è **attualmente quello che funziona meglio**.

#### Strumenti regolari
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) è lo strumento originale per generare dichiarazioni per le classi, categorie e protocolli nel codice formattato in ObjectiveC.

È vecchio e non mantenuto, quindi probabilmente non funzionerà correttamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) è un dump di classi Objective-C moderno e multipiattaforma. Rispetto agli strumenti esistenti, iCDump può funzionare indipendentemente dall'ecosistema Apple ed espone binding Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Analisi statica di Swift

Con i binari Swift, poiché c'è compatibilità con Objective-C, a volte puoi estrarre dichiarazioni utilizzando [class-dump](https://github.com/nygard/class-dump/) ma non sempre.

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
Puoi trovare ulteriori informazioni sulle [**informazioni memorizzate in queste sezioni in questo post del blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Inoltre, **i binari Swift potrebbero avere simboli** (ad esempio, le librerie devono memorizzare simboli affinché le loro funzioni possano essere chiamate). I **simboli di solito contengono informazioni sul nome della funzione** e sugli attributi in un modo poco chiaro, quindi sono molto utili e ci sono "**demanglers"** che possono ottenere il nome originale:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Analisi Dinamica

> [!WARNING]
> Nota che per eseguire il debug dei binari, **SIP deve essere disabilitato** (`csrutil disable` o `csrutil enable --without debug`) oppure copiare i binari in una cartella temporanea e **rimuovere la firma** con `codesign --remove-signature <binary-path>` o consentire il debug del binario (puoi usare [questo script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Nota che per **strumentare i binari di sistema**, (come `cloudconfigurationd`) su macOS, **SIP deve essere disabilitato** (rimuovere solo la firma non funzionerà).

### API

macOS espone alcune API interessanti che forniscono informazioni sui processi:

- `proc_info`: Questo è il principale che fornisce molte informazioni su ciascun processo. Devi essere root per ottenere informazioni su altri processi, ma non hai bisogno di diritti speciali o porte mach.
- `libsysmon.dylib`: Consente di ottenere informazioni sui processi tramite funzioni esposte da XPC, tuttavia, è necessario avere il diritto `com.apple.sysmond.client`.

### Stackshot e microstackshots

**Stackshotting** è una tecnica utilizzata per catturare lo stato dei processi, inclusi gli stack di chiamate di tutti i thread in esecuzione. Questo è particolarmente utile per il debug, l'analisi delle prestazioni e la comprensione del comportamento del sistema in un momento specifico. Su iOS e macOS, lo stackshotting può essere eseguito utilizzando diversi strumenti e metodi come gli strumenti **`sample`** e **`spindump`**.

### Sysdiagnose

Questo strumento (`/usr/bini/ysdiagnose`) raccoglie fondamentalmente molte informazioni dal tuo computer eseguendo decine di comandi diversi come `ps`, `zprint`...

Deve essere eseguito come **root** e il demone `/usr/libexec/sysdiagnosed` ha diritti molto interessanti come `com.apple.system-task-ports` e `get-task-allow`.

Il suo plist si trova in `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` che dichiara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Elimina vecchi archivi in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Porta speciale 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfaccia in modalità utente tramite la classe Obj-C `Libsysdiagnose`. Tre argomenti in un dizionario possono essere passati (`compress`, `display`, `run`)

### Log Unificati

MacOS genera molti log che possono essere molto utili quando si esegue un'applicazione cercando di capire **cosa sta facendo**.

Inoltre, ci sono alcuni log che conterranno il tag `<private>` per **nascondere** alcune informazioni **identificabili** dell'**utente** o del **computer**. Tuttavia, è possibile **installare un certificato per rivelare queste informazioni**. Segui le spiegazioni da [**qui**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Pannello sinistro

Nel pannello sinistro di Hopper è possibile vedere i simboli (**Labels**) del binario, l'elenco delle procedure e delle funzioni (**Proc**) e le stringhe (**Str**). Queste non sono tutte le stringhe, ma quelle definite in diverse parti del file Mac-O (come _cstring o_ `objc_methname`).

#### Pannello centrale

Nel pannello centrale puoi vedere il **codice disassemblato**. E puoi vederlo in un disassemblaggio **grezzo**, come **grafico**, come **decompilato** e come **binario** cliccando sull'icona rispettiva:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Facendo clic destro su un oggetto di codice puoi vedere **riferimenti a/da quell'oggetto** o persino cambiare il suo nome (questo non funziona nel pseudocodice decompilato):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Inoltre, nella **parte centrale in basso puoi scrivere comandi python**.

#### Pannello destro

Nel pannello destro puoi vedere informazioni interessanti come la **cronologia di navigazione** (così sai come sei arrivato alla situazione attuale), il **grafico delle chiamate** dove puoi vedere tutte le **funzioni che chiamano questa funzione** e tutte le funzioni che **questa funzione chiama**, e informazioni sulle **variabili locali**.

### dtrace

Consente agli utenti di accedere alle applicazioni a un livello estremamente **basso** e fornisce un modo per gli utenti di **tracciare** **programmi** e persino cambiare il loro flusso di esecuzione. Dtrace utilizza **probes** che sono **posizionati in tutto il kernel** e si trovano in posizioni come l'inizio e la fine delle chiamate di sistema.

DTrace utilizza la funzione **`dtrace_probe_create`** per creare una sonda per ciascuna chiamata di sistema. Queste sonde possono essere attivate nel **punto di ingresso e uscita di ciascuna chiamata di sistema**. L'interazione con DTrace avviene tramite /dev/dtrace che è disponibile solo per l'utente root.

> [!TIP]
> Per abilitare Dtrace senza disabilitare completamente la protezione SIP, puoi eseguire in modalità di recupero: `csrutil enable --without dtrace`
>
> Puoi anche **`dtrace`** o **`dtruss`** binari che **hai compilato**.

Le sonde disponibili di dtrace possono essere ottenute con:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Il nome della sonda è composto da quattro parti: il fornitore, il modulo, la funzione e il nome (`fbt:mach_kernel:ptrace:entry`). Se non specifichi alcune parti del nome, Dtrace applicherà quella parte come un carattere jolly.

Per configurare DTrace per attivare le sonde e specificare quali azioni eseguire quando si attivano, dovremo utilizzare il linguaggio D.

Una spiegazione più dettagliata e ulteriori esempi possono essere trovati in [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

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

È una struttura di tracciamento del kernel. I codici documentati possono essere trovati in **`/usr/share/misc/trace.codes`**.

Strumenti come `latency`, `sc_usage`, `fs_usage` e `trace` lo utilizzano internamente.

Per interfacciarsi con `kdebug`, si utilizza `sysctl` sul namespace `kern.kdebug` e i MIB da utilizzare possono essere trovati in `sys/sysctl.h`, con le funzioni implementate in `bsd/kern/kdebug.c`.

Per interagire con kdebug con un client personalizzato, questi sono solitamente i passaggi:

- Rimuovere le impostazioni esistenti con KERN_KDSETREMOVE
- Impostare il tracciamento con KERN_KDSETBUF e KERN_KDSETUP
- Usare KERN_KDGETBUF per ottenere il numero di voci del buffer
- Ottenere il proprio client dal tracciamento con KERN_KDPINDEX
- Abilitare il tracciamento con KERN_KDENABLE
- Leggere il buffer chiamando KERN_KDREADTR
- Per abbinare ogni thread al suo processo, chiamare KERN_KDTHRMAP.

Per ottenere queste informazioni, è possibile utilizzare lo strumento Apple **`trace`** o lo strumento personalizzato [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Nota che Kdebug è disponibile solo per 1 cliente alla volta.** Quindi solo uno strumento alimentato da k-debug può essere eseguito contemporaneamente.

### ktrace

Le API `ktrace_*` provengono da `libktrace.dylib`, che avvolgono quelle di `Kdebug`. Quindi, un client può semplicemente chiamare `ktrace_session_create` e `ktrace_events_[single/class]` per impostare callback su codici specifici e poi avviarlo con `ktrace_start`.

Puoi utilizzare questo anche con **SIP attivato**.

Puoi utilizzare come client l'utilità `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

Questo è usato per fare un profiling a livello di kernel ed è costruito utilizzando le chiamate `Kdebug`.

Fondamentalmente, la variabile globale `kernel_debug_active` viene controllata e se è impostata chiama `kperf_kdebug_handler` con il codice `Kdebug` e l'indirizzo del frame del kernel chiamante. Se il codice `Kdebug` corrisponde a uno selezionato, ottiene le "azioni" configurate come un bitmap (controlla `osfmk/kperf/action.h` per le opzioni).

Kperf ha anche una tabella MIB sysctl: (come root) `sysctl kperf`. Questi codici possono essere trovati in `osfmk/kperf/kperfbsd.c`.

Inoltre, un sottoinsieme della funzionalità di Kperf risiede in `kpc`, che fornisce informazioni sui contatori di prestazioni della macchina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) è uno strumento molto utile per controllare le azioni relative ai processi che un processo sta eseguendo (ad esempio, monitorare quali nuovi processi un processo sta creando).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) è uno strumento che stampa le relazioni tra i processi.\
Devi monitorare il tuo mac con un comando come **`sudo eslogger fork exec rename create > cap.json`** (il terminale che lancia questo richiede FDA). E poi puoi caricare il json in questo strumento per visualizzare tutte le relazioni:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) consente di monitorare eventi di file (come creazione, modifiche e cancellazioni) fornendo informazioni dettagliate su tali eventi.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) è uno strumento GUI con l'aspetto e la sensazione che gli utenti Windows potrebbero conoscere da _Procmon_ di Microsoft Sysinternal. Questo strumento consente di avviare e fermare la registrazione di vari tipi di eventi, consente il filtraggio di questi eventi per categorie come file, processo, rete, ecc., e fornisce la funzionalità di salvare gli eventi registrati in formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fanno parte degli strumenti per sviluppatori di Xcode – utilizzati per monitorare le prestazioni delle applicazioni, identificare perdite di memoria e tracciare l'attività del filesystem.

![](<../../../images/image (1138).png>)

### fs_usage

Consente di seguire le azioni eseguite dai processi:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) è utile per vedere le **librerie** utilizzate da un binario, i **file** che sta usando e le **connessioni** di rete.\
Controlla anche i processi binari contro **virustotal** e mostra informazioni sul binario.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**questo post del blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puoi trovare un esempio su come **debuggare un demone in esecuzione** che utilizzava **`PT_DENY_ATTACH`** per prevenire il debugging anche se SIP era disabilitato.

### lldb

**lldb** è lo strumento de **facto** per il **debugging** di binari **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Puoi impostare il sapore intel quando usi lldb creando un file chiamato **`.lldbinit`** nella tua cartella home con la seguente riga:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> All'interno di lldb, esegui il dump di un processo con `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Comando</strong></td><td><strong>Descrizione</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Inizia l'esecuzione, che continuerà senza interruzioni fino a quando non viene colpito un breakpoint o il processo termina.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Inizia l'esecuzione fermandosi al punto di ingresso</td></tr><tr><td><strong>continue (c)</strong></td><td>Continua l'esecuzione del processo in debug.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Esegui la prossima istruzione. Questo comando salterà le chiamate di funzione.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Esegui la prossima istruzione. A differenza del comando nexti, questo comando entrerà nelle chiamate di funzione.</td></tr><tr><td><strong>finish (f)</strong></td><td>Esegui il resto delle istruzioni nella funzione corrente (“frame”) restituisci e ferma.</td></tr><tr><td><strong>control + c</strong></td><td>Metti in pausa l'esecuzione. Se il processo è stato eseguito (r) o continuato (c), questo causerà l'arresto del processo ...dove si trova attualmente in esecuzione.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Qualsiasi funzione chiamata main</p><p><code>b <binname>`main</code> #Funzione principale del bin</p><p><code>b set -n main --shlib <lib_name></code> #Funzione principale del bin indicato</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Qualsiasi metodo NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Interrompi in tutte le funzioni di quella libreria</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Elenco dei breakpoint</p><p><code>br e/dis <num></code> #Abilita/Disabilita breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Ottieni aiuto sul comando breakpoint</p><p>help memory write #Ottieni aiuto per scrivere nella memoria</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Visualizza la memoria come una stringa terminata da null.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Visualizza la memoria come istruzione di assembly.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Visualizza la memoria come byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Questo stamperà l'oggetto referenziato dal parametro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Nota che la maggior parte delle API o dei metodi Objective-C di Apple restituiscono oggetti, e quindi dovrebbero essere visualizzati tramite il comando “print object” (po). Se po non produce un output significativo usa <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Scrivi AAAA in quell'indirizzo<br>memory write -f s $rip+0x11f+7 "AAAA" #Scrivi AAAA nell'indirizzo</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disassembla la funzione corrente</p><p>dis -n <funcname> #Disassembla la funzione</p><p>dis -n <funcname> -b <basename> #Disassembla la funzione<br>dis -c 6 #Disassembla 6 righe<br>dis -c 0x100003764 -e 0x100003768 # Da un indirizzo all'altro<br>dis -p -c 4 # Inizia nell'indirizzo corrente disassemblando</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Controlla l'array di 3 componenti nel registro x1</td></tr><tr><td><strong>image dump sections</strong></td><td>Stampa la mappa della memoria del processo corrente</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Ottieni l'indirizzo di tutti i simboli da CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Quando si chiama la funzione **`objc_sendMsg`**, il registro **rsi** contiene il **nome del metodo** come stringa terminata da null (“C”). Per stampare il nome tramite lldb fai:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Analisi Anti-Dinamica

#### Rilevamento VM

- Il comando **`sysctl hw.model`** restituisce "Mac" quando l'**host è un MacOS** ma qualcosa di diverso quando è una VM.
- Giocando con i valori di **`hw.logicalcpu`** e **`hw.physicalcpu`** alcuni malware cercano di rilevare se è una VM.
- Alcuni malware possono anche **rilevare** se la macchina è **basata su VMware** in base all'indirizzo MAC (00:50:56).
- È anche possibile scoprire **se un processo è in fase di debug** con un semplice codice come:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processo in fase di debug }`
- Può anche invocare la chiamata di sistema **`ptrace`** con il flag **`PT_DENY_ATTACH`**. Questo **preclude** a un deb**u**gger di attaccarsi e tracciare.
- Puoi controllare se la funzione **`sysctl`** o **`ptrace`** è stata **importata** (ma il malware potrebbe importarla dinamicamente)
- Come notato in questo scritto, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Il messaggio Process # exited with **status = 45 (0x0000002d)** è di solito un chiaro segnale che il target di debug sta usando **PT_DENY_ATTACH**_”

## Core Dumps

I core dumps vengono creati se:

- `kern.coredump` sysctl è impostato su 1 (per impostazione predefinita)
- Se il processo non era suid/sgid o `kern.sugid_coredump` è 1 (per impostazione predefinita è 0)
- Il limite `AS_CORE` consente l'operazione. È possibile sopprimere la creazione dei core dump chiamando `ulimit -c 0` e riabilitarli con `ulimit -c unlimited`.

In questi casi il core dump viene generato secondo `kern.corefile` sysctl e solitamente memorizzato in `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizza i processi in crash e salva un rapporto di crash su disco**. Un rapporto di crash contiene informazioni che possono **aiutare uno sviluppatore a diagnosticare** la causa di un crash.\
Per le applicazioni e altri processi **in esecuzione nel contesto di launchd per utente**, ReportCrash viene eseguito come un LaunchAgent e salva i rapporti di crash nella `~/Library/Logs/DiagnosticReports/` dell'utente.\
Per i demoni, altri processi **in esecuzione nel contesto di launchd di sistema** e altri processi privilegiati, ReportCrash viene eseguito come un LaunchDaemon e salva i rapporti di crash nei `/Library/Logs/DiagnosticReports` del sistema.

Se sei preoccupato che i rapporti di crash **vengano inviati ad Apple**, puoi disabilitarli. Se no, i rapporti di crash possono essere utili per **capire come è andato in crash un server**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sonno

Mentre si esegue il fuzzing su MacOS, è importante non permettere al Mac di andare in sonno:

- systemsetup -setsleep Never
- pmset, Preferenze di Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Disconnessione SSH

Se stai eseguendo il fuzzing tramite una connessione SSH, è importante assicurarsi che la sessione non si disconnetta. Quindi modifica il file sshd_config con:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**Controlla la seguente pagina** per scoprire come puoi trovare quale app è responsabile della **gestione dello schema o protocollo specificato:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

Questo è interessante per trovare processi che gestiscono dati di rete:
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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funziona per strumenti CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Funziona "**semplicemente"** con strumenti GUI di macOS. Nota che alcune app di macOS hanno requisiti specifici come nomi di file unici, l'estensione corretta, devono leggere i file dalla sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Maggiori informazioni sul Fuzzing MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Riferimenti

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
