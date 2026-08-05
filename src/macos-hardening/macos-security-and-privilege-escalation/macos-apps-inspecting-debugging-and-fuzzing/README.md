# App macOS - Ispezione, debugging e Fuzzing

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
> Nota che **`disarm`** può funzionare anche con file IM4P compressi (come `kernelcache`) ed estrarre solo le parti richieste o persino analizzare la parte richiesta senza estrarla.
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
> **`Codesign`** è presente in **macOS**, mentre **`ldid`** è presente in **iOS**
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
Questi installer contengono script bash `preinstall` e `postinstall` che gli autori di malware spesso sfruttano per garantire la **persistenza** del **malware**.

### hdiutil

Questo strumento consente di **montare** i file immagine disco di Apple (**.dmg**) per ispezionarli prima di eseguire qualsiasi operazione:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Sarà montato in `/Volumes`

### Binari packed

- Controlla l'entropia elevata
- Controlla le stringhe (se non è presente quasi nessuna stringa comprensibile, è packed)
- Il packer UPX per MacOS genera una sezione chiamata "\_\_XHDR"

## Analisi statica di Objective-C

### Metadati

> [!CAUTION]
> Nota che i programmi scritti in Objective-C **mantengono** le proprie dichiarazioni di classe **quando** vengono **compilati** in [binari Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tali dichiarazioni di classe **includono** il nome e il tipo di:

- Le interfacce definite
- I metodi dell'interfaccia
- Le variabili di istanza dell'interfaccia
- I protocolli definiti

Nota che questi nomi potrebbero essere offuscati per rendere più difficile il reverse engineering del binary.

### Chiamata delle funzioni

Quando viene chiamata una funzione in un binary che utilizza Objective-C, il codice compilato, invece di chiamare tale funzione, chiamerà **`objc_msgSend`**, che chiamerà la funzione finale:

![Metadati - Chiamata delle funzioni: quando viene chiamata una funzione in un binary che utilizza Objective-C, il codice compilato, invece di chiamare tale funzione, chiamerà objc msgSend. Che chiamerà...](<../../../images/image (305).png>)

I parametri attesi da questa funzione sono:

- Il primo parametro (**self**) è "un puntatore che punta all'**istanza della classe destinata a ricevere il messaggio**". In modo più semplice, è l'oggetto sul quale viene invocato il metodo. Se il metodo è un metodo di classe, questo sarà un'istanza dell'oggetto classe (nel suo complesso), mentre per un metodo di istanza, self punterà a un'istanza istanziata della classe come oggetto.
- Il secondo parametro, (**op**), è "il selector del metodo che gestisce il messaggio". In modo ancora più semplice, è semplicemente il **nome del metodo**.
- I parametri rimanenti sono tutti i **valori richiesti dal metodo** (op).

Vedi come **ottenere facilmente queste informazioni con `lldb` in ARM64** in questa pagina:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argomento**      | **Registro**                                                    | **(per) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1° argomento**  | **rdi**                                                         | **self: oggetto sul quale viene invocato il metodo** |
| **2° argomento**  | **rsi**                                                         | **op: nome del metodo**                             |
| **3° argomento**  | **rdx**                                                         | **1° argomento del metodo**                         |
| **4° argomento**  | **rcx**                                                         | **2° argomento del metodo**                         |
| **5° argomento**  | **r8**                                                          | **3° argomento del metodo**                         |
| **6° argomento**  | **r9**                                                          | **4° argomento del metodo**                         |
| **7°+ argomento** | <p><strong>rsp+</strong><br><strong>(sullo stack)</strong></p> | **5°+ argomento del metodo**                        |

### Dump dei metadati di Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) è uno strumento per eseguire il class-dump dei binari Objective-C. Il github specifica le dylib, ma funziona anche con gli eseguibili.
```bash
./dynadump dump /path/to/bin
```
Al momento della stesura, questa è **attualmente quella che funziona meglio**.

#### Strumenti comuni
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) è lo strumento originale per generare le dichiarazioni delle classi, delle categorie e dei protocolli in codice Objective-C formattato.

È obsoleto e non più mantenuto, quindi probabilmente non funzionerà correttamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) è uno strumento moderno e multipiattaforma per effettuare il class dump di Objective-C. Rispetto agli strumenti esistenti, iCDump può essere eseguito indipendentemente dall'ecosistema Apple ed espone binding Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Analisi statica di Swift

Con i binari Swift, grazie alla compatibilità con Objective-C, a volte è possibile estrarre le dichiarazioni usando [class-dump](https://github.com/nygard/class-dump/), ma non sempre.

Con le righe di comando **`jtool -l`** o **`otool -l`** è possibile trovare diverse sezioni che iniziano con il prefisso **`__swift5`**:
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
Puoi trovare ulteriori informazioni sulle [**informazioni memorizzate in queste sezioni in questo blog post**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Inoltre, i **binari Swift potrebbero contenere symbols** (ad esempio, le librerie devono memorizzare i symbols affinché le loro funzioni possano essere chiamate). I **symbols di solito contengono informazioni sul nome della funzione** e sugli attr in modo poco leggibile, quindi sono molto utili e esistono i "**demanglers"**, che possono recuperare il nome originale:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Analisi dinamica

> [!WARNING]
> Nota che, per eseguire il debug dei binari, **SIP deve essere disabilitato** (`csrutil disable` o `csrutil enable --without debug`) oppure è necessario copiare i binari in una cartella temporanea e **rimuovere la firma** con `codesign --remove-signature <binary-path>` o consentire il debug del binario (puoi usare [questo script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Nota che, per **strumentare i binari di sistema** (come `cloudconfigurationd`) su macOS, **SIP deve essere disabilitato** (la semplice rimozione della firma non funzionerà).

### API

macOS espone alcune API interessanti che forniscono informazioni sui processi:

- `proc_info`: è quella principale e fornisce molte informazioni su ogni processo. Devi essere root per ottenere informazioni sugli altri processi, ma non hai bisogno di entitlements speciali o di porte mach.
- `libsysmon.dylib`: consente di ottenere informazioni sui processi tramite funzioni esposte via XPC; tuttavia, è necessario disporre dell'entitlement `com.apple.sysmond.client`.

### Stackshot e microstackshots

Lo **stackshotting** è una tecnica utilizzata per acquisire lo stato dei processi, inclusi gli stack delle chiamate di tutti i thread in esecuzione. È particolarmente utile per il debugging, l'analisi delle prestazioni e la comprensione del comportamento del sistema in un determinato momento. Su iOS e macOS, lo stackshotting può essere eseguito utilizzando diversi strumenti e metodi, come gli strumenti **`sample`** e **`spindump`**.

### Sysdiagnose

Questo strumento (`/usr/bini/ysdiagnose`) raccoglie fondamentalmente molte informazioni dal computer eseguendo decine di comandi diversi, come `ps`, `zprint`...

Deve essere eseguito come **root** e il daemon `/usr/libexec/sysdiagnosed` dispone di entitlements molto interessanti, come `com.apple.system-task-ports` e `get-task-allow`.

Il relativo plist si trova in `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, che dichiara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: elimina i vecchi archivi in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: porta speciale 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: interfaccia in user mode tramite la classe Obj-C `Libsysdiagnose`. È possibile passare tre argomenti in un dict (`compress`, `display`, `run`)

### Unified Logs

MacOS genera molti log che possono essere molto utili quando si esegue un'applicazione e si cerca di capire **cosa sta facendo**.

Inoltre, alcuni log contengono il tag `<private>` per **nascondere** alcune informazioni **identificabili** relative all'**utente** o al **computer**. Tuttavia, è possibile **installare un certificato per rendere visibili queste informazioni**. Segui le spiegazioni [**qui**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Pannello sinistro

Nel pannello sinistro di Hopper è possibile vedere i simboli (**Labels**) del binario, l'elenco delle procedure e delle funzioni (**Proc**) e le stringhe (**Str**). Non si tratta di tutte le stringhe, ma di quelle definite in diverse parti del file Mac-O (come _cstring o `objc_methname`).

#### Pannello centrale

Nel pannello centrale puoi vedere il **codice disassemblato**. Puoi visualizzarlo come disassemblato **raw**, come **grafo**, come **decompilato** e come **binario**, facendo clic sull'icona corrispondente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Facendo clic con il pulsante destro del mouse su un oggetto di codice, puoi visualizzare i **riferimenti a/da quell'oggetto** o persino modificarne il nome (questa funzione non opera nello pseudocodice decompilato):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Inoltre, **nella parte inferiore del pannello centrale puoi scrivere comandi Python**.

#### Pannello destro

Nel pannello destro puoi visualizzare informazioni interessanti, come la **cronologia di navigazione** (così puoi sapere come sei arrivato alla situazione corrente), il **grafo delle chiamate**, in cui puoi vedere tutte le **funzioni che chiamano questa funzione** e tutte le funzioni **chiamate da questa funzione**, oltre alle informazioni sulle **variabili locali**.

### dtrace

Consente agli utenti di accedere alle applicazioni a un livello **molto basso** e offre un modo per **tracciare** i **programmi** e persino modificarne il flusso di esecuzione. Dtrace utilizza delle **probe** che sono **posizionate in tutto il kernel**, in punti come l'inizio e la fine delle system call.

DTrace utilizza la funzione **`dtrace_probe_create`** per creare una probe per ogni system call. Queste probe possono essere attivate nel **punto di ingresso e di uscita di ogni system call**. L'interazione con DTrace avviene tramite /dev/dtrace, che è disponibile solo per l'utente root.

> [!TIP]
> Per abilitare Dtrace senza disabilitare completamente la protezione SIP, puoi eseguire in recovery mode: `csrutil enable --without dtrace`
>
> Puoi anche utilizzare **`dtrace`** o i binari **`dtruss`** che hai compilato.

Le probe disponibili di dtrace possono essere ottenute con:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Il nome della probe è composto da quattro parti: provider, module, function e name (`fbt:mach_kernel:ptrace:entry`). Se non si specifica una parte del nome, DTrace applicherà un wildcard a quella parte.

Per configurare DTrace in modo da attivare le probe e specificare quali azioni eseguire quando vengono attivate, sarà necessario usare il linguaggio D.

Una spiegazione più dettagliata e altri esempi sono disponibili in [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Esempi

Esegui `man -k dtrace` per elencare gli **script DTrace disponibili**. Esempio: `sudo dtruss -n binary`

- Nella riga
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

È una facility di tracing del kernel. I codici documentati si trovano in **`/usr/share/misc/trace.codes`**.

Tool come `latency`, `sc_usage`, `fs_usage` e `trace` lo utilizzano internamente.

Per interfacciarsi con `kdebug` viene utilizzato `sysctl` tramite il namespace `kern.kdebug`; i MIB da utilizzare si trovano in `sys/sysctl.h`, mentre le funzioni sono implementate in `bsd/kern/kdebug.c`.

Per interagire con kdebug tramite un client personalizzato, questi sono generalmente i passaggi:

- Rimuovere le impostazioni esistenti con KERN_KDSETREMOVE
- Impostare il tracing con KERN_KDSETBUF e KERN_KDSETUP
- Utilizzare KERN_KDGETBUF per ottenere il numero di entry del buffer
- Escludere il proprio client dal trace con KERN_KDPINDEX
- Abilitare il tracing con KERN_KDENABLE
- Leggere il buffer chiamando KERN_KDREADTR
- Per associare ogni thread al relativo processo, chiamare KERN_KDTHRMAP.

Per ottenere queste informazioni è possibile utilizzare il tool Apple **`trace`** oppure il tool personalizzato [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Nota: Kdebug è disponibile per un solo cliente alla volta.** Pertanto, è possibile eseguire contemporaneamente un solo tool basato su k-debug.

### ktrace

Le API `ktrace_*` provengono da `libktrace.dylib`, che esegue il wrapping di quelle di `Kdebug`. Un client può quindi chiamare semplicemente `ktrace_session_create` e `ktrace_events_[single/class]` per impostare callback su codici specifici, quindi avviare il tutto con `ktrace_start`.

È possibile utilizzare questo anche con **SIP attivato**

È possibile utilizzare come client l'utility `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Oppure `tailspin`.

### kperf

Viene utilizzato per eseguire il profiling a livello kernel ed è costruito utilizzando i callout di `Kdebug`.

In pratica, viene controllata la variabile globale `kernel_debug_active` e, se è impostata, viene chiamato `kperf_kdebug_handler` con il codice `Kdebug` e l'indirizzo del kernel frame che effettua la chiamata. Se il codice `Kdebug` corrisponde a uno di quelli selezionati, vengono recuperate le "azioni" configurate come bitmap (controlla `osfmk/kperf/action.h` per le opzioni).

Kperf dispone anche di una tabella MIB sysctl: (come root) `sysctl kperf`. Questo codice si trova in `osfmk/kperf/kperfbsd.c`.

Inoltre, un sottoinsieme delle funzionalità di Kperf risiede in `kpc`, che fornisce informazioni sui performance counter della macchina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) è uno strumento molto utile per controllare le azioni relative ai processi eseguite da un processo (ad esempio, monitorare quali nuovi processi sta creando un processo).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) è uno strumento che stampa le relazioni tra i processi.\
È necessario monitorare il Mac con un comando come **`sudo eslogger fork exec rename create > cap.json`** (il terminale che avvia questo comando richiede FDA). Dopodiché, è possibile caricare il json in questo strumento per visualizzare tutte le relazioni:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) consente di monitorare gli eventi relativi ai file (come creazione, modifiche ed eliminazioni), fornendo informazioni dettagliate su tali eventi.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) è uno strumento GUI dall'aspetto e dal comportamento che gli utenti Windows potrebbero conoscere da _Procmon_ di Microsoft Sysinternal. Questo strumento consente di avviare e interrompere la registrazione di vari tipi di eventi, filtrare questi eventi per categorie come file, processo, rete, ecc. e salvare gli eventi registrati in formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fa parte dei Developer tools di Xcode e viene utilizzato per monitorare le performance delle applicazioni, identificare i memory leak e tracciare l'attività del filesystem.

![Crescendo - Apple Instruments: Apple Instruments fa parte dei Developer tools di Xcode e viene utilizzato per monitorare le performance delle applicazioni, identificare i memory leak e tracciare l'attività del filesystem](<../../../images/image (1138).png>)

### fs_usage

Consente di seguire le azioni eseguite dai processi:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) è utile per vedere le **libraries** utilizzate da un binary, i **files** che sta usando e le connessioni di **network**.\
Controlla inoltre i processi binary tramite **virustotal** e mostra informazioni sul binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**questo blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puoi trovare un esempio di come fare il **debug di un daemon in esecuzione** che utilizzava **`PT_DENY_ATTACH`** per impedire il debugging anche quando SIP era disabilitato.

### lldb

**lldb** è il tool de facto per il **debugging** dei binary **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Puoi impostare la variante Intel quando usi **lldb**, creando un file chiamato **`.lldbinit`** nella tua cartella home con la seguente riga:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> All'interno di lldb, esegui il dump di un processo con `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Descrizione</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Avvia l'esecuzione, che continuerà senza interruzioni finché non viene raggiunto un breakpoint o il processo termina.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Avvia l'esecuzione fermandosi all'entry point</td></tr><tr><td><strong>continue (c)</strong></td><td>Continua l'esecuzione del processo sottoposto a debug.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Esegue l'istruzione successiva. Questo comando salta le chiamate a funzione.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Esegue l'istruzione successiva. A differenza del comando nexti, questo comando entra nelle chiamate a funzione.</td></tr><tr><td><strong>finish (f)</strong></td><td>Esegue il resto delle istruzioni nella funzione corrente (“frame”), quindi restituisce il controllo e si arresta.</td></tr><tr><td><strong>control + c</strong></td><td>Mette in pausa l'esecuzione. Se il processo è stato avviato (r) o continuato (c), questo farà arrestare il processo ...nel punto in cui è attualmente in esecuzione.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Visualizza la memoria come stringa con terminazione null.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Visualizza la memoria come istruzione assembly.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Visualizza la memoria come byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Stampa l'oggetto referenziato dal parametro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Nota che la maggior parte delle API o dei metodi Objective-C di Apple restituisce oggetti e dovrebbe quindi essere visualizzata tramite il comando “print object” (po). Se po non produce un output significativo, usa <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Stampa la mappa della memoria del processo corrente</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Quando viene chiamata la funzione **`objc_sendMsg`**, il registro **rsi** contiene il **nome del metodo** come stringa con terminazione null (“C”). Per stampare il nome tramite lldb:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Analisi anti-dinamica

#### Rilevamento delle VM

- Il comando **`sysctl hw.model`** restituisce "Mac" quando l'**host è un MacOS**, ma qualcosa di diverso quando si tratta di una VM.
- Modificando i valori di **`hw.logicalcpu`** e **`hw.physicalcpu`**, alcuni malware tentano di rilevare se il sistema è una VM.
- Alcuni malware possono anche **rilevare** se la macchina è **VMware** in base all'indirizzo MAC (00:50:56).
- È anche possibile determinare **se un processo è sottoposto a debug** con un semplice codice come:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Può anche invocare la system call **`ptrace`** con il flag **`PT_DENY_ATTACH`**. Questo **impedisce a un deb**u**gger di collegarsi e tracciare il processo.
- Puoi verificare se la funzione **`sysctl`** o **`ptrace`** viene **importata** (ma il malware potrebbe importarla dinamicamente)
- Come indicato in questo writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Il messaggio Process # exited with **status = 45 (0x0000002d)** indica solitamente che il target di debug utilizza **PT_DENY_ATTACH**_”

## Core Dumps

I core dump vengono creati se:

- il sysctl `kern.coredump` è impostato su 1 (per impostazione predefinita)
- il processo non era suid/sgid oppure `kern.sugid_coredump` è impostato su 1 (per impostazione predefinita è 0)
- Il limite `AS_CORE` consente l'operazione. È possibile impedire la creazione dei code dump chiamando `ulimit -c 0` e riabilitarli con `ulimit -c unlimited`.

In questi casi il core dump viene generato secondo il sysctl `kern.corefile` e solitamente archiviato in `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizza i processi che causano un crash e salva un crash report su disco**. Un crash report contiene informazioni che possono **aiutare uno sviluppatore a diagnosticare** la causa di un crash.\
Per le applicazioni e gli altri processi **in esecuzione nel contesto launchd per-user**, ReportCrash viene eseguito come LaunchAgent e salva i crash report in `~/Library/Logs/DiagnosticReports/` dell'utente.\
Per i daemon, gli altri processi **in esecuzione nel contesto launchd di sistema** e gli altri processi privilegiati, ReportCrash viene eseguito come LaunchDaemon e salva i crash report nel percorso di sistema `/Library/Logs/DiagnosticReports`

Se temi che i crash report **vengano inviati ad Apple**, puoi disabilitarli. In caso contrario, i crash report possono essere utili per **capire come è andato in crash un server**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sospensione

Durante il fuzzing su un Mac è importante impedire al Mac di entrare in sospensione:

- systemsetup -setsleep Never
- pmset, Preferenze di Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Disconnessione SSH

Se stai eseguendo il fuzzing tramite una connessione SSH, è importante assicurarsi che la sessione non termini. Modifica quindi il file sshd_config con:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Gestori interni

**Consulta la seguente pagina** per scoprire come identificare quale app è responsabile della **gestione dello scheme o del protocollo specificato:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerazione dei processi di rete

Questo è utile per trovare i processi che gestiscono i dati di rete:
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
### Fuzzer

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funziona con strumenti CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

**"funziona e basta"** con gli strumenti GUI di macOS. Nota che alcune app macOS hanno requisiti specifici, come nomi di file univoci, l'estensione corretta, la necessità di leggere i file dalla sandbox (`~/Library/Containers/com.apple.Safari/Data`)... 

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
### Ulteriori informazioni sul Fuzzing di MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Riferimenti

- [1] [Risposta agli incidenti su OS X: scripting e analisi](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [L'arte del malware per Mac, Volume I: analisi](https://taomm.org/vol1/analysis.html)
- [4] [L'arte del malware per Mac: la guida all'analisi dei software dannosi](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
