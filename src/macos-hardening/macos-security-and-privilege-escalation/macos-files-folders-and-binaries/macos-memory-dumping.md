# Dump della memoria di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefatti della memoria

### File di swap

I file di swap, come `/private/var/vm/swapfile0`, fungono da **cache quando la memoria fisica è piena**. Quando non c'è più spazio nella memoria fisica, i dati vengono trasferiti in un file di swap e successivamente riportati nella memoria fisica secondo necessità. Potrebbero essere presenti più file di swap, con nomi come swapfile0, swapfile1 e così via.

### Immagine di ibernazione

Il file situato in `/private/var/vm/sleepimage` è fondamentale durante la **modalità di ibernazione**. **I dati presenti nella memoria vengono archiviati in questo file quando OS X entra in ibernazione**. Quando il computer si riattiva, il sistema recupera i dati della memoria da questo file, consentendo all'utente di riprendere da dove aveva lasciato.

È importante notare che, nei sistemi MacOS moderni, questo file è in genere crittografato per motivi di sicurezza, rendendone difficile il recupero.

- Per verificare se la crittografia è abilitata per sleepimage, è possibile eseguire il comando `sysctl vm.swapusage`. Questo mostrerà se il file è crittografato.

### Log della pressione della memoria

Un altro file importante relativo alla memoria nei sistemi MacOS è il **log della pressione della memoria**. Questi log si trovano in `/var/log` e contengono informazioni dettagliate sull'utilizzo della memoria del sistema e sugli eventi di pressione. Possono essere particolarmente utili per diagnosticare problemi relativi alla memoria o per comprendere come il sistema gestisce la memoria nel tempo.

## Dumping della memoria con osxpmem

Per eseguire il dumping della memoria su una macchina MacOS è possibile usare [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Si tratta ormai principalmente di un **workflow legacy**. `osxpmem` dipende dal caricamento di un'estensione del kernel, il progetto [Rekall](https://github.com/google/rekall) è archiviato, l'ultima release risale al **2017** e il binario pubblicato è destinato ai **Mac Intel**. Nelle release attuali di macOS, soprattutto su **Apple Silicon**, l'acquisizione dell'intera RAM basata su kext è solitamente bloccata dalle moderne restrizioni sulle estensioni del kernel, da SIP e dai requisiti di firma della piattaforma. In pratica, sui sistemi moderni si finirà più spesso per eseguire un **dump limitato a un processo** invece di creare un'immagine dell'intera RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Se trovi questo errore: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Puoi risolverlo eseguendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Altri errori** potrebbero essere risolti **consentendo il caricamento del kext** in "Security & Privacy --> General", è sufficiente **consentirlo**.

Puoi anche usare questo **oneliner** per scaricare l'applicazione, caricare il kext ed eseguire il dump della memoria:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping di processi live con LLDB

Per le **versioni recenti di macOS**, l'approccio più pratico consiste generalmente nel effettuare il dump della memoria di un **processo specifico**, invece di tentare di creare un'immagine dell'intera memoria fisica.

LLDB può salvare un file core Mach-O da un target live:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Per impostazione predefinita, questo crea solitamente uno **skinny core**. Per forzare LLDB a includere tutta la memoria mappata del processo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandi utili di follow-up prima del dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Di solito questo è sufficiente quando l'obiettivo è recuperare:

- Blob di configurazione decrypted
- Token, cookie o credenziali in memoria
- Secret in plaintext protetti solo at rest
- Pagine Mach-O decrypted dopo unpacking / JIT / runtime patching

Se il target è protetto dal **hardened runtime**, oppure se `taskgated` nega l'attach, in genere è necessaria una di queste condizioni:

- Il target include **`get-task-allow`**
- Il debugger è firmato con il corretto **debugger entitlement**
- Sei **root** e il target è un processo di terze parti non-hardened

Per maggiori informazioni sull'ottenimento di una task port e sulle operazioni possibili con essa:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Controlli rapidi prima dell'attach

Prima di dedicare tempo a LLDB/Frida, verifica rapidamente se il target è realisticamente **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operativamente, questo di solito significa:

- Un'app di terze parti distribuita con **`get-task-allow`** è spesso direttamente sottoponibile a dump con LLDB, e il dump risultante può esporre dati protetti da TCC a cui l'app aveva già avuto accesso.<sup>[[1]](#references)</sup>
- Un target **hardened** senza `get-task-allow` rifiuterà comunemente gli attach, anche come `root`, a meno che tu non controlli gli entitlement del debugger pertinenti o il relativo percorso di policy.
- I processi di terze parti non hardened sono ancora il punto più semplice in cui usare `lldb`, `vmmap`, Frida o reader personalizzati basati su `task_for_pid`/`vm_read`.

### Cerca helper annidati sottoponibili a dump

Recenti ricerche sulle app macOS notarizzate continuano a trovare **`get-task-allow` negli helper annidati** anziché nel binario GUI principale. Quando un'app di primo livello sembra hardened, enumera i suoi **servizi XPC**, **login items**, **helper tools** e CLI incluse prima di arrenderti:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Un eseguibile annidato con `get-task-allow` è spesso il punto più semplice a cui collegarsi con `lldb`, eseguire il dump di un core o estrarre la memoria con un client personalizzato `task_for_pid`, anche quando l’app principale è sottoposta a hardening più efficace.

## Dump selettivi con Frida o lettori userland

Quando un core completo contiene troppo rumore, eseguire il dump solo degli **intervalli leggibili interessanti** è spesso più veloce. Frida è particolarmente utile perché funziona bene per l’**estrazione mirata** una volta ottenuto l’accesso al processo.

Approccio di esempio:

1. Enumerare gli intervalli leggibili/scrivibili
2. Filtrare per modulo, heap, stack o memoria anonima
3. Eseguire il dump solo delle regioni che contengono stringhe candidate, chiavi, protobuf, blob plist/XML o codice/dati decrittografati

Esempio minimo di Frida per eseguire il dump di tutti gli intervalli anonimi leggibili:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Questo è utile quando vuoi evitare file core giganteschi e raccogliere solo:

- Chunk dell'heap dell'app contenenti segreti
- Regioni anonime create da packer o loader personalizzati
- Pagine di codice JIT / unpacked dopo la modifica delle protezioni

Quando il target continua ad **allocare / liberare** memoria durante il dump, preferisci la primitiva **`readVolatile()`** di Frida rispetto a **`readByteArray()`** per gli intervalli instabili. È più lenta, ma evita di terminare il target se una pagina diventa illeggibile nel corso della lettura. Per acquisizioni più grandi, può anche essere più pulito trasmettere gli chunk con `send(..., data)` e comprimerli sul lato controller, invece di creare migliaia di piccoli file all'interno del target.

Esistono anche strumenti userland più vecchi come [`readmem`](https://github.com/gdbinit/readmem), ma sono principalmente utili come **riferimenti al codice sorgente** per il dumping diretto in stile `task_for_pid`/`vm_read` e non sono ben mantenuti per i moderni workflow su Apple Silicon.

## Snapshot dell'heap / VM con `.memgraph`

Se ti interessano soprattutto gli **oggetti dell'heap**, la **provenienza delle allocazioni** o uno snapshot che possa essere trasferito su un'altra macchina, un file `.memgraph` è spesso più pratico rispetto a un core Mach-O gigantesco. Gli strumenti `leaks` possono generarne uno da un processo in esecuzione:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Quindi esegui il triage offline con gli strumenti Apple standard:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` è il motivo principale per conservare una capture `-fullContent`, perché le etichette che descrivono i contenuti della memoria vengono omesse da un `.memgraph` minimale.

Questo è particolarmente utile quando:

- Vuoi uno **snapshot più piccolo e condivisibile** invece di un core completo
- `MallocStackLogging` era abilitato e vuoi le **allocation backtraces**
- Conosci già un **indirizzo heap interessante** e vuoi fare pivot con `malloc_history`
- Ti serve una rapida **suddivisione VM/heap** prima di decidere se vale la pena fare un full dump, nonostante il rumore

### Triage differenziale di memgraph

Se controlli il modo in cui il target viene avviato, abilita il **logging storico delle allocation** prima del launch, in modo che gli snapshot successivi conservino backtraces utili delle operazioni di alloc/free:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Quindi acquisisci snapshot prima e dopo l'azione interessante e confrontali offline:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Questo è un modo pratico per isolare **oggetti post-autenticazione**, **buffer `CFData` di grandi dimensioni** o **regioni VM anonime** che compaiono solo dopo una fase di decrittazione, unpacking o recupero di secret.

## Target che fanno ampio uso di Swift: `swift-inspect`

Per le applicazioni che mantengono dati di alto valore all'interno di **oggetti del runtime Swift**, `swift-inspect` può essere un buon complemento a LLDB o Frida. Invece di eseguire prima il dumping di tutto, puoi interrogare strutture specifiche del runtime Swift da un processo in esecuzione:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Questo è utile per identificare:

- Grandi array Swift che memorizzano dati interessanti
- Allocazioni di metadata che rivelano i tipi caricati a runtime
- Lo stato della concorrenza Swift (`Task`, relazioni tra actor e thread) prima di eseguire un dump più mirato

Per un triage a livello di oggetti una volta che puoi già ispezionare il processo, consulta [la pagina dedicata agli oggetti in memoria](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Note per un triage rapido

- `sysctl vm.swapusage` è ancora un metodo rapido per verificare l'**utilizzo della swap** e se la swap è **crittografata**.
- `sleepimage` rimane rilevante principalmente negli scenari di **hibernate/safe sleep**, ma i sistemi moderni la proteggono comunemente, quindi dovrebbe essere trattata come una **fonte di artefatti da verificare**, non come un metodo di acquisizione affidabile.
- Nelle versioni recenti di macOS, il **dumping a livello di processo** è generalmente più realistico rispetto all'**acquisizione dell'intera memoria fisica**, a meno che tu non abbia il controllo dei criteri di avvio, dello stato di SIP e del caricamento dei kext.

## Riferimenti

- [1] [To Allow or Not to get-task-allow: Analisi della sicurezza di macOS](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [pagina man di leaks(1)](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
