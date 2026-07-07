# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

I file di swap, come `/private/var/vm/swapfile0`, servono come **cache quando la memoria fisica è piena**. Quando non c’è più spazio nella memoria fisica, i suoi dati vengono trasferiti in un file di swap e poi riportati nella memoria fisica secondo necessità. Possono essere presenti più file di swap, con nomi come swapfile0, swapfile1, e così via.

### Hibernate Image

Il file situato in `/private/var/vm/sleepimage` è fondamentale durante la **modalità di ibernazione**. **I dati della memoria vengono memorizzati in questo file quando OS X va in ibernazione**. Quando il computer si riattiva, il sistema recupera i dati della memoria da questo file, consentendo all'utente di continuare da dove aveva interrotto.

Vale la pena notare che sui sistemi MacOS moderni, questo file è in genere cifrato per motivi di sicurezza, rendendo difficile il recovery.

- Per verificare se la cifratura è abilitata per il sleepimage, si può eseguire il comando `sysctl vm.swapusage`. Questo mostrerà se il file è cifrato.

### Memory Pressure Logs

Un altro file importante legato alla memoria nei sistemi MacOS è il **memory pressure log**. Questi log si trovano in `/var/log` e contengono informazioni dettagliate sull'utilizzo della memoria del sistema e sugli eventi di pressione. Possono essere particolarmente utili per diagnosticare problemi legati alla memoria o per comprendere come il sistema gestisce la memoria nel tempo.

## Dumping memory with osxpmem

Per fare il dump della memoria su una macchina MacOS puoi usare [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Questo è per lo più un **legacy workflow** ormai. `osxpmem` dipende dal caricamento di una kernel extension, il progetto [Rekall](https://github.com/google/rekall) è archiviato, l'ultima release è del **2017**, e il binario pubblicato è destinato ai **Mac Intel**. Sulle versioni attuali di macOS, specialmente su **Apple Silicon**, l'acquisizione dell'intera RAM basata su kext è di solito bloccata dalle moderne restrizioni sulle kernel extension, da SIP e dai requisiti di platform-signing. In pratica, sui sistemi moderni si finisce più spesso per fare un **process-scoped dump** invece di un'immagine dell'intera RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Se trovi questo errore: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Puoi risolverlo facendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Altri errori** potrebbero essere risolti **consentendo il caricamento del kext** in "Security & Privacy --> General", basta **consentirlo**.

Puoi anche usare questo **oneliner** per scaricare l'applicazione, caricare il kext e fare il dump della memoria:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping di processi live con LLDB

Per le **versioni recenti di macOS**, l'approccio più pratico è di solito fare il dump della memoria di un **processo specifico** invece di cercare di acquisire tutta la memoria fisica.

LLDB può salvare un file core Mach-O da un target live:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Per impostazione predefinita, questo di solito crea un **skinny core**. Per forzare LLDB a includere tutta la memoria mappata del processo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandi di follow-up utili prima del dump:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Questo di solito è sufficiente quando l’obiettivo è recuperare:

- Blob di configurazione decrittati
- Token, cookie o credenziali in memoria
- Secret in plaintext che sono protetti solo at rest
- Pagine Mach-O decrittate dopo unpacking / JIT / runtime patching

Se il target è protetto dal **hardened runtime**, o se `taskgated` nega l’attach, in genere hai bisogno di una di queste condizioni:

- Il target include **`get-task-allow`**
- Il tuo debugger è firmato con il corretto **debugger entitlement**
- Sei **root** e il target è un processo di terze parti non hardened

Per maggiori informazioni su come ottenere un task port e cosa si può fare con esso:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Prima di perdere tempo con LLDB/Frida, verifica rapidamente se il target è realisticamente **dumpable**:
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

- Un'app di terze parti distribuita con **`get-task-allow`** è spesso dumpable direttamente con LLDB, e il dump risultante può esporre dati protetti da TCC a cui l'app ha già avuto accesso.
- Un target **hardened** senza `get-task-allow` di solito rifiuterà gli attach, anche come `root`, a meno che tu non controlli i relativi entitlements del debugger / il percorso di policy.
- I processi di terze parti non hardened restano il posto più semplice per usare `lldb`, `vmmap`, Frida, o reader custom `task_for_pid`/`vm_read`.

## Selective dumps with Frida or userland readers

Quando un core completo è troppo rumoroso, dumpare solo le **interesting readable ranges** è spesso più veloce. Frida è particolarmente utile perché funziona bene per una **targeted extraction** una volta che puoi attaccarti al processo.

Approccio di esempio:

1. Enumerare le readable/writable ranges
2. Filtrare per module, heap, stack, o anonymous memory
3. Dumpare solo le regioni che contengono candidate strings, keys, protobufs, plist/XML blobs, o codice/dati decryptati

Esempio minimo in Frida per dumpare tutte le anonymous ranges leggibili:
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
Questo è utile quando vuoi evitare file core enormi e raccogliere solo:

- Chunk dell'heap dell'app contenenti segreti
- Region anonime create da packer o loader custom
- Pagine di codice JIT / unpacked dopo aver cambiato le protezioni

Esistono anche strumenti userland più vecchi come [`readmem`](https://github.com/gdbinit/readmem), ma sono soprattutto utili come **riferimenti di origine** per il dumping diretto in stile `task_for_pid`/`vm_read` e non sono ben mantenuti per i workflow moderni su Apple Silicon.

## Snapshot dell'heap / VM con `.memgraph`

Se ti interessano principalmente gli **oggetti heap**, la **provenienza delle allocazioni**, o uno snapshot che possa essere spostato su un'altra macchina, spesso un `.memgraph` è più pratico di un enorme core Mach-O. Il tooling `leaks` può generarne uno da un processo live:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Poi eseguilo offline con gli standard Apple tooling:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` è il motivo principale per conservare una cattura `-fullContent`, perché le etichette che descrivono il contenuto della memoria vengono omesse da un `.memgraph` minimale.

Questo è particolarmente utile quando:

- Vuoi uno snapshot **più piccolo e condivisibile** invece di un core completo
- `MallocStackLogging` era abilitato e vuoi i **backtrace di allocazione**
- Conosci già un **indirizzo heap interessante** e vuoi fare pivot con `malloc_history`
- Ti serve una rapida **suddivisione VM/heap** prima di decidere se un dump completo vale il rumore

## Target con forte uso di Swift: `swift-inspect`

Per applicazioni che conservano dati di alto valore dentro oggetti del runtime **Swift**, `swift-inspect` può essere un buon complemento a LLDB o Frida. Invece di dumpare tutto prima, puoi interrogare strutture specifiche del runtime Swift da un processo live:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Questo è utile per identificare:

- Large Swift arrays buffering interesting data
- Metadata allocations that reveal types loaded at runtime
- Swift concurrency state (`Task`, actor, thread relationships) before doing a more targeted dump

Per un triage a livello di oggetti più approfondito, quando puoi già ispezionare il processo, consulta [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` è ancora un modo rapido per controllare **swap usage** e se lo swap è **encrypted**.
- `sleepimage` resta rilevante soprattutto per scenari di **hibernate/safe sleep**, ma i sistemi moderni in genere lo proteggono, quindi va considerato una **artifact source to check**, non un percorso di acquisizione affidabile.
- Sulle versioni recenti di macOS, il **process-level dumping** è in genere più realistico del **full physical memory imaging** a meno che tu non controlli boot policy, stato SIP e caricamento dei kext.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
