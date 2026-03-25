# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Artefatti di memoria

### File di swap

I file di swap, come `/private/var/vm/swapfile0`, fungono da **cache quando la memoria fisica è piena**. Quando non c'è più spazio nella memoria fisica, i suoi dati vengono trasferiti in un file di swap e poi riportati in memoria fisica quando necessario. Possono essere presenti più file di swap, con nomi come swapfile0, swapfile1 e così via.

### Immagine di ibernazione

Il file situato in `/private/var/vm/sleepimage` è cruciale durante la **modalità di ibernazione**. **I dati dalla memoria vengono salvati in questo file quando OS X entra in ibernazione**. Al riavvio del computer, il sistema recupera i dati di memoria da questo file, permettendo all'utente di riprendere da dove aveva interrotto.

Va notato che sui sistemi macOS moderni questo file è tipicamente cifrato per motivi di sicurezza, rendendo il recupero difficile.

- Per verificare se la cifratura è abilitata per lo sleepimage, è possibile eseguire il comando `sysctl vm.swapusage`. Questo mostrerà se il file è cifrato.

### Log di memory pressure

Un altro file importante relativo alla memoria nei sistemi macOS è il **memory pressure log**. Questi log si trovano in `/var/log` e contengono informazioni dettagliate sull'uso della memoria del sistema e sugli eventi di memory pressure. Possono essere particolarmente utili per diagnosticare problemi legati alla memoria o per capire come il sistema gestisce la memoria nel tempo.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Questo è per lo più un flusso di lavoro **legacy** adesso. `osxpmem` dipende dal caricamento di una kernel extension, il progetto [Rekall](https://github.com/google/rekall) è archiviato, l'ultima release risale al **2017**, e il binario pubblicato è destinato ai **Intel Macs**. Sulle release macOS attuali, specialmente su **Apple Silicon**, l'acquisizione full-RAM basata su kext è di solito bloccata dalle moderne restrizioni sulle kernel extension, da SIP e dai requisiti di firma della piattaforma. In pratica, su sistemi moderni finirai più spesso per fare un **process-scoped dump** invece di un'immagine della RAM completa.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Se riscontri questo errore: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Puoi risolverlo eseguendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Altri errori** potrebbero essere risolti permettendo il caricamento del kext in "Sicurezza e Privacy --> Generale", basta **consentirlo**.

Puoi anche usare questo **oneliner** per scaricare l'applicazione, caricare il kext ed eseguire il dump della memoria:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Per le **versioni recenti di macOS**, l'approccio più pratico è solitamente effettuare il dump della memoria di un **processo specifico** invece di cercare di acquisire tutta la memoria fisica.

LLDB può salvare un Mach-O core file da un live target:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Per default questo di solito crea un **skinny core**. Per forzare LLDB a includere tutta la memoria mappata del processo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandi utili da eseguire prima del dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Questo è di solito sufficiente quando l'obiettivo è recuperare:

- blob di configurazione decrittati
- token, cookie o credenziali in memoria
- segreti in chiaro che sono protetti solo a riposo
- pagine Mach-O decrittate dopo unpacking / JIT / runtime patching

Se il target è protetto dal **hardened runtime**, o se `taskgated` nega l'attach, normalmente hai bisogno di una delle seguenti condizioni:

- Il target possiede **`get-task-allow`**
- Il tuo debugger è firmato con la corretta **debugger entitlement**
- Sei **root** e il target è un processo di terze parti non protetto dal **hardened runtime**

Per maggiori dettagli su come ottenere un task port e cosa è possibile farci:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Dump selettivi con Frida o userland readers

Quando un dump completo è troppo rumoroso, eseguire il dump solo degli **intervalli leggibili interessanti** è spesso più veloce. Frida è particolarmente utile perché funziona bene per l'**estrazione mirata** una volta che puoi agganciarti al processo.

Esempio di approccio:

1. Enumerare gli intervalli leggibili/scrivibili
2. Filtrare per modulo, heap, stack o memoria anonima
3. Eseguire il dump solo delle regioni che contengono stringhe candidate, chiavi, protobuf, blob plist/XML o codice/dati decrittati

Esempio minimo con Frida per eseguire il dump di tutti gli intervalli anonimi leggibili:
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
Questo è utile quando vuoi evitare core file giganteschi e raccogliere solo:

- App heap chunks containing secrets
- Anonymous regions created by custom packers or loaders
- JIT / unpacked code pages after changing protections

Older userland tools such as [`readmem`](https://github.com/gdbinit/readmem) also exist, but they are mainly useful as **riferimenti di origine** for direct `task_for_pid`/`vm_read` style dumping and are not well-maintained for modern Apple Silicon workflows.

## Note rapide di triage

- `sysctl vm.swapusage` è ancora un modo rapido per verificare **l'utilizzo dello swap** e se lo swap è **cifrato**.
- `sleepimage` rimane rilevante principalmente per scenari **hibernate/safe sleep**, ma i sistemi moderni lo proteggono comunemente, quindi dovrebbe essere trattato come una **fonte di artefatti da verificare**, non come una via di acquisizione affidabile.
- Nelle release recenti di macOS, **process-level dumping** è generalmente più realistico rispetto a **full physical memory imaging** a meno che tu non controlli boot policy, SIP state, e kext loading.

## Riferimenti

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
