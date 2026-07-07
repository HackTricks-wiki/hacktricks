# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, wie `/private/var/vm/swapfile0`, dienen als **Caches, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr vorhanden ist, werden die Daten in eine Swap-Datei verschoben und bei Bedarf wieder in den physischen Speicher geladen. Es können mehrere Swap-Dateien vorhanden sein, mit Namen wie swapfile0, swapfile1 und so weiter.

### Hibernate Image

Die Datei unter `/private/var/vm/sleepimage` ist während des **Hibernation-Modus** entscheidend. **Daten aus dem Speicher werden in dieser Datei gespeichert, wenn OS X in den Ruhezustand wechselt**. Beim Aufwachen des Computers liest das System die Speicherdaten aus dieser Datei zurück, sodass der Benutzer dort weitermachen kann, wo er aufgehört hat.

Es ist erwähnenswert, dass diese Datei auf modernen MacOS-Systemen aus Sicherheitsgründen typischerweise verschlüsselt ist, was die Wiederherstellung erschwert.

- Um zu prüfen, ob die Verschlüsselung für die sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dies zeigt an, ob die Datei verschlüsselt ist.

### Memory Pressure Logs

Eine weitere wichtige speicherbezogene Datei in MacOS-Systemen ist das **memory pressure log**. Diese Logs befinden sich in `/var/log` und enthalten detaillierte Informationen zur Speicherauslastung des Systems und zu pressure events. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Laufe der Zeit verwaltet.

## Dumping memory with osxpmem

Um den Speicher auf einem MacOS-Computer zu dumpen, kannst du [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Note**: Das ist inzwischen größtenteils ein **Legacy-Workflow**. `osxpmem` hängt davon ab, eine Kernel Extension zu laden, das Projekt [Rekall](https://github.com/google/rekall) ist archiviert, die neueste Release stammt aus **2017**, und das veröffentlichte Binary ist für **Intel Macs** gedacht. Auf aktuellen macOS-Versionen, insbesondere auf **Apple Silicon**, wird eine kext-basierte Full-RAM-Akquise in der Regel durch moderne Kernel-Extension-Beschränkungen, SIP und Plattform-Signing-Anforderungen blockiert. In der Praxis endest du auf modernen Systemen häufiger mit einem **process-scoped dump** statt mit einem vollständigen RAM-Image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn du diesen Fehler findest: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` kannst du ihn so beheben:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** können behoben werden, indem man **das Laden des kext** in "Security & Privacy --> General" erlaubt, also **allow** es.

Du kannst auch diesen **oneliner** verwenden, um die Anwendung herunterzuladen, das kext zu laden und den Speicher zu dumpen:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Für **neuere macOS-Versionen** ist der praktischste Ansatz normalerweise, den Speicher eines **bestimmten Prozesses** zu dumpen, statt zu versuchen, den gesamten physischen Speicher zu image'n.

LLDB kann eine Mach-O-Core-Datei von einem laufenden Target speichern:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Standardmäßig erzeugt dies normalerweise einen **skinny core**. Um LLDB dazu zu zwingen, den gesamten gemappten Prozessspeicher einzuschließen:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Nützliche Follow-up-Befehle vor dem Dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Das reicht normalerweise aus, wenn das Ziel ist, Folgendes wiederherzustellen:

- Entschlüsselte Konfigurations-Blobs
- In-memory Tokens, Cookies oder Credentials
- Plaintext-Secrets, die nur at rest geschützt sind
- Entschlüsselte Mach-O-Seiten nach unpacking / JIT / runtime patching

Wenn das Ziel durch die **hardened runtime** geschützt ist oder wenn `taskgated` den attach verweigert, brauchst du typischerweise eine dieser Bedingungen:

- Das Ziel hat **`get-task-allow`**
- Dein Debugger ist mit dem passenden **debugger entitlement** signiert
- Du bist **root** und das Ziel ist ein nicht gehärteter Third-Party-Prozess

Für mehr Hintergrund zum Erhalten eines task port und dazu, was damit gemacht werden kann:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Bevor du Zeit auf LLDB/Frida verwendest, prüfe schnell, ob das Ziel realistisch **dumpable** ist:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operational bedeutet das meist:

- Eine Third-Party-App, die mit **`get-task-allow`** ausgeliefert wurde, lässt sich oft direkt mit LLDB dumpen, und der resultierende Dump kann TCC-geschützte Daten enthalten, auf die die App bereits zugegriffen hat.
- Ein **hardened** Target ohne `get-task-allow` verweigert Attachments häufig, selbst als `root`, außer du kontrollierst die relevanten Debugger-Entitlements / den Policy-Pfad.
- Unhardened Third-Party-Prozesse sind weiterhin der einfachste Ort, um `lldb`, `vmmap`, Frida oder eigene `task_for_pid`/`vm_read`-Reader zu verwenden.

## Selektive Dumps mit Frida oder Userland-Readern

Wenn ein kompletter Core zu viel Rauschen enthält, ist das Dumpen nur der **interessanten lesbaren Bereiche** oft schneller. Frida ist besonders nützlich, weil es sich für **zielgerichtete Extraktion** gut eignet, sobald du dich an den Prozess anhängen kannst.

Beispielansatz:

1. Lesbare/schreibbare Bereiche enumerieren
2. Nach Modul, Heap, Stack oder anonymem Memory filtern
3. Nur die Bereiche dumpen, die Kandidaten-Strings, Keys, Protobufs, plist/XML-Blobs oder entschlüsselten Code/Daten enthalten

Minimales Frida-Beispiel, um alle lesbaren anonymen Bereiche zu dumpen:
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
Dies ist nützlich, wenn du riesige Core-Dateien vermeiden und nur Folgendes einsammeln willst:

- App-Heap-Chunks, die Secrets enthalten
- Anonyme Regionen, die von Custom-Packern oder Loaders erstellt wurden
- JIT / unpacked Code-Seiten nach dem Ändern von Protections

Ältere Userland-Tools wie [`readmem`](https://github.com/gdbinit/readmem) existieren ebenfalls, sind aber hauptsächlich als **Source-Referenzen** für direktes `task_for_pid`/`vm_read`-artiges Dumping nützlich und für moderne Apple-Silicon-Workflows nicht gut gepflegt.

## Heap / VM-Snapshots mit `.memgraph`

Wenn dich hauptsächlich **Heap-Objekte**, **Allocation Provenance** oder ein Snapshot interessieren, der auf einen anderen Rechner verschoben werden kann, ist eine `.memgraph` oft praktischer als ein riesiger Mach-O-Core. Das `leaks`-Tooling kann eines aus einem laufenden Prozess erzeugen:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Dann triage es offline mit standardmäßigen Apple-Tools:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` ist der Hauptgrund, ein `-fullContent`-Capture aufzubewahren, weil die Labels, die den Speicherinhalt beschreiben, aus einer minimalen `.memgraph` weggelassen werden.

Das ist besonders nützlich, wenn:

- Du lieber einen **kleineren, teilbaren Snapshot** statt eines vollständigen Cores willst
- `MallocStackLogging` aktiviert war und du **Allocation-Backtraces** willst
- Du bereits eine **interessante Heap-Adresse** kennst und mit `malloc_history` weitermachen willst
- Du vorab eine schnelle **VM/Heap-Aufschlüsselung** brauchst, bevor du entscheidest, ob ein vollständiger Dump den zusätzlichen Lärm wert ist

## Swift-heavy targets: `swift-inspect`

Für Anwendungen, die hochwertige Daten in **Swift runtime objects** speichern, kann `swift-inspect` eine gute Ergänzung zu LLDB oder Frida sein. Statt zuerst alles zu dumpen, kannst du gezielt bestimmte Swift runtime-Strukturen aus einem laufenden Prozess abfragen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Das ist hilfreich, um Folgendes zu identifizieren:

- Große Swift-Arrays, die interessante Daten puffern
- Metadata-Allocations, die Typen offenlegen, die zur Laufzeit geladen wurden
- Swift concurrency state (`Task`, actor, thread relationships) vor einem gezielteren Dump

Für weiteres Object-Level-Runtime-Triage, sobald du den Prozess bereits inspizieren kannst, sieh dir [die dedizierte Seite zu objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) an.

## Quick triage notes

- `sysctl vm.swapusage` ist weiterhin ein schneller Weg, um **swap usage** und zu prüfen, ob swap **encrypted** ist.
- `sleepimage` bleibt vor allem für **hibernate/safe sleep**-Szenarien relevant, aber moderne Systeme schützen es häufig, daher sollte es als **artifact source to check** behandelt werden, nicht als verlässlicher Acquisition-Pfad.
- Auf neueren macOS-Versionen ist **process-level dumping** im Allgemeinen realistischer als **full physical memory imaging**, es sei denn, du kontrollierst Boot-Policy, SIP-Zustand und kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
