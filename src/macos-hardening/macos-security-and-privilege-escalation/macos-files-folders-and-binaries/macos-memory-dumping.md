# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap-Dateien wie `/private/var/vm/swapfile0` dienen als **Caches, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr vorhanden ist, werden die Daten in eine Swap-Datei übertragen und bei Bedarf wieder in den physischen Speicher geladen. Es können mehrere Swap-Dateien vorhanden sein, mit Namen wie swapfile0, swapfile1 usw.

### Hibernate Image

Die Datei unter `/private/var/vm/sleepimage` ist während des **Ruhezustands** von entscheidender Bedeutung. **Daten aus dem Speicher werden in dieser Datei gespeichert, wenn OS X in den Ruhezustand wechselt**. Beim Aufwecken des Computers ruft das System die Speicherdaten aus dieser Datei ab, sodass der Benutzer dort fortfahren kann, wo er aufgehört hat.

Beachtenswert ist, dass diese Datei auf modernen MacOS-Systemen aus Sicherheitsgründen typischerweise verschlüsselt ist, wodurch eine Wiederherstellung erschwert wird.

- Um zu überprüfen, ob die Verschlüsselung für das sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dadurch wird angezeigt, ob die Datei verschlüsselt ist.

### Memory Pressure Logs

Eine weitere wichtige speicherbezogene Datei in MacOS-Systemen ist das **Memory-Pressure-Log**. Diese Logs befinden sich in `/var/log` und enthalten detaillierte Informationen über die Speichernutzung des Systems und Memory-Pressure-Ereignisse. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Laufe der Zeit verwaltet.

## Dumping memory with osxpmem

Um den Speicher eines MacOS-Systems zu dumpen, kann [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwendet werden.

**Hinweis**: Dies ist inzwischen größtenteils ein **legacy workflow**. `osxpmem` ist vom Laden einer Kernel-Erweiterung abhängig, das [Rekall](https://github.com/google/rekall)-Projekt ist archiviert, die neueste Veröffentlichung stammt aus dem Jahr **2017**, und die veröffentlichte Binary zielt auf **Intel Macs** ab. Auf aktuellen macOS-Versionen ist die kext-basierte Erfassung des vollständigen RAM, insbesondere auf **Apple Silicon**, durch moderne Einschränkungen für Kernel-Erweiterungen, SIP und Anforderungen an die Plattform-Signierung normalerweise blockiert. In der Praxis führt dies auf modernen Systemen häufiger zu einem **process-scoped dump** anstelle eines vollständigen RAM-Images.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn du diesen Fehler findest: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` kannst du ihn folgendermaßen beheben:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** können möglicherweise behoben werden, indem das **Laden des kext** unter „Sicherheit & Datenschutz --> Allgemein“ **erlaubt** wird. Klicke einfach auf **Erlauben**.

Du kannst auch diesen **oneliner** verwenden, um die Anwendung herunterzuladen, den kext zu laden und den Speicher zu dumpen:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live-Prozess-Dumping mit LLDB

Für **aktuelle macOS-Versionen** besteht der praktischste Ansatz normalerweise darin, den Speicher eines **bestimmten Prozesses** zu dumpen, anstatt zu versuchen, den gesamten physischen Speicher zu imagen.

LLDB kann eine Mach-O-Core-Datei von einem Live-Ziel speichern:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Standardmäßig wird dadurch normalerweise ein **skinny core** erstellt. Um LLDB zu zwingen, den gesamten zugeordneten Prozessspeicher einzuschließen:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Nützliche Folgekommandos vor dem Dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Das reicht normalerweise aus, wenn das Ziel darin besteht, Folgendes wiederherzustellen:

- Entschlüsselte Konfigurationsblobs
- In-memory-Tokens, Cookies oder Zugangsdaten
- Klartext-Geheimnisse, die nur at rest geschützt sind
- Entschlüsselte Mach-O-Seiten nach Unpacking / JIT / Runtime-Patching

Wenn das Ziel durch die **hardened runtime** geschützt ist oder `taskgated` das Attach verweigert, benötigen Sie normalerweise eine dieser Bedingungen:

- Das Ziel verfügt über **`get-task-allow`**
- Ihr Debugger ist mit dem richtigen **debugger entitlement** signiert
- Sie sind **root** und das Ziel ist ein nicht gehärteter Drittanbieterprozess

Weitere Hintergrundinformationen zum Erhalten eines Task-Ports und dazu, was damit möglich ist:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Schnelle Prüfungen vor dem Attach

Bevor Sie Zeit mit LLDB/Frida verbringen, überprüfen Sie schnell, ob das Ziel realistischerweise **dumpbar** ist:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operativ bedeutet dies in der Regel:

- Eine Drittanbieter-App mit **`get-task-allow`** kann oft direkt mit LLDB gedumpt werden, und der resultierende Dump kann durch TCC geschützte Daten offenlegen, auf die die App bereits zugegriffen hat.
- Ein **gehärtetes** Ziel ohne `get-task-allow` wird Attach-Versuche häufig ablehnen, selbst als `root`, sofern du nicht die relevanten Debugger-Entitlements bzw. den entsprechenden Policy-Pfad kontrollierst.
- Nicht gehärtete Drittanbieter-Prozesse sind weiterhin der einfachste Ansatzpunkt für den Einsatz von `lldb`, `vmmap`, Frida oder eigenen `task_for_pid`/`vm_read`-Readern.

### Nach dumpbaren verschachtelten Helfern suchen

Aktuelle Untersuchungen zu notarisierten macOS-Apps finden weiterhin **`get-task-allow`** in verschachtelten Helfern anstelle des zentralen GUI-Binaries. Wenn eine App auf oberster Ebene gehärtet wirkt, solltest du ihre **XPC services**, **login items**, **helper tools** und gebündelten CLIs enumerieren, bevor du aufgibst:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ein verschachteltes Executable mit `get-task-allow` ist oft der einfachste Ort, um sich mit `lldb` anzuhängen, einen Core zu dumpen oder den Speicher mit einem benutzerdefinierten `task_for_pid`-Client auszulesen, selbst wenn die Haupt-App besser gehärtet ist.

## Selektive Dumps mit Frida oder Userland-Readern

Wenn ein vollständiger Core zu viele irrelevante Daten enthält, ist das Dumpen nur der **interessanten lesbaren Speicherbereiche** oft schneller. Frida ist besonders nützlich, weil es sich gut für eine **gezielte Extraktion** eignet, sobald du dich an den Prozess anhängen kannst.

Beispielansatz:

1. Lesbare/schreibbare Speicherbereiche enumerieren
2. Nach Modul, Heap, Stack oder anonymem Speicher filtern
3. Nur die Bereiche dumpen, die potenzielle Strings, Keys, Protobufs, Plist/XML-Blobs oder entschlüsselten Code/Daten enthalten

Minimales Frida-Beispiel zum Dumpen aller lesbaren anonymen Speicherbereiche:
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
Das ist nützlich, wenn du riesige Core-Dateien vermeiden und nur Folgendes erfassen möchtest:

- App-Heap-Chunks, die Secrets enthalten
- Anonyme Regionen, die von benutzerdefinierten Packers oder Loadern erstellt wurden
- JIT- / entpackte Code-Seiten nach dem Ändern von Berechtigungen

Wenn das Target während des Dumps weiterhin **Speicher alloziert / freigibt**, solltest du für instabile Bereiche Fridas **`readVolatile()`**-Primitive gegenüber **`readByteArray()`** bevorzugen. Es ist langsamer, verhindert aber, dass das Target beendet wird, wenn eine Seite während des Lesens unlesbar wird. Bei größeren Erfassungen kann es außerdem sauberer sein, Chunks mit `send(..., data)` zurückzustreamen und sie auf der Controller-Seite zu komprimieren, anstatt Tausende kleiner Dateien innerhalb des Targets zu erstellen.

Ältere Userland-Tools wie [`readmem`](https://github.com/gdbinit/readmem) existieren ebenfalls, sind aber hauptsächlich als **Source-Referenzen** für Dumping im Stil von `task_for_pid`/`vm_read` nützlich und werden für moderne Apple-Silicon-Workflows nicht gut gepflegt.

## Heap- / VM-Snapshots mit `.memgraph`

Wenn du dich hauptsächlich für **Heap-Objekte**, die **Herkunft von Allokationen** oder einen Snapshot interessierst, der auf eine andere Maschine übertragen werden kann, ist ein `.memgraph` oft praktischer als ein riesiger Mach-O-Core. Die `leaks`-Tools können einen solchen aus einem laufenden Prozess erzeugen:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Anschließend offline mit den standardmäßigen Apple-Tools triagieren:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` ist der Hauptgrund, eine `-fullContent`-Aufzeichnung aufzubewahren, da die Beschriftungen zur Beschreibung der Speicherinhalte aus einem minimalen `.memgraph`-Dump weggelassen werden.

Das ist besonders nützlich, wenn:

- du einen **kleineren, teilbaren Snapshot** anstelle eines vollständigen Cores möchtest
- `MallocStackLogging` aktiviert war und du **Allocation-Backtraces** möchtest
- du bereits eine **interessante Heap-Adresse** kennst und mit `malloc_history` weiterarbeiten möchtest
- du eine schnelle **VM-/Heap-Aufschlüsselung** benötigst, bevor du entscheidest, ob sich ein vollständiger Dump angesichts des zusätzlichen Rauschens lohnt

### Differential memgraph triage

Wenn du kontrollierst, wie das Ziel gestartet wird, aktiviere **historical allocation logging** vor dem Start, damit spätere Snapshots nützliche Alloc-/Free-Backtraces bewahren:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Dann erfasse Snapshots rund um die interessante Aktion und vergleiche sie offline:
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
Dies ist eine praktische Möglichkeit, **post-authentication objects**, **große `CFData`-Puffer** oder **anonyme VM-Regionen** zu isolieren, die erst nach einer Entschlüsselungs-, Unpacking- oder Secret-Retrieval-Phase erscheinen.

## Swift-lastige Ziele: `swift-inspect`

Bei Anwendungen, die hochwertige Daten in **Swift runtime objects** speichern, kann `swift-inspect` eine gute Ergänzung zu LLDB oder Frida sein. Statt zunächst alles zu dumpen, können Sie bestimmte Swift-Runtime-Strukturen aus einem laufenden Prozess abfragen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Dies ist nützlich, um Folgendes zu identifizieren:

- Große Swift-Arrays, die interessante Daten puffern
- Metadata-Allokationen, die zur Laufzeit geladene Typen offenlegen
- Swift-concurrency-Zustände (`Task`, Actor- und Thread-Beziehungen), bevor ein gezielterer Dump durchgeführt wird

Für eine weitergehende objektbezogene Runtime-Triage, sobald du den Prozess bereits inspizieren kannst, siehe [die entsprechende Seite zu Objekten im Speicher](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Hinweise zur schnellen Triage

- `sysctl vm.swapusage` ist weiterhin eine schnelle Möglichkeit, die **swap usage** und die Frage zu prüfen, ob der Swap **verschlüsselt** ist.
- `sleepimage` ist hauptsächlich für **hibernate/safe sleep**-Szenarien relevant, moderne Systeme schützen es jedoch häufig. Daher sollte es als **zu prüfende Artefaktquelle** und nicht als zuverlässiger Acquisition-Pfad betrachtet werden.
- Bei aktuellen macOS-Versionen ist **process-level dumping** im Allgemeinen realistischer als **full physical memory imaging**, sofern du nicht die Boot-Policy, den SIP-Status und das Laden von kexts kontrollierst.

## Referenzen

- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [https://keith.github.io/xcode-man-pages/leaks.1.html](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
