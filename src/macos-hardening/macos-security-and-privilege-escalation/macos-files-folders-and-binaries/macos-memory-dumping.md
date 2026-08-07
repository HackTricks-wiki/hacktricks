# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory-Artefakte

### Swap-Dateien

Swap-Dateien wie `/private/var/vm/swapfile0` dienen als **Caches, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr vorhanden ist, werden die Daten in eine Swap-Datei übertragen und bei Bedarf wieder in den physischen Speicher geladen. Es können mehrere Swap-Dateien vorhanden sein, beispielsweise mit den Namen swapfile0, swapfile1 usw.

### Hibernate-Image

Die Datei unter `/private/var/vm/sleepimage` spielt während des **Ruhezustands** eine wichtige Rolle. **Daten aus dem Speicher werden in dieser Datei abgelegt, wenn OS X in den Ruhezustand wechselt**. Beim Aufwecken des Computers ruft das System die Speicherdaten aus dieser Datei ab, sodass der Benutzer dort fortfahren kann, wo er aufgehört hat.

Beachte, dass diese Datei auf modernen MacOS-Systemen aus Sicherheitsgründen normalerweise verschlüsselt ist, was eine Wiederherstellung erschwert.

- Um zu überprüfen, ob die Verschlüsselung für das sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dadurch wird angezeigt, ob die Datei verschlüsselt ist.

### Logs zum Speicherdruck

Eine weitere wichtige speicherbezogene Datei in MacOS-Systemen ist das **Speicherdruck-Log**. Diese Logs befinden sich in `/var/log` und enthalten detaillierte Informationen zur Speichernutzung des Systems sowie zu Speicherdruckereignissen. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Laufe der Zeit verwaltet.

## Dumping des Speichers mit osxpmem

Um den Speicher eines MacOS-Computers zu dumpen, kannst du [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Hinweis**: Dies ist inzwischen größtenteils ein **Legacy-Workflow**. `osxpmem` ist auf das Laden einer Kernel-Erweiterung angewiesen, das [Rekall](https://github.com/google/rekall)-Projekt ist archiviert, die neueste Veröffentlichung stammt aus dem Jahr **2017**, und die veröffentlichte Binärdatei zielt auf **Intel-Macs** ab. Bei aktuellen macOS-Versionen ist die kext-basierte Erfassung des gesamten RAM, insbesondere auf **Apple Silicon**, aufgrund moderner Einschränkungen für Kernel-Erweiterungen, SIP und Anforderungen an die Plattform-Signierung normalerweise blockiert. In der Praxis führt dies auf modernen Systemen häufiger zu einem **prozessbezogenen Dump** anstelle eines Images des gesamten RAMs.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn du auf diesen Fehler stößt: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` kannst du ihn folgendermaßen beheben:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** können möglicherweise behoben werden, indem das **Laden des kext** unter „Security & Privacy --> General“ **erlaubt** wird. Klicke einfach auf **Allow**.

Du kannst auch diesen **oneliner** verwenden, um die Anwendung herunterzuladen, den kext zu laden und den Speicher zu dumpen:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping mit LLDB

Für **aktuelle macOS-Versionen** besteht der praktischste Ansatz normalerweise darin, den Speicher eines **bestimmten Prozesses** zu dumpen, anstatt zu versuchen, den gesamten physischen Speicher zu imagen.

LLDB kann eine Mach-O-Core-Datei von einem Live-Ziel speichern:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Standardmäßig wird dadurch normalerweise ein **skinny core** erstellt. Um LLDB zu zwingen, den gesamten gemappten Prozessspeicher einzubeziehen:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Nützliche Folge-Befehle vor dem Dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Dies reicht normalerweise aus, wenn das Ziel darin besteht, Folgendes wiederherzustellen:

- Entschlüsselte Konfigurationsblobs
- Tokens, Cookies oder Zugangsdaten im Speicher
- Klartext-Secrets, die nur im Ruhezustand geschützt sind
- Entschlüsselte Mach-O-Seiten nach Unpacking / JIT / Runtime-Patching

Wenn das Ziel durch die **hardened runtime** geschützt ist oder `taskgated` das Anhängen verweigert, benötigen Sie typischerweise eine dieser Voraussetzungen:

- Das Ziel enthält **`get-task-allow`**
- Ihr Debugger ist mit dem passenden **debugger entitlement** signiert
- Sie sind **root** und das Ziel ist ein nicht gehärteter Drittanbieterprozess

Weitere Informationen zum Erhalten eines Task-Ports und zu den damit möglichen Aktionen:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Schnelle Prüfungen vor dem Anhängen

Bevor Sie Zeit mit LLDB/Frida verbringen, prüfen Sie kurz, ob das Ziel realistisch **dumpbar** ist:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
In der Praxis bedeutet das normalerweise:

- Eine Drittanbieter-App, die mit **`get-task-allow`** ausgeliefert wird, kann häufig direkt mit LLDB gedumpt werden. Der resultierende Dump kann TCC-geschützte Daten offenlegen, auf die die App bereits zugegriffen hat.<sup>[[1]](#references)</sup>
- Ein **gehärtetes** Ziel ohne `get-task-allow` wird Attach-Versuche normalerweise ablehnen, selbst als `root`, sofern du nicht die relevanten Debugger-Entitlements bzw. den entsprechenden Policy-Pfad kontrollierst.
- Nicht gehärtete Prozesse von Drittanbietern sind weiterhin der einfachste Ansatzpunkt für den Einsatz von `lldb`, `vmmap`, Frida oder benutzerdefinierten `task_for_pid`-/`vm_read`-Readern.

### Dumpbare verschachtelte Helfer suchen

Aktuelle Forschung zu notarisierten macOS-Apps findet weiterhin häufig **`get-task-allow`** in verschachtelten Helfern statt, nicht in der eigentlichen GUI-Binary. Wenn eine übergeordnete App gehärtet wirkt, solltest du ihre **XPC-Services**, **Login-Items**, **Helper-Tools** und gebündelten CLIs untersuchen, bevor du aufgibst:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ein verschachteltes Executable mit `get-task-allow` ist oft der einfachste Ansatzpunkt, um sich mit `lldb` anzuhängen, einen Core zu dumpen oder mit einem benutzerdefinierten `task_for_pid`-Client den Speicher auszulesen, selbst wenn die Haupt-App besser gehärtet ist.

## Selektive Dumps mit Frida oder Userland-Readern

Wenn ein vollständiger Core zu viele irrelevante Daten enthält, ist es oft schneller, nur **interessante lesbare Bereiche** zu dumpen. Frida ist besonders nützlich, da es sich gut für eine **gezielte Extraktion** eignet, sobald du dich an den Prozess anhängen kannst.

Vorgehensweise:

1. Lesbare/schreibbare Bereiche auflisten
2. Nach Modul, Heap, Stack oder anonymem Speicher filtern
3. Nur die Regionen dumpen, die potenzielle Strings, Schlüssel, Protobufs, Plist/XML-Blobs oder entschlüsselten Code/Daten enthalten

Minimales Frida-Beispiel zum Dumpen aller lesbaren anonymen Bereiche:
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
Dies ist nützlich, wenn du riesige Core-Dateien vermeiden und nur Folgendes erfassen möchtest:

- App-Heap-Chunks, die Secrets enthalten
- Anonyme Speicherbereiche, die von benutzerdefinierten Packern oder Loadern erstellt wurden
- JIT- / entpackte Code-Seiten nach dem Ändern von Protection-Flags

Wenn das Ziel während des Dumps weiterhin **Speicher allokiert / freigibt**, solltest du für instabile Bereiche Fridas **`readVolatile()`**-Primitive gegenüber **`readByteArray()`** bevorzugen. Es ist langsamer, verhindert jedoch, dass das Ziel beendet wird, wenn eine Seite während des Lesens unlesbar wird. Bei größeren Acquisitions kann es außerdem sauberer sein, Chunks mit `send(..., data)` zurückzuströmen und sie auf der Controller-Seite zu komprimieren, anstatt Tausende kleiner Dateien innerhalb des Ziels zu erstellen.

Ältere Userland-Tools wie [`readmem`](https://github.com/gdbinit/readmem) gibt es ebenfalls, sie sind jedoch hauptsächlich als **Quellreferenzen** für Dumping nach dem Muster von direktem `task_for_pid`/`vm_read` nützlich und werden für moderne Apple-Silicon-Workflows nicht gut gepflegt.

## Heap- / VM-Snapshots mit `.memgraph`

Wenn du dich hauptsächlich für **Heap-Objekte**, die **Herkunft von Allokationen** oder einen Snapshot interessierst, der auf einen anderen Rechner verschoben werden kann, ist ein `.memgraph` oft praktischer als ein riesiger Mach-O-Core. Die `leaks`-Tools können einen solchen Snapshot aus einem laufenden Prozess erzeugen:<sup>[[2]](#references)</sup>
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Anschließend führe offline eine Triage mit standardmäßigen Apple-Tools durch:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` ist der Hauptgrund, eine `-fullContent`-Aufzeichnung aufzubewahren, da die den Speicherinhalt beschreibenden Labels aus einem minimalen `.memgraph` weggelassen werden.

Dies ist besonders nützlich, wenn:

- du einen **kleineren, teilbaren Snapshot** anstelle eines vollständigen Cores möchtest
- `MallocStackLogging` aktiviert war und du **Allocation-Backtraces** möchtest
- du bereits eine **interessante Heap-Adresse** kennst und mit `malloc_history` pivotieren möchtest
- du eine schnelle **VM-/Heap-Aufschlüsselung** benötigst, bevor du entscheidest, ob sich ein vollständiger Dump angesichts des zusätzlichen Rauschens lohnt

### Differentielle memgraph-Triage

Wenn du kontrollierst, wie das Ziel gestartet wird, aktiviere vor dem Start **historical allocation logging**, damit spätere Snapshots nützliche alloc/free-Backtraces bewahren:
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
Dies ist eine praktische Möglichkeit, **post-authentication objects**, große `CFData`-Puffer oder **anonymous VM regions** zu isolieren, die erst nach einer Entschlüsselungs-, Unpacking- oder Secret-Retrieval-Phase erscheinen.

## Swift-lastige Ziele: `swift-inspect`

Bei Anwendungen, die wichtige Daten in **Swift runtime objects** speichern, kann `swift-inspect` eine gute Ergänzung zu LLDB oder Frida sein. Anstatt zunächst alles zu dumpen, kannst du bestimmte Swift-Laufzeitstrukturen aus einem laufenden Prozess abfragen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Das ist hilfreich, um Folgendes zu identifizieren:

- Große Swift-Arrays, die interessante Daten puffern
- Metadaten-Allokationen, die zur Laufzeit geladene Typen offenlegen
- Swift-Concurrency-Zustand (`Task`, Actor- und Thread-Beziehungen), bevor ein gezielterer Dump durchgeführt wird

Für eine weitergehende Triage auf Objektebene, sobald du den Prozess bereits inspizieren kannst, siehe [die spezielle Seite zu Objekten im Speicher](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Kurze Triage-Hinweise

- `sysctl vm.swapusage` ist weiterhin eine schnelle Möglichkeit, die **Swap-Nutzung** und festzustellen, ob der Swap **verschlüsselt** ist.
- `sleepimage` bleibt hauptsächlich für **hibernate/safe sleep**-Szenarien relevant. Moderne Systeme schützen es jedoch häufig, weshalb es als **zu überprüfende Artefaktquelle** und nicht als zuverlässiger Erfassungspfad betrachtet werden sollte.
- Bei aktuellen macOS-Versionen ist **Dumping auf Prozessebene** im Allgemeinen realistischer als die **vollständige Abbildung des physischen Speichers**, sofern du nicht die Boot-Richtlinie, den SIP-Zustand und das Laden von kexts kontrollierst.

## Referenzen

- [1] [Zulassen oder nicht zulassen von get-task-allow: macOS-Sicherheitsanalyse](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1)-Manpage](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
