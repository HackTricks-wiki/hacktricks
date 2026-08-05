# macOS-Speicher-Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Speicherartefakte

### Swap-Dateien

Swap-Dateien wie `/private/var/vm/swapfile0` dienen als **Caches, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr vorhanden ist, werden die Daten in eine Swap-Datei übertragen und bei Bedarf wieder in den physischen Speicher geladen. Es können mehrere Swap-Dateien vorhanden sein, mit Namen wie swapfile0, swapfile1 usw.

### Hibernate-Image

Die Datei unter `/private/var/vm/sleepimage` ist während des **Ruhezustands** von entscheidender Bedeutung. **Daten aus dem Speicher werden in dieser Datei gespeichert, wenn OS X in den Ruhezustand wechselt**. Beim Aufwecken des Computers ruft das System die Speicherdaten aus dieser Datei ab, sodass der Benutzer dort fortfahren kann, wo er aufgehört hat.

Beachten Sie, dass diese Datei auf modernen MacOS-Systemen aus Sicherheitsgründen typischerweise verschlüsselt ist, was die Wiederherstellung erschwert.

- Um zu prüfen, ob die Verschlüsselung für das sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dadurch wird angezeigt, ob die Datei verschlüsselt ist.

### Speicher-Auslastungsprotokolle

Eine weitere wichtige speicherbezogene Datei in MacOS-Systemen ist das **Speicher-Auslastungsprotokoll**. Diese Protokolle befinden sich in `/var/log` und enthalten detaillierte Informationen zur Speichernutzung des Systems und zu Ereignissen im Zusammenhang mit Speicherdruck. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Laufe der Zeit verwaltet.

## Speicher-Dumping mit osxpmem

Um den Speicher eines MacOS-Computers zu dumpen, können Sie [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Hinweis**: Dies ist inzwischen größtenteils ein **veralteter Workflow**. `osxpmem` hängt vom Laden einer Kernel-Erweiterung ab, das [Rekall](https://github.com/google/rekall)-Projekt ist archiviert, die neueste Version stammt aus dem Jahr **2017**, und die veröffentlichte Binary zielt auf **Intel-Macs** ab. Bei aktuellen macOS-Versionen ist die Erfassung des vollständigen RAM-Inhalts mithilfe von kexts, insbesondere auf **Apple Silicon**, aufgrund moderner Einschränkungen für Kernel-Erweiterungen, SIP und Anforderungen an die Plattform-Signierung normalerweise blockiert. In der Praxis führt dies auf modernen Systemen häufiger zu einem **prozessbezogenen Dump** anstelle eines vollständigen RAM-Images.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn du auf diesen Fehler stößt: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Du kannst ihn folgendermaßen beheben:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** könnten behoben werden, indem du das **Laden des kext** unter „Sicherheit & Datenschutz --> Allgemein“ **erlaubst** – einfach **erlauben**.

Du kannst auch diesen **oneliner** verwenden, um die Anwendung herunterzuladen, das kext zu laden und den Speicher zu dumpen:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live-Prozess-Dumping mit LLDB

Für **aktuelle macOS-Versionen** besteht der praktischste Ansatz normalerweise darin, den Speicher eines **bestimmten Prozesses** zu dumpen, anstatt zu versuchen, den gesamten physischen Speicher zu imagen.

LLDB kann eine Mach-O-Core-Datei von einem Live-Target speichern:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Standardmäßig erstellt dies normalerweise einen **skinny core**. Um LLDB zu zwingen, den gesamten gemappten Prozessspeicher einzubeziehen:
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

- Entschlüsselte Konfigurations-Blobs
- Tokens, Cookies oder Zugangsdaten im Speicher
- Klartextgeheimnisse, die nur im Ruhezustand geschützt sind
- Entschlüsselte Mach-O-Seiten nach Unpacking / JIT / Runtime-Patching

Wenn das Ziel durch die **hardened runtime** geschützt ist oder `taskgated` das Anhängen verweigert, benötigen Sie normalerweise eine der folgenden Bedingungen:

- Das Ziel enthält **`get-task-allow`**
- Ihr Debugger ist mit dem geeigneten **debugger entitlement** signiert
- Sie sind **root** und das Ziel ist ein nicht gehärteter Drittanbieterprozess

Weitere Hintergrundinformationen zum Erlangen eines Task-Ports und zu den damit möglichen Aktionen:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Schnelle Prüfungen vor dem Anhängen

Bevor Sie Zeit mit LLDB/Frida verbringen, prüfen Sie kurz, ob das Ziel realistisch **dumpable** ist:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operativ bedeutet das in der Regel:

- Eine Drittanbieter-App, die mit **`get-task-allow`** ausgeliefert wird, kann oft direkt mit LLDB gedumpt werden, und der resultierende Dump kann durch TCC geschützte Daten offenlegen, auf die die App bereits zugegriffen hat.<sup>[[1]](#references)</sup>
- Ein **hardened** Target ohne `get-task-allow` wird Attaches üblicherweise ablehnen, selbst als `root`, sofern du nicht die relevanten Debugger-Entitlements bzw. den entsprechenden Policy-Pfad kontrollierst.
- Ungehärtete Prozesse von Drittanbietern sind weiterhin der einfachste Ansatzpunkt für die Verwendung von `lldb`, `vmmap`, Frida oder benutzerdefinierten `task_for_pid`/`vm_read`-Readern.

### Suche nach dumpbaren verschachtelten Helfern

Aktuelle Forschung zu notarisierten macOS-Apps findet weiterhin häufig **`get-task-allow`** in verschachtelten Helfern statt im Haupt-GUI-Binary. Wenn eine übergeordnete App gehärtet wirkt, liste ihre **XPC-Services**, **Login Items**, **Helper Tools** und gebündelten CLIs auf, bevor du aufgibst:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ein verschachteltes Executable mit `get-task-allow` ist oft die einfachste Stelle, um sich mit `lldb` anzuhängen, einen Core zu dumpen oder mit einem benutzerdefinierten `task_for_pid`-Client Speicher auszulesen, selbst wenn die Haupt-App besser gehärtet ist.

## Selektive Dumps mit Frida oder Userland-Readern

Wenn ein vollständiger Core zu viele irrelevante Daten enthält, ist es oft schneller, nur **interessante lesbare Bereiche** zu dumpen. Frida ist besonders nützlich, da es sich gut für die **gezielte Extraktion** eignet, sobald du dich an den Prozess anhängen kannst.

Beispielansatz:

1. Lesbare/schreibbare Bereiche aufzählen
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
Dies ist nützlich, wenn du riesige Core-Dateien vermeiden und nur Folgendes sammeln möchtest:

- App-Heap-Chunks mit Secrets
- Anonyme Regions, die von benutzerdefinierten Packers oder Loadern erstellt wurden
- JIT- / entpackte Code-Seiten nach dem Ändern von Protections

Wenn das Ziel während des Dumps weiterhin **Speicher allokiert / freigibt**, solltest du für instabile Bereiche Fridas Primitive **`readVolatile()`** anstelle von **`readByteArray()`** bevorzugen. Es ist langsamer, verhindert jedoch, dass der Zielprozess beendet wird, wenn eine Seite während des Lesens unlesbar wird. Bei größeren Acquisitions kann es außerdem sauberer sein, Chunks mit `send(..., data)` zurückzustreamen und sie auf der Controller-Seite zu komprimieren, anstatt Tausende kleiner Dateien innerhalb des Zielprozesses zu erstellen.

Ältere Userland-Tools wie [`readmem`](https://github.com/gdbinit/readmem) existieren ebenfalls, sind jedoch hauptsächlich als **Source-Referenzen** für Dumping im Stil von `task_for_pid`/`vm_read` nützlich und werden für moderne Apple-Silicon-Workflows nicht mehr besonders gut gepflegt.

## Heap / VM-Snapshots mit `.memgraph`

Wenn du dich hauptsächlich für **Heap-Objekte**, die **Herkunft von Allokationen** oder einen Snapshot interessierst, der auf einen anderen Rechner übertragen werden kann, ist ein `.memgraph` häufig praktischer als ein riesiger Mach-O-Core. Die `leaks`-Tools können einen solchen Snapshot aus einem laufenden Prozess erzeugen:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Führen Sie anschließend offline eine Triage mit den standardmäßigen Apple-Tools durch:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` ist der Hauptgrund, einen Capture mit `-fullContent` aufzubewahren, da die Labels, die den Speicherinhalt beschreiben, aus einem minimalen `.memgraph` weggelassen werden.

Das ist besonders nützlich, wenn:

- du einen **kleineren, teilbaren Snapshot** anstelle eines vollständigen Cores möchtest
- `MallocStackLogging` aktiviert war und du **Allocation-Backtraces** benötigst
- du bereits eine **interessante Heap-Adresse** kennst und mit `malloc_history` pivotieren möchtest
- du eine schnelle **VM-/Heap-Aufschlüsselung** benötigst, bevor du entscheidest, ob sich der Lärm eines vollständigen Dumps lohnt

### Differential-memgraph-Triage

Wenn du kontrollierst, wie das Target startet, aktiviere das **historical allocation logging** vor dem Start, damit spätere Snapshots nützliche Alloc-/Free-Backtraces bewahren:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Erfassen Sie anschließend Snapshots rund um die relevante Aktion und vergleichen Sie sie offline:
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

## Ziele mit starkem Swift-Anteil: `swift-inspect`

Bei Anwendungen, die hochwertige Daten in **Swift runtime objects** speichern, kann `swift-inspect` eine gute Ergänzung zu LLDB oder Frida sein. Statt zunächst alles zu dumpen, können Sie bestimmte Swift-Laufzeitstrukturen aus einem laufenden Prozess abfragen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Dies ist hilfreich, um Folgendes zu identifizieren:

- Große Swift-Arrays, die interessante Daten puffern
- Metadata-Allokationen, die zur Laufzeit geladene Typen offenlegen
- Swift-Concurrency-Zustände (`Task`, Actor- und Thread-Beziehungen), bevor ein gezielterer Dump durchgeführt wird

Für eine detailliertere Triage auf Objektebene, sobald du den Prozess bereits untersuchen kannst, siehe [die spezielle Seite zu Objekten im Speicher](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Hinweise zur schnellen Triage

- `sysctl vm.swapusage` ist weiterhin eine schnelle Möglichkeit, die **Swap-Nutzung** und festzustellen, ob der Swap **verschlüsselt** ist.
- `sleepimage` bleibt hauptsächlich für **Hibernate-/Safe-Sleep**-Szenarien relevant. Moderne Systeme schützen es jedoch häufig, daher sollte es als **zu überprüfende Artefaktquelle** und nicht als zuverlässiger Erfassungspfad behandelt werden.
- Bei aktuellen macOS-Versionen ist **prozessweises Dumping** im Allgemeinen realistischer als ein **vollständiges Abbilden des physischen Speichers**, sofern du nicht die Boot-Richtlinie, den SIP-Status und das Laden von Kexts kontrollierst.

## Referenzen

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
