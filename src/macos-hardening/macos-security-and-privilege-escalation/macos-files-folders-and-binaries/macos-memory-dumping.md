# macOS-Speicherabbild

{{#include ../../../banners/hacktricks-training.md}}

## Speicherartefakte

### Swap-Dateien

Swap-Dateien wie `/private/var/vm/swapfile0` dienen als **Caches, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr vorhanden ist, werden die Daten in eine Swap-Datei übertragen und bei Bedarf wieder in den physischen Speicher geladen. Es können mehrere Swap-Dateien vorhanden sein, mit Namen wie swapfile0, swapfile1 usw.

### Hibernate-Image

Die Datei unter `/private/var/vm/sleepimage` ist während des **Ruhezustands** von entscheidender Bedeutung. **Daten aus dem Speicher werden in dieser Datei gespeichert, wenn OS X in den Ruhezustand wechselt**. Beim Aufwecken des Computers ruft das System die Speicherdaten aus dieser Datei ab, sodass der Benutzer dort weitermachen kann, wo er aufgehört hat.

Es ist erwähnenswert, dass diese Datei auf modernen MacOS-Systemen aus Sicherheitsgründen normalerweise verschlüsselt ist, was eine Wiederherstellung erschwert.

- Um zu überprüfen, ob die Verschlüsselung für das sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dadurch wird angezeigt, ob die Datei verschlüsselt ist.

### Protokolle zum Speicherdruck

Eine weitere wichtige speicherbezogene Datei in MacOS-Systemen ist das **Speicherlastprotokoll**. Diese Protokolle befinden sich in `/var/log` und enthalten detaillierte Informationen über die Speichernutzung des Systems sowie über Ereignisse im Zusammenhang mit Speicherdruck. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Laufe der Zeit verwaltet.

## Speicher mit osxpmem dumpen

Um den Speicher eines MacOS-Computers zu dumpen, kannst du [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Hinweis**: Dies ist inzwischen größtenteils ein **Legacy-Workflow**. `osxpmem` ist auf das Laden einer Kernel-Erweiterung angewiesen, das [Rekall](https://github.com/google/rekall)-Projekt wurde archiviert, die neueste Veröffentlichung stammt aus dem Jahr **2017**, und die veröffentlichte Binary zielt auf **Intel-Macs** ab. Bei aktuellen macOS-Versionen ist die kext-basierte Erfassung des vollständigen RAM, insbesondere auf **Apple Silicon**, aufgrund moderner Einschränkungen für Kernel-Erweiterungen, SIP und Anforderungen an die Plattform-Signierung normalerweise blockiert. In der Praxis führt dies auf modernen Systemen häufiger zu einem **prozessbezogenen Dump** anstelle eines vollständigen RAM-Abbilds.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn dieser Fehler auftritt: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` kannst du ihn wie folgt beheben:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** können möglicherweise behoben werden, indem du das **Laden des kext** unter „Sicherheit & Datenschutz --> Allgemein“ **erlaubst**; **erlaube** es einfach.

Du kannst auch diesen **oneliner** verwenden, um die Anwendung herunterzuladen, den kext zu laden und den Speicher zu dumpen:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live-Prozess-Dumping mit LLDB

Für **aktuelle macOS-Versionen** besteht der praktischste Ansatz normalerweise darin, den Speicher eines **bestimmten Prozesses** zu dumpen, anstatt zu versuchen, den gesamten physischen Speicher zu erfassen.

LLDB kann eine Mach-O-Core-Datei von einem aktiven Ziel speichern:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Standardmäßig wird dadurch normalerweise ein **skinny core** erstellt. Damit LLDB den gesamten zugeordneten Prozessspeicher einbezieht:
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
Das ist normalerweise ausreichend, wenn das Ziel darin besteht, Folgendes wiederherzustellen:

- Entschlüsselte Konfigurations-Blobs
- Tokens, Cookies oder Credentials im Speicher
- Klartext-Secrets, die nur im Ruhezustand geschützt sind
- Entschlüsselte Mach-O-Seiten nach Unpacking / JIT / Runtime-Patching

Wenn das Ziel durch die **hardened runtime** geschützt ist oder `taskgated` das Attach verweigert, benötigst du normalerweise eine dieser Bedingungen:

- Das Ziel verfügt über **`get-task-allow`**
- Dein Debugger ist mit dem entsprechenden **debugger entitlement** signiert
- Du bist **root** und das Ziel ist ein nicht gehärteter Third-Party-Prozess

Weitere Informationen zum Erlangen eines Task-Ports und dazu, was damit möglich ist:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Schnelle Prüfungen vor dem Attach

Bevor du Zeit mit LLDB/Frida verbringst, überprüfe kurz, ob das Ziel realistisch **dumpbar** ist:
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

- Eine Drittanbieter-App mit **`get-task-allow`** kann häufig direkt mit LLDB gedumpt werden, und der resultierende Dump kann möglicherweise durch TCC geschützte Daten offenlegen, auf die die App bereits zugegriffen hat.<sup>[1]</sup>
- Ein **gehärtetes** Ziel ohne `get-task-allow` wird Attach-Versuche gewöhnlich ablehnen, selbst als `root`, sofern du nicht über die relevanten Debugger-Entitlements bzw. den entsprechenden Policy-Pfad verfügst.
- Nicht gehärtete Drittanbieter-Prozesse sind weiterhin der einfachste Ansatzpunkt für die Verwendung von `lldb`, `vmmap`, Frida oder eigenen `task_for_pid`-/`vm_read`-Readern.

### Nach dumpbaren verschachtelten Helfern suchen

Neuere Untersuchungen zu notarized macOS-Apps finden weiterhin **`get-task-allow`** in verschachtelten Helfern statt in der GUI-Hauptbinärdatei. Wenn eine übergeordnete App gehärtet aussieht, solltest du ihre **XPC services**, **login items**, **helper tools** und gebündelten CLIs auflisten, bevor du aufgibst:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Eine verschachtelte ausführbare Datei mit `get-task-allow` ist oft die einfachste Stelle, um sich mit `lldb` anzuhängen, einen Core zu dumpen oder mit einem eigenen `task_for_pid`-Client Speicher auszulesen, selbst wenn die Hauptanwendung besser gehärtet ist.

## Selektive Dumps mit Frida oder Userland-Readern

Wenn ein vollständiger Core zu viele irrelevante Daten enthält, ist es oft schneller, nur **interessante lesbare Bereiche** zu dumpen. Frida ist besonders nützlich, da es sich gut für die **gezielte Extraktion** eignet, sobald das Anhängen an den Prozess möglich ist.

Beispielvorgehen:

1. Lesbare/schreibbare Bereiche enumerieren
2. Nach Module, Heap, Stack oder anonymem Speicher filtern
3. Nur die Regionen dumpen, die potenzielle Strings, Schlüssel, protobufs, plist/XML-Blobs oder entschlüsselten Code/Daten enthalten

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

- App-Heap-Chunks, die Secrets enthalten
- Anonyme Bereiche, die von benutzerdefinierten Packern oder Loadern erstellt wurden
- JIT- / entpackte Code-Seiten nach dem Ändern von Schutzattributen

Wenn das Ziel während des Dumps weiterhin **Speicher allokiert / freigibt**, solltest du für instabile Bereiche Fridas **`readVolatile()`**-Primitive gegenüber **`readByteArray()`** bevorzugen. Es ist langsamer, verhindert aber, dass das Ziel beendet wird, wenn eine Seite während des Lesens unlesbar wird. Bei größeren Erfassungen kann es außerdem sauberer sein, Chunks mit `send(..., data)` zurückzstreamen und sie auf der Controller-Seite zu komprimieren, anstatt Tausende kleiner Dateien im Ziel zu erstellen.

Ältere Userland-Tools wie [`readmem`](https://github.com/gdbinit/readmem) existieren ebenfalls, sind aber hauptsächlich als **Source-Referenzen** für Dumping im Stil von `task_for_pid`/`vm_read` nützlich und werden für moderne Apple-Silicon-Workflows nicht gut gepflegt.

## Heap- / VM-Snapshots mit `.memgraph`

Wenn dir hauptsächlich **Heap-Objekte**, die **Herkunft von Allokationen** oder ein Snapshot wichtig sind, der auf einen anderen Rechner übertragen werden kann, ist ein `.memgraph` oft praktischer als ein riesiger Mach-O-Core. Das `leaks`-Tooling kann einen solchen Snapshot aus einem laufenden Prozess erstellen:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Anschließend führe offline eine Triage mit den standardmäßigen Apple-Tools durch:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` ist der Hauptgrund, einen Capture mit `-fullContent` aufzubewahren, da die den Speicherinhalt beschreibenden Labels aus einem minimalen `.memgraph` weggelassen werden.

Das ist besonders nützlich, wenn:

- du einen **kleineren, teilbaren Snapshot** anstelle eines vollständigen Cores möchtest
- `MallocStackLogging` aktiviert war und du **Allocation-Backtraces** möchtest
- du bereits eine **interessante Heap-Adresse** kennst und mit `malloc_history` pivotieren möchtest
- du eine schnelle **VM-/Heap-Aufschlüsselung** benötigst, bevor du entscheidest, ob sich ein vollständiger Dump und das damit verbundene Rauschen lohnen

### Differential memgraph triage

Wenn du kontrollierst, wie das Target gestartet wird, aktiviere vor dem Start das **historical allocation logging**, damit spätere Snapshots nützliche Alloc-/Free-Backtraces bewahren:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Erfasse anschließend Snapshots rund um die interessante Aktion und führe offline einen Diff durch:
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

## Ziele mit hohem Swift-Anteil: `swift-inspect`

Für Anwendungen, die hochwertige Daten in **Swift runtime objects** speichern, kann `swift-inspect` eine gute Ergänzung zu LLDB oder Frida sein. Anstatt zunächst alles zu dumpen, können Sie bestimmte Swift-Laufzeitstrukturen aus einem laufenden Prozess abfragen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Dies ist hilfreich, um Folgendes zu identifizieren:

- Große Swift-Arrays, die interessante Daten puffern
- Metadata-Allokationen, die zur Laufzeit geladene Typen offenlegen
- Swift-concurrency-Zustand (`Task`, Actor- und Thread-Beziehungen), bevor ein gezielterer Dump durchgeführt wird

Für eine weitergehende Object-Level-Runtime-Triage, sobald du den Prozess bereits inspizieren kannst, siehe [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Kurze Triage-Hinweise

- `sysctl vm.swapusage` ist weiterhin eine schnelle Möglichkeit, die **swap usage** und die Frage zu prüfen, ob der Swap **verschlüsselt** ist.
- `sleepimage` bleibt hauptsächlich für **hibernate/safe sleep**-Szenarien relevant. Moderne Systeme schützen es jedoch häufig, daher sollte es als **zu prüfende Artefaktquelle** und nicht als zuverlässiger Acquisition-Pfad behandelt werden.
- Bei aktuellen macOS-Releases ist **process-level dumping** im Allgemeinen realistischer als ein **vollständiges Abbilden des physischen Speichers**, sofern du nicht die Boot-Policy, den SIP-Status und das Laden von kexts kontrollierst.

## Referenzen

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
