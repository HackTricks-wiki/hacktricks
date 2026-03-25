# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Speicher-Artefakte

### Swap-Dateien

Swap-Dateien, wie z. B. `/private/var/vm/swapfile0`, fungieren als **Cache, wenn der physische Speicher voll ist**. Wenn kein Platz mehr im physischen Speicher vorhanden ist, werden dessen Daten in eine Swap-Datei verschoben und bei Bedarf wieder in den physischen Speicher zurückgeholt. Es können mehrere Swap-Dateien vorhanden sein, mit Namen wie swapfile0, swapfile1 usw.

### Ruhezustandsabbild

Die Datei unter `/private/var/vm/sleepimage` ist im **Ruhezustandsmodus** entscheidend. **Daten aus dem Arbeitsspeicher werden in dieser Datei gespeichert, wenn OS X in den Ruhezustand geht**. Beim Aufwachen des Computers liest das System die Speicherdaten aus dieser Datei aus, sodass der Benutzer dort weitermachen kann, wo er aufgehört hat.

Es ist anzumerken, dass diese Datei auf modernen macOS-Systemen aus Sicherheitsgründen typischerweise verschlüsselt ist, was eine Wiederherstellung erschwert.

- Um zu prüfen, ob die Verschlüsselung für das sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dieser zeigt, ob die Datei verschlüsselt ist.

### Memory Pressure Logs

Eine weitere wichtige speicherbezogene Datei in macOS-Systemen ist das **memory pressure log**. Diese Logs befinden sich in `/var/log` und enthalten detaillierte Informationen zur Speichernutzung und zu Pressure-Ereignissen des Systems. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Zeitverlauf verwaltet.

## Speicher auslesen mit osxpmem

Um den Speicher auf einem macOS-Rechner auszulesen, können Sie [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Hinweis**: Dies ist heute größtenteils ein **Legacy-Workflow**. `osxpmem` ist auf das Laden einer kernel extension angewiesen, das [Rekall](https://github.com/google/rekall) Projekt ist archiviert, die letzte Veröffentlichung stammt aus **2017**, und das veröffentlichte Binary zielt auf **Intel Macs** ab. Bei aktuellen macOS-Versionen, insbesondere auf **Apple Silicon**, wird kext-basierte vollständige RAM-Erfassung in der Regel durch moderne Einschränkungen für kernel extensions, SIP und Anforderungen an die Plattform-Signierung blockiert. In der Praxis führt dies auf modernen Systemen häufiger zu einem **prozess-skopierten Dump** statt eines vollständigen RAM-Abbilds.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn Sie diese Fehlermeldung sehen: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` können Sie es folgendermaßen beheben:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** können behoben werden, indem Sie in "Sicherheit & Datenschutz --> Allgemein" das Laden des kext erlauben — einfach **zulassen**.

Du kannst auch diesen **oneliner** verwenden, um die Anwendung herunterzuladen, das kext zu laden und den Speicher zu dumpen:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live-Prozess-Dumping mit LLDB

Bei **neueren macOS-Versionen** ist der praktischste Ansatz meist, den Speicher eines **bestimmten Prozesses** zu dumpen, anstatt zu versuchen, ein Abbild des gesamten physischen Speichers zu erstellen.

LLDB kann eine Mach-O-Core-Datei von einem laufenden Target speichern:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Standardmäßig erzeugt dies normalerweise einen **skinny core**. Um LLDB zu zwingen, den gesamten zugeordneten Prozessspeicher einzuschließen:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Nützliche Folgebefehle vor dem dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Das ist in der Regel ausreichend, wenn das Ziel darin besteht, wiederherzustellen:

- Entschlüsselte Konfigurationsblobs
- Im Speicher befindliche Tokens, Cookies oder Zugangsdaten
- Klartextgeheimnisse, die nur im Ruhezustand geschützt sind
- Entschlüsselte Mach-O-Seiten nach Entpacken / JIT / Laufzeit-Patching

Wenn das Ziel durch den **hardened runtime** geschützt ist, oder wenn `taskgated` das Attach verweigert, benötigst du in der Regel eine der folgenden Voraussetzungen:

- Das Ziel enthält **`get-task-allow`**
- Dein Debugger ist mit der passenden **debugger entitlement** signiert
- Du bist **root** und das Ziel ist ein nicht-gehärteter Drittanbieterprozess

Für Hintergrundinformationen zum Erhalten eines task port und was damit möglich ist:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Selektive Dumps mit Frida oder userland readers

Wenn ein vollständiger core zu viel Rauschen erzeugt, ist es oft schneller, nur die **interessanten lesbaren Bereiche** zu dumpen. Frida ist besonders nützlich, weil es sich gut für die **gezielte Extraktion** eignet, sobald du dich an den Prozess anhängen kannst.

Beispielvorgehen:

1. Lesbare/schreibbare Bereiche auflisten
2. Nach Modul, heap, stack oder anonymous memory filtern
3. Nur die Regionen dumpen, die Kandidatenstrings, Schlüssel, protobufs, plist/XML-Blobs oder entschlüsselten Code/Daten enthalten

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
Das ist nützlich, wenn man riesige Core-Dateien vermeiden und nur sammeln möchte:

- App-Heap-Abschnitte, die Geheimnisse enthalten
- Anonyme Regionen, die von custom packers oder loaders erstellt werden
- JIT / unpacked Code-Seiten nach Änderung der Speicher-Schutzrechte

Ältere userland-Tools wie [`readmem`](https://github.com/gdbinit/readmem) existieren ebenfalls, sind jedoch hauptsächlich als **Quellenreferenzen** für direkte `task_for_pid`/`vm_read`-artige Dumps nützlich und werden für moderne Apple Silicon workflows nicht gut gepflegt.

## Schnelle Triage-Hinweise

- `sysctl vm.swapusage` ist weiterhin ein schneller Weg, die **Swap-Nutzung** und ob der Swap **verschlüsselt** ist, zu prüfen.
- `sleepimage` bleibt hauptsächlich für **hibernate/safe sleep**-Szenarien relevant, aber moderne Systeme schützen es häufig. Es sollte daher als **Artefaktquelle zur Überprüfung** und nicht als verlässlicher Erfassungsweg betrachtet werden.
- Auf aktuellen macOS-Releases ist **process-level dumping** generell realistischer als **full physical memory imaging**, sofern du nicht die boot policy, den SIP state und das kext loading kontrollierst.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
