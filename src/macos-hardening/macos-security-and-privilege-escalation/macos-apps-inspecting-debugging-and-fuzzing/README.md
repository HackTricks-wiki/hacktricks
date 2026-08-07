# macOS Apps - Untersuchen, Debuggen und Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Statische Analyse

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

Du kannst [**disarm hier herunterladen**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Beachte, dass **`disarm`** auch mit komprimierten IM4P-Dateien (wie `kernelcache`) arbeiten und nur die erforderlichen Teile extrahieren oder den erforderlichen Teil sogar analysieren kann, ohne ihn zu extrahieren.
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
> **`Codesign`** ist in **macOS** zu finden, während **`ldid`** in **iOS** zu finden ist.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ist ein nützliches Tool, um **.pkg**-Dateien (Installer) zu untersuchen und zu sehen, was darin enthalten ist, bevor sie installiert werden.\
Diese Installer enthalten `preinstall`- und `postinstall`-Bash-Skripte, die Malware-Autoren normalerweise missbrauchen, um **die** **Malware** dauerhaft zu verankern.

### hdiutil

Dieses Tool ermöglicht es, Apple-Disk-Images (**.dmg**) zu **mounten**, um sie zu untersuchen, bevor irgendetwas ausgeführt wird:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Es wird in `/Volumes` eingehängt.

### Gepackte Binaries

- Auf hohe Entropie prüfen
- Die Strings prüfen (gibt es fast keine verständlichen Strings, ist die Datei gepackt)
- Der UPX packer für MacOS erzeugt einen Abschnitt namens "\_\_XHDR"

## Statische Objective-C-Analyse

### Metadaten

> [!CAUTION]
> Beachte, dass in Objective-C geschriebene Programme ihre Klassendeklarationen **beibehalten**, **wenn** sie in [Mach-O-Binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **kompiliert** werden. Solche Klassendeklarationen **enthalten** den Namen und Typ von:

- Den definierten Interfaces
- Den Interface-Methoden
- Den Interface-Instanzvariablen
- Den definierten Protokollen

Beachte, dass diese Namen obfuskiert werden könnten, um das Reversing des Binaries zu erschweren.

### Funktionsaufrufe

Wenn eine Funktion in einem Binary aufgerufen wird, das Objective-C verwendet, ruft der kompilierte Code nicht direkt diese Funktion auf, sondern **`objc_msgSend`**. Dieses ruft die endgültige Funktion auf:

![Metadaten – Funktionsaufrufe: Wenn eine Funktion in einem Binary aufgerufen wird, das Objective-C verwendet, ruft der kompilierte Code nicht direkt diese Funktion auf, sondern objc msgSend. Dieses ruft die endgültige Funktion auf...](<../../../images/image (305).png>)

Die von dieser Funktion erwarteten Parameter sind:

- Der erste Parameter (**self**) ist „ein Zeiger, der auf die **Instanz der Klasse zeigt, die die Nachricht empfangen soll**“. Einfacher ausgedrückt ist es das Objekt, auf dem die Methode aufgerufen wird. Wenn die Methode eine Klassenmethode ist, handelt es sich dabei um eine Instanz des Klassenobjekts (als Ganzes), während `self` bei einer Instanzmethode auf eine instanziierte Instanz der Klasse als Objekt zeigt.
- Der zweite Parameter (**op**) ist „der Selector der Methode, die die Nachricht verarbeitet“. Einfacher ausgedrückt ist dies lediglich der **Name der Methode**.
- Die verbleibenden Parameter sind alle **von der Methode benötigten Werte** (op).

Auf dieser Seite erfährst du, wie du diese Informationen mit `lldb` in **ARM64** einfach abrufen kannst:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**         | **Register**                                                     | **(für) objc_msgSend**                                |
| -------------------- | ---------------------------------------------------------------- | ----------------------------------------------------- |
| **1. Argument**      | **rdi**                                                          | **self: Objekt, auf dem die Methode aufgerufen wird** |
| **2. Argument**      | **rsi**                                                          | **op: Name der Methode**                               |
| **3. Argument**      | **rdx**                                                          | **1. Argument der Methode**                            |
| **4. Argument**      | **rcx**                                                          | **2. Argument der Methode**                            |
| **5. Argument**      | **r8**                                                           | **3. Argument der Methode**                            |
| **6. Argument**      | **r9**                                                           | **4. Argument der Methode**                            |
| **7.+ Argument**     | <p><strong>rsp+</strong><br><strong>(auf dem Stack)</strong></p> | **5.+ Argument der Methode**                          |

### Objective-C-Metadaten dumpen

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ist ein Tool zum Class-Dumpen von Objective-C-Binaries. Auf GitHub werden dylibs angegeben, aber das Tool funktioniert auch mit Executables.
```bash
./dynadump dump /path/to/bin
```
Zum Zeitpunkt der Erstellung ist dies **derzeit die Methode, die am besten funktioniert**.

#### Reguläre Tools
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ist das ursprüngliche Tool zum Generieren von Deklarationen für Klassen, Kategorien und Protokolle in formatiertem Objective-C-Code.

Es ist veraltet und wird nicht mehr gepflegt, daher funktioniert es wahrscheinlich nicht ordnungsgemäß.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) ist ein modernes und plattformübergreifendes Objective-C class dump. Im Vergleich zu vorhandenen Tools kann iCDump unabhängig vom Apple-Ökosystem ausgeführt werden und stellt Python-Bindings bereit.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statische Swift-Analyse

Bei Swift-Binaries kann man aufgrund der Objective-C-Kompatibilität manchmal Deklarationen mit [class-dump](https://github.com/nygard/class-dump/) extrahieren, aber nicht immer.

Mit den Befehlszeilen **`jtool -l`** oder **`otool -l`** ist es möglich, mehrere Abschnitte zu finden, die mit dem Präfix **`__swift5`** beginnen:
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
Weitere Informationen zu den [**in diesen Abschnitten gespeicherten Informationen finden Sie in diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Außerdem können **Swift-Binaries Symbole** enthalten (beispielsweise müssen Bibliotheken Symbole speichern, damit ihre Funktionen aufgerufen werden können). Die **Symbole enthalten normalerweise Informationen über den Funktionsnamen** und Attribute auf unschöne Weise, daher sind sie sehr nützlich, und es gibt "**demanglers**", die den ursprünglichen Namen ermitteln können:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamische Analyse

> [!WARNING]
> Beachte, dass zum Debuggen von Binaries **SIP deaktiviert** sein muss (`csrutil disable` oder `csrutil enable --without debug`). Alternativ können die Binaries in einen temporären Ordner kopiert und die **Signatur entfernt** werden, mit `codesign --remove-signature <binary-path>`, oder das Debugging der Binary kann erlaubt werden (du kannst [dieses Script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) verwenden).

> [!WARNING]
> Beachte, dass zum **Instrumentieren von System-Binaries** (wie `cloudconfigurationd`) unter macOS **SIP deaktiviert** sein muss (das alleinige Entfernen der Signatur funktioniert nicht).

### APIs

macOS stellt einige interessante APIs bereit, die Informationen über die Prozesse liefern:

- `proc_info`: Dies ist die wichtigste API und liefert viele Informationen über jeden Prozess. Du musst root sein, um Informationen über andere Prozesse zu erhalten, benötigst jedoch keine speziellen Entitlements oder Mach-Ports.
- `libsysmon.dylib`: Ermöglicht das Abrufen von Prozessinformationen über bereitgestellte XPC-Funktionen. Dafür ist jedoch das Entitlement `com.apple.sysmond.client` erforderlich.

### Stackshot & microstackshots

**Stackshotting** ist eine Technik, mit der der Zustand der Prozesse erfasst wird, einschließlich der Call Stacks aller laufenden Threads. Dies ist besonders nützlich für Debugging, Performance-Analysen und das Verständnis des Systemverhaltens zu einem bestimmten Zeitpunkt. Unter iOS und macOS kann Stackshotting mit verschiedenen Tools und Methoden wie den Tools **`sample`** und **`spindump`** durchgeführt werden.

### Sysdiagnose

Dieses Tool (`/usr/bini/ysdiagnose`) sammelt grundsätzlich viele Informationen von deinem Computer, indem es Dutzende verschiedene Befehle wie `ps`, `zprint` ... ausführt.

Es muss als **root** ausgeführt werden, und der Daemon `/usr/libexec/sysdiagnosed` verfügt über sehr interessante Entitlements wie `com.apple.system-task-ports` und `get-task-allow`.

Seine Plist befindet sich unter `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` und deklariert 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Löscht alte Archive in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Spezieller Port 23 (Kernel)
- `com.apple.sysdiagnose.service.xpc`: User-Mode-Schnittstelle über die Obj-C-Klasse `Libsysdiagnose`. Drei Argumente können in einem Dict übergeben werden (`compress`, `display`, `run`).

### Unified Logs

macOS erzeugt viele Logs, die beim Ausführen einer Anwendung sehr nützlich sein können, um zu verstehen, **was sie tut**.

Außerdem gibt es einige Logs, die das Tag `<private>` enthalten, um bestimmte **Benutzer-** oder **Computerinformationen** zu **verbergen, anhand derer eine Identifizierung möglich ist**. Es ist jedoch möglich, **ein Zertifikat zu installieren, um diese Informationen offenzulegen**. Folge den Erklärungen [**hier**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Linkes Panel

Im linken Panel von Hopper können die Symbole (**Labels**) der Binary, die Liste der Prozeduren und Funktionen (**Proc**) sowie die Strings (**Str**) angezeigt werden. Dabei handelt es sich nicht um alle Strings, sondern um diejenigen, die in mehreren Teilen der Mac-O-Datei definiert sind (wie _cstring oder_ `objc_methname`).

#### Mittleres Panel

Im mittleren Panel siehst du den **disassemblierten Code**. Du kannst ihn durch Klicken auf das jeweilige Symbol als **rohen** Disassembly-Code, als **Graph**, als **dekompilierten Code** oder als **Binary** anzeigen:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Durch einen Rechtsklick auf ein Codeobjekt kannst du **Referenzen zu/von diesem Objekt** anzeigen oder seinen Namen ändern (dies funktioniert nicht im dekompilierten Pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Außerdem kannst du unten im **mittleren Panel Python-Befehle schreiben**.

#### Rechtes Panel

Im rechten Panel siehst du interessante Informationen wie den **Navigationsverlauf** (damit du weißt, wie du zur aktuellen Situation gelangt bist), den **Aufrufgraphen**, in dem du alle **Funktionen sehen kannst, die diese Funktion aufrufen**, sowie alle Funktionen, die **von dieser Funktion aufgerufen werden**, und Informationen zu **lokalen Variablen**.

### dtrace

Es ermöglicht Benutzern den Zugriff auf Anwendungen auf einer extrem **niedrigen Ebene** und bietet eine Möglichkeit, **Programme zu tracen** und sogar ihren Ausführungsfluss zu ändern. Dtrace verwendet **Probes**, die **im gesamten Kernel platziert** sind, beispielsweise am Anfang und Ende von Systemaufrufen.

DTrace verwendet die Funktion **`dtrace_probe_create`**, um für jeden Systemaufruf eine Probe zu erstellen. Diese Probes können am **Eintritts- und Austrittspunkt jedes Systemaufrufs** ausgelöst werden. Die Interaktion mit DTrace erfolgt über /dev/dtrace, das nur für den root-Benutzer verfügbar ist.<sup>[[1]](#references)</sup>

> [!TIP]
> Um Dtrace zu aktivieren, ohne den SIP-Schutz vollständig zu deaktivieren, kannst du im Recovery-Modus Folgendes ausführen: `csrutil enable --without dtrace`
>
> Du kannst auch **`dtrace`**- oder **`dtruss`**-Binaries verwenden, die **du selbst kompiliert** hast.

Die verfügbaren Probes von dtrace können folgendermaßen abgerufen werden:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Der Name einer Probe besteht aus vier Teilen: Provider, Modul, Funktion und Name (`fbt:mach_kernel:ptrace:entry`). Wenn du einen Teil des Namens nicht angibst, verwendet Dtrace diesen Teil als Wildcard.

Um DTrace so zu konfigurieren, dass Probes aktiviert werden und festzulegen, welche Aktionen bei deren Auslösung ausgeführt werden sollen, müssen wir die D-Sprache verwenden.

Eine ausführlichere Erklärung und weitere Beispiele findest du unter [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Beispiele

Führe `man -k dtrace` aus, um die **verfügbaren DTrace-Skripte** aufzulisten. Beispiel: `sudo dtruss -n binary`

- In Zeile
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- Skript
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

Es handelt sich um eine Kernel-Tracing-Funktion. Die dokumentierten Codes befinden sich in **`/usr/share/misc/trace.codes`**.

Tools wie `latency`, `sc_usage`, `fs_usage` und `trace` verwenden sie intern.

Für die Schnittstelle zu `kdebug` wird `sysctl` über den Namespace `kern.kdebug` verwendet. Die zu verwendenden MIBs befinden sich in `sys/sysctl.h`; die Funktionen sind in `bsd/kern/kdebug.c` implementiert.

Um mit einem benutzerdefinierten Client mit kdebug zu interagieren, sind dies normalerweise die Schritte:

- Vorhandene Einstellungen mit KERN_KDSETREMOVE entfernen
- Tracing mit KERN_KDSETBUF und KERN_KDSETUP einrichten
- KERN_KDGETBUF verwenden, um die Anzahl der Buffer-Einträge abzurufen
- Den eigenen Client mit KERN_KDPINDEX aus dem Trace entfernen
- Tracing mit KERN_KDENABLE aktivieren
- Den Buffer durch Aufruf von KERN_KDREADTR lesen
- KERN_KDTHRMAP verwenden, um jeden Thread seinem Prozess zuzuordnen.

Um diese Informationen abzurufen, kann das Apple-Tool **`trace`** oder das benutzerdefinierte Tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** verwendet werden.**

**Beachte, dass Kdebug jeweils nur für 1 Benutzer verfügbar ist.** Daher kann immer nur ein von k-debug unterstütztes Tool gleichzeitig ausgeführt werden.

### ktrace

Die `ktrace_*`-APIs stammen aus `libktrace.dylib` und kapseln die APIs von `Kdebug`. Ein Client kann daher einfach `ktrace_session_create` und `ktrace_events_[single/class]` aufrufen, um Callbacks für bestimmte Codes festzulegen, und anschließend mit `ktrace_start` starten.

Du kannst dieses Tool auch bei **aktiviertem SIP** verwenden.

Als Clients kannst du das Utility `ktrace` verwenden:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Oder `tailspin`.

### kperf

Dies wird für das Profiling auf Kernel-Ebene verwendet und basiert auf `Kdebug`-Callouts.

Grundsätzlich wird die globale Variable `kernel_debug_active` überprüft. Wenn sie gesetzt ist, wird `kperf_kdebug_handler` mit dem `Kdebug`-Code und der Adresse des aufrufenden Kernel-Frames aufgerufen. Wenn der `Kdebug`-Code mit einem ausgewählten Code übereinstimmt, werden die als Bitmap konfigurierten „actions“ abgerufen (siehe `osfmk/kperf/action.h` für die Optionen).

Kperf verfügt außerdem über eine sysctl-MIB-Tabelle: (als root) `sysctl kperf`. Dieser Code befindet sich in `osfmk/kperf/kperfbsd.c`.

Darüber hinaus befindet sich eine Teilmenge der Kperf-Funktionalität in `kpc`, das Informationen über die Performance-Counter der Maschine bereitstellt.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ist ein sehr nützliches Tool, um die prozessbezogenen Aktionen zu überprüfen, die ein Prozess ausführt (zum Beispiel, welche neuen Prozesse ein Prozess erstellt).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ist ein Tool, das die Beziehungen zwischen Prozessen ausgibt.\
Du musst deinen Mac mit einem Befehl wie **`sudo eslogger fork exec rename create > cap.json`** überwachen (das Terminal, in dem dieser Befehl gestartet wird, benötigt FDA). Anschließend kannst du die JSON-Datei in diesem Tool laden, um alle Beziehungen anzuzeigen:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) ermöglicht die Überwachung von Datei-Ereignissen (wie Erstellung, Änderungen und Löschungen) und liefert detaillierte Informationen zu diesen Ereignissen.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ist ein GUI-Tool mit dem Aussehen und Verhalten, das Windows-Benutzer möglicherweise von Microsoft Sysinternal’s _Procmon_ kennen. Mit diesem Tool kann die Aufzeichnung verschiedener Ereignistypen gestartet und angehalten werden. Außerdem können diese Ereignisse nach Kategorien wie Datei, Prozess, Netzwerk usw. gefiltert und die aufgezeichneten Ereignisse im JSON-Format gespeichert werden.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) sind Bestandteil der Developer Tools von Xcode und werden zur Überwachung der Anwendungs-Performance, zur Identifizierung von memory leaks und zur Nachverfolgung von Dateisystemaktivitäten verwendet.

![Crescendo - Apple Instruments: Apple Instruments sind Bestandteil der Developer Tools von Xcode und werden zur Überwachung der Anwendungs-Performance, zur Identifizierung von memory leaks und zur Nachverfolgung von Dateisystemaktivitäten verwendet](<../../../images/image (1138).png>)

### fs_usage

Ermöglicht die Nachverfolgung der von Prozessen ausgeführten Aktionen:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ist nützlich, um die von einer **Binärdatei** verwendeten **Bibliotheken**, die von ihr verwendeten **Dateien** und die **Netzwerkverbindungen** anzuzeigen.\
Außerdem überprüft es die Binärdateiprozesse mit **virustotal** und zeigt Informationen über die Binärdatei an.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**diesem Blogbeitrag**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) findest du ein Beispiel dafür, wie man einen **laufenden Daemon debuggt**, der **`PT_DENY_ATTACH`** verwendet hat, um Debugging zu verhindern, selbst wenn SIP deaktiviert war.<sup>[[6]](#references)</sup>

### lldb

**lldb** ist das De-facto-Tool für das **Debugging** von **macOS**-Binärdateien.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Sie können beim Verwenden von lldb die Intel-Syntax festlegen, indem Sie in Ihrem Home-Verzeichnis eine Datei namens **`.lldbinit`** mit der folgenden Zeile erstellen:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Innerhalb von lldb einen Prozess mit `process save-core` dumpen

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Befehl</strong></td><td><strong>Beschreibung</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Startet die Ausführung, die ohne Unterbrechung fortgesetzt wird, bis ein Breakpoint erreicht wird oder der Prozess beendet wird.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Startet die Ausführung und hält am Einstiegspunkt an</td></tr><tr><td><strong>continue (c)</strong></td><td>Setzt die Ausführung des debugged Prozesses fort.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Führt die nächste Instruktion aus. Dieser Befehl überspringt Funktionsaufrufe.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Führt die nächste Instruktion aus. Anders als der Befehl nexti steigt dieser Befehl in Funktionsaufrufe ein.</td></tr><tr><td><strong>finish (f)</strong></td><td>Führt den Rest der Instruktionen in der aktuellen Funktion („Frame“) aus, kehrt zurück und hält an.</td></tr><tr><td><strong>control + c</strong></td><td>Unterbricht die Ausführung. Wenn der Prozess mit (r) gestartet oder mit (c) fortgesetzt wurde, wird der Prozess angehalten ...wo auch immer er gerade ausgeführt wird.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Zeigt den Speicher als nullterminierte Zeichenkette an.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Zeigt den Speicher als Assembly-Instruktion an.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Zeigt den Speicher als Byte an.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Dies gibt das vom Parameter referenzierte Objekt aus</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Beachte, dass die meisten Objective-C-APIs oder -Methoden von Apple Objekte zurückgeben und daher mit dem Befehl „print object“ (po) angezeigt werden sollten. Wenn po keine aussagekräftige Ausgabe liefert, verwende <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Gibt eine Karte des Speichers des aktuellen Prozesses aus</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Beim Aufruf der Funktion **`objc_sendMsg`** enthält das Register **rsi** den **Namen der Methode** als nullterminierte („C“-)Zeichenkette. Um den Namen über lldb auszugeben:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Der Befehl **`sysctl hw.model`** gibt „Mac“ zurück, wenn der **Host ein MacOS** ist, bei einer VM jedoch etwas anderes.<sup>[[3]](#references)</sup>
- Durch das Verändern der Werte von **`hw.logicalcpu`** und **`hw.physicalcpu`** versuchen manche Malwares zu erkennen, ob es sich um eine VM handelt.<sup>[[4]](#references)</sup>
- Manche Malwares können außerdem anhand der MAC-Adresse (00:50:56) erkennen, ob es sich um **VMware** handelt.
- Es ist auch möglich, mit einfachem Code festzustellen, **ob ein Prozess debugged wird**, etwa so:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Außerdem kann der **`ptrace`**-Systemaufruf mit dem Flag **`PT_DENY_ATTACH`** aufgerufen werden. Dies **verhindert**, dass sich ein Deb**u**gger anhängt und den Prozess verfolgt.
- Du kannst prüfen, ob die Funktion **`sysctl`** oder **`ptrace`** **importiert** wird (die Malware könnte sie jedoch dynamisch importieren).
- Wie in diesem Write-up angemerkt, „[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)“:<sup>[[7]](#references)</sup>\
„_Die Meldung Process # exited with **status = 45 (0x0000002d)** ist normalerweise ein eindeutiges Zeichen dafür, dass das Debug-Ziel **PT_DENY_ATTACH** verwendet._“

## Core-Dumps

Core-Dumps werden erstellt, wenn:

- `kern.coredump` sysctl auf 1 gesetzt ist (standardmäßig)
- Der Prozess nicht suid/sgid war oder `kern.sugid_coredump` auf 1 gesetzt ist (standardmäßig 0)
- Das Limit **AS_CORE** den Vorgang erlaubt. Die Erstellung von Core-Dumps kann mit `ulimit -c 0` unterdrückt und mit `ulimit -c unlimited` wieder aktiviert werden.

In diesen Fällen wird der Core-Dump entsprechend dem `kern.corefile` sysctl generiert und normalerweise unter `/cores/core/.%P` gespeichert.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analysiert abstürzende Prozesse und speichert einen Crash-Report auf der Festplatte**. Ein Crash-Report enthält Informationen, die **einem Entwickler helfen können, die Ursache eines Absturzes zu diagnostizieren**.\
Für Anwendungen und andere Prozesse, **die im per-user-Kontext von launchd ausgeführt werden**, läuft ReportCrash als LaunchAgent und speichert Crash-Reports im Benutzerverzeichnis `~/Library/Logs/DiagnosticReports/`\
Für Daemons, andere Prozesse, **die im systemweiten Kontext von launchd ausgeführt werden**, sowie andere privilegierte Prozesse läuft ReportCrash als LaunchDaemon und speichert Crash-Reports unter `/Library/Logs/DiagnosticReports`

Wenn du Bedenken hast, dass Crash-Reports **an Apple gesendet werden**, kannst du sie deaktivieren. Andernfalls können Crash-Reports nützlich sein, um **herauszufinden, warum ein Server abgestürzt ist**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Ruhezustand

Beim Fuzzing unter MacOS ist es wichtig, den Mac nicht in den Ruhezustand wechseln zu lassen:

- systemsetup -setsleep Never
- pmset, Systemeinstellungen
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-Verbindung trennen

Wenn du über eine SSH-Verbindung fuzzst, ist es wichtig sicherzustellen, dass die Sitzung nicht beendet wird. Ändere daher die Datei sshd_config wie folgt:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interne Handler

**Sieh dir die folgende Seite an**, um herauszufinden, welche App für die **Verarbeitung des angegebenen Schemas oder Protokolls zuständig ist:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Aufzählung von Netzwerkprozessen

Dies ist nützlich, um Prozesse zu finden, die Netzwerkdaten verwalten:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Oder verwenden Sie `netstat` oder `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzer

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funktioniert für CLI tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Es "**funktioniert einfach"** mit macOS GUI tools. Beachte, dass einige macOS-Apps bestimmte Anforderungen haben, wie eindeutige Dateinamen, die richtige Dateiendung oder dass die Dateien aus der sandbox gelesen werden müssen (`~/Library/Containers/com.apple.Safari/Data`) ...

Einige Beispiele:
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
### Weitere Informationen zu Fuzzing unter macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Quellen

- [1] [Incident Response unter OS X: Scripting und Analyse](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: macOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Die Kunst der Mac Malware, Band I: Analyse](https://taomm.org/vol1/analysis.html)
- [4] [Die Kunst der Mac Malware: Leitfaden zur Analyse von Schadsoftware](https://taomm.org/)
- [5] [knight.sc - In diesem Blogbeitrag gespeicherte Informationen](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging von Apple-Binaries, die Pt Deny Attach verwenden](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug-Techniken überwinden: macOS-ptrace-Varianten](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
