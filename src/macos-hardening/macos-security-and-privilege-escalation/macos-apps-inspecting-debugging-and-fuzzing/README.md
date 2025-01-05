# macOS Apps - Inspektion, Debugging und Fuzzing

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
### jtool2 & Disarm

Sie können [**disarm von hier herunterladen**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Sie können [**jtool2 hier herunterladen**](http://www.newosxbook.com/tools/jtool.html) oder es mit `brew` installieren.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool ist veraltet zugunsten von disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** ist in **macOS** zu finden, während **`ldid`** in **iOS** zu finden ist.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ist ein nützliches Tool, um **.pkg**-Dateien (Installer) zu inspizieren und zu sehen, was darin enthalten ist, bevor man sie installiert.\
Diese Installer haben `preinstall` und `postinstall` Bash-Skripte, die von Malware-Autoren häufig missbraucht werden, um **die** **Malware** **persistieren** zu lassen.

### hdiutil

Dieses Tool ermöglicht es, Apple-Disk-Images (**.dmg**) zu **mounten**, um sie zu inspizieren, bevor man etwas ausführt:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Es wird in `/Volumes` gemountet

### Gepackte Binärdateien

- Überprüfen Sie die hohe Entropie
- Überprüfen Sie die Strings (wenn es fast keinen verständlichen String gibt, gepackt)
- Der UPX-Packer für MacOS generiert einen Abschnitt namens "\_\_XHDR"

## Statische Objective-C-Analyse

### Metadaten

> [!CAUTION]
> Beachten Sie, dass Programme, die in Objective-C geschrieben sind, **ihre** Klassendeklarationen **beibehalten**, **wenn** sie in [Mach-O-Binärdateien](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **kompiliert** werden. Solche Klassendeklarationen **beinhaltet** den Namen und Typ von:

- Den definierten Schnittstellen
- Den Schnittstellenmethoden
- Den Instanzvariablen der Schnittstelle
- Den definierten Protokollen

Beachten Sie, dass diese Namen obfuskiert sein könnten, um das Reverse Engineering der Binärdatei zu erschweren.

### Funktionsaufruf

Wenn eine Funktion in einer Binärdatei aufgerufen wird, die Objective-C verwendet, wird der kompilierte Code anstelle des Aufrufs dieser Funktion **`objc_msgSend`** aufrufen. Dies wird die endgültige Funktion aufrufen:

![](<../../../images/image (305).png>)

Die Parameter, die diese Funktion erwartet, sind:

- Der erste Parameter (**self**) ist "ein Zeiger, der auf die **Instanz der Klasse zeigt, die die Nachricht empfangen soll**". Einfacher ausgedrückt, es ist das Objekt, auf dem die Methode aufgerufen wird. Wenn die Methode eine Klassenmethode ist, wird dies eine Instanz des Klassenobjekts (als Ganzes) sein, während bei einer Instanzmethode self auf eine instanziierte Instanz der Klasse als Objekt zeigt.
- Der zweite Parameter (**op**) ist "der Selektor der Methode, die die Nachricht verarbeitet". Einfacher ausgedrückt, dies ist nur der **Name der Methode.**
- Die verbleibenden Parameter sind alle **Werte, die von der Methode benötigt werden** (op).

Siehe, wie man **diese Informationen einfach mit `lldb` in ARM64 erhält** auf dieser Seite:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(für) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. Argument**   | **rdi**                                                         | **self: Objekt, auf dem die Methode aufgerufen wird**  |
| **2. Argument**   | **rsi**                                                         | **op: Name der Methode**                               |
| **3. Argument**   | **rdx**                                                         | **1. Argument für die Methode**                        |
| **4. Argument**   | **rcx**                                                         | **2. Argument für die Methode**                        |
| **5. Argument**   | **r8**                                                          | **3. Argument für die Methode**                        |
| **6. Argument**   | **r9**                                                          | **4. Argument für die Methode**                        |
| **7. Argument und mehr** | <p><strong>rsp+</strong><br><strong>(auf dem Stack)</strong></p> | **5. Argument und mehr für die Methode**              |

### ObjectiveC-Metadaten dumpen

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ist ein Tool zum Klassendump von Objective-C-Binärdateien. Das GitHub gibt dylibs an, funktioniert aber auch mit ausführbaren Dateien.
```bash
./dynadump dump /path/to/bin
```
Zum Zeitpunkt des Schreibens ist dies **derzeit der, der am besten funktioniert**.

#### Reguläre Werkzeuge
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ist das ursprüngliche Tool, um Deklarationen für die Klassen, Kategorien und Protokolle im Objective-C formatierten Code zu generieren.

Es ist alt und wird nicht mehr gewartet, daher funktioniert es wahrscheinlich nicht richtig.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) ist ein modernes und plattformübergreifendes Objective-C-Klassendump. Im Vergleich zu bestehenden Tools kann iCDump unabhängig vom Apple-Ökosystem ausgeführt werden und bietet Python-Bindings.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statische Swift-Analyse

Mit Swift-Binärdateien, da es eine Objective-C-Kompatibilität gibt, können Sie manchmal Deklarationen mit [class-dump](https://github.com/nygard/class-dump/) extrahieren, aber nicht immer.

Mit den **`jtool -l`** oder **`otool -l`** Befehlen ist es möglich, mehrere Abschnitte zu finden, die mit dem **`__swift5`** Präfix beginnen:
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
Sie finden weitere Informationen über die [**Informationen, die in diesem Abschnitt gespeichert sind, in diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Darüber hinaus **könnten Swift-Binärdateien Symbole enthalten** (zum Beispiel müssen Bibliotheken Symbole speichern, damit ihre Funktionen aufgerufen werden können). Die **Symbole enthalten normalerweise Informationen über den Funktionsnamen** und Attribute auf eine unansehnliche Weise, sodass sie sehr nützlich sind, und es gibt "**Demangler**", die den ursprünglichen Namen wiederherstellen können:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamische Analyse

> [!WARNING]
> Beachten Sie, dass zum Debuggen von Binärdateien **SIP deaktiviert sein muss** (`csrutil disable` oder `csrutil enable --without debug`) oder die Binärdateien in einen temporären Ordner kopiert und **die Signatur entfernt** werden muss mit `codesign --remove-signature <binary-path>` oder das Debuggen der Binärdatei erlaubt werden muss (Sie können [dieses Skript](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) verwenden).

> [!WARNING]
> Beachten Sie, dass zum **Instrumentieren von System-Binärdateien** (wie `cloudconfigurationd`) auf macOS **SIP deaktiviert sein muss** (das Entfernen der Signatur funktioniert nicht).

### APIs

macOS bietet einige interessante APIs, die Informationen über die Prozesse bereitstellen:

- `proc_info`: Dies ist die Haupt-API, die viele Informationen über jeden Prozess liefert. Sie müssen root sein, um Informationen über andere Prozesse zu erhalten, aber Sie benötigen keine speziellen Berechtigungen oder Mach-Ports.
- `libsysmon.dylib`: Es ermöglicht, Informationen über Prozesse über XPC-exponierte Funktionen zu erhalten, jedoch ist es erforderlich, die Berechtigung `com.apple.sysmond.client` zu haben.

### Stackshot & Mikrostackshots

**Stackshotting** ist eine Technik, die verwendet wird, um den Zustand der Prozesse zu erfassen, einschließlich der Aufrufstapel aller laufenden Threads. Dies ist besonders nützlich für Debugging, Leistungsanalyse und das Verständnis des Verhaltens des Systems zu einem bestimmten Zeitpunkt. Auf iOS und macOS kann Stackshotting mit mehreren Tools und Methoden wie den Tools **`sample`** und **`spindump`** durchgeführt werden.

### Sysdiagnose

Dieses Tool (`/usr/bini/ysdiagnose`) sammelt im Wesentlichen viele Informationen von Ihrem Computer, indem es Dutzende von verschiedenen Befehlen wie `ps`, `zprint`... ausführt.

Es muss als **root** ausgeführt werden, und der Daemon `/usr/libexec/sysdiagnosed` hat sehr interessante Berechtigungen wie `com.apple.system-task-ports` und `get-task-allow`.

Seine plist befindet sich in `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, die 3 MachServices deklariert:

- `com.apple.sysdiagnose.CacheDelete`: Löscht alte Archive in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Spezialport 23 (Kernel)
- `com.apple.sysdiagnose.service.xpc`: Benutzeroberflächenmodus über die `Libsysdiagnose` Obj-C-Klasse. Drei Argumente in einem Dict können übergeben werden (`compress`, `display`, `run`)

### Vereinheitlichte Protokolle

MacOS generiert viele Protokolle, die sehr nützlich sein können, wenn Sie eine Anwendung ausführen und versuchen zu verstehen, **was sie tut**.

Darüber hinaus gibt es einige Protokolle, die das Tag `<private>` enthalten, um einige **Benutzer**- oder **Computer**-**identifizierbare** Informationen zu **verbergen**. Es ist jedoch möglich, **ein Zertifikat zu installieren, um diese Informationen offenzulegen**. Folgen Sie den Erklärungen von [**hier**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Linke Spalte

In der linken Spalte von Hopper ist es möglich, die Symbole (**Labels**) der Binärdatei, die Liste der Prozeduren und Funktionen (**Proc**) und die Strings (**Str**) zu sehen. Dies sind nicht alle Strings, sondern die, die in verschiedenen Teilen der Mac-O-Datei definiert sind (wie _cstring oder_ `objc_methname`).

#### Mittlere Spalte

In der mittleren Spalte können Sie den **disassemblierten Code** sehen. Und Sie können ihn als **rohen** Disassemble, als **Grafik**, als **dekompiliert** und als **Binärdatei** anzeigen, indem Sie auf das jeweilige Symbol klicken:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Wenn Sie mit der rechten Maustaste auf ein Codeobjekt klicken, können Sie **Referenzen zu/von diesem Objekt** sehen oder sogar seinen Namen ändern (dies funktioniert nicht im dekompilierten Pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Darüber hinaus können Sie in der **mittleren unteren Ecke Python-Befehle** eingeben.

#### Rechte Spalte

In der rechten Spalte können Sie interessante Informationen wie die **Navigationshistorie** sehen (damit Sie wissen, wie Sie zur aktuellen Situation gekommen sind), das **Aufrufdiagramm**, in dem Sie alle **Funktionen sehen können, die diese Funktion aufrufen**, und alle Funktionen, die **diese Funktion aufruft**, sowie Informationen zu **lokalen Variablen**.

### dtrace

Es ermöglicht Benutzern den Zugriff auf Anwendungen auf einem extrem **niedrigen Niveau** und bietet eine Möglichkeit für Benutzer, **Programme** zu **verfolgen** und sogar ihren Ausführungsfluss zu ändern. Dtrace verwendet **Proben**, die **im gesamten Kernel** platziert sind und sich an Orten wie dem Anfang und Ende von Systemaufrufen befinden.

DTrace verwendet die Funktion **`dtrace_probe_create`**, um eine Probe für jeden Systemaufruf zu erstellen. Diese Proben können am **Einstieg und Ausgangspunkt jedes Systemaufrufs** ausgelöst werden. Die Interaktion mit DTrace erfolgt über /dev/dtrace, das nur für den Root-Benutzer verfügbar ist.

> [!TIP]
> Um Dtrace zu aktivieren, ohne den SIP-Schutz vollständig zu deaktivieren, können Sie im Wiederherstellungsmodus ausführen: `csrutil enable --without dtrace`
>
> Sie können auch **`dtrace`** oder **`dtruss`** Binärdateien verwenden, die **Sie kompiliert haben**.

Die verfügbaren Proben von dtrace können mit:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Der Probenname besteht aus vier Teilen: dem Anbieter, dem Modul, der Funktion und dem Namen (`fbt:mach_kernel:ptrace:entry`). Wenn Sie einen Teil des Namens nicht angeben, wendet Dtrace diesen Teil als Platzhalter an.

Um DTrace zu konfigurieren, um Proben zu aktivieren und anzugeben, welche Aktionen ausgeführt werden sollen, wenn sie ausgelöst werden, müssen wir die D-Sprache verwenden.

Eine detailliertere Erklärung und weitere Beispiele finden Sie unter [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Beispiele

Führen Sie `man -k dtrace` aus, um die **verfügbaren DTrace-Skripte** aufzulisten. Beispiel: `sudo dtruss -n binary`
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

Es handelt sich um eine Kernel-Trace-Einrichtung. Die dokumentierten Codes sind in **`/usr/share/misc/trace.codes`** zu finden.

Tools wie `latency`, `sc_usage`, `fs_usage` und `trace` verwenden es intern.

Um mit `kdebug` zu interagieren, wird `sysctl` über den `kern.kdebug`-Namespace verwendet, und die MIBs, die verwendet werden können, sind in `sys/sysctl.h` zu finden, wobei die Funktionen in `bsd/kern/kdebug.c` implementiert sind.

Um mit kdebug über einen benutzerdefinierten Client zu interagieren, sind dies normalerweise die Schritte:

- Entfernen Sie vorhandene Einstellungen mit KERN_KDSETREMOVE
- Setzen Sie Trace mit KERN_KDSETBUF und KERN_KDSETUP
- Verwenden Sie KERN_KDGETBUF, um die Anzahl der Puffer-Einträge zu erhalten
- Holen Sie sich den eigenen Client aus dem Trace mit KERN_KDPINDEX
- Aktivieren Sie das Tracing mit KERN_KDENABLE
- Lesen Sie den Puffer, indem Sie KERN_KDREADTR aufrufen
- Um jeden Thread mit seinem Prozess abzugleichen, rufen Sie KERN_KDTHRMAP auf.

Um diese Informationen zu erhalten, ist es möglich, das Apple-Tool **`trace`** oder das benutzerdefinierte Tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Beachten Sie, dass Kdebug nur für 1 Kunden gleichzeitig verfügbar ist.** Daher kann nur ein k-debug-gestütztes Tool zur gleichen Zeit ausgeführt werden.

### ktrace

Die `ktrace_*` APIs stammen von `libktrace.dylib`, die die von `Kdebug` umhüllen. Ein Client kann einfach `ktrace_session_create` und `ktrace_events_[single/class]` aufrufen, um Rückrufe für spezifische Codes festzulegen, und dann mit `ktrace_start` starten.

Sie können dies sogar mit **aktiviertem SIP** verwenden.

Sie können als Clients das Dienstprogramm `ktrace` verwenden:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

Dies wird verwendet, um ein Kernel-Level-Profiling durchzuführen und ist mit `Kdebug`-Aufrufen erstellt.

Grundsätzlich wird die globale Variable `kernel_debug_active` überprüft und wenn sie gesetzt ist, wird `kperf_kdebug_handler` mit dem `Kdebug`-Code und der Adresse des aufrufenden Kernel-Frames aufgerufen. Wenn der `Kdebug`-Code mit einem ausgewählten übereinstimmt, werden die als Bitmap konfigurierten "Aktionen" abgerufen (siehe `osfmk/kperf/action.h` für die Optionen).

Kperf hat auch eine sysctl MIB-Tabelle: (als root) `sysctl kperf`. Diese Codes sind in `osfmk/kperf/kperfbsd.c` zu finden.

Darüber hinaus residiert ein Teil der Funktionalität von Kperf in `kpc`, das Informationen über Maschinenleistungszähler bereitstellt.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ist ein sehr nützliches Tool, um die prozessbezogenen Aktionen zu überprüfen, die ein Prozess ausführt (zum Beispiel, um zu überwachen, welche neuen Prozesse ein Prozess erstellt).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ist ein Tool, das die Beziehungen zwischen Prozessen ausgibt.\
Sie müssen Ihren Mac mit einem Befehl wie **`sudo eslogger fork exec rename create > cap.json`** überwachen (das Terminal, das dies startet, benötigt FDA). Und dann können Sie die JSON in dieses Tool laden, um alle Beziehungen anzuzeigen:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) ermöglicht es, Dateiereignisse (wie Erstellung, Änderungen und Löschungen) zu überwachen und bietet detaillierte Informationen über solche Ereignisse.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ist ein GUI-Tool, das das Aussehen und Gefühl hat, das Windows-Benutzer von Microsoft Sysinternals _Procmon_ kennen. Dieses Tool ermöglicht es, verschiedene Ereignistypen zu starten und zu stoppen, ermöglicht das Filtern dieser Ereignisse nach Kategorien wie Datei, Prozess, Netzwerk usw. und bietet die Funktionalität, die aufgezeichneten Ereignisse im JSON-Format zu speichern.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) sind Teil der Entwicklerwerkzeuge von Xcode – verwendet zur Überwachung der Anwendungsleistung, zur Identifizierung von Speicherlecks und zur Verfolgung der Dateisystemaktivität.

![](<../../../images/image (1138).png>)

### fs_usage

Ermöglicht das Verfolgen von Aktionen, die von Prozessen ausgeführt werden:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ist nützlich, um die **Bibliotheken** zu sehen, die von einer Binärdatei verwendet werden, die **Dateien**, die sie verwendet, und die **Netzwerk**-Verbindungen.\
Es überprüft auch die Binärprozesse gegen **virustotal** und zeigt Informationen über die Binärdatei an.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**diesem Blogbeitrag**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) finden Sie ein Beispiel, wie man einen **laufenden Daemon** debuggt, der **`PT_DENY_ATTACH`** verwendet, um das Debuggen zu verhindern, selbst wenn SIP deaktiviert war.

### lldb

**lldb** ist das de **facto Tool** für **macOS** Binärdatei **Debugging**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Sie können den Intel-Geschmack festlegen, wenn Sie lldb verwenden, indem Sie eine Datei mit dem Namen **`.lldbinit`** in Ihrem Home-Verzeichnis mit der folgenden Zeile erstellen:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Innerhalb von lldb, dumpen Sie einen Prozess mit `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Befehl</strong></td><td><strong>Beschreibung</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Startet die Ausführung, die ununterbrochen fortgesetzt wird, bis ein Haltepunkt erreicht wird oder der Prozess beendet wird.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Startet die Ausführung und stoppt am Einstiegspunkt</td></tr><tr><td><strong>continue (c)</strong></td><td>Setzt die Ausführung des debugged Prozesses fort.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Führt die nächste Anweisung aus. Dieser Befehl überspringt Funktionsaufrufe.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Führt die nächste Anweisung aus. Im Gegensatz zum nexti-Befehl wird dieser Befehl in Funktionsaufrufe eintreten.</td></tr><tr><td><strong>finish (f)</strong></td><td>Führt den Rest der Anweisungen in der aktuellen Funktion (“frame”) aus, gibt zurück und stoppt.</td></tr><tr><td><strong>control + c</strong></td><td>Pause die Ausführung. Wenn der Prozess ausgeführt (r) oder fortgesetzt (c) wurde, wird dies den Prozess anhalten ...wo auch immer er sich gerade befindet.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Jede Funktion, die main genannt wird</p><p><code>b <binname>`main</code> #Hauptfunktion des Bins</p><p><code>b set -n main --shlib <lib_name></code> #Hauptfunktion des angegebenen Bins</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Jede NSFileManager-Methode</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Brechen in allen Funktionen dieser Bibliothek</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint-Liste</p><p><code>br e/dis <num></code> #Aktivieren/Deaktivieren des Breakpoints</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Hilfe zum Breakpoint-Befehl erhalten</p><p>help memory write #Hilfe zum Schreiben in den Speicher erhalten</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Zeigt den Speicher als nullterminierten String an.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Zeigt den Speicher als Assemblieranweisung an.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Zeigt den Speicher als Byte an.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Dies wird das Objekt drucken, auf das der Parameter verweist</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Beachten Sie, dass die meisten von Apples Objective-C APIs oder Methoden Objekte zurückgeben und daher über den Befehl “print object” (po) angezeigt werden sollten. Wenn po keine sinnvolle Ausgabe erzeugt, verwenden Sie <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Schreibt AAAA in diese Adresse<br>memory write -f s $rip+0x11f+7 "AAAA" #Schreibt AAAA in die Adresse</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disassembliert die aktuelle Funktion</p><p>dis -n <funcname> #Disassembliert die Funktion</p><p>dis -n <funcname> -b <basename> #Disassembliert die Funktion<br>dis -c 6 #Disassembliert 6 Zeilen<br>dis -c 0x100003764 -e 0x100003768 # Von einer Adresse zur anderen<br>dis -p -c 4 # Beginnt an der aktuellen Adresse mit dem Disassemblieren</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Überprüft das Array von 3 Komponenten im x1-Register</td></tr><tr><td><strong>image dump sections</strong></td><td>Gibt die Karte des aktuellen Prozessspeichers aus</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Erhält die Adresse aller Symbole von CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Beim Aufrufen der **`objc_sendMsg`** Funktion hält das **rsi** Register den **Namen der Methode** als nullterminierten (“C”) String. Um den Namen über lldb auszugeben, tun Sie:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analyse

#### VM-Erkennung

- Der Befehl **`sysctl hw.model`** gibt "Mac" zurück, wenn der **Host ein MacOS** ist, aber etwas anderes, wenn es sich um eine VM handelt.
- Durch das Spielen mit den Werten von **`hw.logicalcpu`** und **`hw.physicalcpu`** versuchen einige Malware, zu erkennen, ob es sich um eine VM handelt.
- Einige Malware kann auch **erkennen**, ob die Maschine **VMware** basiert ist, basierend auf der MAC-Adresse (00:50:56).
- Es ist auch möglich zu finden, **ob ein Prozess debuggt wird** mit einem einfachen Code wie:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //prozess wird debuggt }`
- Es kann auch den **`ptrace`** Systemaufruf mit dem **`PT_DENY_ATTACH`** Flag aufrufen. Dies **verhindert**, dass ein Debugger sich anheftet und verfolgt.
- Sie können überprüfen, ob die **`sysctl`** oder **`ptrace`** Funktion **importiert** wird (aber die Malware könnte sie dynamisch importieren)
- Wie in diesem Bericht erwähnt, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Die Nachricht Process # exited with **status = 45 (0x0000002d)** ist normalerweise ein sicheres Zeichen dafür, dass das Debug-Ziel **PT_DENY_ATTACH** verwendet_”

## Core Dumps

Core Dumps werden erstellt, wenn:

- `kern.coredump` sysctl auf 1 gesetzt ist (standardmäßig)
- Wenn der Prozess nicht suid/sgid war oder `kern.sugid_coredump` auf 1 gesetzt ist (standardmäßig 0)
- Das `AS_CORE` Limit die Operation erlaubt. Es ist möglich, die Erstellung von Core Dumps zu unterdrücken, indem Sie `ulimit -c 0` aufrufen und sie mit `ulimit -c unlimited` wieder aktivieren.

In diesen Fällen wird der Core Dump gemäß dem `kern.corefile` sysctl generiert und normalerweise in `/cores/core/.%P` gespeichert.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analysiert abstürzende Prozesse und speichert einen Absturzbericht auf der Festplatte**. Ein Absturzbericht enthält Informationen, die einem Entwickler helfen können, die Ursache eines Absturzes zu diagnostizieren.\
Für Anwendungen und andere Prozesse, die **im benutzerspezifischen launchd-Kontext** ausgeführt werden, läuft ReportCrash als LaunchAgent und speichert Absturzberichte im `~/Library/Logs/DiagnosticReports/` des Benutzers.\
Für Daemons, andere Prozesse, die **im systemweiten launchd-Kontext** ausgeführt werden, und andere privilegierte Prozesse, läuft ReportCrash als LaunchDaemon und speichert Absturzberichte im `/Library/Logs/DiagnosticReports` des Systems.

Wenn Sie sich Sorgen über Absturzberichte **machen, die an Apple gesendet werden**, können Sie sie deaktivieren. Andernfalls können Absturzberichte nützlich sein, um **herauszufinden, wie ein Server abgestürzt ist**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Schlaf

Beim Fuzzing auf einem MacOS ist es wichtig, den Mac nicht in den Schlafmodus zu versetzen:

- systemsetup -setsleep Never
- pmset, Systemeinstellungen
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-Trennung

Wenn Sie über eine SSH-Verbindung fuzzing, ist es wichtig sicherzustellen, dass die Sitzung nicht abbricht. Ändern Sie daher die sshd_config-Datei mit:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**Überprüfen Sie die folgende Seite**, um herauszufinden, wie Sie herausfinden können, welche App für **die Verarbeitung des angegebenen Schemas oder Protokolls verantwortlich ist:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

Es ist interessant, Prozesse zu finden, die Netzwerkdaten verwalten:
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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funktioniert für CLI-Tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Es "**funktioniert einfach"** mit macOS GUI-Tools. Beachten Sie, dass einige macOS-Apps spezifische Anforderungen haben, wie eindeutige Dateinamen, die richtige Erweiterung, und dass die Dateien aus dem Sandbox (`~/Library/Containers/com.apple.Safari/Data`) gelesen werden müssen...

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
### Weitere Fuzzing MacOS Informationen

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referenzen

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
