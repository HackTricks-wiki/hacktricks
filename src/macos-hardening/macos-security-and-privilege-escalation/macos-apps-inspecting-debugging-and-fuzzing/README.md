# macOS-Apps – Untersuchen, Debuggen und Fuzzing

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
> Beachte, dass **`disarm`** auch mit komprimierten IM4P-Dateien (wie `kernelcache`) arbeiten und nur die benötigten Teile extrahieren oder sogar den benötigten Teil analysieren kann, ohne ihn zu extrahieren.

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
> **`Codesign`** ist unter **macOS** zu finden, während **`ldid`** unter **iOS** zu finden ist.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ist ein nützliches Tool, um **.pkg**-Dateien (Installationsprogramme) zu untersuchen und zu sehen, was sie enthalten, bevor man sie installiert.\
Diese Installationsprogramme enthalten `preinstall`- und `postinstall`-Bash-Skripte, die Malware-Autoren häufig missbrauchen, um **die** **Malware** **dauerhaft** zu installieren.

### hdiutil

Dieses Tool bindet Apple-Disk-Images (`.dmg`-Dateien) ein, damit sie untersucht werden können, bevor etwas ausgeführt wird:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Es wird unter `/Volumes` eingehängt

### Gepackte Binärdateien

- Auf hohe Entropie prüfen
- Die Strings prüfen (gibt es kaum verständliche Strings? Dann ist die Datei gepackt)
- Der UPX-Packer für macOS erzeugt eine Section namens `__XHDR`.

## Statische Objective-C-Analyse

### Metadaten

> [!CAUTION]
> Beachte, dass in Objective-C geschriebene Programme ihre Klassendeklarationen **behalten**, **wenn** sie in [Mach-O-Binärdateien](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **kompiliert** werden. Solche Klassendeklarationen **enthalten** Namen und Typen von:

- Den definierten Interfaces
- Den Interface-Methoden
- Den Interface-Instanzvariablen
- Den definierten Protokollen

Beachte, dass diese Namen obfuskiert werden können, um das Reverse Engineering der Binärdatei zu erschweren.

### Funktionsaufrufe

Wenn eine Funktion in einer Binärdatei aufgerufen wird, die Objective-C verwendet, ruft der kompilierte Code nicht direkt diese Funktion auf, sondern **`objc_msgSend`**. Diese Funktion ruft dann die endgültige Funktion auf:

![Metadaten – Funktionsaufrufe: Wenn eine Funktion in einer Binärdatei aufgerufen wird, die Objective-C verwendet, ruft der kompilierte Code nicht direkt diese Funktion auf, sondern objc_msgSend. Diese Funktion ruft dann die endgültige Funktion auf.](<../../../images/image (305).png>)

Diese Funktion erwartet folgende Parameter:

- Der erste Parameter (**self**) ist „ein Zeiger auf die **Instanz der Klasse, die die Nachricht empfangen soll**“. Einfacher ausgedrückt: Es ist das Objekt, für das die Methode aufgerufen wird. Wenn es sich um eine Klassenmethode handelt, ist dies eine Instanz des Klassenobjekts (als Ganzes). Bei einer Instanzmethode zeigt self auf eine instanziierte Instanz der Klasse als Objekt.
- Der zweite Parameter (**op**) ist „der Selector der Methode, die die Nachricht verarbeitet“. Einfacher ausgedrückt: Das ist der **Name der Methode.**
- Die übrigen Parameter sind alle **Werte, die von der Methode benötigt werden** (op).

Auf dieser Seite erfährst du, wie du diese Informationen mit `lldb` in ARM64 ganz einfach **ermittelst**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(für) objc_msgSend**                                       |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------------ |
| **1. Argument**   | **rdi**                                                         | **self: Objekt, für das die Methode aufgerufen wird**        |
| **2. Argument**   | **rsi**                                                         | **op: Name der Methode**                                     |
| **3. Argument**   | **rdx**                                                         | **1. Argument der Methode**                                  |
| **4. Argument**   | **rcx**                                                         | **2. Argument der Methode**                                  |
| **5. Argument**   | **r8**                                                          | **3. Argument der Methode**                                  |
| **6. Argument**   | **r9**                                                          | **4. Argument der Methode**                                  |
| **7.+ Argument**  | <p><strong>rsp+</strong><br><strong>(auf dem Stack)</strong></p> | **5.+ Argument der Methode**                                 |

### ObjectiveC-Metadaten dumpen

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ist ein Tool, um Objective-C-Binärdateien mit class-dump zu untersuchen. Im GitHub-Repository werden dylibs erwähnt, aber das Tool funktioniert auch mit ausführbaren Dateien.

```bash
./dynadump dump /path/to/bin
```

Zum Zeitpunkt der Erstellung dieses Textes ist dies **aktuell die am besten funktionierende Methode**.

#### Reguläre Tools

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ist das ursprüngliche Tool zum Generieren von Deklarationen für Klassen, Kategorien und Protokolle in formatiertem Objective-C-Code.

Es ist alt und wird nicht mehr gewartet, daher funktioniert es wahrscheinlich nicht richtig.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) ist ein modernes, plattformübergreifendes Objective-C-Class-Dump-Tool. Im Gegensatz zu vorhandenen Tools kann iCDump unabhängig vom Apple-Ökosystem ausgeführt werden und bietet Python-Bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statische Swift-Analyse

Bei Swift-Binärdateien kann man aufgrund der Objective-C-Kompatibilität manchmal Deklarationen mit [class-dump](https://github.com/nygard/class-dump/) extrahieren, aber nicht immer.

Mit den Befehlszeilen **`jtool -l`** oder **`otool -l`** lassen sich mehrere Abschnitte finden, die mit dem Präfix **`__swift5`** beginnen:

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

Außerdem können **Swift-Binaries Symbole enthalten** (zum Beispiel müssen Bibliotheken Symbole speichern, damit ihre Funktionen aufgerufen werden können). Die **Symbole enthalten normalerweise Informationen über den Funktionsnamen** und Attribute in einer unschönen Form. Daher sind sie sehr nützlich, und es gibt sogenannte **„demanglers“**, die den ursprünglichen Namen wiederherstellen können:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dynamische Analyse

> [!WARNING]
> **Deaktiviere SIP nicht standardmäßig als Debugging-Schritt.** Entwicklungs-Builds mit `com.apple.security.get-task-allow` können bei aktiviertem SIP debuggt werden. Prüfe das Ziel mit `codesign -d --entitlements :- /path/to/binary`, bevor du LLDB ausprobierst. Eine Debugger-Berechtigung allein gewährt keinen Zugriff auf durch SIP geschützte Ziele.<sup>[[15]](#references)</sup>
>
> Bei einer veröffentlichten App mit gehärteter Laufzeitumgebung fehlt `get-task-allow` normalerweise, und das Anhängen eines Debuggers wird blockiert. Verwende nach Möglichkeit einen vom Entwickler bereitgestellten Debug-Build; das erneute Signieren einer entbehrlichen Kopie kann das zu untersuchende Verhalten verändern. Wenn ein geschütztes Ziel erfordert, SIP zu deaktivieren, verwende dafür einen dedizierten Testrechner oder eine VM statt eines Rechners, auf den du angewiesen bist.<sup>[[16]](#references)</sup>

> [!WARNING]
> Beachte, dass SIP deaktiviert sein muss, um **System-Binaries zu instrumentieren** (wie `cloudconfigurationd`) — nur die Signatur zu entfernen reicht nicht.

### APIs

macOS stellt einige interessante APIs bereit, die Informationen über Prozesse liefern:

- `proc_info`: Diese API liefert die meisten Informationen zu jedem Prozess. Um Informationen zu anderen Prozessen abzurufen, musst du Root sein; spezielle Berechtigungen oder Mach-Ports sind jedoch nicht erforderlich.
- `libsysmon.dylib`: Stellt Prozessinformationen über XPC-Funktionen bereit, aber Aufrufer benötigen die Berechtigung `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** ist eine Technik, mit der der Zustand von Prozessen erfasst wird, einschließlich der Aufrufstapel aller laufenden Threads. Das ist besonders nützlich für Debugging, Performance-Analysen und zum Verständnis des Systemverhaltens zu einem bestimmten Zeitpunkt. Unter iOS und macOS kann Stackshotting mit verschiedenen Tools und Methoden durchgeführt werden, etwa mit den Tools **`sample`** und **`spindump`**.

### Sysdiagnose

Dieses Tool (`/usr/bini/ysdiagnose`) sammelt im Wesentlichen viele Informationen von deinem Computer, indem es Dutzende verschiedener Befehle wie `ps`, `zprint` usw. ausführt.

Es muss als **Root** ausgeführt werden. Der Daemon `/usr/libexec/sysdiagnosed` verfügt über sehr interessante Berechtigungen wie `com.apple.system-task-ports` und `get-task-allow`.

Seine Plist befindet sich unter `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`. Darin sind drei MachServices definiert:

- `com.apple.sysdiagnose.CacheDelete`: Löscht alte Archive in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Spezieller Port 23 (Kernel)
- `com.apple.sysdiagnose.service.xpc`: Schnittstelle im User Mode über die Obj-C-Klasse `Libsysdiagnose`. Es können drei Argumente in einem Dict übergeben werden (`compress`, `display`, `run`)

### Unified Logs

macOS erzeugt umfangreiche Logs, die bei der Analyse des Verhaltens einer Anwendung nützlich sind.

Einige Log-Felder enthalten das Tag `<private>`, um Informationen zu verbergen, anhand derer sich Benutzer oder Geräte identifizieren lassen. Ältere Anleitungen beschreiben manchmal die Installation eines Zertifikats, um diese Felder sichtbar zu machen. Die aktuelle Debugging-Dokumentation empfiehlt stattdessen ein explizit abgegrenztes Konfigurationsprofil mit `Enable-Private-Data` oder anwendungsspezifische `OSLogPreferences`. Das Verhalten kann je nach Subsystem und macOS-Version variieren. Die ältere Diskussion zu Zertifikaten und Profilen ist in den Referenzen erhalten. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Linkes Fenster

Im linken Fenster von Hopper kannst du die Symbole (**Labels**) des Binaries, die Liste der Prozeduren und Funktionen (**Proc**) sowie die Strings (**Str**) sehen. Es sind nicht alle Strings, sondern nur jene, die in bestimmten Bereichen der Mach-O-Datei definiert sind (wie _cstring oder_ `objc_methname`).

#### Mittleres Fenster

Im mittleren Fenster siehst du den **disassemblierten Code**. Du kannst ihn als **rohes** Disassembly, als **Graph**, als **dekompilierten Code** oder als **Binary** anzeigen, indem du auf das jeweilige Symbol klickst:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Wenn du mit der rechten Maustaste auf ein Codeobjekt klickst, kannst du **Referenzen zu oder von diesem Objekt** anzeigen oder sogar dessen Namen ändern (das funktioniert nicht im dekompilierten Pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Außerdem kannst du **unten in der Mitte Python-Befehle eingeben**.

#### Rechtes Fenster

Im rechten Fenster findest du interessante Informationen wie den **Navigationsverlauf** (damit du weißt, wie du zur aktuellen Stelle gelangt bist), den **Aufrufgraphen**, in dem du alle **Funktionen siehst, die diese Funktion aufrufen**, sowie alle Funktionen, **die von dieser Funktion aufgerufen werden**, und Informationen zu **lokalen Variablen**.

### dtrace

Es ermöglicht Benutzern den Zugriff auf Anwendungen auf extrem **niedriger Ebene** und bietet ihnen eine Möglichkeit, **Programme zu tracen** und sogar deren Ausführungsablauf zu ändern. Dtrace verwendet **Probes**, die **im gesamten Kernel platziert** sind, etwa am Anfang und Ende von Systemaufrufen.

DTrace verwendet die Funktion **`dtrace_probe_create`**, um für jeden Systemaufruf eine Probe zu erstellen. Diese Probes können am **Eintritts- und Austrittspunkt jedes Systemaufrufs** ausgelöst werden. Die Interaktion mit DTrace erfolgt über /dev/dtrace, das nur für den Root-Benutzer verfügbar ist.<sup>[[1]](#references)</sup>

> [!TIP]
> Um Dtrace zu aktivieren, ohne den SIP-Schutz vollständig zu deaktivieren, kannst du im Wiederherstellungsmodus Folgendes ausführen: `csrutil enable --without dtrace`
>
> Du kannst auch **`dtrace`** oder **`dtruss`** für Binaries verwenden, **die du selbst kompiliert hast**.

Die verfügbaren Probes von dtrace lassen sich wie folgt abrufen:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Der Probe-Name besteht aus vier Teilen: Provider, Modul, Funktion und Name (`fbt:mach_kernel:ptrace:entry`). Wenn Sie einen Teil des Namens nicht angeben, verwendet Dtrace dafür einen Platzhalter.

Um DTrace so zu konfigurieren, dass Probes aktiviert werden und festzulegen, welche Aktionen bei ihrem Auslösen ausgeführt werden sollen, müssen wir die D-Sprache verwenden.

Eine ausführlichere Erklärung und weitere Beispiele finden Sie unter [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Beispiele

Führen Sie `man -k dtrace` aus, um die **verfügbaren DTrace-Skripte** aufzulisten. Beispiel: `sudo dtruss -n binary`

- In einer Zeile

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

Es handelt sich um eine Kernel-Tracing-Funktion. Die dokumentierten Codes sind in **`/usr/share/misc/trace.codes`** zu finden.

Tools wie `latency`, `sc_usage`, `fs_usage` und `trace` verwenden sie intern.

Für die Schnittstelle zu `kdebug` wird `sysctl` über den Namespace `kern.kdebug` verwendet. Die zu verwendenden MIBs sind in `sys/sysctl.h` zu finden; die Funktionen sind in `bsd/kern/kdebug.c` implementiert.

Für die Interaktion mit kdebug über einen eigenen Client sind dies üblicherweise die Schritte:

- Vorhandene Einstellungen mit KERN_KDSETREMOVE entfernen
- Trace mit KERN_KDSETBUF und KERN_KDSETUP einrichten
- Mit KERN_KDGETBUF die Anzahl der Puffereinträge abrufen
- Den eigenen Client mit KERN_KDPINDEX aus dem Trace abrufen
- Tracing mit KERN_KDENABLE aktivieren
- Den Puffer durch Aufrufen von KERN_KDREADTR auslesen
- Mit KERN_KDTHRMAP jeden Thread seinem Prozess zuordnen

Um diese Informationen abzurufen, können das Apple-Tool **`trace`** oder das eigene Tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** verwendet werden.

**Beachte, dass Kdebug jeweils nur für einen Kunden verfügbar ist.** Daher kann immer nur ein Kdebug-basiertes Tool gleichzeitig ausgeführt werden.

### ktrace

Die `ktrace_*`-APIs stammen aus `libktrace.dylib`, das die APIs von `Kdebug` umschließt. Ein Client kann dann einfach `ktrace_session_create` und `ktrace_events_[single/class]` aufrufen, um Callbacks für bestimmte Codes einzurichten, und anschließend mit `ktrace_start` starten.

Du kannst dieses Tool auch mit **aktiviertem SIP** verwenden.

Als Client kannst du das Dienstprogramm `ktrace` verwenden:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Or `tailspin`.

### kperf

Dies wird für Kernel-Level-Profiling verwendet und basiert auf `Kdebug`-Callouts.

Grundsätzlich wird die globale Variable `kernel_debug_active` überprüft. Ist sie gesetzt, wird `kperf_kdebug_handler` mit dem `Kdebug`-Code und der Adresse des aufrufenden Kernel-Frames aufgerufen. Stimmt der `Kdebug`-Code mit einem ausgewählten Code überein, werden die als Bitmap konfigurierten „actions“ ausgeführt (die verfügbaren Optionen findest du unter `osfmk/kperf/action.h`).

Kperf verfügt außerdem über eine sysctl-MIB-Tabelle: (als root) `sysctl kperf`. Der Code dafür befindet sich in `osfmk/kperf/kperfbsd.c`.

Darüber hinaus befindet sich ein Teil der Kperf-Funktionalität in `kpc`, das Informationen zu den Performance Counters des Computers bereitstellt.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ist ein sehr nützliches Tool, um prozessbezogene Aktionen eines Prozesses zu überprüfen (zum Beispiel zu überwachen, welche neuen Prozesse ein Prozess erstellt).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ist ein Tool, das die Beziehungen zwischen Prozessen darstellt.\
Du musst deinen Mac mit einem Befehl wie **`sudo eslogger fork exec rename create > cap.json`** überwachen (das Terminal, von dem aus dieser Befehl gestartet wird, benötigt FDA). Anschließend kannst du die JSON-Datei in dieses Tool laden, um alle Beziehungen anzuzeigen:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) überwacht Datei-Ereignisse wie Erstellung, Änderung und Löschung.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ist ein GUI-Tool, dessen Look and Feel Windows-Benutzer möglicherweise von Microsoft Sysinternal’s _Procmon_ kennen. Mit diesem Tool kannst du die Aufzeichnung verschiedener Ereignistypen starten und stoppen, diese Ereignisse nach Kategorien wie Datei, Prozess, Netzwerk usw. filtern und die aufgezeichneten Ereignisse im JSON-Format speichern.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) ist Teil der Xcode-Developer-Tools und dient zur Überwachung der Anwendungsleistung, zum Erkennen von Memory-Leaks und zum Verfolgen von Dateisystemaktivitäten.

![Crescendo - Apple Instruments: Apple Instruments ist Teil der Xcode-Developer-Tools und dient zur Überwachung der Anwendungsleistung, zum Erkennen von Memory-Leaks und zum Verfolgen von Dateisystemaktivitäten](<../../../images/image (1138).png>)

### fs_usage

Ermöglicht es, die von Prozessen ausgeführten Aktionen zu verfolgen:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ist nützlich, um die von einer Binärdatei verwendeten **Bibliotheken**, die verwendeten **Dateien** und die **Netzwerk**verbindungen anzuzeigen.\
Außerdem überprüft es die Prozesse der Binärdatei mit **virustotal** und zeigt Informationen zur Binärdatei an.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**diesem Blogbeitrag**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) findest du ein Beispiel dafür, wie sich ein laufender Daemon debuggen lässt, der **`PT_DENY_ATTACH`** verwendet, um das Debugging zu verhindern, selbst wenn SIP deaktiviert ist.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` ist eine Darwin-spezifische `ptrace(2)`-Anfrage mit dem Wert **31** (`0x1f`); die übrigen Argumente werden ignoriert. Ein Prozess kann sie direkt und ohne Fork aufrufen, um späteres Tracing durch den Elternprozess zu verhindern.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU-Zustand und Aufrufreihenfolge

Das Ergebnis hängt davon ab, welche `ptrace`-Anfrage XNU zuerst erreicht:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB hängt sich zuerst an:** `debugserver` verwendet `PT_ATTACHEXC`; XNU wandelt dies in `PT_ATTACH` um, führt die Autorisierung `KAUTH_PROCESS_CANTRACE` durch und setzt `P_LTRACED` beim Zielprozess. Ein nachfolgendes `PT_DENY_ATTACH` erkennt dieses Flag und beendet den Zielprozess mit `W_EXITCODE(ENOTSUP, 0)`, was LLDB normalerweise als Status **45** (`0x2d`) anzeigt.
- **Der Zielprozess verweigert zuerst:** XNU setzt `P_LNOATTACH`. Ein späterer Attach-Versuch wird durch die Prozess-Trace-Autorisierung abgelehnt; der Attach-Fehlerpfad erkennt `P_LNOATTACH` und sendet `SIGSEGV` an den Prozess, der den Attach-Versuch ausführt. Dies kann in LLDB als verlorene `debugserver`-Verbindung erscheinen.

Um diese Pfade zu unterscheiden, aktiviere die `debugserver`-Protokollierung vor dem Starten oder Anhängen und prüfe die `ptrace`-Anfragen:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Statische Identifizierung und Umgehung unter ARM64

Suche bei einem nicht verschleierten ARM64-Mach-O nach dem importierten `_ptrace`-Stub und untersuche die Aufrufstellen. Das erste Integer-Argument wird in `w0` übergeben, sodass diese Sequenz die Anti-Debugging-Anforderung direkt offenlegt. Das Fehlen des Imports ist kein schlüssiger Beweis, da Code `ptrace` dynamisch auflösen kann. Ein importiertes `_sysctl` kann ebenfalls auf Anti-Debugging-Prüfungen hindeuten, kann aber auch dynamisch aufgelöst werden.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

Im gezeigten Beispiel ändert das Patchen des Immediate-Werts von `0x1f` auf `0x0` die Anfrage zu `PT_TRACE_ME` und ermöglicht es dem Programm, unter LLDB fortzufahren. Dies ist ein **spezifischer Bypass für dieses Beispiel**, kein allgemeiner no-op: Prüfe die Rückgabewertprüfungen und den Kontrollfluss des Aufrufers, bevor du entscheidest, ob du die Anfrage änderst, den Aufruf überspringst oder eine erfolgreiche Rückgabe erzwingst.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** ist das **De-facto-Tool** zum **macOS**-Debugging von Binärdateien.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Du kannst bei der Verwendung von lldb die Intel-Syntax festlegen, indem du in deinem Home-Verzeichnis eine Datei namens **`.lldbinit`** mit folgender Zeile erstellst:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Innerhalb von lldb einen Prozess mit `process save-core` dumpen

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Befehl</strong></td><td><strong>Beschreibung</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Startet die Ausführung. Sie läuft weiter, bis ein Breakpoint erreicht wird oder der Prozess beendet wird.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Startet die Ausführung und hält am Einstiegspunkt an.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Setzt die Ausführung des debugten Prozesses fort.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Führt die nächste Instruktion aus. Dieser Befehl überspringt Funktionsaufrufe.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Führt die nächste Instruktion aus. Anders als der Befehl <code>nexti</code> steigt dieser Befehl in Funktionsaufrufe ein.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Führt die verbleibenden Instruktionen der aktuellen Funktion (des aktuellen Frames) aus, kehrt zurück und hält an.</td></tr>
<tr><td><strong>control + c</strong></td><td>Hält die Ausführung an. Wenn der Prozess gestartet (<code>r</code>) oder fortgesetzt (<code>c</code>) wurde, hält er genau an der Stelle an, an der er gerade ausgeführt wird.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Any function called main</p>
<p><code>b &lt;binname&gt;`main</code> # Main function of the binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Main function of the indicated binary</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Any NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint list</p>
<p><code>br e/dis &lt;num&gt;</code> # Enable/disable breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Get help for the breakpoint command</p>
<p><code>help memory write</code> # Get help for writing to memory</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Zeigt den Speicher als nullterminierte Zeichenfolge an.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Zeigt den Speicher als Assembler-Instruktion an.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Zeigt den Speicher als Byte an.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Gibt das Objekt aus, auf das der Parameter verweist.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
Die meisten Apple-Objective-C-APIs oder -Methoden geben Objekte zurück und sollten daher mit dem Befehl „print object“ (<code>po</code>) angezeigt werden. Wenn <code>po</code> keine aussagekräftige Ausgabe liefert, verwenden Sie <code>x/b</code>.
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Write AAAA at that address<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Write AAAA at the address
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassemble the current function</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassemble a function</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassemble a function<br>
<code>dis -c 6</code> # Disassemble six lines<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassemble from one address to the other<br>
<code>dis -p -c 4</code> # Start disassembling at the current address</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspect an array of three components in the <code>x1</code> register</td></tr>
<tr><td><strong>image dump sections</strong></td><td>Gibt eine Karte des Speichers des aktuellen Prozesses aus.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Get the address of every symbol from CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Beim Aufruf der Funktion **`objc_sendMsg`** enthält das Register **rsi** den **Namen der Methode** als nullterminierte („C“-)Zeichenfolge. So geben Sie den Namen mit lldb aus:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamische Analyse

#### VM-Erkennung

- Der Befehl **`sysctl hw.model`** gibt auf physischer Hardware normalerweise eine Mac-Modellkennung zurück und kann in einer VM einen anderen Wert liefern.<sup>[[3]](#references)</sup>
- Einige Schadprogramme versuchen anhand der Werte von **`hw.logicalcpu`** und **`hw.physicalcpu`** zu erkennen, ob sie in einer VM laufen.<sup>[[4]](#references)</sup>
- Einige Schadprogramme können außerdem anhand der MAC-Adresse (00:50:56) erkennen, ob der Rechner auf **VMware** basiert.
- Mit einfachem Code wie diesem lässt sich ebenfalls feststellen, **ob ein Prozess debuggt wird**:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Außerdem kann der **`ptrace`**-Systemaufruf mit dem Flag **`PT_DENY_ATTACH`** aufgerufen werden. Im [Abschnitt zu PT_DENY_ATTACH](#page-title) finden Sie Informationen zum reihenfolgeabhängigen Verhalten von XNU, zur Protokollierung durch `debugserver` und zum ARM64-Patching-Workflow.<sup>[[7]](#references)[[12]](#references)</sup>

- Außerdem kann der **`ptrace`**-Systemaufruf mit dem Flag **`PT_DENY_ATTACH`** aufgerufen werden. Dadurch wird verhindert, dass ein Deb**u**gger angehängt wird und den Prozess verfolgt.
  - Sie können prüfen, ob die Funktion **`sysctl`** oder **`ptrace`** **importiert** wird (das Schadprogramm könnte sie jedoch dynamisch importieren).
  - Wie in diesem Write-up beschrieben: „[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)“:<sup>[[7]](#references)</sup>\
    „_Die Meldung Process # exited with **status = 45 (0x0000002d)** ist normalerweise ein eindeutiger Hinweis darauf, dass das Debug-Ziel **PT_DENY_ATTACH** verwendet._“
#### `fork()`-Prozessübergabe

Ein Prozess kann einem Debugger entgehen, der weiterhin an der ursprünglichen PID hängt, indem er kurz nach dem Start `fork()` aufruft, den Parent-Prozess beendet (`fork()` gibt eine positive Child-PID zurück) und die geschützte Logik nur im Child-Prozess fortsetzt (`fork()` gibt `0` zurück). Wird `fork` mit `dlsym(RTLD_DEFAULT, "fork")` aufgelöst, verschwindet außerdem der direkte `_fork`-Aufrufpunkt. Dies ist jedoch nur ein Hindernis für die Analyse: Die Zeichenfolge des Symbolnamens und der Datenfluss der dynamischen Auflösung bleiben in der Mach-O-Binärdatei sichtbar.<sup>[[13]](#references)[[14]](#references)</sup>

Erkennen Sie dieses Muster auf arm64, indem Sie dem Datenfluss statt festen Adressen folgen: Die ersten beiden Argumente für `dlsym` werden in `x0` und `x1` übergeben, `RTLD_DEFAULT` kann als `-2` erscheinen (zum Beispiel `movn x0, #1`), und ein `adrp`/`add`-Paar erzeugt häufig die Adresse der Zeichenfolge `"fork"`. Verfolgen Sie nach dem `bl` zum `dlsym`-Stub den zurückgegebenen Zeiger aus `x0` durch die Nullprüfung und Speicherung bis zu einem späteren indirekten `blr`. Folgen Sie dann dem Ergebnis von `fork()` in `w0`: Der Wert null führt zur Fortsetzung im Child-Prozess, während positive Werte und `-1` zum Pfad des Parent-Prozesses beziehungsweise zum Fehlerpfad führen.<sup>[[13]](#references)[[14]](#references)</sup>

Eine statische Umgehung besteht darin, den indirekten Aufruf zu unterdrücken und die bestehende Ergebnisprüfung so zu beeinflussen, dass sie den Child-Pfad nimmt. Wenn der Compiler beispielsweise die unten gezeigte Sequenz erzeugt hat, patchen Sie `blr` und die Ergebnisspeicherung mit `nop`, setzen Sie ein synthetisches Ergebnis von null ein und behalten Sie die Vergleichs- und Sprunglogik bei. Die Anwendung läuft dann unter der ursprünglichen PID weiter, ohne einen Child-Prozess zu erstellen. Instruktionsregister und Sprungziele müssen an die analysierte Build-Version angepasst werden.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Core Dumps werden erstellt, wenn:

- der sysctl `kern.coredump` auf 1 gesetzt ist (Standardwert)
- der Prozess nicht suid/sgid ist oder `kern.sugid_coredump` auf 1 gesetzt ist (Standardwert ist 0)
- das Limit `AS_CORE` den Vorgang zulässt. Die Erstellung von Core Dumps lässt sich mit `ulimit -c 0` unterdrücken und mit `ulimit -c unlimited` wieder aktivieren.

In diesen Fällen werden die Core Dumps gemäß dem sysctl `kern.corefile` erzeugt und üblicherweise unter `/cores/core/.%P` gespeichert.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analysiert abstürzende Prozesse und speichert einen Crash-Bericht auf der Festplatte**. Ein Crash-Bericht enthält Informationen, die **Entwicklern helfen können, die Ursache eines Absturzes zu diagnostizieren**.\
Bei Anwendungen und anderen Prozessen, die **im launchd-Kontext des jeweiligen Benutzers laufen**, wird ReportCrash als LaunchAgent ausgeführt und speichert Crash-Berichte unter `~/Library/Logs/DiagnosticReports/` des Benutzers.\
Bei Daemons, anderen Prozessen, die **im systemweiten launchd-Kontext laufen**, und anderen privilegierten Prozessen wird ReportCrash als LaunchDaemon ausgeführt und speichert Crash-Berichte unter `/Library/Logs/DiagnosticReports` des Systems.

Wenn Sie Bedenken haben, dass Crash-Berichte **an Apple gesendet werden**, können Sie diese Funktion deaktivieren. Andernfalls können Crash-Berichte nützlich sein, um **herauszufinden, warum ein Server abgestürzt ist**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Ruhezustand

Verhindere beim Fuzzing unter macOS, dass der Mac in den Ruhezustand wechselt:

- systemsetup -setsleep Never
- pmset, Systemeinstellungen
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-Verbindungsabbruch

Wenn du über eine SSH-Verbindung fuzzst, solltest du sicherstellen, dass die Sitzung nicht abbricht. Ändere dazu die Datei sshd_config wie folgt:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Interne Handler

**Sieh dir die folgende Seite an**, um herauszufinden, welche App für die **Verarbeitung des angegebenen Schemas oder Protokolls** zuständig ist:


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Netzwerkprozesse auflisten

Das ist interessant, um Prozesse zu finden, die Netzwerkdaten verwalten:

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

### Zustandsbehaftetes Mach IPC fuzzing

Mach-Services, die von privilegierten Daemons bereitgestellt werden, sind nützliche Fuzzing-Ziele, wenn ein nicht privilegierter oder in einer Sandbox ausgeführter Client ein Senderecht erhalten kann. Beginne mit dem `MachServices`-Eintrag des Daemons in launchd und verwende den [MIG-Analyse-Workflow](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md), um Nachrichten-IDs den Handlern zuzuordnen. Bevor du Bytes veränderst, setze einen Breakpoint auf die MIG-Serverroutine, während ein normaler Client den Service nutzt, und speichere gültige Request-Nachrichten als Seed-Eingaben. Erhalte die erforderlichen Header-Felder, Nachrichtengrößen und das Descriptor-Layout, damit Mutationen den Handler erreichen und nicht sofort bei der Dispatch fehlschlagen.<sup>[[17]](#references)</sup>

Viele Handler hängen von vorherigen Aufrufen ab. Lass den Harness den Service-Zustand initialisieren und verarbeite dann jede Fuzz-Eingabe als Folge von **Operationen plus Argumenten**: Sende Setup-Requests (etwa zum Öffnen oder Erstellen), behalte zurückgegebene Bezeichner und verwende sie in späteren Requests. So kann das Coverage-Feedback Zustandsübergänge erkunden, statt wiederholt an einer Prüfung auf nicht initialisierte Objekte zu scheitern.<sup>[[17]](#references)</sup>

Für ein Closed-Source-Ziel kann ein In-Process-Harness, das die MIG-Dispatch-Routine aufruft, mit Jackalope/TinyInst instrumentiert werden. Der [CoreAudioFuzz-Harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) ist eine konkrete Implementierung und kein direkt einsetzbarer Harness für andere Services.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Validiere jeden Crash über den echten IPC-Pfad.** Ein Direct-Dispatch-Harness überspringt die Kernel-Validierung von Mach-Nachrichten und kann falsch positive Ergebnisse liefern, insbesondere wenn es ungültige Out-of-Line-(OOL-)Speicherbereiche oder Port-Deskriptoren bereitstellt. Weise dem Harness gültigen OOL-Speicher zu und spiele den reduzierten Testfall anschließend über `mach_msg` von einem Client mit dem ursprünglichen Service-Zugriff erneut ab. Verifiziere, dass der Daemon weiterhin abstürzt.<sup>[[17]](#references)</sup>

### Fuzzer

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funktioniert mit CLI-Tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Funktioniert mit vielen macOS-GUI-Tools „**einfach so**“. Einige Anwendungen haben zusätzliche Anforderungen, etwa eindeutige Dateinamen, eine bestimmte Dateiendung oder das Lesen von Dateien aus ihrem Sandbox-Container (`~/Library/Containers/com.apple.Safari/Data`).

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

### Weitere Informationen zum Fuzzing unter macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)



## References

- [1] [OS X Incident Response: Skripting und Analyse](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown – Summer of Fuzz: MacOS – DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Band I: Analyse](https://taomm.org/)
- [4] [No Starch Press – The Art of Mac Malware: Der Leitfaden zur Analyse bösartiger Software](https://nostarch.com/art-mac-malware)
- [5] [knight.sc – In diesen Abschnitten gespeicherte Informationen in diesem Blogbeitrag](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc – Debugging von Apple-Binärdateien, die Pt Deny Attach verwenden](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com – Anti-Debug-Techniken umgehen: macOS-ptrace-Varianten](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums – Strukturierte Xcode-Logs und `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User – Private Daten im einheitlichen macOS-Log anzeigen](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Definitionen der Apple-XNU-`ptrace.h`-Anforderungen](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple-XNU-`ptrace`-Implementierung in `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society – ptrace-Interna: Wie das Anhängen eines Debuggers verhindert wird](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples – fork-Beispiele](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society – Anti-Debug-Technik mit dlsym und fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple – Berechtigung für Debugging-Tools](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums – Debugging einer gehärteten Drittanbieter-App](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero – Die Schallmauer durchbrechen, Teil I: Fuzzing von CoreAudio mit Mach Messages](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero – CoreAudioFuzz-Harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero – Jackalope-Fuzzer](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
