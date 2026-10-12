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
> Beachte, dass **`disarm`** auch mit komprimierten IM4P-Dateien (wie `kernelcache`) arbeiten und nur die erforderlichen Teile extrahieren oder den erforderlichen Teil sogar ohne Extraktion analysieren kann.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ist ein nützliches Tool, um **.pkg**-Dateien (Installer) zu überprüfen und vor der Installation zu sehen, was sie enthalten.\
Diese Installer enthalten `preinstall`- und `postinstall`-Bash-Skripte, die Malware-Autoren häufig missbrauchen, um **die** **Malware** zu **persistieren**.

### hdiutil

Dieses Tool **mountet** Apple-Disk-Image-Dateien (`.dmg`), damit sie überprüft werden können, bevor irgendetwas ausgeführt wird:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Es wird unter `/Volumes` eingehängt.

### Gepackte Binärdateien

- Auf hohe Entropie prüfen
- Die Zeichenketten prüfen (wenn es fast keine verständlichen Zeichenketten gibt, ist die Datei gepackt)
- Der UPX-Packer für macOS erzeugt einen Abschnitt namens `__XHDR`.

## Statische Objective-C-Analyse

### Metadaten

> [!CAUTION]
> Beachte, dass in Objective-C geschriebene Programme ihre Klassendeklarationen **beibehalten**, wenn sie zu [Mach-O-Binärdateien](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **kompiliert** werden. Solche Klassendeklarationen **enthalten** Namen und Typen von:

- den definierten Interfaces
- den Interface-Methoden
- den Instanzvariablen der Interfaces
- den definierten Protokollen

Beachte, dass diese Namen verschleiert werden können, um das Reverse Engineering der Binärdatei zu erschweren.

### Funktionsaufrufe

Wenn eine Funktion in einer Binärdatei aufgerufen wird, die Objective-C verwendet, ruft der kompilierte Code anstelle dieser Funktion **`objc_msgSend`** auf. Diese Funktion ruft die endgültige Funktion auf:

![Metadaten – Funktionsaufrufe: Wenn eine Funktion in einer Binärdatei aufgerufen wird, die Objective-C verwendet, ruft der kompilierte Code anstelle dieser Funktion objc_msgSend auf. Diese Funktion ruft ... auf](<../../../images/image (305).png>)

Diese Funktion erwartet folgende Parameter:

- Der erste Parameter (**self**) ist „ein Zeiger auf die **Instanz der Klasse, die die Nachricht empfangen soll**“. Einfacher gesagt: Es ist das Objekt, auf das die Methode angewendet wird. Bei einer Klassenmethode ist dies eine Instanz des Klassenobjekts (als Ganzes); bei einer Instanzmethode zeigt `self` auf eine instanziierte Instanz der Klasse als Objekt.
- Der zweite Parameter (**op**) ist „der Selektor der Methode, die die Nachricht verarbeitet“. Einfacher gesagt: Dies ist der **Name der Methode**.
- Die übrigen Parameter sind alle **Werte, die von der Methode benötigt werden** (op).

Auf dieser Seite erfährst du, wie du diese Informationen mit `lldb` unter **ARM64** ganz einfach abrufst:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(für) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. Argument**   | **rdi**                                                         | **self: Objekt, auf das die Methode angewendet wird** |
| **2. Argument**   | **rsi**                                                         | **op: Name der Methode**                              |
| **3. Argument**   | **rdx**                                                         | **1. Argument der Methode**                           |
| **4. Argument**   | **rcx**                                                         | **2. Argument der Methode**                           |
| **5. Argument**   | **r8**                                                          | **3. Argument der Methode**                           |
| **6. Argument**   | **r9**                                                          | **4. Argument der Methode**                           |
| **7.+ Argument**  | <p><strong>rsp+</strong><br><strong>(auf dem Stack)</strong></p> | **5.+ Argument der Methode**                         |

### Objective-C-Metadaten dumpen

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ist ein Tool, um Objective-C-Binärdateien mit `class-dump` zu untersuchen. Im GitHub-Repository werden dylibs erwähnt, das Tool funktioniert jedoch auch mit ausführbaren Dateien.

```bash
./dynadump dump /path/to/bin
```

Zum Zeitpunkt der Erstellung funktioniert **dieses derzeit am besten**.

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

[**iCDump**](https://github.com/romainthomas/iCDump) ist ein modernes, plattformübergreifendes Objective-C-Class-Dump-Tool. Im Vergleich zu bestehenden Tools kann iCDump unabhängig vom Apple-Ökosystem ausgeführt werden und bietet Python-Bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statische Swift-Analyse

Bei Swift-Binaries kann man aufgrund der Objective-C-Kompatibilität manchmal Deklarationen mit [class-dump](https://github.com/nygard/class-dump/) extrahieren, aber nicht immer.

Mit den Befehlszeilen **`jtool -l`** oder **`otool -l`** lassen sich mehrere Sektionen finden, die mit dem Präfix **`__swift5`** beginnen:

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

Außerdem können **Swift-Binaries Symbole enthalten** (zum Beispiel müssen Bibliotheken Symbole speichern, damit ihre Funktionen aufgerufen werden können). Die **Symbole enthalten normalerweise auf unübersichtliche Weise Informationen über den Funktionsnamen** und die Attribute. Daher sind sie sehr nützlich, und es gibt sogenannte **„demanglers“**, die den ursprünglichen Namen ermitteln können:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dynamische Analyse

> [!WARNING]
> Beachte, dass zum Debuggen von Binärdateien **SIP deaktiviert sein muss** (`csrutil disable` oder `csrutil enable --without debug`). Alternativ kannst du die Binärdateien in einen temporären Ordner kopieren und die Signatur mit `codesign --remove-signature <binary-path>` **entfernen** oder das Debuggen der Binärdatei erlauben (du kannst [dieses Skript](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) verwenden).

> [!WARNING]
> Beachte, dass zum **Instrumentieren von Systembinärdateien** (wie `cloudconfigurationd`) unter macOS **SIP deaktiviert sein muss** (nur die Signatur zu entfernen reicht nicht).

### APIs

macOS stellt einige interessante APIs bereit, die Informationen über Prozesse liefern:

- `proc_info`: Dies ist die wichtigste API und liefert viele Informationen zu jedem Prozess. Um Informationen über andere Prozesse zu erhalten, musst du root sein. Spezielle Entitlements oder Mach-Ports sind jedoch nicht erforderlich.
- `libsysmon.dylib`: Stellt Prozessinformationen über XPC-Funktionen bereit. Aufrufende Prozesse benötigen jedoch das Entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** ist eine Technik, mit der der Zustand von Prozessen erfasst wird, einschließlich der Call Stacks aller laufenden Threads. Das ist besonders nützlich für Debugging, Performance-Analysen und um das Verhalten des Systems zu einem bestimmten Zeitpunkt zu verstehen. Unter iOS und macOS kann Stackshotting mit verschiedenen Tools und Methoden durchgeführt werden, etwa mit den Tools **`sample`** und **`spindump`**.

### Sysdiagnose

Dieses Tool (`/usr/bini/ysdiagnose`) sammelt im Wesentlichen viele Informationen von deinem Computer, indem es Dutzende verschiedener Befehle wie `ps`, `zprint` usw. ausführt.

Es muss als **root** ausgeführt werden. Der Daemon `/usr/libexec/sysdiagnosed` verfügt über sehr interessante Entitlements wie `com.apple.system-task-ports` und `get-task-allow`.

Seine plist befindet sich unter `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`. Darin sind 3 MachServices definiert:

- `com.apple.sysdiagnose.CacheDelete`: Löscht alte Archive in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Spezieller Port 23 (Kernel)
- `com.apple.sysdiagnose.service.xpc`: Schnittstelle im User Mode über die Obj-C-Klasse `Libsysdiagnose`. Es können drei Argumente in einem Dict übergeben werden (`compress`, `display`, `run`)

### Unified Logs

macOS erstellt umfangreiche Logs, die bei der Analyse des Verhaltens einer Anwendung nützlich sind.

Einige Log-Felder enthalten das Tag `<private>`, um Informationen zu verbergen, mit denen sich Benutzer oder Geräte identifizieren lassen. Ältere Anleitungen beschreiben mitunter die Installation eines Zertifikats, um diese Felder sichtbar zu machen. Aktuelle Debugging-Anleitungen verwenden stattdessen ein explizit eingeschränktes Konfigurationsprofil mit `Enable-Private-Data` oder anwendungsspezifische `OSLogPreferences`. Das Verhalten kann je nach Subsystem und macOS-Version variieren. Die ältere Diskussion zu Zertifikaten und Profilen ist in den Referenzen enthalten. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Linkes Panel

Im linken Panel von Hopper kannst du die Symbole (**Labels**) der Binärdatei, die Liste der Prozeduren und Funktionen (**Proc**) sowie die Strings (**Str**) sehen. Das sind nicht alle Strings, sondern nur die, die in verschiedenen Bereichen der Mac-O-Datei definiert sind (wie _cstring oder_ `objc_methname`).

#### Mittleres Panel

Im mittleren Panel siehst du den **disassemblierten Code**. Du kannst ihn als **rohes** Disassembly, als **Graph**, als **dekompilierten Code** oder als **Binärdaten** anzeigen lassen, indem du auf das jeweilige Symbol klickst:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Wenn du mit der rechten Maustaste auf ein Codeobjekt klickst, kannst du **Referenzen zu/von diesem Objekt** anzeigen oder sogar dessen Namen ändern (das funktioniert nicht im dekompilierten Pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Außerdem kannst du **unten in der Mitte Python-Befehle eingeben**.

#### Rechtes Panel

Im rechten Panel findest du interessante Informationen wie den **Navigationsverlauf** (damit du weißt, wie du zur aktuellen Stelle gelangt bist), den **Aufrufgraphen**, in dem du alle **Funktionen sehen kannst, die diese Funktion aufrufen**, sowie alle Funktionen, **die von dieser Funktion aufgerufen werden**, und Informationen zu **lokalen Variablen**.

### dtrace

Damit erhalten Benutzer Zugriff auf Anwendungen auf einem extrem **niedrigen Level**. Außerdem können sie **Programme nachverfolgen** und sogar ihren Ausführungsfluss ändern. Dtrace verwendet **Probes**, die **im gesamten Kernel platziert** sind, etwa am Anfang und Ende von Systemaufrufen.

DTrace verwendet die Funktion **`dtrace_probe_create`**, um für jeden Systemaufruf eine Probe zu erstellen. Diese Probes können am **Eintritts- und Austrittspunkt jedes Systemaufrufs** ausgelöst werden. Die Interaktion mit DTrace erfolgt über /dev/dtrace, das nur für den root-Benutzer verfügbar ist.<sup>[[1]](#references)</sup>

> [!TIP]
> Um Dtrace zu aktivieren, ohne den SIP-Schutz vollständig zu deaktivieren, kannst du im Recovery-Modus Folgendes ausführen: `csrutil enable --without dtrace`
>
> Du kannst auch **`dtrace`** oder **`dtruss`** für Binärdateien verwenden, **die du selbst kompiliert hast**.

Die verfügbaren Probes von dtrace kannst du mit folgendem Befehl abrufen:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Der Probe-Name besteht aus vier Teilen: dem Provider, dem Modul, der Funktion und dem Namen (`fbt:mach_kernel:ptrace:entry`). Wenn Sie einen Teil des Namens nicht angeben, verwendet Dtrace dafür einen Platzhalter.

Um DTrace so zu konfigurieren, dass Probes aktiviert werden und festzulegen, welche Aktionen beim Auslösen ausgeführt werden sollen, müssen wir die D-Sprache verwenden.

Eine ausführlichere Erklärung und weitere Beispiele finden Sie unter [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Beispiele

Führen Sie `man -k dtrace` aus, um **verfügbare DTrace-Skripte** aufzulisten. Beispiel: `sudo dtruss -n binary`

- In der Zeile

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

Dies ist eine Kernel-Tracing-Funktion. Die dokumentierten Codes finden Sie in **`/usr/share/misc/trace.codes`**.

Tools wie `latency`, `sc_usage`, `fs_usage` und `trace` verwenden sie intern.

Für die Schnittstelle zu `kdebug` wird `sysctl` im Namespace `kern.kdebug` verwendet. Die MIBs finden Sie in `sys/sysctl.h`; die Funktionen sind in `bsd/kern/kdebug.c` implementiert.

Für die Interaktion mit kdebug über einen eigenen Client sind üblicherweise folgende Schritte erforderlich:

- Vorhandene Einstellungen mit KERN_KDSETREMOVE entfernen
- Tracing mit KERN_KDSETBUF und KERN_KDSETUP konfigurieren
- Mit KERN_KDGETBUF die Anzahl der Puffereinträge ermitteln
- Den eigenen Client mit KERN_KDPINDEX aus dem Trace auslesen
- Tracing mit KERN_KDENABLE aktivieren
- Den Puffer mit KERN_KDREADTR auslesen
- Mit KERN_KDTHRMAP jeden Thread seinem Prozess zuordnen

Um diese Informationen abzurufen, können Sie das Apple-Tool **`trace`** oder das eigene Tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** verwenden.

**Beachten Sie, dass Kdebug jeweils nur für einen Benutzer verfügbar ist.** Daher kann immer nur ein Tool mit k-debug-Unterstützung gleichzeitig ausgeführt werden.

### ktrace

Die `ktrace_*`-APIs stammen aus `libktrace.dylib`, das die Kdebug-APIs umschließt. Ein Client kann dann einfach `ktrace_session_create` und `ktrace_events_[single/class]` aufrufen, um Callbacks für bestimmte Codes festzulegen, und das Tracing anschließend mit `ktrace_start` starten.

Sie können dieses Tool auch bei aktiviertem **SIP** verwenden.

Als Client können Sie das Hilfsprogramm `ktrace` verwenden:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Oder `tailspin`.

### kperf

Dies wird für Kernel-Level-Profiling verwendet und basiert auf `Kdebug`-Callouts.

Im Grunde wird die globale Variable `kernel_debug_active` überprüft. Ist sie gesetzt, wird `kperf_kdebug_handler` mit dem `Kdebug`-Code und der Adresse des Kernel-Frames aufgerufen. Stimmt der `Kdebug`-Code mit einem ausgewählten Code überein, werden die als Bitmap konfigurierten „Aktionen“ ausgeführt (die Optionen finden sich in `osfmk/kperf/action.h`).

Kperf verfügt außerdem über eine sysctl-MIB-Tabelle: (als root) `sysctl kperf`. Der entsprechende Code findet sich in `osfmk/kperf/kperfbsd.c`.

Darüber hinaus befindet sich ein Teil der Kperf-Funktionalität in `kpc`, das Informationen über die Performance-Counter der Maschine bereitstellt.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ist ein sehr nützliches Tool, um prozessbezogene Aktionen eines Prozesses zu überprüfen (beispielsweise zu überwachen, welche neuen Prozesse ein Prozess erstellt).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ist ein Tool, das die Beziehungen zwischen Prozessen darstellt.\
Du musst deinen Mac mit einem Befehl wie **`sudo eslogger fork exec rename create > cap.json`** überwachen (das Terminal, von dem aus dieser Befehl gestartet wird, benötigt FDA). Anschließend kannst du die JSON-Datei in dieses Tool laden, um alle Beziehungen anzuzeigen:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) überwacht Datei-Ereignisse wie Erstellung, Änderung und Löschung.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ist ein GUI-Tool, dessen Erscheinungsbild und Bedienung Windows-Nutzer möglicherweise von Microsoft Sysinternals’ _Procmon_ kennen. Mit diesem Tool lassen sich verschiedene Ereignistypen aufzeichnen und die Aufzeichnung stoppen. Die Ereignisse können nach Kategorien wie Datei, Prozess, Netzwerk usw. gefiltert werden. Außerdem können die aufgezeichneten Ereignisse im JSON-Format gespeichert werden.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) sind Teil der Xcode-Entwicklerwerkzeuge. Sie dienen dazu, die Anwendungsleistung zu überwachen, Speicher-Leaks zu erkennen und Dateisystemaktivitäten nachzuverfolgen.

![Crescendo - Apple Instruments: Apple Instruments sind Teil der Xcode-Entwicklerwerkzeuge. Sie dienen dazu, die Anwendungsleistung zu überwachen, Speicher-Leaks zu erkennen und Dateisystemaktivitäten nachzuverfolgen](<../../../images/image (1138).png>)

### fs_usage

Ermöglicht es, von Prozessen ausgeführte Aktionen zu verfolgen:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ist nützlich, um die von einer Binärdatei verwendeten **Bibliotheken**, die von ihr genutzten **Dateien** und ihre **Netzwerk**verbindungen anzuzeigen.\
Außerdem überprüft es die Prozesse der Binärdatei mit **virustotal** und zeigt Informationen über die Binärdatei an.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**diesem Blogbeitrag**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) findest du ein Beispiel dafür, wie man einen laufenden Daemon **debuggen** kann, der **`PT_DENY_ATTACH`** verwendet hat, um das Debugging zu verhindern, selbst wenn SIP deaktiviert war.<sup>[[6]](#references)</sup>

### lldb

**lldb** ist das De-facto-Tool zum **Debugging** von **macOS**-Binärdateien.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Sie können den Intel-Flavour festlegen, wenn Sie lldb verwenden, indem Sie in Ihrem Home-Verzeichnis eine Datei namens **`.lldbinit`** mit folgender Zeile erstellen:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Innerhalb von lldb einen Prozess mit `process save-core` sichern

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Beschreibung</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Startet die Ausführung, die fortgesetzt wird, bis ein Breakpoint erreicht wird oder der Prozess endet.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Startet die Ausführung und hält am Einstiegspunkt an.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Setzt die Ausführung des debugten Prozesses fort.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Führt die nächste Instruktion aus. Dieser Befehl überspringt Funktionsaufrufe.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Führt die nächste Instruktion aus. Anders als der Befehl <code>nexti</code> steigt dieser Befehl in Funktionsaufrufe ein.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Führt die verbleibenden Instruktionen der aktuellen Funktion (des aktuellen Frames) aus, kehrt zurück und hält an.</td></tr>
<tr><td><strong>control + c</strong></td><td>Hält die Ausführung an. Wurde der Prozess gestartet (<code>r</code>) oder fortgesetzt (<code>c</code>), hält er an der Stelle an, an der er gerade ausgeführt wird.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Jede Funktion namens main</p>
<p><code>b &lt;binname&gt;`main</code> # Hauptfunktion des Binaries</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Hauptfunktion des angegebenen Binaries</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Jede NSFileManager-Methode</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Breakpoint in allen Funktionen dieser Library</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint-Liste</p>
<p><code>br e/dis &lt;num&gt;</code> # Breakpoint aktivieren/deaktivieren</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Hilfe zum Befehl breakpoint anzeigen</p>
<p><code>help memory write</code> # Hilfe zum Schreiben in den Speicher anzeigen</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Zeigt den Speicher als nullterminierte Zeichenkette an.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Zeigt den Speicher als Assembler-Instruktion an.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Zeigt den Speicher als Byte an.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Gibt das vom Parameter referenzierte Objekt aus.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
Die meisten Apple-Objective-C-APIs oder -Methoden geben Objekte zurück, die daher mit dem Befehl „print object“ (<code>po</code>) angezeigt werden sollten. Liefert <code>po</code> keine aussagekräftige Ausgabe, verwende <code>x/b</code>.
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Schreibt AAAA an diese Adresse<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Schreibt AAAA an diese Adresse
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassembliert die aktuelle Funktion</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassembliert eine Funktion</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassembliert eine Funktion<br>
<code>dis -c 6</code> # Disassembliert sechs Zeilen<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassembliert von einer Adresse bis zur anderen<br>
<code>dis -p -c 4</code> # Beginnt die Disassemblierung an der aktuellen Adresse</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Untersucht ein Array mit drei Elementen im Register <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Gibt eine Abbildung des Speichers des aktuellen Prozesses aus.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Ermittelt die Adresse jedes Symbols aus CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Beim Aufruf der Funktion **`objc_sendMsg`** enthält das Register **rsi** den **Methodennamen** als nullterminierte („C“-)Zeichenkette. Um den Namen mit lldb auszugeben:
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
- Durch Manipulation der Werte von **`hw.logicalcpu`** und **`hw.physicalcpu`** versuchen manche Malware-Programme zu erkennen, ob sie in einer VM laufen.<sup>[[4]](#references)</sup>
- Manche Malware-Programme können auch anhand der MAC-Adresse (00:50:56) erkennen, ob die Maschine auf **VMware** basiert.
- Mit einfachem Code wie dem folgenden lässt sich ebenfalls **erkennen, ob ein Prozess debuggt wird**:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Außerdem kann der **`ptrace`**-Systemaufruf mit dem Flag **`PT_DENY_ATTACH`** aufgerufen werden. Dadurch wird **verhindert**, dass ein deb**u**gger angehängt wird und den Prozess verfolgt.
  - Du kannst prüfen, ob die Funktion **`sysctl`** oder **`ptrace`** **importiert** wird (die Malware könnte sie jedoch dynamisch importieren).
  - Wie in diesem Write-up beschrieben: „[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)“ :<sup>[[7]](#references)</sup>\
    „_Die Meldung Process # exited with **status = 45 (0x0000002d)** ist normalerweise ein deutliches Anzeichen dafür, dass das Debug-Ziel **PT_DENY_ATTACH** verwendet_“

#### `fork()`-Prozessübergabe

Ein Prozess kann einem Debugger entgehen, der weiterhin an die ursprüngliche PID angehängt ist, indem er beim Start `fork()` aufruft, den Elternprozess beendet (`fork()` gibt eine positive Child-PID zurück) und die geschützte Logik nur im Child fortsetzt (`fork()` gibt `0` zurück). Auch das Auflösen von `fork` mit `dlsym(RTLD_DEFAULT, "fork")` entfernt zwar den direkten `_fork`-Aufruf, stellt aber nur ein Hindernis für die Analyse dar: Der Symbolnamen-String und der Datenfluss der dynamischen Auflösung bleiben im Mach-O-Binary sichtbar.<sup>[[10]](#references)[[11]](#references)</sup>

Erkenne dieses Muster auf arm64, indem du dem Datenfluss statt festen Adressen folgst: Die ersten beiden Argumente für `dlsym` werden in `x0` und `x1` übergeben, `RTLD_DEFAULT` kann als `-2` erscheinen (zum Beispiel mit `movn x0, #1`), und ein `adrp`/`add`-Paar erzeugt häufig die Adresse des Strings `"fork"`. Verfolge nach dem `bl` zum `dlsym`-Stub den zurückgegebenen Zeiger von `x0` durch seine Nullprüfung und Speicherung bis zu einem späteren indirekten `blr`. Verfolge anschließend das Ergebnis von `fork()` in `w0`: Der Wert null führt zum Child-Pfad, positive Werte und `-1` dagegen zum Pfad des Elternprozesses beziehungsweise zum Fehlerpfad.<sup>[[10]](#references)[[11]](#references)</sup>

Eine statische Umgehung besteht darin, den indirekten Aufruf zu unterdrücken und die vorhandene Ergebnisprüfung so zu beeinflussen, dass sie den Child-Pfad einschlägt. Wenn der Compiler beispielsweise die unten gezeigte Sequenz generiert hat, patche `blr` und die Ergebnisspeicherung mit `nop`, setze ein synthetisches Ergebnis von null und lass die Vergleichs- und Sprunglogik bestehen. Die Anwendung läuft dann unter der ursprünglichen PID weiter, ohne einen Child-Prozess zu erzeugen. Instruktionsregister und Sprungziele müssen an die untersuchte Build-Version angepasst werden.<sup>[[10]](#references)[[11]](#references)</sup>

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

- der sysctl `kern.coredump` auf 1 gesetzt ist (standardmäßig)
- der Prozess nicht suid/sgid ist oder `kern.sugid_coredump` auf 1 gesetzt ist (standardmäßig 0)
- das Limit `AS_CORE` den Vorgang zulässt. Die Erstellung von Core Dumps lässt sich mit `ulimit -c 0` unterdrücken und mit `ulimit -c unlimited` wieder aktivieren.

In diesen Fällen werden die Core Dumps entsprechend dem sysctl `kern.corefile` generiert und üblicherweise unter `/cores/core/.%P` gespeichert.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analysiert abstürzende Prozesse und speichert einen Crash-Report auf der Festplatte**. Ein Crash-Report enthält Informationen, die **einem Entwickler helfen können, die Ursache eines Absturzes zu diagnostizieren**.\
Für Anwendungen und andere Prozesse, die **im launchd-Kontext des jeweiligen Benutzers laufen**, wird ReportCrash als LaunchAgent ausgeführt und speichert Crash-Reports unter `~/Library/Logs/DiagnosticReports/` des Benutzers.\
Für Daemons, andere Prozesse, die **im systemweiten launchd-Kontext laufen**, und andere privilegierte Prozesse wird ReportCrash als LaunchDaemon ausgeführt und speichert Crash-Reports unter `/Library/Logs/DiagnosticReports` des Systems.

Wenn du Bedenken hast, dass Crash-Reports **an Apple gesendet werden**, kannst du diese Funktion deaktivieren. Andernfalls können Crash-Reports hilfreich sein, um **herauszufinden, warum ein Server abgestürzt ist**.

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
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-Verbindungsabbruch

Wenn du über eine SSH-Verbindung fuzzst, musst du sicherstellen, dass die Sitzung nicht abbricht. Ändere dazu die Datei sshd_config wie folgt:

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

Oder verwende `netstat` oder `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzer

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funktioniert mit CLI-Tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Es „**funktioniert einfach**“ mit vielen macOS-GUI-Tools. Einige Anwendungen haben zusätzliche Anforderungen, etwa eindeutige Dateinamen, eine bestimmte Dateiendung oder das Lesen von Dateien aus ihrem Sandbox-Container (`~/Library/Containers/com.apple.Safari/Data`).

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

### Weitere Informationen zum macOS-Fuzzing

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS X Incident Response: Skripting und Analyse](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Sommer des Fuzzing: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Die Kunst der Mac-Malware, Band I: Analyse](https://taomm.org/)
- [4] [No Starch Press - Die Kunst der Mac-Malware: Der Leitfaden zur Analyse bösartiger Software](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - Informationen, die in diesen Abschnitten dieses Blogbeitrags gespeichert sind](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debuggen von Apple-Binärdateien, die Pt Deny Attach verwenden](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug-Techniken umgehen: macOS-ptrace-Varianten](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Strukturierte Xcode-Protokolle und `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Private Daten im einheitlichen macOS-Protokoll anzeigen](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - fork-Beispiele](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - Anti-Debugging-Technik mit dlsym und fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
