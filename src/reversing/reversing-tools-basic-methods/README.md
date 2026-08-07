# Reverse-Engineering-Tools und grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## ImGui-basierte Reverse-Engineering-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Verwende [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (binär) nach wat (Klartext) zu **decompilieren**
- Verwende [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um von wat nach wasm zu **compilieren**
- Du kannst auch versuchen, [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) zum Decompilieren zu verwenden

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein decompiler, der **mehrere Formate decompiliert und untersucht**, darunter **Bibliotheken** (.dll), **Windows-Metadatendatei**n (.winmd) und **ausführbare Dateien** (.exe). Nach dem Decompilieren kann eine Assembly als Visual-Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil besteht darin, dass diese Maßnahme Zeit sparen kann, wenn der verlorene Quellcode aus einer älteren Assembly wiederhergestellt werden muss. Außerdem bietet dotPeek eine praktische Navigation durch den decompilierten Code und ist damit eines der perfekten Tools für die **Analyse von Xamarin-Algorithmen.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an deine genauen Anforderungen anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die Vielzahl der Reverse-Engineering-Dienste an, die dieses Tool bietet:

- Gibt Einblick in den Datenfluss durch eine Bibliothek oder Komponente
- Gibt Einblick in die Implementierung und Verwendung von .NET-Sprachen und Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblies
- Ermittelt den genauen Ort von Fehlern in deinem Code, in Komponenten und Bibliotheken von Drittanbietern.
- Debuggt in den Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es unter jedem Betriebssystem verwenden (du kannst es direkt aus VSCode installieren, ohne das git herunterzuladen. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du **decompilieren**, **modifizieren** und anschließend erneut **compilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### DNSpy Logging

Um **DNSpy einige Informationen in einer Datei protokollieren zu lassen**, kannst du dieses Snippet verwenden:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Um Code mit DNSpy zu debuggen, müssen Sie:

Zuerst die **Assembly attributes** im Zusammenhang mit dem **Debugging** ändern:

![DNSpy Logging - DNSpy Debugging: Zuerst die Assembly attributes im Zusammenhang mit dem Debugging ändern](<../../images/image (973).png>)

Von:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
An:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Und klicken Sie auf **compile**:

![DNSpy Logging - DNSpy Debugging: Und klicken Sie auf compile](<../../images/image (314) (1).png>)

Speichern Sie anschließend die neue Datei über _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Speichern Sie anschließend die neue Datei über File Save module](<../../images/image (602).png>)

Dies ist notwendig, denn wenn Sie dies nicht tun, werden zur **runtime** mehrere **Optimierungen** auf den Code angewendet, sodass es möglich ist, dass beim Debugging ein **break-point nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn Ihre .NET-Anwendung anschließend von **IIS** **ausgeführt** wird, können Sie sie mit folgendem Befehl **neu starten**:
```
iisreset /noforce
```
Dann sollten Sie, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Dann sollten Sie, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und im Debug Tab Attach to Process auswählen](<../../images/image (318).png>)

Wählen Sie anschließend **w3wp.exe** aus, um den **IIS server** zu verbinden, und klicken Sie auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wählen Sie anschließend w3wp.exe aus, um den IIS server zu verbinden, und klicken Sie auf attach](<../../images/image (113).png>)

Da wir nun den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicken Sie zuerst auf _Debug >> Break All_ und anschließend auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Da wir nun den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicken Sie zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Da wir nun den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicken Sie zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (834).png>)

Klicken Sie in **Modules** auf ein beliebiges Modul und wählen Sie **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicken Sie in Modules auf ein beliebiges Modul und wählen Sie Open All Modules aus](<../../images/image (922).png>)

Klicken Sie in **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und klicken Sie auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Klicken Sie in Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und klicken Sie auf Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Wählen Sie den **Windbg** debugger aus
- Wählen Sie "**Suspend on library load/unload**" aus

![Debugging DLLs - Using IDA: Wählen Sie " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Konfigurieren Sie die **parameters** der Ausführung, indem Sie den **path to the DLL** und die Funktion angeben, die Sie aufrufen möchten:

![Debugging DLLs - Using IDA: Konfigurieren Sie die parameters der Ausführung, indem Sie den path to the DLL und die Funktion angeben, die Sie aufrufen möchten](<../../images/image (704).png>)

Wenn Sie anschließend mit dem Debugging beginnen, wird **die Ausführung angehalten, sobald jede DLL geladen wird**. Wenn rundll32 Ihre DLL lädt, wird die Ausführung also angehalten.

Aber wie gelangen Sie zum Code der geladenen DLL? Mit dieser Methode weiß ich nicht, wie das geht.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) und setzen Sie den Pfad der DLL sowie die Funktion, die Sie aufrufen möchten, fest, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ändern Sie _Options --> Settings_ und wählen Sie "**DLL Entry**" aus.
- **Starten Sie anschließend die Ausführung**. Der Debugger hält bei jedem dll main an. Irgendwann werden Sie **bei der dll Entry Ihrer DLL angehalten**. Suchen Sie von dort aus einfach nach den Stellen, an denen Sie einen Breakpoint setzen möchten.

Beachten Sie, dass Sie in win64dbg, wenn die Ausführung aus irgendeinem Grund angehalten wurde, **im oberen Bereich des win64dbg-Fensters** sehen können, **in welchem Code Sie sich befinden**:

![Using IDA - Using x64dbg/x32dbg: Beachten Sie, dass Sie in win64dbg, wenn die Ausführung aus irgendeinem Grund angehalten wurde, im oberen Bereich des win64dbg-Fensters sehen können, in welchem Code Sie sich befinden](<../../images/image (842).png>)

Anhand dessen können Sie sehen, wann die Ausführung in der DLL angehalten wurde, die Sie debuggen möchten.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert werden, und sie zu ändern. Weitere Informationen finden Sie unter:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Front-end-/reverse-engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle mit reverse engineering zusammenhängenden Aufgaben verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Front-end für eine Reihe von Decompilern. Dieser Webservice ermöglicht es Ihnen, die Ausgabe verschiedener Decompiler bei kleinen ausführbaren Dateien zu vergleichen.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **alloziert** den **shellcode** in einem Speicherbereich, **zeigt** Ihnen die **Speicheradresse** an, an der der shellcode alloziert wurde, und **hält** die Ausführung an.\
Anschließend müssen Sie einen **Debugger an den Prozess anhängen** (Ida oder x64dbg), einen **Breakpoint an der angegebenen Speicheradresse setzen** und die Ausführung **fortsetzen**. Auf diese Weise debuggen Sie den shellcode.

Die GitHub-Releases-Seite enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Eine leicht modifizierte Version von Blobrunner finden Sie unter folgendem Link. Um sie zu kompilieren, müssen Sie lediglich **ein C/C++-Projekt in Visual Studio Code erstellen, den Code kopieren und einfügen und das Projekt erstellen**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)ist blobrunner sehr ähnlich. Es **alloziert** den **shellcode** in einem Speicherbereich und startet eine **Endlosschleife**. Anschließend müssen Sie den **Debugger an den Prozess anhängen**, **play start wait 2-5 secs and press stop**. Sie befinden sich dann innerhalb der **Endlosschleife**. Springen Sie zur nächsten Anweisung der Endlosschleife, da es sich dabei um einen Aufruf des shellcodes handelt. Schließlich führen Sie den shellcode aus.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it ist blobrunner sehr ähnlich. Es alloziert den shellcode in einem Speicherbereich und startet eine...](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it finden Sie auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter können Sie den shellcode emulieren und dynamisch untersuchen.

Beachten Sie, dass Cutter **Open File** und **Open Shellcode** anbietet. In meinem Fall wurde der shellcode korrekt dekompiliert, wenn ich ihn als Datei geöffnet habe. Wenn ich ihn jedoch als shellcode geöffnet habe, war dies nicht der Fall:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Beachten Sie, dass Cutter "Open File" und "Open Shellcode" anbietet. In meinem Fall wurde der shellcode korrekt dekompiliert, wenn ich ihn als Datei geöffnet habe...](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setzen Sie dort einen bp. Offenbar startet Cutter die Emulation anschließend automatisch an dieser Stelle:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Um die Emulation an der gewünschten Stelle zu starten, setzen Sie dort einen bp. Offenbar startet Cutter die Emulation anschließend automatisch...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Um die Emulation an der gewünschten Stelle zu starten, setzen Sie dort einen bp. Offenbar startet Cutter die Emulation anschließend automatisch...](<../../images/image (387).png>)

Sie können beispielsweise den Stack innerhalb eines Hex-Dumps anzeigen:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Sie können beispielsweise den Stack innerhalb eines Hex-Dumps anzeigen](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Sie sollten [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Es zeigt Ihnen beispielsweise, **welche Funktionen** der shellcode verwendet und ob der shellcode sich im Speicher **selbst decodiert**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg verfügt auch über einen grafischen Launcher, in dem Sie die gewünschten Optionen auswählen und den shellcode ausführen können

![Debugging von shellcode mit Cutter - Deobfuscation von shellcode und Ermittlung ausgeführter Funktionen: scDbg verfügt auch über einen grafischen Launcher, in dem Sie die gewünschten Optionen auswählen und den...](<../../images/image (258).png>)

Die Option **Create Dump** erstellt einen Dump des finalen shellcode, wenn der shellcode dynamisch im Speicher verändert wird (nützlich zum Herunterladen des deobfuskierten shellcode). Der **start offset** kann nützlich sein, um den shellcode an einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den shellcode über das scDbg-Terminal zu debuggen (ich finde jedoch, dass sich dafür jede der zuvor erklärten Optionen besser eignet, da Sie Ida oder x64dbg verwenden können).

### Disassemblieren mit CyberChef

Laden Sie Ihre shellcode-Datei als Input hoch und verwenden Sie das folgende Rezept, um sie zu dekompilieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuscation von MBA obfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, shifts) kombinieren. Der wichtige Punkt ist, dass diese Identitäten normalerweise nur unter **arithmetischer Modulo-Rechnung mit fester Bitbreite** korrekt sind, sodass Carries und Overflows eine Rolle spielen:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kannst du leicht ein falsches Ergebnis erhalten, da die Bitbreiten-Semantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite** aus dem gelifteten Code/IR/Decompiler-Output (`8/16/32/64` Bits) bei.
2. **Klassifiziere den Ausdruck**, bevor du versuchst, ihn zu vereinfachen:
- **Linear**: gewichtete Summen bitweiser Atome
- **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
- **Polynomial**: Produkte sind vorhanden
- **Gemischt**: Produkte und bitweise Logik sind miteinander verschachtelt, häufig mit wiederholten Teilausdrücken
3. **Verifiziere jede mögliche Umschreibung** durch zufällige Tests oder einen SMT-Beweis. Wenn die Äquivalenz nicht bewiesen werden kann, behalte den ursprünglichen Ausdruck bei, anstatt zu raten.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Simplifier für Malware-Analyse und Protected-Binary-Reversing. Das Tool klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, statt auf alles einen einzigen generischen Rewrite-Pass anzuwenden.<sup>[[2]](#references)</sup>

Kurzverwendung:
```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```
Nützliche Fälle:

- **Linear MBA**: CoBRA wertet den Ausdruck auf booleschen Eingaben aus, leitet eine Signatur ab und lässt mehrere Recovery-Methoden wie Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation gegeneinander antreten.
- **Semilinear MBA**: Constant-masked atoms werden mit einer bit-partitionierten Rekonstruktion neu aufgebaut, sodass maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Subexpressions können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel für eine häufig lohnende Mixed-Identity, die wiederhergestellt werden kann:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dies lässt sich verkürzen zu:
```c
x * y
```
### Reversing-Notizen

- Führe CoBRA bevorzugt auf **lifted IR expressions** oder der Decompiler-Ausgabe aus, nachdem du die exakte Berechnung isoliert hast.
- Verwende `--bitwidth` explizit, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt benötigst, sieh dir die lokalen Z3-Notizen hier an:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM pass plugin** (`libCobraPass.so`) ausgeliefert. Das ist nützlich, wenn du MBA-lastige LLVM IR vor nachfolgenden Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte carry-sensitive mixed-domain residuals sollten als Signal behandelt werden, den ursprünglichen Ausdruck beizubehalten und den carry path manuell zu analysieren.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator **modifiziert alle Instruktionen für `mov`** (ja, wirklich cool). Er verwendet außerdem Unterbrechungen, um Ausführungsabläufe zu verändern. Weitere Informationen zu seiner Funktionsweise:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Wenn du Glück hast, wird [demovfuscator](https://github.com/kirschju/demovfuscator) das Binary deobfuskieren. Es hat mehrere Abhängigkeiten.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Und [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **entry point** zu finden, durchsuche die Funktionen nach `::main`, wie in:

![Movfuscator - Rust: Um den entry point zu finden, durchsuche die Funktionen nach ::main, wie in](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main function ist.\
Suche anhand des **Namens** der aufgerufenen **Funktionen** im **Internet**, um mehr über deren **inputs** und **outputs** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binaries werden viele statische Strings nicht als C-style NUL-terminierte Pointer referenziert. Ein übliches `rustc`-Layout ist ein **Pointer/Length-Tuple** innerhalb von **`.data.rel.ro`**, das auf den eigentlichen String-Blob in **`.rodata`** zeigt:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Strings zusammenführen oder Cross-References vollständig übersehen kann.<sup>[[3]](#references)</sup>

Schneller Workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Enumeriere **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen String-Zeiger.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (beispielsweise Längen zwischen **4** und **100** Bytes berücksichtigen).
6. Lies genau `length` Bytes aus `.rodata`, anstatt bis `0x00` zu scannen.

Minimale Extraktionslogik:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Dies ist beim Reversing von Firmware besonders nützlich, da wiederhergestellte Rust-Strings häufig **HTTP-Routen, RPC-Namen, Log-Meldungen, Assertions, Dateinamen, Config-Keys, Command-Handler und Auth-bezogene Logik** offenlegen.

Wenn Ghidra diese Strings nicht erkennt, führe ein benutzerdefiniertes Script/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um diese Idee an andere **Wortbreiten, Endianness und Section-Layouts** anzupassen.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Für kompilierte Delphi-Binaries kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du ein Delphi-Binary reverse musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) zu verwenden.

Drücke einfach **ATL+f7** (Python-Plugin in IDA importieren) und wähle das Python-Plugin aus.

Dieses Plugin führt das Binary aus und löst die Funktionsnamen zu Beginn des Debugging dynamisch auf. Nachdem du das Debugging gestartet hast, drücke erneut den Start-Button (den grünen oder f9), woraufhin ein Breakpoint am Anfang des eigentlichen Codes erreicht wird.

Es ist außerdem sehr interessant, da der Debugger beim Drücken eines Buttons in der grafischen Anwendung in der von diesem Button ausgeführten Funktion anhält.

## Golang

Wenn du ein Golang-Binary reverse musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) zu verwenden.

Drücke einfach **ATL+f7** (Python-Plugin in IDA importieren) und wähle das Python-Plugin aus.

Dadurch werden die Namen der Funktionen aufgelöst.

## Kompiliertes Python

Auf dieser Seite findest du Informationen dazu, wie du den Python-Code aus einem kompilierten ELF/EXE-Python-Binary erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Wenn du das **Binary** eines GBA-Spiels erhältst, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Interface
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), unter _**Options --> Emulation Setup --> Controls**_** ** kannst du sehen, wie die Game-Boy-Advance-**Buttons** gedrückt werden.

![no$gba-Konfiguration der Steuerung mit den Game-Boy-Advance-Button-Zuordnungen](<../../images/image (581).png>)

Beim Drücken erhält jeder **Key einen Wert**, durch den er identifiziert werden kann:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
In dieser Art von Programm wird der interessante Teil darin bestehen, **wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** finden Sie die häufig anzutreffende Funktion: **KEYINPUT**.

![Ghidra-Ansicht einer GBA-Binärdatei mit einem Verweis auf KEYINPUT an der Adresse 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild sehen Sie, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion, nach einigen Initialisierungsoperationen (ohne Bedeutung):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Dieser Code wurde gefunden:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Die letzte **`if`-Bedingung** prüft, ob **`uVar4`** in den letzten **Keys** enthalten und nicht der aktuelle Key ist, also ob eine Taste losgelassen wird (der aktuelle Key wird in **`uVar1`** gespeichert).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Im vorherigen Code ist zu sehen, dass wir **uVar1** (die Stelle, an der sich der **Wert des gedrückten Buttons** befindet) mit einigen Werten vergleichen:

- Zuerst wird er mit dem **Wert 4** (**SELECT** button) verglichen: In der Challenge löscht dieser Button den Bildschirm.
- Danach wird er mit dem **Wert 8** (**START** button) verglichen: In der Challenge wird hier geprüft, ob der Code gültig ist, um die Flag zu erhalten.
- In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Wenn der Wert identisch ist, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein bestimmter Zähler (**`DAT_030000d4`**) geprüft. Es handelt sich um einen Zähler, da direkt nach dem Eingeben des Codes 1 addiert wird.\
**W**enn der Wert kleiner als 8 ist, wird etwas ausgeführt, das Werte zu **`DAT_030000d8`** addiert (im Grunde werden die Werte der gedrückten Tasten zu dieser Variable addiert, solange der Zähler kleiner als 8 ist).

Für diese Challenge musste man also, wenn man die Werte der Buttons kannte, **eine Kombination mit einer Länge von weniger als 8 drücken, deren resultierende Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binäre Deobfuskation)

## Referenzen

- [1] [MBA-Obfuskation mit CoBRA vereinfachen](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings decodieren - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
