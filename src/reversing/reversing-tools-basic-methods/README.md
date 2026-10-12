# Reversing-Tools & grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## ImGui-basierte Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows-Kernel-Debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-Decompiler / Wat-Compiler

Online:

- Verwende [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (binär) zu wat (Klartext) zu **dekompilieren**
- Verwende [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um von wat zu wasm zu **kompilieren**
- Du kannst zur Dekompilierung auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) ausprobieren.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-Bytecode-Cache

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualisierte Payloads und benutzerdefinierte VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET-Decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der mehrere Formate **dekompiliert und untersucht**, darunter **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **ausführbare Dateien** (.exe). Nach der Dekompilierung kann eine Assembly als Visual-Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil dabei ist, dass sich verlorener Quellcode, der aus einer älteren Assembly wiederhergestellt werden muss, so schneller rekonstruieren lässt. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der perfekten Tools für die **Analyse von Xamarin-Algorithmen**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool genau an deine Bedürfnisse anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die zahlreichen Reverse-Engineering-Funktionen dieses Tools an:

- Bietet Einblick in den Datenfluss durch eine Bibliothek oder Komponente
- Bietet Einblick in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, damit du mehr aus den verwendeten APIs und Technologien herausholen kannst.
- Findet Abhängigkeiten und verschiedene Assemblies
- Ermittelt die genaue Stelle von Fehlern in deinem Code, in Komponenten von Drittanbietern und in Bibliotheken.
- Ermöglicht das Debuggen im Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem Betriebssystem verwenden (du kannst es direkt über VSCode installieren; ein Download von git ist nicht erforderlich. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du **dekompilieren**, **ändern** und anschließend erneut **kompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon verwenden: [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### DNSpy-Logging

Um **DNSpy einige Informationen in einer Datei protokollieren zu lassen**, kannst du dieses Snippet verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly-Attribute** ändern, die sich auf **Debugging** beziehen:

![DNSpy Logging - DNSpy Debugging: Ändere zuerst die Assembly-Attribute, die sich auf Debugging beziehen](<../../images/image (973).png>)

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

Und klicke auf **compile**:

![DNSpy Logging - DNSpy Debugging: Und klicke auf compile](<../../images/image (314) (1).png>)

Speichere dann die neue Datei über _**Datei >> Modul speichern...**_:

![DNSpy Logging - DNSpy Debugging: Speichere dann die neue Datei über Datei Modul speichern](<../../images/image (602).png>)

Das ist notwendig, denn wenn du das nicht tust, werden zur **Laufzeit** verschiedene **Optimierungen** auf den Code angewendet. Dadurch kann es passieren, dass beim Debuggen ein **Breakpoint nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn deine .NET-Anwendung von **IIS** **ausgeführt** wird, kannst du sie folgendermaßen **neu starten**:

```
iisreset /noforce
```

Dann sollten Sie zunächst alle geöffneten Dateien schließen. Wählen Sie anschließend im **Debug-Tab** die Option **Attach to Process...** aus:

![DNSpy Logging - DNSpy Debugging: Schließen Sie zunächst alle geöffneten Dateien. Wählen Sie anschließend im Debug-Tab die Option Attach to Process aus, um das Debugging zu starten](<../../images/image (318).png>)

Wählen Sie **w3wp.exe** aus, um eine Verbindung zum **IIS-Server** herzustellen, und klicken Sie auf **Attach**:

![DNSpy Logging - DNSpy Debugging: Wählen Sie w3wp.exe aus, um eine Verbindung zum IIS-Server herzustellen, und klicken Sie auf Attach](<../../images/image (113).png>)

Nachdem wir den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicken Sie zuerst auf _Debug >> Break All_ und anschließend auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Nachdem wir den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicken Sie zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Nachdem wir den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicken Sie zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (834).png>)

Klicken Sie unter **Modules** auf ein beliebiges Modul und wählen Sie **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicken Sie unter Modules auf ein beliebiges Modul und wählen Sie Open All Modules aus](<../../images/image (922).png>)

Klicken Sie im **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und wählen Sie **Sort Assemblies** aus:

![DNSpy Logging - DNSpy Debugging: Klicken Sie im Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und wählen Sie Sort Assemblies aus](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### Mit IDA

- **Rundll32 laden** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Den **Windbg**-Debugger auswählen
- "**Suspend on library load/unload**" auswählen

![Debugging DLLs - Mit IDA: Wählen Sie " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Die **Parameter** der Ausführung konfigurieren und dabei den **Pfad zur DLL** sowie die aufzurufende Funktion angeben:

![Debugging DLLs - Mit IDA: Konfigurieren Sie die Parameter der Ausführung und geben Sie den Pfad zur DLL sowie die aufzurufende Funktion an](<../../images/image (704).png>)

Wenn Sie dann das Debugging starten, **wird die Ausführung angehalten, sobald eine DLL geladen wird**. Wenn rundll32 Ihre DLL lädt, wird die Ausführung also angehalten.

Diese Methode hält bei Ereignissen zum Laden von Modulen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist damit jedoch weniger direkt als mit dem unten beschriebenen x64dbg-Workflow.

### Mit x64dbg/x32dbg

- **Rundll32 laden** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Die **Befehlszeile ändern** ( _File --> Change Command Line_ ) und den Pfad der DLL sowie die aufzurufende Funktion angeben, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Unter _Options --> Settings_ die Option "**DLL Entry**" auswählen.
- Anschließend **die Ausführung starten**. Der Debugger hält bei jedem dll main an. Irgendwann wird er **beim DLL-Einstiegspunkt Ihrer DLL anhalten**. Suchen Sie von dort aus einfach nach den Stellen, an denen Sie einen Breakpoint setzen möchten.

Beachten Sie, dass Sie in win64dbg **oben im win64dbg-Fenster** sehen können, **in welchem Code Sie sich befinden**, wenn die Ausführung aus irgendeinem Grund angehalten wurde:

![Mit IDA - Mit x64dbg/x32dbg: Beachten Sie, dass Sie in win64dbg oben im win64dbg-Fenster sehen können, in welchem Code Sie sich befinden, wenn die Ausführung aus irgendeinem Grund angehalten wurde](<../../images/image (842).png>)

Diese Anzeige bestätigt, wenn die Ausführung innerhalb der DLL angehalten wurde, die Sie debuggen möchten.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels abgelegt sind, und sie zu ändern. Weitere Informationen finden Sie unter:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Frontend-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Reverse-Engineering-Aufgaben verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Frontend für verschiedene Decompiler. Mit diesem Webdienst können Sie die Ausgaben verschiedener Decompiler für kleine ausführbare Dateien vergleichen.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Einen Shellcode mit blobrunner debuggen

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert Speicher für den **Shellcode**, gibt dessen **Speicheradresse** aus und hält die Ausführung an.\
Binden Sie einen Debugger wie IDA oder x64dbg an, setzen Sie an der ausgegebenen Adresse einen Breakpoint und setzen Sie die Ausführung fort, um den Shellcode zu debuggen.

Die GitHub-Releases-Seite enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unter dem folgenden Link finden Sie eine leicht modifizierte Version von Blobrunner. Um sie zu kompilieren, **erstellen Sie einfach ein C/C++-Projekt in Visual Studio Code, kopieren Sie den Code hinein und erstellen Sie das Projekt**.


{{#ref}}
blobrunner.md
{{#endref}}

### Einen Shellcode mit jmp2it debuggen

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) funktioniert ähnlich wie BlobRunner. Es reserviert Speicher für den Shellcode und startet eine Endlosschleife. Binden Sie den Debugger an, setzen Sie die Ausführung für **2–5 Sekunden** fort, halten Sie sie innerhalb dieser Schleife an und gehen Sie dann zum folgenden Aufruf, der die Ausführung an den reservierten Shellcode übergibt.

![Debugger in jmp2its Endlosschleife unmittelbar vor dem Aufruf des reservierten Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it finden Sie auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode mit Cutter debuggen

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter können Sie den Shellcode emulieren und dynamisch untersuchen.

Beachten Sie, dass Cutter die Optionen „Open File“ und „Open Shellcode“ bietet. In meinem Fall wurde der Shellcode korrekt dekompiliert, wenn ich ihn als Datei öffnete, nicht aber, wenn ich ihn als Shellcode öffnete:

![Cutter zeigt unterschiedliche Analyseergebnisse beim Öffnen derselben Bytes als Datei oder als Shellcode](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setzen Sie dort einen bp. Offenbar startet Cutter die Emulation dann automatisch an dieser Stelle:

![Breakpoint am gewünschten Shellcode-Einstiegspunkt setzen, bevor die Cutter-Emulation gestartet wird](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Sie können sich beispielsweise den Stack in einem Hex-Dump ansehen:

![Den Stack des emulierten Shellcodes im Hex-Dump von Cutter anzeigen](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Probieren Sie [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aus.\
Das Tool zeigt beispielsweise, **welche Funktionen** der Shellcode verwendet und ob der Shellcode sich im Speicher selbst **decodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg bietet außerdem einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und den Shellcode ausführen kannst

![Grafischer Launcher von scDbg zum Auswählen von Shellcode-Emulations- und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der finale Shellcode gedumpt, falls er zur Laufzeit im Speicher verändert wird (nützlich, um den dekodierten Shellcode herunterzuladen). Mit **start offset** kannst du den Shellcode ab einem bestimmten Offset starten. Die Option **Debug Shell** ist nützlich, um den Shellcode über das scDbg-Terminal zu debuggen (ich finde allerdings eine der zuvor erklärten Optionen dafür besser, da du dann Ida oder x64dbg verwenden kannst).

### Disassemblieren mit CyberChef

Lade deine Shellcode-Datei als Eingabe hoch und verwende das folgende Rezept, um sie zu dekompilieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskierung von MBA-Obfuskierung

Die **Mixed Boolean-Arithmetic (MBA)**-Obfuskierung verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten in der Regel nur bei **modularer Arithmetik mit fester Bitbreite** gelten, sodass Überträge und Überläufe eine Rolle spielen:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du diese Art von Ausdruck mit allgemeinen Algebra-Tools vereinfachst, kannst du leicht ein falsches Ergebnis erhalten, weil die Bitbreiten-Semantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite bei**, die der geliftete Code/die IR/der Decompiler-Ausgabecode verwendet (`8/16/32/64` Bits).
2. **Ordne den Ausdruck ein**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
   - **Polynomial**: Es kommen Produkte vor
   - **Gemischt**: Produkte und bitweise Logik sind verschachtelt, oft mit wiederholten Teilausdrücken
3. **Überprüfe jede mögliche Umformung** durch zufällige Tests oder einen SMT-Beweis. Wenn die Äquivalenz nicht bewiesen werden kann, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Umgehe abgeflachten Kontrollfluss mit einem engen Ausführungsslice

Die vollständige Rekonstruktion des Kontrollflussgraphen ist oft unnötig. Folge bei Control-Flow-Flattening, opaque predicates, großen Dispatchern oder MBA-lastigem Code den Referenzen von verschlüsselten Blobs und Ausgabepuffern bis zur kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Datenfluss-Slice oder führe ihn unabhängig aus; der Dispatcher gehört nicht zur erforderlichen Lösung, wenn der relevante Zustand direkt initialisiert werden kann.<sup>[[7]](#references)</sup>

Ein praktischer Workflow ist:<sup>[[7]](#references)</sup>

1. Erfasse ausführbare und Datensektionen, Relokationen und Querverweise. Gib mögliche Tabellen aus `.rodata` aus und behalte dabei Byte-Reihenfolge und Elementbreite bei.
2. Ermittle die letzte Routine, die den Klartext- oder Ausgabepuffer beschreibt. Notiere ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und den erforderlichen globalen Zustand.
3. Überführe nur diese Operationen in ein Python-Modell mit fester Bitbreite. Wenn der Slice weiterhin von zu viel Zustand abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, statt das gesamte Programm zu emulieren.
4. Überprüfe, ob der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binärdatei ableitet: Entferne stille Fallbacks, suche darin nach eingebetteten Antworten und teste ihn mit unbekannten Builds, in denen Strings, Schlüssel, Bezeichner, Layouts und Obfuskations-Seeds geändert wurden.

Nützliche Befehle für einen ersten Durchlauf sind:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### MBA-Ausdrücke erkennen, die als Konstanten getarnt sind

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann seine Eingabe vollständig aufheben. Nachdem die Tabellen extrahiert wurden, lässt sich der Ausdruck über den gesamten 8-Bit-Wertebereich auswerten. Eine einelementige Ausgabemenge beweist, dass das Byte konstant ist, ohne dass die umgebende Zustandsmaschine rekonstruiert werden muss.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Behalte die abschließende Maske bei, da die ursprüngliche Addition einen Wraparound auf Bytebreite hat. Frage bei einem größeren Wertebereich einen SMT-Solver, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Umgebungsgebundene Decodierung erkennen

Anti-Analyse-Prüfungen müssen weder einen Branch auslösen noch abstürzen. Ein Decoder kann das Ergebnis eines Sensors in ein Schlüsselbit, eine Konstante eines opaken Prädikats oder den Zustand eines abgeflachten Dispatchers einmischen, normal weiterlaufen und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehler-Branches zu patchen; verfolge die Datenabhängigkeiten von Umgebungsprüfungen bis zum Decoderzustand, vergleiche denselben Ausschnitt auf dem authentischen Gerät und im Emulator und teste, wie sich das Erzwingen jedes Sensorergebnisses auf den endgültigen Puffer auswirkt.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Simplifier für Malware-Analyse und das Reverse Engineering geschützter Binärdateien. Es klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, anstatt auf alles einen allgemeinen Rewrite-Pass anzuwenden.<sup>[[2]](#references)</sup>

Schnelle Verwendung:

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

Nützliche Anwendungsfälle:

- **Linear MBA**: CoBRA wertet den Ausdruck mit booleschen Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden gegeneinander antreten, etwa Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: Constant-masked Atome werden mit bitpartitionierter Rekonstruktion neu aufgebaut, damit maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel einer gemischten Identität, deren Wiederherstellung sich oft lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich reduzieren auf:

```c
x * y
```

### Hinweise zum Reverse Engineering

- CoBRA am besten auf **angehobenen IR-Ausdrücken** oder Decompiler-Ausgaben ausführen, nachdem du die genaue Berechnung isoliert hast.
- `--bitwidth` explizit angeben, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt brauchst, sieh dir die lokalen Z3-Hinweise hier an:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA gibt es auch als **LLVM-Pass-Plugin** (`libCobraPass.so`). Es ist nützlich, wenn du MBA-lastiges LLVM IR vor späteren Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte, carry-sensitive Residuen mit gemischten Wertebereichen sind ein Hinweis darauf, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell zu analysieren.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch `mov`-basierte Instruktionssequenzen und verwendet Signal-/Exception-Handling, um den Kontrollfluss zu verändern. Weitere Details:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Bei unterstützten Binärdateien kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuskieren. Dafür werden mehrere Abhängigkeiten benötigt.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Und [installiere keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du ein **CTF spielst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **Einstiegspunkt** zu finden, durchsuche die Funktionen nach `::main`, wie hier:

![Einen Rust-Einstiegspunkt in Ghidra finden, indem Funktionsnamen nach doppeltem Doppelpunkt und main durchsucht werden](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Suche im **Internet** nach den **Namen** der aufgerufenen **Funktionen**, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binaries werden viele statische Strings nicht über C-Style, NUL-terminierte Pointer referenziert. Ein gängiges `rustc`-Layout ist ein **Pointer-/Längen-Tupel** in **`.data.rel.ro`**, das auf den tatsächlichen String-Blob in **`.rodata`** verweist:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Zeichenketten zusammenführen oder Querverweise vollständig übersehen kann.<sup>[[3]](#references)</sup>

Schneller Arbeitsablauf:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Durchlaufe **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen Zeiger auf einen String.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (behalte zum Beispiel Längen zwischen **4** und **100** Bytes).
6. Lies genau `length` Bytes aus `.rodata`, statt bis `0x00` zu scannen.

Minimale Extractor-Logik:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Das ist besonders nützlich beim Firmware-Reversing, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Konfigurationsschlüssel, Command-Handler und Auth-bezogene Logik** offenlegen.

Wenn Ghidra diese Strings übersieht, führe ein benutzerdefiniertes Skript/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **Wortgrößen, Endianness und Abschnittslayouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du eine Delphi-Binärdatei reverse-engineeren musst, empfehle ich das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi).

Drücke in IDA **Alt+F7**, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dieses Plugin führt die Binärdatei aus und löst zu Beginn des Debuggings dynamisch Funktionsnamen auf. Starte nach Beginn des Debuggings erneut mit der Start-Schaltfläche (der grünen oder f9); dann wird am Anfang des echten Codes ein Breakpoint ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche klickst, kann der Debugger in der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Bei gewöhnlichen Go-Binärdateien kann [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) Runtime-Strukturen wiederherstellen und Funktionsnamen in IDA verbessern. Lade das Python-Plugin mit **Alt+F7**.

### Metadaten ohne Symboltabelle wiederherstellen

Auch eine gestripte Go-Executable benötigt Runtime-Metadaten, um Program Counter Funktionen zuzuordnen. [GoReSym](https://github.com/mandiant/GoReSym) findet und parst mithilfe von Code, der aus der Go-Runtime abgeleitet wurde, Strukturen wie `pclntab` und `moduledata`. Dadurch lassen sich Funktionsgrenzen, Namen, Quellpfade, Typen und Build-Details wiederherstellen, ohne auf die herkömmliche Symboltabelle angewiesen zu sein.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ein Obfuscator kann diese Strukturen weiterhin nutzbar lassen und gleichzeitig die wiederhergestellten Namen ersetzen. Garble hasht beispielsweise Bezeichner und Paketpfade und entfernt Build-, Modul- und Debug-Informationen.<sup>[[12]](#references)</sup> Das obfuskierte Paket-Token muss für Funktionen aus diesem Paket konsistent bleiben. Gruppiere Funktionen nach dem wiederholt auftretenden Token, leite anhand der aufgerufenen Funktionen, Strings und APIs ein Paket ab und weise anschließend der gesamten Gruppe dieses Paketlabel zu.<sup>[[13]](#references)</sup>

### Garble-Namen mit GoResolver wiederherstellen

[GoResolver](https://github.com/volexity/GoResolver) kombiniert die Extraktion von Laufzeitsymbolen mit der Generierung sauberer Referenzen und dem Abgleich von Kontrollflussgraphen (CFGs). Gehe dabei wie folgt vor:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler-Version ermitteln.** Prüfe zuerst `BuildInfo` und eingebettete Versionsstrings. Falls der Obfuscator diese entfernt hat, vergleiche Teile der gebündelten Go-Runtime mit versionierten Referenz-Runtimes. In den Tests von Volexity reichten etwa `2%` der Runtime aus, um die Hauptversionen von Go zu unterscheiden. Betrachte dies als empirische Optimierung, nicht als allgemeingültigen Schwellenwert.<sup>[[13]](#references)</sup>
2. **Passende Referenzen erstellen.** Erzeuge saubere Binaries für die ermittelte Go-Version, die Zielarchitektur und wahrscheinliche Bibliotheken. Eine übereinstimmende Toolchain verringert Unterschiede in den vom Compiler generierten CFGs.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Funktionen vergleichen.** GoGrapher gleicht Funktions-CFGs ab und gibt normalisierte Werte zwischen `0.0` und `1.0` aus. Der Abgleich der Basic Blocks basiert auf einem gewichteten Vergleich ähnlicher Instruktionen. Zuverlässige Treffer ordnen randomisierten Funktionen die saubere Implementierung zu. Weniger zuverlässige Treffer können dennoch ein Paket oder Modul identifizieren.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validieren und importieren.** Bestätige vorgeschlagene Namen anhand von Aufrufbeziehungen, Konstanten, Strings und Seiteneffekten und importiere anschließend den JSON-Bericht mit dem GoResolver-Plugin für IDA oder Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installiere die Toolchain und führe den kombinierten Extractor und Graph Matcher aus:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Der standardmäßige Schwellenwert für signifikante Treffer ist `0.9`. Mit den Optionen `--extract` und `--graph` lässt sich jeweils eine der beiden Phasen isoliert ausführen. Standardmäßig werden beide ausgeführt, da sich die wiederhergestellten Laufzeitmetadaten und die CFG-Belege ergänzen.<sup>[[10]](#references)</sup> CFG-Scores sind heuristisch: Inlining, Build-Flags, Architektur und Unterschiede zwischen Bibliotheksversionen können die Graphstruktur verändern. Behalte daher nicht aufgelöste Funktionen bei, statt ihnen Namen mit geringer Konfidenz zuzuweisen.<sup>[[13]](#references)</sup>

## Compiled Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einer kompilierten ELF-/EXE-Python-Binärdatei erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du die **Binärdatei** eines GBA-Spiels erhältst, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Die Debug-Version herunterladen_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_** ** sehen, wie sich die Game-Boy-Advance-**Tasten** betätigen lassen

![no$gba-Konfiguration der Steuerelemente mit den Belegungen der Game-Boy-Advance-Tasten](<../../images/image (581).png>)

Beim Drücken hat jede **Taste einen Wert**, anhand dessen sie identifiziert werden kann:

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

In dieser Art von Programm ist also interessant, **wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** finden Sie die häufig anzutreffende Funktion: **KEYINPUT**.

![Ghidra-Ansicht einer GBA-Binärdatei mit Verweis auf KEYINPUT an Adresse 0x4000130](<../../images/image (447).png>)

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

Dabei wurde folgender Code gefunden:

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

Die letzte if-Abfrage prüft, ob **`uVar4`** in den **letzten Keys** enthalten und nicht die aktuelle Taste ist. Das bedeutet, dass eine Taste losgelassen wird (die aktuelle Taste wird in **`uVar1`** gespeichert).

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

Im vorherigen Code sehen Sie, dass **uVar1** (die Stelle, an der sich der **Wert der gedrückten Taste** befindet) mit einigen Werten verglichen wird:

- Zuerst wird es mit dem **Wert 4** (der **SELECT**-Taste) verglichen: In der Challenge löscht diese Taste den Bildschirm.
- Dann wird der Wert mit **8** (der **START**-Taste) verglichen; in dieser Challenge wird in diesem Pfad geprüft, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen, und wenn der Wert übereinstimmt, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und erhöht.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

In dieser Challenge mussten Sie also, da Ihnen die Werte der Tasten bekannt waren, **eine Kombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [archivierter Write-up zur Nostalgia-Challenge](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary-Deobfuskation)

## References

- [1] [MBA-Verschleierung mit CoBRA vereinfachen](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [CoBRA-Repository von Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings entschlüsseln - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-gestütztes Reverse Engineering schlagen – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Ein Ansatz zum Vergleich von Kontrollflussgraphen anhand des Abgleichs grundlegender Blöcke](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-Verschleierungsmechanismus](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Verwendung der Ähnlichkeit von Kontrollflussgraphen zur automatischen Deobfuskation von Go-Binärdateien](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
