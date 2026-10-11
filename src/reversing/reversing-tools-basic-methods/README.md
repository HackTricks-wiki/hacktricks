# Reversing-Tools & grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## Auf ImGui basierende Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows-Kernel-Debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-Decompiler / Wat-Compiler

Online:

- Verwende [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (Binärdatei) zu wat (Klartext) zu **dekompilieren**
- Verwende [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um von wat zu wasm zu **kompilieren**
- Für die Dekompilierung kannst du auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) ausprobieren.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-Bytecode-Cache

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET-Decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der mehrere Formate **dekompiliert und untersucht**, darunter **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **ausführbare Dateien** (.exe). Eine dekompilierte Assembly lässt sich als Visual-Studio-Projekt (.csproj) speichern.

Der Vorteil: Wenn verlorener Quellcode aus einer älteren Assembly wiederhergestellt werden muss, kann das Zeit sparen. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der idealen Tools für die **Xamarin-Algorithmusanalyse.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, mit der sich das Tool genau an deine Anforderungen anpassen lässt, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Werfen wir einen Blick auf die zahlreichen Reverse-Engineering-Funktionen dieses Tools:

- Gibt Einblick in den Datenfluss durch eine Bibliothek oder Komponente
- Gibt Einblick in die Implementierung und Nutzung von .NET-Sprachen und -Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, damit du mehr aus den verwendeten APIs und Technologien herausholen kannst.
- Findet Abhängigkeiten und verschiedene Assemblies
- Spürt die genaue Stelle von Fehlern in deinem Code, in Komponenten von Drittanbietern und in Bibliotheken auf.
- Ermöglicht das Debugging im Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem Betriebssystem verwenden (du kannst es direkt in VSCode installieren, ein Download des Git-Repositories ist nicht nötig. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du erneut **dekompilieren**, **ändern** und **kompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### DNSpy-Protokollierung

Um **DNSpy einige Informationen in eine Datei protokollieren zu lassen**, kannst du dieses Snippet verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly-Attribute** für das **Debugging** ändern:

![DNSpy Logging - DNSpy Debugging: Zuerst die Assembly-Attribute für das Debugging ändern](<../../images/image (973).png>)

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

Speichere dann die neue Datei über _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Speichere dann die neue Datei über File Save module](<../../images/image (602).png>)

Das ist notwendig, denn wenn du das nicht machst, werden zur **Laufzeit** mehrere **Optimierungen** auf den Code angewendet. Dadurch kann es passieren, dass beim Debuggen ein **Haltepunkt nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn deine .NET-Anwendung von **IIS** **ausgeführt** wird, kannst du sie anschließend mit folgendem Befehl **neu starten**:

```
iisreset /noforce
```

Dann solltest du, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Um mit dem Debugging zu beginnen, solltest du alle geöffneten Dateien schließen und im Debug Tab Attach to Process auswählen](<../../images/image (318).png>)

Wähle anschließend **w3wp.exe** aus, um eine Verbindung zum **IIS server** herzustellen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle w3wp.exe aus, um eine Verbindung zum IIS server herzustellen, und klicke auf attach](<../../images/image (113).png>)

Da wir nun den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Da wir nun den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Da wir nun den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (834).png>)

Klicke unter **Modules** auf ein beliebiges Modul und wähle **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicke unter Modules auf ein beliebiges Modul und wähle Open All Modules aus](<../../images/image (922).png>)

Klicke im **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und dann auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Klicke im Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und dann auf Sort Assemblies](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### Mit IDA

- **rundll32 laden** (64 Bit unter C:\Windows\System32\rundll32.exe und 32 Bit unter C:\Windows\SysWOW64\rundll32.exe)
- Den **Windbg**-Debugger auswählen
- "**Suspend on library load/unload**" auswählen

![Debugging DLLs - Using IDA: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Die **Parameter** der Ausführung konfigurieren, indem du den **Pfad zur DLL** und die aufzurufende Funktion angibst:

![Debugging DLLs - Using IDA: Konfiguriere die Parameter der Ausführung, indem du den Pfad zur DLL und die aufzurufende Funktion angibst](<../../images/image (704).png>)

Wenn du dann mit dem Debugging beginnst, **wird die Ausführung beim Laden jeder DLL angehalten**. Sobald rundll32 deine DLL lädt, wird die Ausführung angehalten.

Diese Methode hält bei Modul-Ladeereignissen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist jedoch weniger direkt als mit dem unten beschriebenen x64dbg-Workflow.

### Mit x64dbg/x32dbg

- **rundll32 laden** (64 Bit unter C:\Windows\System32\rundll32.exe und 32 Bit unter C:\Windows\SysWOW64\rundll32.exe)
- Die **Command Line ändern** ( _File --> Change Command Line_ ) und den Pfad der DLL sowie die aufzurufende Funktion angeben, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Unter _Options --> Settings_ **"DLL Entry"** auswählen.
- Dann **die Ausführung starten**. Der Debugger hält bei jedem DLL-Main an. Irgendwann hält er beim DLL-Einstiegspunkt deiner DLL an. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte: Wenn die Ausführung aus irgendeinem Grund in win64dbg angehalten wird, kannst du oben im **win64dbg-Fenster** sehen, **in welchem Code du dich befindest**:

![Using IDA - Using x64dbg/x32dbg: Beachte: Wenn die Ausführung aus irgendeinem Grund in win64dbg angehalten wird, kannst du oben im win64dbg-Fenster sehen, in welchem Code du dich befindest](<../../images/image (842).png>)

Diese Anzeige bestätigt, dass die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern. Weitere Informationen:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Frontend-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Aufgaben im Zusammenhang mit Reverse Engineering verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein webbasiertes Frontend für verschiedene Decompiler. Mit diesem Webdienst kannst du die Ausgabe verschiedener Decompiler für kleine ausführbare Dateien vergleichen.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Einen Shellcode mit blobrunner debuggen

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert Speicher für den **Shellcode**, gibt dessen **Speicheradresse** aus und hält die Ausführung an.\
Verbinde einen Debugger wie IDA oder x64dbg, setze einen Breakpoint an der ausgegebenen Adresse und setze die Ausführung fort, um den Shellcode zu debuggen.

Die GitHub-Releases-Seite enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unter folgendem Link findest du eine leicht modifizierte Version von Blobrunner. Um sie zu kompilieren, **erstelle einfach ein C/C++-Projekt in Visual Studio Code, kopiere den Code hinein und erstelle den Build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Einen Shellcode mit jmp2it debuggen

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) ähnelt BlobRunner. Es reserviert Speicher für den Shellcode und tritt in eine Endlosschleife ein. Verbinde den Debugger, setze die Ausführung für **2–5 Sekunden** fort, halte sie innerhalb dieser Schleife an und gehe dann schrittweise zum nächsten Aufruf, der die Ausführung an den reservierten Shellcode übergibt.

![Debugger in jmp2its Endlosschleife direkt vor dem Aufruf des reservierten Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it findest du auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode mit Cutter debuggen

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter **"Open File"** und **"Open Shellcode"** unterstützt. In meinem Fall wurde der Shellcode korrekt dekompiliert, wenn ich ihn als Datei öffnete, nicht aber, wenn ich ihn als Shellcode öffnete:

![Cutter zeigt unterschiedliche Analyseergebnisse, wenn dieselben Bytes als Datei oder als Shellcode geöffnet werden](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen bp. Offenbar startet Cutter die Emulation dann automatisch an dieser Stelle:

![Breakpoint am gewünschten Shellcode-Einstiegspunkt setzen, bevor die Cutter-Emulation gestartet wird](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Du kannst zum Beispiel den Stack in einem Hex-Dump anzeigen lassen:

![Den Stack des emulierten Shellcodes im Hex-Dump von Cutter anzeigen](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Das Tool zeigt dir unter anderem, **welche Funktionen** der Shellcode verwendet und ob er sich im Speicher **selbst decodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg bietet außerdem einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und den Shellcode ausführen kannst

![Grafischer Launcher von scDbg zum Auswählen der Shellcode-Emulation und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der finale Shellcode ausgegeben, wenn der Shellcode dynamisch im Speicher verändert wird (nützlich, um den decodierten Shellcode herunterzuladen). Der **start offset** kann nützlich sein, um den Shellcode ab einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den Shellcode mit dem scDbg-Terminal zu debuggen (ich finde jedoch eine der zuvor erläuterten Optionen dafür besser, da du Ida oder x64dbg verwenden kannst).

### Disassemblieren mit CyberChef

Lade deine Shellcode-Datei als Eingabe hoch und verwende das folgende Rezept, um sie zu dekompilieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA-Obfuskation deobfuskieren

**Mixed Boolean-Arithmetic (MBA)**-Obfuskation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) mit bitweisen Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten in der Regel nur unter **Modulararithmetik fester Breite** korrekt sind, weshalb Überträge und Überläufe eine Rolle spielen:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kann das leicht zu einem falschen Ergebnis führen, weil die Bitbreitensemantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite bei**, die aus dem gelifteten Code/IR/Decompiler-Output hervorgeht (`8/16/32/64` Bit).
2. **Ordne den Ausdruck ein**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
   - **Polynomiell**: Produkte treten auf
   - **Gemischt**: Produkte und bitweise Logik sind miteinander verschachtelt, oft mit wiederholten Teilausdrücken
3. **Verifiziere jede mögliche Umformung** durch zufällige Tests oder einen SMT-Beweis. Wenn die Äquivalenz nicht bewiesen werden kann, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Umgehe abgeflachte Kontrollflüsse mit einem schmalen Ausführungsslice

Die Wiederherstellung des vollständigen Kontrollflussgraphen ist oft unnötig. Folge bei Control-Flow Flattening, opaken Prädikaten, großen Dispatchern oder MBA-lastigem Code den Referenzen von verschlüsselten Blobs und Ausgabepuffern bis zur kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Datenfluss-Slice oder führe ihn unabhängig aus; der Dispatcher ist für die erforderliche Lösung nicht relevant, wenn sich der relevante Zustand direkt initialisieren lässt.<sup>[[7]](#references)</sup>

Ein praktischer Workflow sieht so aus:<sup>[[7]](#references)</sup>

1. Erstelle eine Bestandsaufnahme der ausführbaren und Datensektionen, Relokationen und Querverweise. Dump mögliche Tabellen aus `.rodata` und behalte dabei Byte-Reihenfolge und Elementbreite bei.
2. Ermittle die letzte Routine, die den Klartext- oder Ausgabepuffer beschreibt. Notiere ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und den erforderlichen globalen Zustand.
3. Übertrage nur diese Operationen in ein Python-Modell mit fester Bitbreite. Wenn der Slice noch von zu viel Zustand abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, statt das ganze Programm zu emulieren.
4. Überprüfe, dass der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binärdatei ableitet: Entferne stille Fallbacks, durchsuche sie nach eingebetteten Antworten und führe ihn mit unbekannten Builds aus, bei denen Strings, Schlüssel, Bezeichner, Layouts und Obfuskations-Seeds geändert wurden.

Nützliche Befehle für die erste Analyse sind:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Versteckte Konstanten in MBA-Ausdrücken erkennen

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann sich vollständig von seiner Eingabe unabhängig aufheben. Nachdem die Tabellen extrahiert wurden, werte den Ausdruck über dem vollständigen 8-Bit-Wertebereich aus; eine einelementige Ausgabemenge beweist, dass das Byte konstant ist, ohne die umgebende Zustandsmaschine rekonstruieren zu müssen.<sup>[[7]](#references)</sup>

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

Behalte die abschließende Maske bei, da die ursprüngliche Addition einen Wraparound auf Bytebreite verursacht. Frage für einen größeren Wertebereich einen SMT-Solver, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Umgebungsabhängige Decodierung erkennen

Anti-Analyse-Prüfungen müssen nicht verzweigen oder abstürzen. Ein Decoder kann ein Sensorergebnis in ein Schlüsselbit, eine opaque-predicate-Konstante oder den Zustand eines flattened dispatchers einmischen, normal fortfahren und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehlerzweige zu patchen. Verfolge stattdessen die Datenabhängigkeiten von Umgebungsprüfungen bis in den Decoderzustand, vergleiche denselben Ausschnitt auf dem echten Gerät und im Emulator und teste, wie sich das Erzwingen jedes Sensorergebnisses auf den finalen Puffer auswirkt.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Vereinfacher für Malware-Analysen und das Reverse Engineering geschützter Binaries. Es klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, anstatt auf alles denselben allgemeinen Rewrite-Pass anzuwenden.<sup>[[2]](#references)</sup>

Kurzanleitung:

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

- **Linear MBA**: CoBRA wertet den Ausdruck mit booleschen Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden parallel gegeneinander antreten, etwa Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: Atome mit konstanten Masken werden mithilfe einer bitpartitionierten Rekonstruktion wiederhergestellt, sodass maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel für eine gemischte Identität, deren Wiederherstellung sich häufig lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich zusammenfassen zu:

```c
x * y
```

### Hinweise zum Reversing

- CoBRA am besten auf **gelifteten IR-Ausdrücken** oder Decompiler-Ausgaben ausführen, nachdem du die exakte Berechnung isoliert hast.
- Verwende explizit `--bitwidth`, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt benötigst, sieh dir die lokalen Z3-Notizen hier an:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ist auch als **LLVM-Pass-Plugin** (`libCobraPass.so`) verfügbar. Das ist nützlich, wenn du MBA-lastiges LLVM IR vor späteren Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte carry-sensitive Residuen aus gemischten Domänen solltest du als Signal auffassen, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell zu analysieren.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch `mov`-basierte Instruktionssequenzen und nutzt Signal-/Exception-Handling, um den Kontrollfluss zu ändern. Details:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Für unterstützte Binaries kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuskieren. Es hat mehrere Abhängigkeiten.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Und [keystone installieren](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **Einstiegspunkt** zu finden, suche in den Funktionen nach `::main`, wie hier:

![Finding a Rust entry point in Ghidra by searching function names for double-colon main](<../../images/image (1080).png>)

In diesem Fall hieß die Binärdatei authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Wenn du den **Namen** der aufgerufenen **Funktionen** hast, suche im **Internet** danach, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binärdateien werden viele statische Strings nicht als C-artige, NUL-terminierte Zeiger referenziert. Ein häufiges `rustc`-Layout ist ein **Zeiger/Längen-Tupel** in **`.data.rel.ro`**, das auf den tatsächlichen String-Blob in **`.rodata`** verweist:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Strings zusammenführen oder Querverweise vollständig übersehen kann.<sup>[[3]](#references)</sup>

Schnellworkflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Durchlaufe **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen String-Zeiger.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (behalte zum Beispiel Längen zwischen **4** und **100** Bytes).
6. Lies genau `length` Bytes aus `.rodata`, statt bis zum nächsten `0x00` zu scannen.

Minimale Extractor-Logik:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Dies ist beim Firmware-Reversing besonders nützlich, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Config-Schlüssel, Command-Handler und Auth-bezogene Logik** offenbaren.

Wenn Ghidra diese Strings übersieht, führe ein benutzerdefiniertes Script/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **Wortbreiten, Endianness und Section-Layouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binaries kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du ein Delphi-Binary reverse-engineeren musst, würde ich dir das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) empfehlen.

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle anschließend die Plugin-Datei aus.

Dieses Plugin führt das Binary aus und löst beim Start des Debuggings dynamisch Funktionsnamen auf. Drücke nach dem Start des Debuggings erneut auf die Start-Schaltfläche (die grüne oder F9), dann wird am Anfang des echten Codes ein Breakpoint ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche klickst, kann der Debugger in der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Wenn du ein Golang-Binary reverse-engineeren musst, würde ich dir das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) empfehlen.

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle anschließend die Plugin-Datei aus.

Dadurch werden die Namen der Funktionen aufgelöst.

## Kompiliertes Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einem kompilierten Python-Binary im ELF/EXE-Format erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du das **Binary** eines GBA-Spiels erhältst, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_** ** sehen, wie die Game Boy Advance-**Tasten** gedrückt werden.

![no$gba-Konfiguration der Steuerung mit den Tastenbelegungen des Game Boy Advance](<../../images/image (581).png>)

Jede **Taste hat beim Drücken einen Wert**, anhand dessen sie identifiziert wird:

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

Bei dieser Art von Programm ist also interessant, **wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** finden Sie die häufig anzutreffende Funktion: **KEYINPUT**.

![Ghidra-Ansicht einer GBA-Binärdatei mit einem Verweis auf KEYINPUT an der Adresse 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild sehen Sie, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion folgt nach einigen Init-Operationen (die nicht wichtig sind):

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

Folgender Code wurde gefunden:

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

Das letzte if prüft, ob **`uVar4`** in den **letzten Keys** enthalten und nicht der aktuelle Key ist – also ob eine Taste losgelassen wird (der aktuelle Key ist in **`uVar1`** gespeichert).

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

Im vorherigen Code siehst du, dass wir **uVar1** (die Stelle, an der sich der **Wert der gedrückten Taste** befindet) mit einigen Werten vergleichen:

- Zuerst wird es mit dem **Wert 4** (der **SELECT**-Taste) verglichen: In der Challenge löscht diese Taste den Bildschirm.
- Dann wird der Wert mit **8** (der **START**-Taste) verglichen; in dieser Challenge prüft dieser Pfad, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Wenn der Wert übereinstimmt, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) überprüft und erhöht.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

Für diese Challenge musstest du also die Werte der Tasten kennen und **eine Kombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary-Deobfuskierung)

## References

- [1] [MBA-Verschleierung mit CoBRA vereinfachen](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-Repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings decodieren – Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering – Rust-Strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering – RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia – GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-gestütztes Reverse Engineering vereiteln – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
