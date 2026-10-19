# Reversing-Tools und grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## ImGui-basierte Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-Automatisierung im User-Mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows-Kernel-Debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-Decompiler / Wat-Compiler

Online:

- Verwende [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (Binärformat) zu wat (Klartext) zu **dekompilieren**
- Verwende [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um wat zu wasm zu **kompilieren**
- Du kannst für die Dekompilierung auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) ausprobieren.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-Bytecode aus dem Cache

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

Der Vorteil besteht darin, dass sich Zeit sparen lässt, wenn verlorener Quellcode aus einer älteren Assembly wiederhergestellt werden muss. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der perfekten Tools für die **Analyse von Xamarin-Algorithmen.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an deine genauen Anforderungen anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die zahlreichen Reverse-Engineering-Funktionen dieses Tools an:

- Zeigt, wie Daten durch eine Bibliothek oder Komponente fließen
- Bietet Einblicke in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, damit du mehr aus den verwendeten APIs und Technologien herausholen kannst.
- Findet Abhängigkeiten und verschiedene Assemblies
- Findet die genaue Stelle von Fehlern in deinem Code, in Komponenten von Drittanbietern und in Bibliotheken.
- Ermöglicht das Debuggen im Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem Betriebssystem verwenden (du kannst es direkt in VSCode installieren, ohne das Git-Repository herunterzuladen. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du erneut **dekompilieren**, **ändern** und **kompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Methode ändern**, um etwas innerhalb einer Funktion zu ändern).

### Ausführungsfreie verwaltete Analyse mit REA

**REA** kann PE/CLI-Metadaten und CIL untersuchen, ohne die Assembly zu laden. Beginne mit der Identität des Artefakts und untersuche anschließend die Member und deklarierten nativen Grenzen. Das ist hilfreich, wenn du verdächtige Aufrufe prüfst, bevor du einen Decompiler verwendest oder das Programm ausführst.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Beim Version-Diffing verwendet `compare_managed_members` die rohe CIL-/Signatur-Identität und Fingerprints decodierter Instruktionen, statt Metadaten-Tokens als buildübergreifend stabil zu behandeln. Eine P/Invoke-Deklaration beweist nicht, dass nativer Code ausgeführt wurde; `verify_managed_native_boundaries` benötigt passende native Exporte oder Function Evidence, um diese Grenze zu überprüfen. Bewahre den Artefakt-Digest, die MVID und nicht aufgelöste Zuordnungen zusammen mit dem Ergebnis auf.<sup>[[17]](#references)</sup>

### DNSpy-Protokollierung

Um **DNSpy einige Informationen in eine Datei protokollieren zu lassen**, kannst du dieses Snippet verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy-Debugging

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

Das ist notwendig, denn andernfalls werden zur **Laufzeit** mehrere **Optimierungen** auf den Code angewendet. Dadurch kann es passieren, dass beim Debuggen ein **Breakpoint nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn deine .NET-Anwendung von **IIS** **ausgeführt** wird, kannst du sie anschließend mit folgendem Befehl **neu starten**:

```
iisreset /noforce
```

Dann solltest du zunächst alle geöffneten Dateien schließen. Wähle anschließend im **Debug Tab** **Attach to Process...** aus, um mit dem Debugging zu beginnen:

![DNSpy Logging - DNSpy Debugging: Schließe zunächst alle geöffneten Dateien und wähle im Debug Tab Attach to Process aus, um mit dem Debugging zu beginnen](<../../images/image (318).png>)

Wähle anschließend **w3wp.exe** aus, um eine Verbindung zum **IIS server** herzustellen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle w3wp.exe aus, um eine Verbindung zum IIS server herzustellen, und klicke auf attach](<../../images/image (113).png>)

Nachdem wir nun den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf _Debug >> Break All_ und anschließend auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Nachdem wir nun den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Nachdem wir nun den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (834).png>)

Klicke im Bereich **Modules** auf ein beliebiges Modul und wähle **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicke im Bereich Modules auf ein beliebiges Modul und wähle Open All Modules aus](<../../images/image (922).png>)

Klicke im **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und klicke auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Klicke im Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und klicke auf Sort Assemblies](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Wähle den **Windbg**-Debugger aus
- Wähle "**Suspend on library load/unload**" aus

![Debugging DLLs - Using IDA: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Konfiguriere die **parameters** der Ausführung, indem du den **path to the DLL** und die aufzurufende Funktion angibst:

![Debugging DLLs - Using IDA: Konfiguriere die Parameter der Ausführung, indem du den Pfad zur DLL und die aufzurufende Funktion angibst](<../../images/image (704).png>)

Wenn du dann mit dem Debugging beginnst, **wird die Ausführung beim Laden jeder DLL angehalten**. Sobald rundll32 deine DLL lädt, wird die Ausführung also angehalten.

Diese Methode hält bei Ereignissen zum Laden von Modulen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist jedoch weniger direkt als mit dem unten beschriebenen x64dbg-Workflow.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) und gib den Pfad der DLL sowie die aufzurufende Funktion an, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ändere _Options --> Settings_ und wähle "**DLL Entry**" aus.
- **Starte anschließend die Ausführung**. Der Debugger hält bei jedem DLL-Main an. Irgendwann hält er dann **beim DLL Entry deiner DLL** an. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte: Wenn die Ausführung in win64dbg aus irgendeinem Grund angehalten wird, kannst du **oben im win64dbg-Fenster** sehen, **in welchem Code du dich befindest**:

![Using IDA - Using x64dbg/x32dbg: Beachte: Wenn die Ausführung in win64dbg aus irgendeinem Grund angehalten wird, kannst du oben im win64dbg-Fenster sehen, in welchem Code du dich befindest](<../../images/image (842).png>)

Diese Anzeige bestätigt, wenn die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Anwendungen / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern. Weitere Informationen findest du unter:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Frontend- und Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Aufgaben im Bereich Reverse Engineering verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Frontend für verschiedene Decompiler. Mit diesem Webdienst kannst du die Ausgabe verschiedener Decompiler für kleine ausführbare Dateien vergleichen.

## Evidenzbasierte native Untersuchung mit REA

**REA** stellt Analysen aus Hopper, Ghidra und IDA über CLI und MCP bereit. Dafür sind Node.js 22.x (mindestens 22.19), 24.x (mindestens 24.11) oder 26+ sowie npm erforderlich. Konfiguriere zuerst einen vorhandenen nativen Provider. Prüfe `rea providers --json` und wähle explizit einen Provider aus, wenn mehrere das Ziel unterstützen. Verwende anstelle von `0x1000` unten einen beobachteten Funktionsnamen oder eine Adresse aus dem Inventar.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Beginne mit einem Feature-String oder Symbol, folge den Referenzen und Aufrufern und untersuche dann das ausgewählte Funktionsdossier und den Pseudocode mit `rea decompile`. REA bindet eine Sitzung an den ausgewählten Provider, statt ihn nach einem Fehler stillschweigend zu ersetzen. Für wiederholbare Abfragen verwendet `--snapshot PATH` nur dann dieselben Artefaktbytes, wenn Provider, Einstellungen, Vorgang und Parameter übereinstimmen. Ein Snapshot ist ein lokaler Cache, keine gespeicherte Provider-Datenbank. Bewahre das zurückgegebene Evidence und explizite Unbekannte auf, statt erschlossene Pfade oder Decompiler-Text als Originalquelle zu behandeln.<sup>[[16]](#references)[[18]](#references)</sup>

Informationen zu JavaScript-/Electron-Einstiegspunkten, die zu nativen Add-ons führen, findest du unter [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Shellcode mit BlobRunner debuggen

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert Speicher für den **Shellcode**, gibt dessen **Speicheradresse** aus und hält die Ausführung an.\
Hänge einen Debugger wie IDA oder x64dbg an, setze an der ausgegebenen Adresse einen Breakpoint und setze die Ausführung fort, um den Shellcode zu debuggen.

Auf der GitHub-Releases-Seite befinden sich ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unter folgendem Link findest du eine leicht modifizierte Version von BlobRunner. Um sie zu kompilieren, **erstelle einfach ein C/C++-Projekt in Visual Studio Code, kopiere den Code hinein und erstelle den Build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Shellcode mit jmp2it debuggen

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) funktioniert ähnlich wie BlobRunner. Es reserviert Speicher für den Shellcode und geht in eine Endlosschleife. Hänge den Debugger an, setze die Ausführung für **2–5 Sekunden** fort, halte sie innerhalb dieser Schleife an und gehe zum nächsten Aufruf, der die Ausführung an den reservierten Shellcode übergibt.

![Debugger in jmp2its Endlosschleife direkt vor dem Aufruf des reservierten Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it findest du auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode mit Cutter debuggen

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter die Optionen „Open File“ und „Open Shellcode“ bietet. In meinem Fall wurde der Shellcode korrekt dekompiliert, als ich ihn als Datei öffnete. Als Shellcode geöffnet, funktionierte es jedoch nicht:

![Cutter zeigt unterschiedliche Analyseergebnisse beim Öffnen derselben Bytes als Datei oder Shellcode](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen Breakpoint. Offenbar startet Cutter die Emulation dann automatisch an dieser Stelle:

![Breakpoint am gewünschten Shellcode-Einstiegspunkt vor dem Start der Cutter-Emulation gesetzt](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Du kannst beispielsweise den Stack in einem Hexdump anzeigen:

![Der emulierte Shellcode-Stack im Hexdump von Cutter](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Das Tool zeigt dir unter anderem, **welche Funktionen** der Shellcode verwendet und ob er sich im Speicher **dekodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg verfügt außerdem über einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und den Shellcode ausführen kannst.

![Grafischer Launcher von scDbg zum Auswählen von Shellcode-Emulations- und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der endgültige Shellcode als Dump gespeichert, falls er zur Laufzeit im Speicher verändert wird (nützlich, um den decodierten Shellcode herunterzuladen). Mit **start offset** kannst du den Shellcode an einem bestimmten Offset starten. Die Option **Debug Shell** ist nützlich, um den Shellcode über das scDbg-Terminal zu debuggen. Für diesen Zweck finde ich jedoch eine der zuvor erläuterten Optionen besser, da du damit Ida oder x64dbg verwenden kannst.

### Disassemblieren mit CyberChef

Lade deine Shellcode-Datei als Eingabe hoch und verwende das folgende Rezept, um sie zu disassemblieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskation von MBA-Obfuskation

**Mixed Boolean-Arithmetic (MBA)**-Obfuskation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) mit bitweisen Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten normalerweise nur bei **modularer Arithmetik mit fester Bitbreite** gelten, daher sind Überträge und Überläufe relevant:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kann leicht ein falsches Ergebnis herauskommen, weil die Bitbreitensemantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite bei**, die aus dem gelifteten Code/IR/Decompiler-Output stammt (`8/16/32/64` Bit).
2. **Klassifiziere den Ausdruck**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
   - **Polynomial**: Produkte kommen vor
   - **Mixed**: Produkte und bitweise Logik sind miteinander verschachtelt, oft mit wiederholten Teilausdrücken
3. **Überprüfe jede mögliche Umschreibung** durch zufällige Tests oder einen SMT-Beweis. Wenn sich die Äquivalenz nicht beweisen lässt, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Umgehe abgeflachte Kontrollflüsse mit einem schmalen Ausführungsslice

Die Rekonstruktion des vollständigen Kontrollflussgraphen ist oft unnötig. Folge bei Control-Flow-Flattening, opaque predicates, großen Dispatchern oder MBA-lastigem Code den Referenzen von verschlüsselten Blobs und Ausgabepuffern bis zur kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Datenfluss-Slice oder führe ihn unabhängig aus; der Dispatcher ist für die erforderliche Lösung nicht relevant, wenn sich der betreffende Zustand direkt initialisieren lässt.<sup>[[7]](#references)</sup>

Ein praktischer Workflow:<sup>[[7]](#references)</sup>

1. Erfasse ausführbare und Datenabschnitte, Relokationen und Querverweise. Dumpe mögliche Tabellen aus `.rodata` und behalte dabei ihre Byte-Reihenfolge und Elementbreite bei.
2. Ermittle die letzte Routine, die den Klartext oder Ausgabepuffer schreibt. Notiere ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und erforderlichen globalen Zustände.
3. Überführe nur diese Operationen in ein Python-Modell mit fester Breite. Falls der Slice weiterhin von zu vielen Zuständen abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, statt das gesamte Programm zu emulieren.
4. Überprüfe, ob der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binärdatei ableitet: Entferne stille Fallbacks, durchsuche sie nach eingebetteten Antworten und führe ihn mit unbekannten Builds aus, in denen sich Strings, Schlüssel, Bezeichner, Layouts und Obfuskations-Seeds geändert haben.

Nützliche Befehle für den ersten Durchlauf:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Als Konstanten getarnte MBA-Ausdrücke erkennen

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann seine Eingabe vollständig aufheben. Nachdem Sie seine Tabellen extrahiert haben, werten Sie den Ausdruck über den vollständigen 8-Bit-Bereich aus; eine Ausgabemenge mit nur einem Element beweist, dass das Byte konstant ist, ohne dass Sie die umgebende Zustandsmaschine rekonstruieren müssen.<sup>[[7]](#references)</sup>

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

Behalte die abschließende Maske bei, da die ursprüngliche Addition einen Überlauf bei der Bytebreite aufweist. Für einen größeren Wertebereich kannst du einen SMT-Solver fragen, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Umgebunggebundene Dekodierung erkennen

Anti-Analysis-Prüfungen müssen weder verzweigen noch abstürzen. Ein Decoder kann ein Sensorergebnis in ein Schlüsselbit, eine Konstante eines opaque-predicate oder den Zustand eines abgeflachten Dispatchers einmischen, normal weiterlaufen und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehlerzweige zu patchen; verfolge die Datenabhängigkeiten von Umgebungsprüfungen bis in den Decoderzustand, vergleiche denselben Ausschnitt auf dem echten Gerät und im Emulator und teste, wie sich das Erzwingen jedes Sensorergebnisses auf den endgültigen Puffer auswirkt.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Vereinfacher für Malware-Analyse und das Reverse Engineering geschützter Binärdateien. Es klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, statt alles mit einem einzigen generischen Rewrite-Durchlauf zu bearbeiten.<sup>[[2]](#references)</sup>

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

Nützliche Fälle:

- **Linear MBA**: CoBRA wertet den Ausdruck mit booleschen Eingaben aus, leitet eine Signatur ab und probiert mehrere Recovery-Methoden parallel aus, etwa Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: Konstantenmaskierte Atome werden mit bitpartitionierter Rekonstruktion wiederhergestellt, damit maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel für eine gemischte Identität, deren Wiederherstellung sich häufig lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich reduzieren auf:

```c
x * y
```

### Hinweise zum Reverse Engineering

- Führe CoBRA bevorzugt auf **lifted IR-Ausdrücken** oder auf Decompiler-Ausgaben aus, nachdem du die exakte Berechnung isoliert hast.
- Verwende `--bitwidth` explizit, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt benötigst, sieh dir die lokalen Z3-Notizen hier an:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM-Pass-Plugin** (`libCobraPass.so`) ausgeliefert. Es ist nützlich, wenn du MBA-lastiges LLVM IR vor späteren Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte carry-sensitive Residuen aus gemischten Domänen sollten als Signal verstanden werden, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell nachzuvollziehen.

## XOR-state control-flow flattening rekonstruieren

Ein OLLVM-artiger Flattener kann den Zustand des aktuellen Basic Blocks in zwei 64-Bit-Registern speichern und ihn am Dispatcher per XOR rekonstruieren. Jeder ursprüngliche Block schreibt das Registerpaar für den nächsten Zustand und springt zurück zum Dispatcher. Ein bedingter Block kann `CMOVcc` verwenden, um eine Hälfte des Paars anhand der CPU-Flags zu ersetzen. Wer also nur sichtbaren Branch-Instruktionen folgt, übersieht die beiden Nachfolger. Anders als ein Indirect-Jump-Dispatcher kann diese Struktur durchgehend direkte Rücksprünge verwenden.<sup>[[19]](#references)[[20]](#references)</sup>

Um den Graphen wiederherzustellen, identifiziere den Vergleichsbaum des Dispatchers und die beiden Zustandsregister, ordne jeden verglichenen XOR-Zustand seinem Zielblock zu und verfolge dann die erreichenden Schreibzugriffe auf das Registerpaar in jedem ursprünglichen Block. Berücksichtige bei bedingten Schreibzugriffen die Flags setzende Instruktion und beide `CMOVcc`-Ergebnisse. Ersetze den Dispatcher-Ausgang jedes Blocks durch seinen aufgelösten direkten Nachfolger oder bedingten Branch; danach ist der Dispatcher unerreichbar, ohne dass die Binärdatei gepatcht werden muss. Dies ist ein vollständiger CFG-Ansatz. Wenn nur ein Decoder relevant ist, kann der oben beschriebene [Workflow mit engem Ausführungsslice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) schneller sein.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatisiert diese Struktur in Binary Ninja. Kopiere `plugins/DispatchThis` in das Benutzer-Plugin-Verzeichnis von Binary Ninja und starte das Programm neu. Öffne bei der betroffenen Funktion **Function Settings** und wähle `OLLVM_XOR_64`. Wenn die Analyse nicht startet, verwende **Analysis → Reanalyze All Functions**. Dieser Modus schreibt MLIL-Kontrollflusskanten um, nicht die Bytes der Datei, und benötigt weder Z3 noch den Indirect-Jump-Resolver. Er wurde mit Binary Ninja 5.3.9757+ getestet. Die ungenutzten Zustands-Schreibzugriffe pro Block werden nicht entfernt; verwechsle sie daher nicht mit noch aktiven Übergängen.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch `mov`-basierte Instruktionssequenzen und verwendet Signal-/Exception-Handling, um den Kontrollfluss zu ändern. Weitere Details:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Bei unterstützten Binärdateien kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuskieren. Es hat mehrere Abhängigkeiten.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Und [installiere keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **entry point** zu finden, suche in den Funktionen nach `::main`, wie hier:

![Einen Rust-entry point in Ghidra finden, indem Funktionsnamen nach doppeltem Doppelpunkt und main durchsucht werden](<../../images/image (1080).png>)

In diesem Fall hieß die Binärdatei authenticator, daher ist es ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Wenn du den **Namen** der aufgerufenen **Funktionen** kennst, suche im **Internet** nach ihnen, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binärdateien werden viele statische Strings nicht über C-ähnliche, NUL-terminierte Zeiger referenziert. Ein übliches `rustc`-Layout ist ein **Zeiger-/Längen-Tupel** in **`.data.rel.ro`**, das auf den eigentlichen String-Blob in **`.rodata`** verweist:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Zeichenketten zusammenführen oder Querverweise vollständig übersehen können.<sup>[[3]](#references)</sup>

Schneller Arbeitsablauf:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Durchlaufe **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen Zeiger auf einen String.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (behalte beispielsweise Längen zwischen **4** und **100** Bytes bei).
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

Das ist beim Firmware-Reversing besonders nützlich, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Config-Schlüssel, Command-Handler und Auth-bezogene Logik** offenlegen.

Wenn Ghidra diese Strings nicht findet, führe ein benutzerdefiniertes Script/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **Wortgrößen, Endianness-Formate und Section-Layouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du eine Delphi-Binärdatei reverse-engineeren musst, empfehle ich das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi).

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dieses Plugin führt die Binärdatei aus und löst Funktionsnamen zu Beginn des Debuggings dynamisch auf. Drücke nach dem Start des Debuggings erneut die Start-Schaltfläche (die grüne oder f9), dann wird am Anfang des eigentlichen Codes ein Breakpoint ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche klickst, kann der Debugger in der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Für gewöhnliche Go-Binärdateien kann [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) Runtime-Strukturen wiederherstellen und Funktionsnamen in IDA verbessern. Lade das Python-Plugin mit **Alt+F7**.

Wenn du eine Golang-Binärdatei reverse-engineeren musst, empfehle ich das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper).

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dadurch werden die Funktionsnamen aufgelöst.

### Metadaten ohne Symboltabelle wiederherstellen

Auch eine gestrippte Go-Executable benötigt Runtime-Metadaten, um Program Counter Funktionen zuzuordnen. [GoReSym](https://github.com/mandiant/GoReSym) findet und parst Strukturen wie `pclntab` und `moduledata` mithilfe von Code, der aus der Go-Runtime abgeleitet wurde. Damit lassen sich Funktionsgrenzen, Namen, Quellpfade, Typen und Build-Details wiederherstellen, ohne auf die herkömmliche Symboltabelle angewiesen zu sein.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ein Obfuscator kann diese Strukturen nutzbar lassen und gleichzeitig die wiederhergestellten Namen ersetzen. Garble hasht beispielsweise Bezeichner und Paketpfade und entfernt Build-, Modul- und Debug-Informationen.<sup>[[12]](#references)</sup> Das obfuskierte Paket-Token muss für Funktionen desselben Pakets konsistent bleiben. Gruppiere Funktionen anhand des wiederholt auftretenden Tokens, leite ein Paket aus dessen Callees, Strings und APIs ab und übertrage dieses Paketlabel anschließend auf die gesamte Gruppe.<sup>[[13]](#references)</sup>

### Garble-Namen mit GoResolver wiederherstellen

[GoResolver](https://github.com/volexity/GoResolver) kombiniert die Extraktion von Runtime-Symbolen mit der Generierung sauberer Referenzen und dem Abgleich von Kontrollflussgraphen (CFGs). Gehe dabei wie folgt vor:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler-Version ermitteln.** Probiere zuerst `BuildInfo` und eingebettete Versionsstrings aus. Wenn der Obfuscator sie entfernt hat, vergleiche Teile der gebündelten Go-Runtime mit versionierten Referenz-Runtimes. In den Tests von Volexity reichten etwa `2%` der Runtime aus, um wichtige Go-Versionen voneinander zu unterscheiden. Betrachte dies als empirische Optimierung, nicht als allgemeingültigen Schwellenwert.<sup>[[13]](#references)</sup>
2. **Passende Referenzen erstellen.** Generiere saubere Binaries für die ermittelte Go-Version, die Zielarchitektur und wahrscheinliche Libraries. Ein übereinstimmender Toolchain reduziert CFG-Unterschiede, die der Compiler erzeugt.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Funktionen vergleichen.** GoGrapher gleicht Funktions-CFGs ab und gibt normalisierte Scores von `0.0` bis `1.0` aus. Der Abgleich von Basic Blocks basiert auf einem gewichteten Vergleich ähnlicher Instruktionen. Matches mit hoher Konfidenz ordnen randomisierte Funktionen der sauberen Implementierung zu. Schwächere Matches können dennoch ein Paket oder Modul identifizieren.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validieren und importieren.** Bestätige vorgeschlagene Namen anhand von Aufrufbeziehungen, Konstanten, Strings und Side Effects und importiere anschließend den JSON-Report mit dem GoResolver-Plugin für IDA oder Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Der standardmäßige Schwellenwert für signifikante Übereinstimmungen ist `0.9`. Mit den Schaltern `--extract` und `--graph` lässt sich jeweils eine der beiden Phasen isolieren. Standardmäßig werden beide ausgeführt, da sich die wiederhergestellten Runtime-Metadaten und die CFG-Belege ergänzen.<sup>[[10]](#references)</sup> CFG-Scores sind heuristisch: Inlining, Build-Flags, Architektur und Unterschiede zwischen Bibliotheksversionen können die Graphstruktur verändern. Behalte daher nicht aufgelöste Funktionen bei, statt ihnen Namen mit geringer Konfidenz aufzuzwingen.<sup>[[13]](#references)</sup>

### Go-String-Tabelle wiederherstellen

Go-Binaries speichern die String-Bytes aller gelinkten Pakete in einer zusammenhängenden Tabelle. Die Einträge sind nicht NUL-terminiert, und Runtime-Strukturen geben weder die Basisadresse noch die Größe der Tabelle preis. Der Compiler ordnet die Einträge jedoch auf allen Betriebssystemen und Architekturen zuerst nach Länge und dann alphabetisch. Nachdem ein Eintrag gefunden wurde, kann ein Analyst daher benachbarte Einträge durchgehen und mithilfe von Datenquerverweisen Strings dem Code zuordnen.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatisiert diesen Ablauf in IDA Pro und Ghidra. Lass zunächst die automatische Analyse abschließen, da das Plugin auf Datenquerverweisen basiert. Als Standardanker dient der Runtime-String `entersyscall`. Anschließend kann das Plugin in beide Richtungen suchen, die wiederhergestellten Strings in der Datenbank definieren und ein JSON-Mapping von Strings zu den darauf verweisenden Funktionen exportieren.<sup>[[14]](#references)</sup>

Filtere den Bericht nach dem Paket der verweisenden Funktion, um Anwendungs- oder Malware-Code von verknüpften Bibliotheken zu unterscheiden. Mit dieser Technik lassen sich keine Literale wiederherstellen, die durch Obfuskation zerstört wurden, etwa durch Garbles Transformation `-literals`. Sie kann jedoch Runtime-Strings ordnen, die nicht obfuskiert wurden.<sup>[[14]](#references)[[15]](#references)</sup>

### Go-Runtime-Typen wiederherstellen

Go bettet Runtime-Typinformationen ein, die von Funktionen wie der Garbage Collection verwendet werden. Wenn Build-Informationen entfernt wurden oder der Disassembler diese Metadaten nicht parst, sehen Anweisungen möglicherweise so aus, als würden sie beliebige Datenadressen laden, und der Zielbereich bleibt untypisiert. Durch die Wiederherstellung der Metadaten werden diese Adressen zu lesbaren Typreferenzen, sodass sich die Fähigkeiten eines Pakets leichter verstehen lassen.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kann Symbole extrahieren und Runtime-Typen parsen, um einen JSON-Bericht zu erstellen. Die aktuelle CLI verwendet den Unterbefehl `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die Option `-y`/`--types` aktiviert das Parsen von Typen. Importiere den Bericht mit dem IDA-Pro- oder Ghidra-Plugin von GoResolver, um die wiederhergestellten Typen zu definieren und ihre Verweise in der Analysedatenbank anzuwenden. Im mit dieser Funktion eingeführten Berichtsformat sind die RTTI-Adresse und die Elemente für wiederhergestellte Typen null, wenn `-y` weggelassen wird.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver unterstützt PE-, ELF- und Mach-O-Dateien für x86, AMD64, ARM und ARM64. Daher gilt derselbe Workflow für Go-Binärdateien unter Windows, Linux und macOS.<sup>[[10]](#references)</sup>

## Kompiliertes Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einer kompilierten ELF-/EXE-Python-Binärdatei erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du die **Binärdatei** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug-Version herunterladen_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Optionen --> Emulationseinstellungen --> Steuerung**_** sehen, wie du die **Tasten** des Game Boy Advance drückst

![no$gba-Konfiguration der Steuerung mit den Tastenbelegungen des Game Boy Advance](<../../images/image (581).png>)

Jede **Taste hat einen Wert**, anhand dessen sie identifiziert werden kann:

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

In dieser Art von Programm ist also **die Art und Weise, wie das Programm die Benutzereingabe verarbeitet**, interessant. An der Adresse **0x4000130** finden Sie die häufig vorkommende Funktion: **KEYINPUT**.

![Ghidra-Ansicht einer GBA-Binärdatei mit Verweis auf KEYINPUT an Adresse 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild sehen Sie, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion, nach einigen Init-Operationen (ohne Bedeutung):

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

Es wurde folgender Code gefunden:

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

Die letzte if-Anweisung prüft, ob **`uVar4`** zu den **letzten Keys** gehört und nicht die aktuelle Taste ist. Das entspricht dem Loslassen einer Taste (die aktuelle Taste wird in **`uVar1`** gespeichert).

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

- Zuerst wird der Wert mit **4** (der **SELECT**-Taste) verglichen: In der Challenge löscht diese Taste den Bildschirm.
- Dann wird der Wert mit **8** (der **START**-Taste) verglichen; in dieser Challenge prüft dieser Ausführungspfad, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Wenn der Wert übereinstimmt, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und erhöht.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

Für diese Challenge musste man also, wenn man die Werte der Tasten kannte, **eine Kombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [archivierter Lösungsbericht zur Nostalgia-Challenge](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binäre Deobfuskierung)

## References

- [1] [MBA-Verschleierung mit CoBRA vereinfachen](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-Repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings dekodieren - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust-Strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-gestütztes Reverse Engineering vereiteln – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Ein Ansatz zum Vergleich von Kontrollflussgraphen auf Grundlage des Abgleichs von Basisblöcken](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-Repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-Verschleierungsmechanismus](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kontrollflussgraph-Ähnlichkeit nutzen, um Golang-Binärdateien automatisch zu deobfuskieren](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-Repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Aktualisierungen der Golang-Tools von Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Alles reverse engineeren](https://github.com/morluto/rea)
- [17] [REA-Analyse von Managed Code](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA-Anleitung zu CLI und Beweismitteln](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Workflow zum Aufheben der Kontrollfluss-Obfuskierung in Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut-MF-Zero-Day-Eindringen, Java-Loader, Web-Shell und AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
{{#include ../../banners/hacktricks-training.md}}
