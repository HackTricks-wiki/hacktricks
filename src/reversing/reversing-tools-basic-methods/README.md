# Reversing-Tools & grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## Auf ImGui basierende Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-Automatisierung im Benutzermodus

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

## Node.js / V8-gebytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualisierte Payloads und benutzerdefinierte VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET-Decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der mehrere Formate **dekompiliert und untersucht**, darunter **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **ausführbare Dateien** (.exe). Eine dekompilierte Assembly kann als Visual-Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil: Wenn verlorener Quellcode aus einer älteren Assembly wiederhergestellt werden muss, kann das Zeit sparen. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und eignet sich dadurch hervorragend für die **Xamarin-Algorithmusanalyse.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, mit der sich das Tool an deine genauen Anforderungen anpassen lässt, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die zahlreichen Reverse-Engineering-Funktionen dieses Tools an:

- Zeigt, wie Daten durch eine Bibliothek oder Komponente fließen
- Gibt Einblick in die Implementierung und Verwendung von .NET-Sprachen und Frameworks
- Findet nicht dokumentierte und nicht offengelegte Funktionen, damit du mehr aus den verwendeten APIs und Technologien herausholen kannst.
- Findet Abhängigkeiten und verschiedene Assemblies
- Spürt die genaue Stelle von Fehlern in deinem Code, Drittanbieterkomponenten und Bibliotheken auf.
- Ermöglicht das Debuggen im Quellcode aller .NET-Codebasen, mit denen du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem Betriebssystem verwenden (du kannst es direkt über VSCode installieren; ein Download von git ist nicht nötig. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du erneut **dekompilieren**, **ändern** und **kompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### Ausführungsfreie verwaltete Untersuchung mit REA

**REA** kann PE/CLI-Metadaten und CIL untersuchen, ohne die Assembly zu laden. Beginne mit der Identität des Artefakts und untersuche dann die Member und deklarierten nativen Schnittstellen. Das ist hilfreich, wenn du verdächtige Aufrufe überprüfst, bevor du einen Decompiler verwendest oder das Programm ausführst.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Für den Versionsvergleich verwendet `compare_managed_members` die Identität von rohem CIL und Signaturen sowie Fingerprints decodierter Instruktionen, statt Metadaten-Tokens als buildübergreifend stabil zu behandeln. Eine P/Invoke-Deklaration ist kein Beweis dafür, dass nativer Code ausgeführt wurde; `verify_managed_native_boundaries` benötigt einen passenden nativen Export oder Funktions-Evidence, um diese Grenze zu überprüfen. Bewahre den Artefakt-Digest, die MVID und nicht aufgelöste Zuordnungen zusammen mit dem Ergebnis auf.<sup>[[17]](#references)</sup>

### DNSpy-Protokollierung

Um **DNSpy dazu zu bringen, einige Informationen in einer Datei zu protokollieren**, kannst du dieses Snippet verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugging mit DNSpy

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly attributes** für das **Debugging** ändern:

![DNSpy Logging - Debugging mit DNSpy: Zuerst die Assembly attributes für das Debugging ändern](<../../images/image (973).png>)

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

Und klicken Sie auf **Kompilieren**:

![DNSpy Logging - DNSpy Debugging: Und klicken Sie auf Kompilieren](<../../images/image (314) (1).png>)

Speichern Sie dann die neue Datei über _**Datei >> Modul speichern...**_:

![DNSpy Logging - DNSpy Debugging: Speichern Sie dann die neue Datei über Datei Modul speichern](<../../images/image (602).png>)

Das ist notwendig, denn andernfalls werden zur **Laufzeit** mehrere **Optimierungen** auf den Code angewendet. Dadurch kann es passieren, dass beim Debuggen ein **break-point nie ausgelöst wird** oder einige **Variablen nicht existieren**.

Wenn Ihre .NET-Anwendung von **IIS** **ausgeführt** wird, können Sie sie anschließend mit folgendem Befehl **neu starten**:

```
iisreset /noforce
```

Dann solltest du, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und auf der Registerkarte **Debug** die Option **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Schließe alle geöffneten Dateien und wähle auf der Registerkarte Debug die Option Attach to Process aus, um mit dem Debugging zu beginnen](<../../images/image (318).png>)

Wähle anschließend **w3wp.exe** aus, um eine Verbindung zum **IIS-Server** herzustellen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle w3wp.exe aus, um eine Verbindung zum IIS-Server herzustellen, und klicke auf attach](<../../images/image (113).png>)

Da wir den Prozess jetzt debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Halte den Prozess an und lade alle Module. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Halte den Prozess an und lade alle Module. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (834).png>)

Klicke unter **Modules** auf ein beliebiges Modul und wähle **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicke unter Modules auf ein beliebiges Modul und wähle Open All Modules aus](<../../images/image (922).png>)

Klicke in **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und wähle **Sort Assemblies** aus:

![DNSpy Logging - DNSpy Debugging: Klicke in Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und wähle Sort Assemblies aus](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### Mit IDA

- **rundll32 laden** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Den **Windbg**-Debugger auswählen
- "**Suspend on library load/unload**" auswählen

![Debugging DLLs - Using IDA: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Die **Parameter** für die Ausführung konfigurieren, indem du den **Pfad zur DLL** und die aufzurufende Funktion angibst:

![Debugging DLLs - Using IDA: Konfiguriere die Parameter für die Ausführung, indem du den Pfad zur DLL und die aufzurufende Funktion angibst](<../../images/image (704).png>)

Wenn du anschließend mit dem Debugging beginnst, **wird die Ausführung beim Laden jeder DLL angehalten**. Sobald rundll32 deine DLL lädt, wird die Ausführung also angehalten.

Diese Methode hält bei Modul-Ladeereignissen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist jedoch weniger direkt als mit dem unten beschriebenen x64dbg-Workflow.

### Mit x64dbg/x32dbg

- **rundll32 laden** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Die **Befehlszeile ändern** ( _File --> Change Command Line_ ) und den Pfad zur DLL sowie die aufzurufende Funktion angeben, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ ändern und "**DLL Entry**" auswählen.
- Dann **die Ausführung starten**. Der Debugger hält bei jedem dll main an. Irgendwann hält er bei **DLL Entry deiner DLL** an. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte, dass du in win64dbg, wenn die Ausführung aus irgendeinem Grund angehalten wird, **oben im win64dbg-Fenster** sehen kannst, **in welchem Code du dich gerade befindest**:

![Using IDA - Using x64dbg/x32dbg: Beachte, dass du oben im win64dbg-Fenster sehen kannst, in welchem Code du dich gerade befindest, wenn die Ausführung aus irgendeinem Grund angehalten wird](<../../images/image (842).png>)

Anhand dieser Anzeige kannst du erkennen, wann die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Anwendungen / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels abgelegt sind, und sie zu ändern. Weitere Informationen unter:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Frontend-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Aufgaben im Bereich Reverse Engineering verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein webbasiertes Frontend für verschiedene Decompiler. Mit diesem Webdienst kannst du die Ausgaben verschiedener Decompiler für kleine ausführbare Dateien vergleichen.

## Evidenzbasierte Untersuchung nativer Programme mit REA

**REA** stellt Analysen mit Hopper, Ghidra und IDA über CLI und MCP bereit. Erfordert Node.js 22.x (mindestens 22.19), 24.x (mindestens 24.11) oder 26+ sowie npm. Konfiguriere zunächst einen vorhandenen nativen Provider. Prüfe `rea providers --json` und wähle explizit einen Provider aus, wenn mehrere das Ziel unterstützen. Verwende unten anstelle von `0x1000` einen in der Bestandsaufnahme gefundenen Funktionsnamen oder eine Adresse.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Beginne mit einem Feature-String oder Symbol, folge den Referenzen und Aufrufern und untersuche dann das ausgewählte Funktionsdossier und den Pseudocode mit `rea decompile`. REA bindet eine Sitzung an den ausgewählten Provider, statt ihn nach einem Fehler stillschweigend zu ersetzen. Für wiederholbare Abfragen verwendet `--snapshot PATH` nur dann dieselben Artefakt-Bytes erneut, wenn Provider, Einstellungen, Operation und Parameter übereinstimmen; ein Snapshot ist ein lokaler Cache, keine gespeicherte Provider-Datenbank. Bewahre die zurückgegebenen Evidence und expliziten Unbekannten, statt abgeleitete Pfade oder Decompiler-Text als Original-Quellcode zu behandeln.<sup>[[16]](#references)[[18]](#references)</sup>

Informationen zu JavaScript-/Electron-Einstiegspunkten, die zu nativen Add-ons führen, findest du unter [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging eines Shellcodes mit blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert Speicher für den **Shellcode**, gibt dessen **Speicheradresse** aus und hält die Ausführung an.\
Hänge einen Debugger wie IDA oder x64dbg an, setze am ausgegebenen Speicherort einen Breakpoint und setze die Ausführung fort, um den Shellcode zu debuggen.

Die GitHub-Releases-Seite enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Eine leicht modifizierte Version von Blobrunner findest du unter folgendem Link. Um sie zu kompilieren, **erstelle einfach ein C/C++-Projekt in Visual Studio Code, kopiere den Code hinein und baue das Projekt**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging eines Shellcodes mit jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) funktioniert ähnlich wie BlobRunner. Es reserviert Speicher für den Shellcode und tritt in eine Endlosschleife ein. Hänge den Debugger an, setze die Ausführung für **2–5 Sekunden** fort, halte sie innerhalb dieser Schleife an und gehe dann zum folgenden Aufruf, der die Ausführung an den reservierten Shellcode übergibt.

![Debugger in jmp2its Endlosschleife direkt vor dem Aufruf des reservierten Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it findest du auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Debugging von Shellcode mit Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Cutter bietet die Optionen „Open File“ und „Open Shellcode“. In meinem Fall wurde der Shellcode korrekt dekompiliert, wenn ich ihn als Datei öffnete, aber nicht, wenn ich ihn als Shellcode öffnete:

![Cutter zeigt unterschiedliche Analyseergebnisse, wenn dieselben Bytes als Datei oder als Shellcode geöffnet werden](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen Breakpoint. Cutter startet die Emulation dann offenbar automatisch an dieser Stelle:

![Breakpoint am gewünschten Shellcode-Einstiegspunkt gesetzt, bevor die Cutter-Emulation gestartet wird](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Du kannst zum Beispiel den Stack in einem Hexdump ansehen:

![Der emulierte Shellcode-Stack im Hexdump von Cutter](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Das Tool zeigt beispielsweise, **welche Funktionen** der Shellcode verwendet und ob er sich im Speicher selbst **dekodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg verfügt auch über einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und den Shellcode ausführen kannst.

![Grafischer Launcher von scDbg zum Auswählen von Shellcode-Emulations- und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der finale Shellcode ausgegeben, wenn der Shellcode zur Laufzeit im Speicher verändert wird (nützlich, um den dekodierten Shellcode herunterzuladen). Der **start offset** kann nützlich sein, um den Shellcode ab einem bestimmten Offset zu starten. Die Option **Debug Shell** ist hilfreich, um den Shellcode über das scDbg-Terminal zu debuggen (ich finde allerdings alle zuvor erklärten Optionen dafür besser, da du Ida oder x64dbg verwenden kannst).

### Disassemblieren mit CyberChef

Lade deine Shellcode-Datei als Eingabe hoch und verwende das folgende Rezept, um sie zu disassemblieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA-Verschleierung aufheben

**Mixed Boolean-Arithmetic (MBA)**-Verschleierung verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Verschiebungen) kombinieren. Wichtig ist, dass diese Identitäten normalerweise nur bei **arithmetischen Operationen mit fester Bitbreite und Modulo** gelten, sodass Überträge und Überläufe eine Rolle spielen:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du einen solchen Ausdruck mit generischen Algebra-Werkzeugen vereinfachst, kann leicht ein falsches Ergebnis herauskommen, weil die Bitbreitensemantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite bei**, die aus dem gehobenen Code/IR/Decompiler-Output hervorgeht (`8/16/32/64` Bits).
2. **Ordne den Ausdruck ein**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear mit zusätzlichen konstanten Masken wie `x & 0xFF`
   - **Polynomial**: Produkte kommen vor
   - **Gemischt**: Produkte und bitweise Logik sind miteinander verschachtelt, oft mit wiederholten Teilausdrücken
3. **Überprüfe jede mögliche Umformung** durch zufällige Tests oder einen SMT-Beweis. Lässt sich die Äquivalenz nicht beweisen, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Umgehe abgeflachten Kontrollfluss mit einem schmalen Ausführungsslice

Den vollständigen Kontrollflussgraphen wiederherzustellen, ist oft unnötig. Bei control-flow flattening, opaque predicates, großen Dispatchern oder MBA-lastigem Code verfolgst du Referenzen von verschlüsselten Blobs und Ausgabepuffern bis zur kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Datenflussslice oder führe ihn unabhängig aus; der Dispatcher gehört nicht zur erforderlichen Lösung, wenn sich der relevante Zustand direkt initialisieren lässt.<sup>[[7]](#references)</sup>

Ein praktischer Workflow sieht so aus:<sup>[[7]](#references)</sup>

1. Erfasse ausführbare und Datensektionen, Relokationen und Querverweise. Gib mögliche Tabellen aus `.rodata` aus und bewahre dabei ihre Byte-Reihenfolge und Elementbreite.
2. Finde die letzte Routine, die in den Klartext- oder Ausgabepuffer schreibt. Notiere ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und den erforderlichen globalen Zustand.
3. Überführe nur diese Operationen in ein Python-Modell mit fester Bitbreite. Falls der Slice noch von zu viel Zustand abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, anstatt das ganze Programm zu emulieren.
4. Überprüfe, dass der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binärdatei ableitet: Entferne stille Fallbacks, durchsuche sie nach eingebetteten Antworten und teste ihn mit bisher unbekannten Builds mit geänderten Strings, Schlüsseln, Bezeichnern, Layouts und Obfuskations-Seeds.

Nützliche Befehle für die erste Analyse sind:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### MBA-Ausdrücke erkennen, die Konstanten verschleiern

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann seine Eingabe vollständig aufheben. Nachdem die zugehörigen Tabellen extrahiert wurden, lässt sich der Ausdruck über den gesamten 8-Bit-Wertebereich auswerten; eine einelementige Ausgabemenge beweist, dass das Byte konstant ist, ohne die umgebende Zustandsmaschine rekonstruieren zu müssen.<sup>[[7]](#references)</sup>

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

Behalte die abschließende Maske bei, da die ursprüngliche Addition einen Überlauf bei der Bytegröße aufweist. Frage bei einem größeren Wertebereich einen SMT-Solver, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Erkennen umgebungsgebundener Decodierung

Anti-Analysis-Prüfungen müssen weder verzweigen noch abstürzen. Ein Decoder kann das Ergebnis eines Sensors in ein Schlüsselbit, eine Konstante eines opaque predicate oder den Zustand eines abgeflachten Dispatchers einmischen, normal weiterlaufen und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehlerzweige zu patchen. Verfolge die Datenabhängigkeiten von Umgebungssonden bis in den Decoder-Zustand, vergleiche denselben Slice auf dem authentischen Gerät und im Emulator und teste, wie das Erzwingen jedes Sensorergebnisses den endgültigen Puffer verändert.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Vereinfacher für die Malware-Analyse und das Reverse Engineering geschützter Binaries. Das Tool klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, anstatt auf alles denselben generischen Rewrite-Pass anzuwenden.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA wertet den Ausdruck mit booleschen Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden konkurrieren, etwa Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: Konstant maskierte Atome werden mit einer bitpartitionierten Rekonstruktion wiederhergestellt, damit maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel einer gemischten Identität, deren Wiederherstellung sich häufig lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich reduzieren auf:

```c
x * y
```

### Reversing-Notizen

- CoBRA bevorzugt auf **angehobenen IR-Ausdrücken** oder Decompiler-Ausgaben ausführen, nachdem du die genaue Berechnung isoliert hast.
- `--bitwidth` explizit angeben, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt benötigst, sieh dir die lokalen Z3-Notizen hier an:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM-Pass-Plugin** (`libCobraPass.so`) ausgeliefert. Es ist nützlich, wenn du MBA-lastiges LLVM IR vor nachfolgenden Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte, carry-sensitive Residuen aus gemischten Domänen sollten als Signal verstanden werden, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell zu analysieren.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch `mov`-basierte Instruktionssequenzen und verwendet Signal-/Exception-Handling, um den Kontrollfluss zu ändern. Weitere Informationen:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Bei unterstützten Binärdateien kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuskieren. Es hat mehrere Abhängigkeiten.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du bei einem **CTF** mitmachst, kann dieser Workaround zum Finden der Flag sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **entry point** zu finden, suche die Funktionen nach `::main` ab, wie hier:

![Einen Rust-entry point in Ghidra finden, indem nach Funktionsnamen mit doppeltem Doppelpunkt und main gesucht wird](<../../images/image (1080).png>)

In diesem Fall hieß die Binärdatei authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Suche im **Internet** nach den **Namen** der aufgerufenen **Funktionen**, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binärdateien werden viele statische Strings nicht über NUL-terminierte Zeiger im C-Stil referenziert. Ein häufiges `rustc`-Layout ist ein **Zeiger-/Längen-Tupel** in **`.data.rel.ro`**, das auf den tatsächlichen String-Blob in **`.rodata`** verweist:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Strings zusammenführen oder Querverweise vollständig übersehen können.<sup>[[3]](#references)</sup>

Schneller Workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Durchlaufe **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen Stringzeiger.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (beispielsweise nur Längen zwischen **4** und **100** Byte).
6. Lies genau `length` Byte aus `.rodata`, anstatt bis `0x00` zu scannen.

Minimale Extractor-Logik:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Das ist beim Firmware-Reversing besonders nützlich, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Konfigurationsschlüssel, Command-Handler und Auth-bezogene Logik** offenbaren.

Wenn Ghidra diese Strings übersieht, führe ein benutzerdefiniertes Script/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **Wortgrößen, Endianness-Formate und Section-Layouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binaries kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du ein Delphi-Binary reversen musst, würde ich dir das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) empfehlen.

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle anschließend die Plugin-Datei aus.

Dieses Plugin führt das Binary aus und löst die Funktionsnamen zu Beginn des Debuggings dynamisch auf. Nachdem du das Debugging gestartet hast, drücke erneut die Start-Schaltfläche (die grüne oder f9), und ein Breakpoint wird am Anfang des eigentlichen Codes ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche drückst, kann der Debugger in der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Für gewöhnliche Go-Binaries kann [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) Runtime-Strukturen wiederherstellen und Funktionsnamen in IDA verbessern. Lade das Python-Plugin mit **Alt+F7**.

Wenn du ein Golang-Binary reversen musst, würde ich dir das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) empfehlen.

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle anschließend die Plugin-Datei aus.

Dadurch werden die Funktionsnamen aufgelöst.

### Metadaten ohne Symboltabelle wiederherstellen

Ein gestrippter Go-Executable benötigt weiterhin Runtime-Metadaten, um Program Counter Funktionen zuzuordnen. [GoReSym](https://github.com/mandiant/GoReSym) findet und parst Strukturen wie `pclntab` und `moduledata` mithilfe von Code, der aus der Go-Runtime abgeleitet wurde. So lassen sich Funktionsgrenzen, Namen, Quellcodepfade, Typen und Build-Details wiederherstellen, ohne auf die herkömmliche Symboltabelle angewiesen zu sein.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ein Obfuscator kann diese Strukturen nutzbar lassen und gleichzeitig die wiederhergestellten Namen ersetzen. Garble hasht beispielsweise Bezeichner und Paketpfade und entfernt Build-, Modul- und Debug-Informationen.<sup>[[12]](#references)</sup> Das obfuskierte Paket-Token muss für alle Funktionen dieses Pakets konsistent bleiben. Gruppiere Funktionen anhand des wiederholt auftretenden Tokens, leite anhand der Callees, Strings und APIs auf ein Paket und übertrage diese Paketbezeichnung anschließend auf die gesamte Gruppe.<sup>[[13]](#references)</sup>

### Garble-Namen mit GoResolver wiederherstellen

[GoResolver](https://github.com/volexity/GoResolver) kombiniert die Extraktion von Runtime-Symbolen mit der Erstellung sauberer Referenzen und dem Matching von Kontrollflussgraphen (CFGs). Gehe dabei wie folgt vor:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler-Version bestimmen.** Prüfe zuerst `BuildInfo` und eingebettete Versions-Strings. Falls der Obfuscator diese entfernt hat, vergleiche Teile der mitgelieferten Go-Runtime mit versionierten Referenz-Runtimes. In den Tests von Volexity reichten etwa `2%` der Runtime aus, um größere Go-Versionen zu unterscheiden. Betrachte dies als empirische Optimierung, nicht als allgemeingültigen Schwellenwert.<sup>[[13]](#references)</sup>
2. **Passende Referenzen erstellen.** Erzeuge saubere Binaries für die ermittelte Go-Version, die Zielarchitektur und wahrscheinliche Libraries. Eine passende Toolchain verringert die Unterschiede zwischen den vom Compiler erzeugten CFGs.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Funktionen vergleichen.** GoGrapher vergleicht CFGs von Funktionen und gibt normalisierte Scores von `0.0` bis `1.0` aus. Das Matching der Basic Blocks basiert auf einem gewichteten Vergleich ähnlicher Instruktionen. Matches mit hoher Konfidenz ordnen randomisierte Funktionen der sauberen Implementierung zu. Schwächere Matches können dennoch ein Paket oder Modul identifizieren.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validieren und importieren.** Bestätige vorgeschlagene Namen anhand von Aufrufbeziehungen, Konstanten, Strings und Seiteneffekten. Importiere dann den JSON-Bericht mit dem GoResolver-Plugin für IDA oder Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installiere die Toolchain und führe den kombinierten Extractor und Graph-Matcher aus:<sup>[[10]](#references)</sup>

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

Der standardmäßige Schwellenwert für signifikante Übereinstimmungen ist `0.9`. Mit den Optionen `--extract` und `--graph` lässt sich jeweils eine der beiden Phasen isolieren. Standardmäßig werden beide ausgeführt, da sich die wiederhergestellten Laufzeitmetadaten und die CFG-Evidenz ergänzen.<sup>[[10]](#references)</sup> CFG-Bewertungen sind heuristisch: Inlining, Build-Flags, Architektur und Unterschiede zwischen Bibliotheksversionen können die Graphstruktur verändern. Behalte daher nicht aufgelöste Funktionen bei, statt ihnen Namen mit geringer Zuverlässigkeit zuzuweisen.<sup>[[13]](#references)</sup>

### Go-Stringtabelle wiederherstellen

Go-Binaries platzieren die String-Bytes aller gelinkten Pakete in einer zusammenhängenden Tabelle. Die Einträge sind nicht mit NUL terminiert, und Laufzeitstrukturen legen weder die Basisadresse noch die Größe der Tabelle offen. Der Compiler ordnet Einträge jedoch unter allen Betriebssystemen und Architekturen zuerst nach Länge und dann alphabetisch. Nachdem ein Eintrag gefunden wurde, kann ein Analyst daher benachbarte Einträge durchgehen und Strings mithilfe von Datenreferenzen dem Code zuordnen.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatisiert diesen Workflow in IDA Pro und Ghidra. Warte zuerst, bis die automatische Analyse abgeschlossen ist, da das Plugin auf Datenreferenzen im Datensegment angewiesen ist. Der standardmäßige Anker ist der Runtime-String `entersyscall`. Von dort aus kann das Plugin in beide Richtungen suchen, die wiederhergestellten Strings in der Datenbank definieren und eine JSON-Zuordnung von Strings zu referenzierenden Funktionen exportieren.<sup>[[14]](#references)</sup>

Filtere den Bericht nach dem Paket der referenzierenden Funktion, um Anwendungscode oder Malware-Code von verknüpftem Bibliotheksrauschen zu trennen. Mit dieser Technik lassen sich keine Literale wiederherstellen, die durch Obfuskation zerstört wurden, etwa durch Garbles Transformation `-literals`. Sie kann jedoch weiterhin Runtime-Strings strukturieren, die nicht obfuskiert wurden.<sup>[[14]](#references)[[15]](#references)</sup>

### Go-Runtime-Typen wiederherstellen

Go bettet Runtime-Typinformationen ein, die von Funktionen wie der Garbage Collection verwendet werden. Wenn Build-Informationen entfernt wurden oder der Disassembler diese Metadaten nicht analysiert, scheinen Instruktionen beliebige Datenadressen zu laden, und der Zielbereich bleibt untypisiert. Durch die Wiederherstellung der Metadaten werden diese Adressen zu lesbaren Typreferenzen, wodurch sich die Fähigkeiten der Pakete leichter verstehen lassen.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kann Symbole extrahieren und Runtime-Typen analysieren, um einen JSON-Bericht zu erstellen. Die aktuelle CLI verwendet den Unterbefehl `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die Option `-y`/`--types` aktiviert das Parsen von Typen. Importiere den Bericht mit dem IDA-Pro- oder Ghidra-Plugin von GoResolver, um die wiederhergestellten Typen zu definieren und ihre Referenzen in der Analysedatenbank anzuwenden. Im mit diesem Feature eingeführten Berichtsformat bleiben die Mitglieder für RTTI-Adresse und wiederhergestellte Typen null, wenn `-y` weggelassen wird.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver unterstützt PE-, ELF- und Mach-O-Dateien für x86, AMD64, ARM und ARM64, daher lässt sich derselbe Workflow auf Go-Binärdateien von Windows, Linux und macOS anwenden.<sup>[[10]](#references)</sup>

## Kompiliertes Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einer kompilierten Python-Binärdatei im ELF-/EXE-Format erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du die **Binärdatei** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Oberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_** ** sehen, wie die **Tasten** des Game Boy Advance gedrückt werden

![Konfiguration der no$gba-Steuerung mit den Tastenbelegungen des Game Boy Advance](<../../images/image (581).png>)

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

In dieser Art von Programm ist also interessant, **wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** findest du die häufig anzutreffende Funktion: **KEYINPUT**.

![Ghidra-Ansicht eines GBA-Binaries mit einem Verweis auf KEYINPUT an Adresse 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild siehst du, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion, nach einigen Initialisierungsoperationen (die nicht wichtig sind):

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

Dabei wurde dieser Code gefunden:

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

Die letzte if-Bedingung prüft, ob **`uVar4`** zu den **zuletzt gedrückten Tasten** gehört und nicht die aktuelle Taste ist. Das entspricht dem Loslassen einer Taste (die aktuelle Taste ist in **`uVar1`** gespeichert).

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

Im vorherigen Code sieht man, dass wir **uVar1** (die Stelle, an der sich der **Wert der gedrückten Taste** befindet) mit einigen Werten vergleichen:

- Zuerst wird er mit dem **Wert 4** (**SELECT**-Taste) verglichen: In der Challenge löscht diese Taste den Bildschirm.
- Dann wird der Wert mit **8** (der **START**-Taste) verglichen; in dieser Challenge wird in diesem Zweig geprüft, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Stimmen die Werte überein, wird Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und erhöht.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

Für diese Challenge musste man also die Werte der Tasten kennen und **eine Kombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

**Quelle für dieses Tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binäre Deobfuskierung)

## References

- [1] [Vereinfachung der MBA-Verschleierung mit CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-Repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings dekodieren - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust-Strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-unterstütztes Reverse Engineering vereiteln – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Ein Ansatz zum Vergleich von Kontrollflussgraphen auf Basis des Abgleichs grundlegender Blöcke](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-Repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-Verschleierungsmechanismus](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kontrollflussgraph-Ähnlichkeit nutzen, um Golang-Binärdateien automatisch zu deobfuskieren](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-Repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Aktualisierungen der Volexity-Golang-Tools](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Alles reverse-engineeren](https://github.com/morluto/rea)
- [17] [REA-Analyse von Managed Code](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA-Anleitung zu CLI und Evidenz](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
