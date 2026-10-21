# Reversing-Tools & grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## Auf ImGui basierende Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-Automatisierung im User-Modus

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows-Kernel-Debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-Decompiler / Wat-Compiler

Online:

- Verwenden Sie [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (Binärdatei) zu wat (Klartext) zu **dekompilieren**
- Verwenden Sie [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um wat zu wasm zu **kompilieren**
- Sie können auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) zur Dekompilierung ausprobieren.

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

dotPeek ist ein Decompiler, der mehrere Formate **dekompiliert und untersucht**, darunter **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **ausführbare Dateien** (.exe). Eine dekompilierte Assembly kann als Visual-Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil: Wenn verlorener Quellcode aus einer älteren Assembly wiederhergestellt werden muss, kann dies Zeit sparen. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der idealen Tools für die **Analyse von Xamarin-Algorithmen.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an Ihre genauen Anforderungen anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die zahlreichen Reverse-Engineering-Funktionen dieses Tools an:

- Zeigt, wie Daten durch eine Bibliothek oder Komponente fließen
- Bietet Einblick in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, damit Sie APIs und verwendete Technologien besser nutzen können.
- Findet Abhängigkeiten und verschiedene Assemblies
- Ermittelt den genauen Ort von Fehlern in Ihrem Code, Drittanbieterkomponenten und Bibliotheken.
- Ermöglicht das Debuggen im Quellcode aller .NET-Codes, mit denen Sie arbeiten.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Sie können es unter jedem Betriebssystem verwenden (Sie können es direkt aus VSCode installieren; ein Download von git ist nicht nötig. Klicken Sie auf **Extensions** und **suchen Sie nach ILSpy**).\
Wenn Sie erneut **dekompilieren**, **ändern** und **kompilieren** müssen, können Sie [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### Managed-Code-Inspektion ohne Ausführung mit REA

**REA** kann PE/CLI-Metadaten und CIL untersuchen, ohne die Assembly zu laden. Beginnen Sie mit der Identität des Artefakts und untersuchen Sie anschließend die Member und deklarierten nativen Grenzen. Das ist nützlich, wenn Sie verdächtige Aufrufe überprüfen, bevor Sie einen Decompiler verwenden oder das Programm ausführen.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Für den Versionsvergleich verwendet `compare_managed_members` die rohe CIL-/Signaturidentität und Fingerprints dekodierter Instruktionen, statt Metadaten-Tokens als buildübergreifend stabil zu behandeln. Eine P/Invoke-Deklaration beweist nicht, dass nativer Code ausgeführt wurde; `verify_managed_native_boundaries` benötigt passende native Exporte oder Function Evidence, um diese Grenze zu überprüfen. Bewahre den Artifact-Digest, die MVID und nicht aufgelöste Zuordnungen zusammen mit dem Ergebnis auf.<sup>[[17]](#references)</sup>

### DNSpy-Logging

Um **DNSpy einige Informationen in eine Datei schreiben zu lassen**, kannst du dieses Snippet verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy-Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assemblyattribute** für das **Debugging** ändern:

![DNSpy-Logging – DNSpy-Debugging: Zuerst die Assemblyattribute für das Debugging ändern](<../../images/image (973).png>)

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

Speichern Sie dann die neue Datei über _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Speichern Sie dann die neue Datei über File Save module](<../../images/image (602).png>)

Das ist notwendig, denn andernfalls werden **zur Laufzeit** mehrere **Optimierungen** auf den Code angewendet. Dadurch kann es passieren, dass beim Debuggen ein **Breakpoint nie erreicht wird** oder einige **Variablen nicht vorhanden sind**.

Wenn Ihre .NET-Anwendung von **IIS** **ausgeführt** wird, können Sie sie anschließend wie folgt **neu starten**:

```
iisreset /noforce
```

Dann solltest du zunächst alle geöffneten Dateien schließen. Wähle anschließend im **Debug Tab** die Option **Attach to Process...** aus, um mit dem Debugging zu beginnen:

![DNSpy Logging - DNSpy Debugging: Schließe zunächst alle geöffneten Dateien und wähle im Debug Tab die Option Attach to Process aus, um mit dem Debugging zu beginnen](<../../images/image (318).png>)

Wähle dann **w3wp.exe** aus, um eine Verbindung zum **IIS server** herzustellen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle w3wp.exe aus, um eine Verbindung zum IIS server herzustellen, und klicke auf attach](<../../images/image (113).png>)

Da wir den Prozess nun debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Da wir den Prozess nun debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Da wir den Prozess nun debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (834).png>)

Klicke im Bereich **Modules** auf ein beliebiges Modul und wähle **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicke im Bereich Modules auf ein beliebiges Modul und wähle Open All Modules aus](<../../images/image (922).png>)

Klicke im **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und dann auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Klicke im Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und dann auf Sort Assemblies](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### Mit IDA

- **Lade rundll32** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Wähle den **Windbg**-Debugger aus
- Wähle "**Suspend on library load/unload**" aus

![Debugging DLLs - Mit IDA: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Konfiguriere die **Parameter** der Ausführung, indem du den **Pfad zur DLL** und die aufzurufende Funktion angibst:

![Debugging DLLs - Mit IDA: Konfiguriere die Parameter der Ausführung, indem du den Pfad zur DLL und die aufzurufende Funktion angibst](<../../images/image (704).png>)

Wenn du dann mit dem Debugging beginnst, **wird die Ausführung beim Laden jeder DLL angehalten**. Wenn rundll32 deine DLL lädt, wird die Ausführung also angehalten.

Diese Methode hält die Ausführung bei Ereignissen zum Laden von Modulen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist jedoch weniger direkt als beim weiter unten beschriebenen x64dbg-Ablauf.

### Mit x64dbg/x32dbg

- **Lade rundll32** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- **Ändere die Command Line** ( _File --> Change Command Line_ ) und gib den Pfad zur DLL sowie die aufzurufende Funktion an, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ändere _Options --> Settings_ und wähle "**DLL Entry**" aus.
- **Starte dann die Ausführung**. Der Debugger hält bei jedem dll main an. Irgendwann hält er **beim DLL Entry deiner DLL** an. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte, dass du in win64dbg **oben im Fenster von win64dbg** sehen kannst, **in welchem Code du dich befindest**, wenn die Ausführung aus irgendeinem Grund angehalten wird:

![Mit IDA - Mit x64dbg/x32dbg: Beachte, dass du oben im Fenster von win64dbg sehen kannst, in welchem Code du dich befindest, wenn die Ausführung aus irgendeinem Grund angehalten wird](<../../images/image (842).png>)

Diese Anzeige bestätigt, dass die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Arbeitsspeicher eines laufenden Spiels gespeichert sind, und sie zu ändern. Weitere Informationen findest du unter:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Frontend- und Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Reverse-Engineering-Aufgaben verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Frontend für mehrere Decompiler. Mit diesem Webdienst kannst du die Ausgaben verschiedener Decompiler für kleine ausführbare Dateien vergleichen.

## Evidenzgestützte native Analyse mit REA

**REA** stellt Analysen aus Hopper, Ghidra und IDA über CLI und MCP bereit. Voraussetzung sind Node.js 22.x (mindestens 22.19), 24.x (mindestens 24.11) oder 26+ sowie npm. Konfiguriere zuerst einen vorhandenen nativen Provider. Prüfe `rea providers --json` und wähle explizit einen Provider aus, wenn mehrere das Ziel unterstützen. Ersetze `0x1000` unten durch einen beobachteten Funktionsnamen oder eine Adresse aus dem Inventar.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Beginne mit einem Feature-String oder Symbol, folge Referenzen und Aufrufern und untersuche anschließend das ausgewählte Funktionsdossier und den Pseudocode mit `rea decompile`. REA bindet eine Sitzung an den ausgewählten Provider, statt ihn nach einem Fehler stillschweigend zu ersetzen. Für wiederholbare Abfragen verwendet `--snapshot PATH` nur übereinstimmende Artefakt-Bytes, Provider, Einstellungen, Operationen und Parameter wieder; ein Snapshot ist ein lokaler Cache, keine gespeicherte Provider-Datenbank. Bewahre die zurückgegebenen Evidence und expliziten Unbekannten, statt erschlossene Pfade oder Decompiler-Text als Originalquellcode zu behandeln.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript-/Electron-Einstiegspunkte, die zu nativen Add-ons führen, findest du unter [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptgesteuerte IDA- und Ghidra-Analyse mit einer lokalen TCP-Bridge

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) läuft innerhalb einer **bereits geöffneten** IDA-Datenbank oder eines Ghidra-CodeBrowser-Programms und ermöglicht einem separaten Skript, diese Analysedatenbank abzufragen und zu ändern. Führe `ID_Server.py` über die Python-CLI von IDA aus (`import ID_Server`) oder `Ghidra_Server.py` über den Script Manager von Ghidra. IDA bindet ab Port `5073` an `127.0.0.1` und prüft höhere Ports. Das aktuelle Ghidra-Skript startet bei Port `5093` und versucht zehn Ports bis einschließlich `5102`; sein Java-Socket bindet an die Wildcard-Adresse, nicht nur an Loopback. Prüfe vor dem Verbindungsaufbau den vom Instanzskript ausgegebenen Port. Anders als ein Headless Analyzer arbeitet diese Bridge mit dem Programm, das gerade in dieser GUI-Instanz geöffnet ist.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Sende **einen mit einem Zeilenumbruch abgeschlossenen Befehl pro Verbindung** und lies die mit einem Zeilenumbruch abgeschlossene Antwort. Das Ergebnis ist normalerweise JSON. Nachdem du beispielsweise eine importierte API gefunden hast, die für einen Eingabepfad relevant ist, ermittelt `IMPORTXREF` ihre Aufrufstellen; `DECOMP_XREF` dekompiliert dann stapelweise Aufrufer einer ausgewählten Adresse. `FUNC` untersucht eine Funktion, während `PCODE` die Zwischenrepräsentation des Decompilers zurückgibt. Verwende die Adresse aus der aktiven Datenbank, nicht eine Adresse, die aus einem anders rebasierten Binary übernommen wurde. Das folgende Beispiel verwendet den Standardport von IDA; für Ghidra verwendest du den von dessen Skript ausgegebenen Port.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Der gleiche Kanal kann **die Analysis-Datenbank ändern**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` und `PATCH` ändern Namen, Typen, Strukturdefinitionen, Funktionsgrenzen oder gespeicherte Bytes. `PATCH` ist eine Bearbeitung der Datenbank und **kein** Beleg für einen Patch im laufenden Prozess. Für keinen der Listener ist eine Authentifizierung dokumentiert. IDA ist nur über Loopback erreichbar, Ghidra hingegen möglicherweise auch über Netzwerkschnittstellen; beschränke den Zugriff auf den Ghidra-Listener, wenn du ihn verwendest. `QUIT` stoppt beide Listener, und IDA stellt außerdem `ida_bridge_stop()` bereit.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Shellcode mit BlobRunner debuggen

[**BlobRunner**](https://github.com/OALabs/BlobRunner) weist dem **Shellcode** Speicher zu, gibt dessen **Speicheradresse** aus und pausiert die Ausführung.\
Hänge einen Debugger wie IDA oder x64dbg an, setze einen Breakpoint an der ausgegebenen Adresse und setze die Ausführung fort, um den Shellcode zu debuggen.

Die GitHub-Seite mit den Releases enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unter folgendem Link findest du eine leicht modifizierte Version von Blobrunner. Um sie zu kompilieren, **erstelle einfach ein C/C++-Projekt in Visual Studio Code, kopiere den Code hinein und füge ihn ein und baue das Projekt**.


{{#ref}}
blobrunner.md
{{#endref}}

### Shellcode mit jmp2it debuggen

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) funktioniert ähnlich wie BlobRunner. Es weist dem Shellcode Speicher zu und tritt in eine Endlosschleife ein. Hänge den Debugger an, setze die Ausführung für **2–5 Sekunden** fort, pausiere innerhalb dieser Schleife und gehe dann schrittweise zum nächsten Aufruf, der die Ausführung an den zugewiesenen Shellcode übergibt.

![Debugger in jmp2its Endlosschleife unmittelbar vor dem Aufruf des zugewiesenen Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it findest du auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode mit Cutter debuggen

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter die Optionen „Open File“ und „Open Shellcode“ bietet. In meinem Fall wurde der Shellcode korrekt dekompiliert, als ich ihn als Datei öffnete, aber nicht, als ich ihn als Shellcode öffnete:

![Cutter zeigt unterschiedliche Analyseergebnisse, wenn dieselben Bytes als Datei oder als Shellcode geöffnet werden](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen bp; offenbar startet Cutter die Emulation dann automatisch von dort:

![Breakpoint am gewünschten Shellcode-Einstiegspunkt setzen, bevor die Cutter-Emulation gestartet wird](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Du kannst den Stack beispielsweise in einem Hexdump anzeigen:

![Den emulierten Shellcode-Stack im Hexdump von Cutter anzeigen](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Das Tool zeigt dir unter anderem, **welche Funktionen** der Shellcode verwendet und ob er sich im Speicher selbst **dekodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg verfügt außerdem über einen grafischen Launcher, in dem Sie die gewünschten Optionen auswählen und den Shellcode ausführen können

![Grafischer Launcher von scDbg zur Auswahl von Shellcode-Emulation und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der finale Shellcode ausgegeben, falls der Shellcode zur Laufzeit dynamisch im Speicher verändert wird (nützlich, um den decodierten Shellcode herunterzuladen). Der **start offset** kann hilfreich sein, um den Shellcode ab einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den Shellcode über das scDbg-Terminal zu debuggen (ich finde allerdings eine der zuvor erläuterten Optionen dafür besser, da Sie Ida oder x64dbg verwenden können).

### Disassemblieren mit CyberChef

Laden Sie Ihre Shellcode-Datei als Eingabe hoch und verwenden Sie das folgende Rezept, um sie zu disassemblieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA-Obfuskation deobfuskieren

Die Obfuskation mit **Mixed Boolean-Arithmetic (MBA)** verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten normalerweise nur bei **modularer Arithmetik mit fester Wortbreite** korrekt sind, daher spielen Überträge und Überläufe eine Rolle:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kann leicht ein falsches Ergebnis entstehen, weil die Bitbreiten-Semantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Arbeitsablauf

1. **Behalte die ursprüngliche Bitbreite bei**, die im gelifteten Code/IR/Decompiler-Output angegeben ist (`8/16/32/64` Bits).
2. **Ordne den Ausdruck ein**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
   - **Polynomial**: Produkte kommen vor
   - **Gemischt**: Produkte und bitweise Logik sind miteinander verflochten, oft mit wiederholten Teilausdrücken
3. **Verifiziere jede mögliche Umschreibung** durch Zufallstests oder einen SMT-Beweis. Lässt sich die Äquivalenz nicht beweisen, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Control-Flow-Flattening mit einem schmalen Ausführungsslice umgehen

Die Wiederherstellung des vollständigen Kontrollflussgraphen ist oft unnötig. Bei Control-Flow-Flattening, opaque predicates, großen Dispatchern oder MBA-lastigem Code folgst du den Referenzen von verschlüsselten Blobs und Output-Puffern bis zur kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Data-Flow-Slice oder führe ihn unabhängig aus; der Dispatcher ist für die erforderliche Lösung nicht nötig, wenn sich der relevante Zustand direkt initialisieren lässt.<sup>[[7]](#references)</sup>

Ein praktischer Arbeitsablauf ist:<sup>[[7]](#references)</sup>

1. Erfasse ausführbare und Datenabschnitte, Relocations und Cross-References. Dump die in `.rodata` liegenden Kandidatentabellen und bewahre dabei ihre Byte-Reihenfolge und Elementbreite.
2. Finde die letzte Routine, die den Klartext oder den Output-Puffer schreibt. Halte ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und den benötigten globalen Zustand fest.
3. Übertrage nur diese Operationen in ein Python-Modell mit fester Bitbreite. Wenn der Slice noch von zu vielen Zustandsdaten abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, statt das gesamte Programm zu emulieren.
4. Überprüfe, ob der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binärdatei ableitet: Entferne stille Fallbacks, durchsuche die Binärdatei nach eingebetteten Antworten und teste den Extractor mit unbekannten Builds, in denen Strings, Schlüssel, Bezeichner, Layouts und Obfuskations-Seeds geändert wurden.

Nützliche Befehle für einen ersten Durchlauf sind:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### MBA-Ausdrücke erkennen, die Konstanten verschleiern

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann seine Eingabe vollständig aufheben. Werte nach dem Extrahieren seiner Tabellen den gesamten 8-Bit-Wertebereich aus; eine einelementige Ausgabemenge beweist, dass das Byte konstant ist, ohne dass die umgebende Zustandsmaschine rekonstruiert werden muss.<sup>[[7]](#references)</sup>

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

Die abschließende Maske muss erhalten bleiben, da die ursprüngliche Addition einen Überlauf bei Bytebreite aufweist. Für einen größeren Wertebereich kann ein SMT solver prüfen, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Umgebungsgebundene Decodierung erkennen

Anti-Analyse-Prüfungen müssen weder Verzweigungen auslösen noch Abstürze verursachen. Ein Decoder kann ein Sensorergebnis in ein Schlüsselbit, eine Konstante eines opaque predicate oder den Zustand eines abgeflachten Dispatchers einmischen, normal fortfahren und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehlerzweige zu patchen; verfolge die Datenabhängigkeiten von Umgebungsprüfungen bis in den Decoderzustand, vergleiche denselben Ausschnitt auf dem authentischen Gerät und im Emulator und teste, wie sich das Erzwingen jedes Sensorergebnisses auf den endgültigen Puffer auswirkt.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Vereinfacher für Malware-Analyse und Reverse Engineering geschützter Binärdateien. Es klassifiziert den Ausdruck und leitet ihn durch spezialisierte Verarbeitungspipelines, statt auf alles denselben allgemeinen Rewrite-Durchlauf anzuwenden.<sup>[[2]](#references)</sup>

Schnellstart:

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

- **Linear MBA**: CoBRA wertet den Ausdruck mit booleschen Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden gegeneinander antreten, etwa Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: Konstantenmaskierte Atome werden mithilfe einer bitpartitionierten Rekonstruktion neu aufgebaut, damit maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in Temporärvariablen ausgelagert werden.

Beispiel für eine gemischte Identität, deren Wiederherstellung sich häufig lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich reduzieren auf:

```c
x * y
```

### Hinweise zum Reverse Engineering

- CoBRA sollte bevorzugt auf **lifted IR-Ausdrücken** oder Decompiler-Ausgaben ausgeführt werden, nachdem die genaue Berechnung isoliert wurde.
- Verwende `--bitwidth` explizit, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt benötigst, lies die lokalen Z3-Notizen hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM-Pass-Plugin** (`libCobraPass.so`) ausgeliefert. Es ist nützlich, wenn du MBA-lastiges LLVM IR vor nachfolgenden Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte, carry-sensitive Residuen aus gemischten Domänen sollten als Signal verstanden werden, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell zu untersuchen.

## XOR-State-Control-Flow-Flattening rekonstruieren

Ein OLLVM-artiger Flattener kann den aktuellen Basic-Block-State in zwei 64-Bit-Registern speichern und ihn am Dispatcher mit XOR rekonstruieren. Jeder ursprüngliche Block schreibt das Registerpaar für seinen nächsten State und springt zurück zum Dispatcher. Ein bedingter Block kann `CMOVcc` verwenden, um eine Hälfte des Paars anhand der CPU-Flags zu ersetzen. Wer nur sichtbaren Branch-Instruktionen folgt, übersieht daher beide Nachfolger. Anders als ein Dispatcher mit indirektem Sprung kann diese Form ausschließlich direkte Rücksprünge verwenden.<sup>[[19]](#references)[[20]](#references)</sup>

Um den Graphen zu rekonstruieren, identifiziere den Vergleichsbaum des Dispatchers und die beiden State-Register, ordne jeden verglichenen XOR-State seinem Zielblock zu und verfolge dann die erreichenden Schreibzugriffe auf das Registerpaar in jedem ursprünglichen Block. Berücksichtige bei bedingten Schreibzugriffen die flagsetzende Instruktion und beide `CMOVcc`-Ergebnisse. Ersetze den Dispatcher-Ausgang jedes Blocks durch seinen aufgelösten direkten Nachfolger oder bedingten Branch; anschließend ist der Dispatcher unerreichbar, ohne dass die Binärdatei gepatcht werden muss. Dies ist ein vollständiger CFG-Ansatz. Wenn nur ein Decoder relevant ist, kann der oben beschriebene [Workflow mit einem schmalen Ausführungsslice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) schneller sein.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatisiert diese Form in Binary Ninja. Kopiere `plugins/DispatchThis` in das Benutzer-Plugin-Verzeichnis von Binary Ninja und starte das Programm neu. Öffne bei der betroffenen Funktion **Function Settings** und wähle `OLLVM_XOR_64`. Falls die Analyse nicht startet, verwende **Analysis → Reanalyze All Functions**. Dieser Modus schreibt MLIL-Control-Flow-Kanten um, nicht die Bytes der Datei, und benötigt weder Z3 noch den Resolver für indirekte Sprünge. Er wurde mit Binary Ninja 5.3.9757+ getestet. Die inaktiven State-Schreibzugriffe in den einzelnen Blöcken werden nicht entfernt; verwechsle sie daher nicht mit weiterhin aktiven Übergängen.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch `mov`-basierte Instruktionssequenzen und verwendet Signal- und Exception-Handling, um den Control Flow zu verändern. Weitere Informationen:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Für unterstützte Binärdateien kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuskieren. Es hat mehrere Abhängigkeiten.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Und [installiere keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **Einstiegspunkt** zu finden, suche in den Funktionen nach `::main`, wie hier:

![Einen Rust-Einstiegspunkt in Ghidra finden, indem nach Funktionsnamen mit doppeltem Doppelpunkt und main gesucht wird](<../../images/image (1080).png>)

In diesem Fall hieß die Binärdatei authenticator, daher ist ziemlich offensichtlich, dass dies die interessante Hauptfunktion ist.\
Wenn du den **Namen** der aufgerufenen **Funktionen** kennst, suche im **Internet** nach ihnen, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binärdateien werden viele statische Strings nicht über C-artige, NUL-terminierte Zeiger referenziert. Ein gängiges `rustc`-Layout ist ein **Zeiger-/Längen-Tupel** in **`.data.rel.ro`**, das auf den eigentlichen String-Block in **`.rodata`** zeigt:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Zeichenketten zusammenführen oder Querverweise vollständig übersehen kann.<sup>[[3]](#references)</sup>

Schnell-Workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Durchlaufe **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen String-Zeiger.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (behalte zum Beispiel Längen zwischen **4** und **100** Bytes bei).
6. Lies genau `length` Bytes aus `.rodata`, anstatt bis `0x00` zu suchen.

Minimale Extractor-Logik:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Das ist beim Firmware-Reversing besonders nützlich, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Config-Schlüssel, Command-Handler und Auth-bezogene Logik** offenlegen.

Wenn Ghidra diese Strings übersieht, führe ein benutzerdefiniertes Skript/Plugin aus, das dieselbe Heuristik anwendet und an den referenzierten `.rodata`-Offsets String-Daten erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **Wortbreiten, Endianness und Abschnittslayouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du eine Delphi-Binärdatei reverse-engineeren musst, empfehle ich das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi).

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dieses Plugin führt die Binärdatei aus und löst zu Beginn des Debuggings dynamisch Funktionsnamen auf. Nachdem du das Debugging gestartet hast, drücke erneut die Start-Schaltfläche (die grüne oder f9), und ein Breakpoint wird am Anfang des eigentlichen Codes ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche klickst, kann der Debugger in der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Für gewöhnliche Go-Binärdateien kann [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) Laufzeitstrukturen wiederherstellen und Funktionsnamen in IDA verbessern. Lade das Python-Plugin mit **Alt+F7**.

Wenn du eine Golang-Binärdatei reverse-engineeren musst, empfehle ich das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper).

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dadurch werden die Funktionsnamen aufgelöst.

### Metadaten ohne Symboltabelle wiederherstellen

Auch eine gestrippte Go-Programmdatei benötigt Laufzeitmetadaten, um Program Counter Funktionen zuzuordnen. [GoReSym](https://github.com/mandiant/GoReSym) findet und analysiert mithilfe von Code, der von der Go-Runtime abgeleitet ist, Strukturen wie `pclntab` und `moduledata`. So lassen sich Funktionsgrenzen, Namen, Quellpfade, Typen und Build-Details wiederherstellen, ohne auf die herkömmliche Symboltabelle angewiesen zu sein.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ein Obfuscator kann diese Strukturen weiterhin nutzbar lassen und gleichzeitig die wiederhergestellten Namen ersetzen. Garble hasht beispielsweise Bezeichner und Paketpfade und entfernt Build-, Modul- und Debug-Informationen.<sup>[[12]](#references)</sup> Das obfuskierte Paket-Token muss für alle Funktionen desselben Pakets konsistent bleiben. Gruppiere Funktionen anhand des wiederholten Tokens, leite ein Paket aus dessen Callees, Strings und APIs ab und übertrage diese Paketbezeichnung anschließend auf die gesamte Gruppe.<sup>[[13]](#references)</sup>

### Garble-Namen mit GoResolver wiederherstellen

[GoResolver](https://github.com/volexity/GoResolver) kombiniert die Extraktion von Runtime-Symbolen mit der Generierung sauberer Referenzen und dem Abgleich von Kontrollflussgraphen (CFGs). Gehe dabei wie folgt vor:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler-Version ermitteln.** Prüfe zuerst `BuildInfo` und eingebettete Versions-Strings. Hat der Obfuscator diese entfernt, vergleiche Teile der mitgelieferten Go-Runtime mit Referenz-Runtimes verschiedener Versionen. In den Tests von Volexity reichten etwa `2%` der Runtime aus, um wichtige Go-Versionen zu unterscheiden. Betrachte dies als empirische Optimierung, nicht als universellen Schwellenwert.<sup>[[13]](#references)</sup>
2. **Passende Referenzen erstellen.** Erzeuge saubere Binaries für die ermittelte Go-Version, die Zielarchitektur und wahrscheinliche Libraries. Ein passender Toolchain verringert die Unterschiede in den vom Compiler generierten CFGs.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Funktionen vergleichen.** GoGrapher gleicht Funktions-CFGs ab und gibt normalisierte Scores von `0.0` bis `1.0` aus. Der Abgleich von Basic Blocks basiert auf einem gewichteten Vergleich ähnlicher Instruktionen. Treffer mit hoher Konfidenz ordnen randomisierte Funktionen der sauberen Implementierung zu. Auch schwächere Treffer können ein Paket oder Modul identifizieren.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validieren und importieren.** Bestätige vorgeschlagene Namen anhand von Aufrufbeziehungen, Konstanten, Strings und Seiteneffekten. Importiere anschließend den JSON-Bericht mit dem GoResolver-Plugin für IDA oder Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Der standardmäßige Schwellenwert für signifikante Übereinstimmungen ist `0.9`. Mit den Schaltern `--extract` und `--graph` lässt sich jeweils eine der beiden Phasen isolieren. Standardmäßig werden beide ausgeführt, da sich die wiederhergestellten Runtime-Metadaten und die CFG-Belege ergänzen.<sup>[[10]](#references)</sup> CFG-Scores sind heuristisch: Inlining, Build-Flags, Architektur und Unterschiede zwischen Bibliotheksversionen können die Graphstruktur verändern. Behalte daher nicht aufgelöste Funktionen bei, statt ihnen Namen mit geringer Konfidenz zuzuweisen.<sup>[[13]](#references)</sup>

### Wiederherstellen der Go-Stringtabelle

Go-Binaries legen die String-Bytes aller gelinkten Packages in einer zusammenhängenden Tabelle ab. Die Einträge sind nicht NUL-terminiert, und Runtime-Strukturen geben weder die Basisadresse noch die Größe der Tabelle an. Der Compiler sortiert die Einträge jedoch unter verschiedenen Betriebssystemen und Architekturen zuerst nach Länge und dann alphabetisch. Nachdem ein Eintrag gefunden wurde, kann ein Analyst daher benachbarte Einträge durchlaufen und mithilfe von Datenquerverweisen Strings mit Code verknüpfen.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatisiert diesen Workflow in IDA Pro und Ghidra. Warte zunächst, bis die automatische Analyse abgeschlossen ist, da das Plugin auf Datenquerverweisen zu Datensegmenten angewiesen ist. Als Standard-Anker dient der Runtime-String `entersyscall`. Anschließend kann das Plugin in beide Richtungen suchen, die wiederhergestellten Strings in der Datenbank definieren und ein JSON-Mapping von Strings zu referenzierenden Funktionen exportieren.<sup>[[14]](#references)</sup>

Filtere den Bericht nach dem Package der referenzierenden Funktion, um Anwendungscode oder Malware-Code von nicht relevantem Code gelinkter Bibliotheken zu trennen. Mit dieser Technik lassen sich keine Literale wiederherstellen, die durch Obfuskation zerstört wurden, etwa durch Garbles Transformation `-literals`. Sie kann jedoch weiterhin Runtime-Strings organisieren, die nicht obfuskiert wurden.<sup>[[14]](#references)[[15]](#references)</sup>

### Wiederherstellen von Go-Runtime-Typen

Go bettet Runtime-Typinformationen ein, die von Funktionen wie der Garbage Collection verwendet werden. Wenn Build-Informationen entfernt wurden oder der Disassembler diese Metadaten nicht auswertet, können Anweisungen so wirken, als würden sie beliebige Datenadressen laden, und der Zielbereich bleibt untypisiert. Durch das Wiederherstellen der Metadaten werden diese Adressen zu lesbaren Typverweisen, wodurch sich die Funktionen eines Packages leichter nachvollziehen lassen.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kann Symbole extrahieren und Runtime-Typen in einen JSON-Bericht parsen. Die aktuelle CLI verwendet den Unterbefehl `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die Option `-y`/`--types` aktiviert das Parsen von Typen. Importiere den Bericht mit dem IDA-Pro- oder Ghidra-Plugin von GoResolver, um die wiederhergestellten Typen zu definieren und ihre Referenzen in der Analysedatenbank anzuwenden. Im mit dieser Funktion eingeführten Berichtsformat bleiben die Mitglieder für die RTTI-Adresse und die wiederhergestellten Typen null, wenn `-y` weggelassen wird.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver unterstützt PE-, ELF- und Mach-O-Dateien für x86, AMD64, ARM und ARM64. Daher gilt derselbe Workflow für Go-Binärdateien unter Windows, Linux und macOS.<sup>[[10]](#references)</sup>

## Compiled Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einer kompilierten Python-ELF-/EXE-Binärdatei erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du die **Binärdatei** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_** ** sehen, wie die Game-Boy-Advance-**Tasten** gedrückt werden

![no$gba-Konfiguration der Steuerung mit Zuordnung der Game-Boy-Advance-Tasten](<../../images/image (581).png>)

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

In dieser Art von Programm ist also **entscheidend, wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** finden Sie die häufig anzutreffende Funktion: **KEYINPUT**.

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

Das letzte if prüft, ob **`uVar4`** zu den zuletzt gedrückten Tasten gehört und nicht die aktuelle Taste ist – also, ob eine Taste losgelassen wird (die aktuelle Taste wird in **`uVar1`** gespeichert).

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

- Zuerst wird er mit dem **Wert 4** (der **SELECT**-Taste) verglichen: In dieser Challenge löscht diese Taste den Bildschirm.
- Anschließend wird der Wert mit **8** (der **START**-Taste) verglichen; in dieser Challenge prüft dieser Pfad, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Stimmen die Werte überein, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und inkrementiert.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

In dieser Challenge musste man also, wenn man die Werte der Tasten kennt, **eine Kombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [archivierter Nostalgia-Challenge-Write-up](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary-Deobfuskation)

## References

- [1] [MBA-Obfuskation mit CoBRA vereinfachen](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA-Repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings dekodieren - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust-Strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-gestütztes Reverse Engineering vereiteln – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Ein Ansatz zum Vergleich von Kontrollflussgraphen auf Basis des Abgleichs von Basisblöcken](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-Repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-Obfuskationsmechanismus](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kontrollflussgraph-Ähnlichkeit nutzen, um Golang-Binärdateien automatisch zu deobfuskieren](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-Repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Aktualisierungen der Golang-Tools von Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Alles reverse engineeren](https://github.com/morluto/rea)
- [17] [REA-Analyse von Managed Code](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA-Anleitung zu CLI und Belegen](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Workflow zur Aufhebung der Kontrollfluss-Obfuskation in Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut-MF-Zero-Day-Einbruch, Java-Loader, Web-Shell und AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge-README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementierung des IDA-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementierung des Ghidra-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) bindet an die Platzhalteradresse](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
