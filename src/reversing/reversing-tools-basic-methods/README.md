# Reversing Tools & grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## Auf ImGui basierende Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-Automatisierung im Benutzermodus

{{#ref}}
windbg-automation.md
{{#endref}}

## Ausnahmegesteuerter Kontrollfluss unter Windows

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows-Kernel-Debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-Decompiler / Wat-Compiler

Online:

- Verwende [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (Binärformat) zu wat (Klartext) zu **dekompilieren**
- Verwende [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um wat zu wasm zu **kompilieren**
- Du kannst zur Dekompilierung auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) ausprobieren.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-gecachter Bytecode

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

Der Vorteil: Wenn verlorener Quellcode aus einer älteren Assembly wiederhergestellt werden muss, kann dies Zeit sparen. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der idealen Tools für die **Analyse von Xamarin-Algorithmen**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, mit der sich das Tool genau an deine Anforderungen anpassen lässt, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die zahlreichen Reverse-Engineering-Funktionen dieses Tools an:

- Gibt Einblick in den Datenfluss durch eine Bibliothek oder Komponente
- Gibt Einblick in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblies
- Ermittelt den genauen Ort von Fehlern in deinem Code sowie in Komponenten und Bibliotheken von Drittanbietern.
- Ermöglicht das Debuggen im Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem Betriebssystem verwenden (du kannst es direkt in VSCode installieren; ein Download von Git ist nicht nötig. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du **dekompilieren**, **ändern** und anschließend erneut **kompilieren** möchtest, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### Ausführungsfreie verwaltete Untersuchung mit REA

**REA** kann PE/CLI-Metadaten und CIL untersuchen, ohne die Assembly zu laden. Beginne mit der Identität des Artefakts und untersuche anschließend Member und deklarierte native Grenzen. Das ist hilfreich, wenn verdächtige Aufrufe geprüft werden sollen, bevor ein Decompiler verwendet oder das Programm ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Für den Versionsvergleich verwendet `compare_managed_members` die rohe CIL-/Signatur-Identität und Fingerprints dekodierter Instruktionen, statt Metadaten-Token als buildübergreifend stabil zu behandeln. Eine P/Invoke-Deklaration beweist nicht, dass nativer Code ausgeführt wurde; `verify_managed_native_boundaries` benötigt passende native Exporte oder Function Evidence, um diese Grenze zu prüfen. Bewahre den Artefakt-Digest, die MVID und ungelöste Zuordnungen zusammen mit dem Ergebnis auf.<sup>[[17]](#references)</sup>

### DNSpy-Protokollierung

Um **DNSpy einige Informationen in eine Datei protokollieren zu lassen**, kannst du diesen Ausschnitt verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy-Debugging

Um Code mit DNSpy zu debuggen, musst du Folgendes tun:

Ändere zuerst die **Assembly-Attribute** für das **Debugging**:

![DNSpy Logging – DNSpy-Debugging: Ändere zuerst die Assembly-Attribute für das Debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Speichere dann die neue Datei über _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Das ist notwendig, da andernfalls zur **runtime** mehrere **Optimierungen** auf den Code angewendet werden. Dadurch kann es passieren, dass beim Debuggen ein **breakpoint nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn deine .NET-Anwendung von **IIS** **ausgeführt** wird, kannst du sie anschließend wie folgt **neu starten**:

```
iisreset /noforce
```

Dann solltest du, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Dann solltest du, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und im Debug Tab Attach to Process auswählen](<../../images/image (318).png>)

Wähle anschließend **w3wp.exe** aus, um eine Verbindung zum **IIS server** herzustellen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle anschließend w3wp.exe aus, um eine Verbindung zum IIS server herzustellen, und klicke auf attach](<../../images/image (113).png>)

Da wir jetzt den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Da wir jetzt den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Da wir jetzt den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (834).png>)

Klicke unter **Modules** auf ein beliebiges Modul und wähle **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicke unter Modules auf ein beliebiges Modul und wähle Open All Modules aus](<../../images/image (922).png>)

Klicke in **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und klicke auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Klicke in Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und klicke auf Sort Assemblies](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### IDA verwenden

- **rundll32 laden** (64-bit-Version unter C:\Windows\System32\rundll32.exe und 32-bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Den **Windbg**-Debugger auswählen
- "**Suspend on library load/unload**" auswählen

![Debugging von DLLs - IDA verwenden: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Die **Parameter** für die Ausführung konfigurieren und dabei den **Pfad zur DLL** sowie die aufzurufende Funktion angeben:

![Debugging von DLLs - IDA verwenden: Konfiguriere die Parameter für die Ausführung und gib dabei den Pfad zur DLL sowie die aufzurufende Funktion an](<../../images/image (704).png>)

Wenn du dann mit dem Debugging beginnst, **wird die Ausführung angehalten, sobald eine DLL geladen wird**. Wenn rundll32 deine DLL lädt, wird die Ausführung also angehalten.

Diese Methode hält bei Ereignissen zum Laden von Modulen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist jedoch weniger direkt als beim weiter unten beschriebenen x64dbg-Workflow.

### x64dbg/x32dbg verwenden

- **rundll32 laden** (64-bit-Version unter C:\Windows\System32\rundll32.exe und 32-bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Die **Command Line ändern** ( _File --> Change Command Line_ ) und den Pfad der DLL sowie die aufzurufende Funktion angeben, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ ändern und "**DLL Entry**" auswählen.
- Anschließend **die Ausführung starten**. Der Debugger hält bei jedem DLL-Main-Einstiegspunkt an. Irgendwann hält er **am DLL-Einstiegspunkt deiner DLL** an. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte: Wenn die Ausführung in win64dbg aus irgendeinem Grund angehalten wird, kannst du **oben im win64dbg-Fenster** sehen, **in welchem Code du dich gerade befindest**:

![IDA verwenden - x64dbg/x32dbg verwenden: Beachte: Wenn die Ausführung in win64dbg aus irgendeinem Grund angehalten wird, kannst du oben im win64dbg-Fenster sehen, in welchem Code du dich gerade befindest](<../../images/image (842).png>)

Diese Anzeige bestätigt, dass die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Anwendungen / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern. Weitere Informationen:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Front-End-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Aufgaben im Bereich Reverse Engineering verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Front-End für verschiedene Decompiler. Mit diesem Webdienst kannst du die Ausgabe verschiedener Decompiler für kleine ausführbare Dateien vergleichen.

## Evidenzgestützte native Untersuchung mit REA

**REA** stellt Analysen von Hopper, Ghidra und IDA über CLI und MCP bereit. Erfordert Node.js 22.x (mindestens 22.19), 24.x (mindestens 24.11) oder 26+ sowie npm. Konfiguriere zuerst einen vorhandenen nativen Provider. Prüfe `rea providers --json` und wähle explizit einen Provider aus, wenn mehrere das Ziel unterstützen. Verwende anstelle von `0x1000` unten einen beobachteten Funktionsnamen oder eine Adresse aus dem Inventar.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Beginne mit einem Feature-String oder Symbol, folge Referenzen und Aufrufern und untersuche dann das Dossier und den Pseudocode der ausgewählten Funktion mit `rea decompile`. REA bindet eine Sitzung an den ausgewählten Provider, statt ihn nach einem Fehler stillschweigend zu ersetzen. Für wiederholbare Abfragen verwendet `--snapshot PATH` nur übereinstimmende Artefakt-Bytes, Provider, Einstellungen, Operationen und Parameter erneut; ein Snapshot ist ein lokaler Cache und keine gespeicherte Provider-Datenbank. Bewahre die zurückgegebenen Evidence und explizit als unbekannt gekennzeichnete Informationen auf, statt abgeleitete Pfade oder Decompiler-Text als Originalquellcode zu behandeln.<sup>[[16]](#references)[[18]](#references)</sup>

Informationen zu JavaScript-/Electron-Einstiegspunkten, die zu nativen Add-ons führen, findest du unter [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Scriptgesteuerte IDA- und Ghidra-Analyse mit einer lokalen TCP-Bridge

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) läuft innerhalb einer **bereits geöffneten** IDA-Datenbank oder eines Ghidra-CodeBrowser-Programms und ermöglicht es einem separaten Skript, diese Analysedatenbank abzufragen und zu ändern. Führe `ID_Server.py` über die Python-CLI von IDA aus (`import ID_Server`) oder `Ghidra_Server.py` über den Script Manager von Ghidra. IDA bindet sich ab Port `5073` an `127.0.0.1` und durchsucht höhere Ports. Das aktuelle Ghidra-Skript startet bei Port `5093` und versucht zehn Ports bis einschließlich `5102`; sein Java-Socket bindet sich an die Wildcard-Adresse und nicht nur an Loopback. Prüfe vor dem Verbinden den von der Instanz ausgegebenen Port. Anders als ein Headless Analyzer arbeitet diese Bridge mit dem Programm, das aktuell in dieser GUI-Instanz geöffnet ist.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Sende **einen mit einem Zeilenumbruch abgeschlossenen Befehl pro Verbindung** und lies die mit einem Zeilenumbruch abgeschlossene Antwort. Das Ergebnis ist normalerweise JSON. Nachdem du beispielsweise eine importierte API gefunden hast, die für einen Eingabepfad relevant ist, ermittelt `IMPORTXREF` deren Aufrufstellen; `DECOMP_XREF` dekompiliert anschließend gesammelt die Aufrufer einer ausgewählten Adresse. `FUNC` untersucht eine Funktion, während `PCODE` die Zwischendarstellung des Decompilers zurückgibt. Verwende die Adresse aus der aktiven Datenbank und keine Adresse, die aus einem anders rebasierten Binary kopiert wurde. Das folgende Beispiel verwendet den Standardport von IDA; verwende für Ghidra den vom Skript ausgegebenen Port.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Der gleiche Channel kann **die Analysedatenbank ändern**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` und `PATCH` ändern Namen, Typen, Strukturdefinitionen, Funktionsgrenzen oder gespeicherte Bytes. `PATCH` ist eine Datenbankänderung und **kein** Beleg für einen Patch eines laufenden Prozesses. Keiner der Listener dokumentiert eine Authentifizierung. IDA ist nur über Loopback erreichbar, Ghidra hingegen möglicherweise über Netzwerkschnittstellen; beschränke den Zugriff auf den Ghidra-Listener, wenn du ihn verwendest. `QUIT` beendet beide Listener, und IDA stellt außerdem `ida_bridge_stop()` bereit.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Einen Shellcode mit blobrunner debuggen

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert Speicher für den **Shellcode**, gibt dessen **Speicheradresse** aus und hält die Ausführung an.\
Hänge einen Debugger wie IDA oder x64dbg an, setze einen Breakpoint an der ausgegebenen Adresse und setze die Ausführung fort, um den Shellcode zu debuggen.

Die GitHub-Releases-Seite enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unter folgendem Link findest du eine leicht veränderte Version von Blobrunner. Um sie zu kompilieren, **erstelle einfach ein C/C++-Projekt in Visual Studio Code, kopiere den Code hinein und erstelle den Build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Einen Shellcode mit jmp2it debuggen

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) funktioniert ähnlich wie BlobRunner. Es reserviert Speicher für den Shellcode und wechselt in eine Endlosschleife. Hänge den Debugger an, setze die Ausführung für **2–5 Sekunden** fort, halte sie innerhalb der Schleife an und gehe zum folgenden Aufruf, der die Ausführung an den reservierten Shellcode überträgt.

![Debugger in jmp2its Endlosschleife direkt vor dem Aufruf des reservierten Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it findest du auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode mit Cutter debuggen

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter die Optionen „Open File“ und „Open Shellcode“ bietet. In meinem Fall wurde der Shellcode korrekt dekompiliert, wenn ich ihn als Datei öffnete, aber nicht, wenn ich ihn als Shellcode öffnete:

![Cutter zeigt unterschiedliche Analyseergebnisse beim Öffnen derselben Bytes als Datei oder als Shellcode](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen bp. Offenbar startet Cutter die Emulation dann automatisch an dieser Stelle:

![Breakpoint am gewünschten Einstiegspunkt des Shellcodes setzen, bevor die Cutter-Emulation gestartet wird](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Du kannst beispielsweise den Stack in einem Hexdump anzeigen:

![Den emulierten Shellcode-Stack im Hexdump von Cutter anzeigen](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Das Tool zeigt dir beispielsweise, **welche Funktionen** der Shellcode verwendet und ob er sich im Speicher selbst **dekodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg verfügt auch über einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und den Shellcode ausführen kannst.

![Grafischer Launcher von scDbg zur Auswahl von Shellcode-Emulation und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der finale Shellcode ausgegeben, wenn er dynamisch im Speicher geändert wurde (nützlich, um den dekodierten Shellcode herunterzuladen). Der **start offset** kann nützlich sein, um den Shellcode ab einem bestimmten Offset zu starten. Die Option **Debug Shell** eignet sich zum Debuggen des Shellcodes über das scDbg-Terminal. Ich finde allerdings eine der zuvor beschriebenen Optionen dafür besser, da du dann Ida oder x64dbg verwenden kannst.

### Disassemblieren mit CyberChef

Lade deine Shellcode-Datei als Eingabe hoch und verwende das folgende Rezept, um sie zu disassemblieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskation von MBA-Obfuskation

**Mixed Boolean-Arithmetic (MBA)**-Obfuskation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) mit bitweisen Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten in der Regel nur bei **modularer Arithmetik mit fester Bitbreite** korrekt sind, sodass Überträge und Überläufe eine Rolle spielen:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kann das Ergebnis leicht falsch sein, weil die Semantik der Bitbreite ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite bei**, die aus dem gehobenen Code/der IR/der Decompiler-Ausgabe stammt (`8/16/32/64` Bit).
2. **Ordne den Ausdruck ein**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
   - **Polynomial**: Produkte kommen vor
   - **Gemischt**: Produkte und bitweise Logik sind verschachtelt, oft mit wiederholten Teilausdrücken
3. **Überprüfe jede mögliche Umschreibung** durch zufällige Tests oder einen SMT-Beweis. Wenn sich die Äquivalenz nicht beweisen lässt, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Umgehe abgeflachte Kontrollflüsse mit einem schmalen Ausführungsslice

Die vollständige Rekonstruktion des Kontrollflussgraphen ist oft unnötig. Bei Control-Flow-Flattening, opaque predicates, großen Dispatchern oder MBA-lastigem Code folgst du den Referenzen von verschlüsselten Blobs und Ausgabepuffern bis zur kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Datenfluss-Slice oder führe ihn unabhängig aus; der Dispatcher gehört nicht zur erforderlichen Lösung, wenn sich der relevante Zustand direkt initialisieren lässt.<sup>[[7]](#references)</sup>

Ein praktischer Workflow ist:<sup>[[7]](#references)</sup>

1. Erfasse ausführbare und Datensektionen, Relokationen und Querverweise. Dumppe mögliche Tabellen aus `.rodata` und bewahre dabei Byte-Reihenfolge und Elementbreite.
2. Ermittle die letzte Routine, die den Klartext- oder Ausgabepuffer beschreibt. Halte ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und den benötigten globalen Zustand fest.
3. Übertrage nur diese Operationen in ein Python-Modell mit fester Bitbreite. Wenn der Slice weiterhin von zu viel Zustand abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, statt das gesamte Programm zu emulieren.
4. Überprüfe, ob der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binary ableitet: Entferne stille Fallbacks, durchsuche sie nach eingebetteten Antworten und teste ihn mit unbekannten Builds, in denen Strings, Schlüssel, Bezeichner, Layouts und Obfuskations-Seeds geändert wurden.

Nützliche Befehle für einen ersten Durchlauf sind:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### MBA-Ausdrücke erkennen, die als Konstanten getarnt sind

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann seine Eingabe vollständig aufheben. Nachdem die Tabellen extrahiert wurden, werte den Ausdruck über den gesamten 8-Bit-Wertebereich aus. Eine einelementige Ausgabemenge beweist, dass das Byte konstant ist, ohne die umgebende Zustandsmaschine rekonstruieren zu müssen.<sup>[[7]](#references)</sup>

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

Behalte die abschließende Maske bei, da die ursprüngliche Addition bei der Bytebreite überläuft. Frage für einen größeren Wertebereich einen SMT-Solver, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Umgebungsgebundene Decodierung erkennen

Anti-Analyse-Prüfungen müssen nicht zwingend einen Sprung oder Absturz auslösen. Ein Decoder kann das Ergebnis eines Sensors in ein Schlüsselbit, eine Konstante eines opaque predicate oder den Zustand eines abgeflachten Dispatchers einmischen, normal fortfahren und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehlerzweige zu patchen. Verfolge die Datenabhängigkeiten von Umgebungsprüfungen bis in den Decoder-Zustand, vergleiche denselben Slice auf dem echten Gerät und im Emulator und teste, wie sich das Erzwingen jedes Sensorergebnisses auf den endgültigen Puffer auswirkt.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Simplifier für Malware-Analyse und das Reversing geschützter Binaries. Das Tool klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, anstatt auf alles denselben generischen Rewrite-Pass anzuwenden.<sup>[[2]](#references)</sup>

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

Nützliche Anwendungsfälle:

- **Linear MBA**: CoBRA wertet den Ausdruck mit Boolean-Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden wie Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation gegeneinander antreten.
- **Semilinear MBA**: Konstantmaskierte Atome werden mit einer bitpartitionierten Rekonstruktion wiederhergestellt, damit maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel für eine gemischte Identität, deren Wiederherstellung sich oft lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich reduzieren auf:

```c
x * y
```

### Hinweise zum Reversing

- Führe CoBRA bevorzugt auf **lifted IR-Ausdrücken** oder Decompiler-Ausgaben aus, nachdem du die genaue Berechnung isoliert hast.
- Verwende explizit `--bitwidth`, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt benötigst, sieh dir die lokalen Z3-Hinweise hier an:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM-Pass-Plugin** (`libCobraPass.so`) ausgeliefert. Das ist nützlich, wenn du MBA-lastiges LLVM IR vor späteren Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte, carry-sensitive Residuen aus gemischten Domänen solltest du als Hinweis auffassen, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell nachzuvollziehen.

## XOR-state control-flow flattening wiederherstellen

Ein OLLVM-artiger Flattener kann den aktuellen Basic-Block-Zustand in zwei 64-Bit-Registern speichern und ihn an einem Dispatcher per XOR rekonstruieren. Jeder ursprüngliche Block schreibt das Registerpaar für seinen Folgezustand und springt zurück zum Dispatcher. Ein bedingter Block kann `CMOVcc` verwenden, um abhängig von CPU-Flags eine Hälfte des Paars zu ersetzen. Wenn du nur sichtbaren Branch-Instruktionen folgst, übersiehst du daher die beiden möglichen Nachfolger. Anders als ein Dispatcher mit indirektem Sprung kann diese Form durchgehend direkte Rücksprünge verwenden.<sup>[[19]](#references)[[20]](#references)</sup>

Um den Graphen wiederherzustellen, identifiziere den Vergleichsbaum des Dispatchers und die beiden Zustandsregister, ordne jeden verglichenen XOR-Zustand seinem Zielblock zu und verfolge dann die erreichenden Schreibzugriffe auf das Registerpaar in jedem ursprünglichen Block. Beziehe bei bedingten Schreibzugriffen die Flags setzende Instruktion und beide `CMOVcc`-Ergebnisse mit ein. Ersetze den Dispatcher-Ausgang jedes Blocks durch seinen aufgelösten direkten Nachfolger oder bedingten Branch. Danach ist der Dispatcher unerreichbar, ohne dass du die Binärdatei patchen musst. Dieser Ansatz berücksichtigt das vollständige CFG. Wenn nur ein Decoder relevant ist, ist der oben beschriebene [Workflow mit einem engen Ausführungsslice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) möglicherweise schneller.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatisiert diese Form in Binary Ninja. Kopiere `plugins/DispatchThis` in das Benutzer-Plugin-Verzeichnis von Binary Ninja und starte das Programm neu. Öffne bei der betroffenen Funktion **Function Settings** und wähle `OLLVM_XOR_64`. Falls die Analyse nicht startet, verwende **Analysis → Reanalyze All Functions**. Dieser Modus schreibt MLIL-Kontrollflusskanten um, nicht die Dateibytes, und benötigt weder Z3 noch den Resolver für indirekte Sprünge. Er wurde mit Binary Ninja 5.3.9757+ getestet. Die inaktiven Zustands-Schreibzugriffe pro Block werden dadurch nicht entfernt; verwechsle sie also nicht mit weiterhin aktiven Übergängen.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch auf `mov` basierende Instruktionssequenzen und verwendet Signal- und Exception-Handling, um den Kontrollfluss zu verändern. Weitere Details:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Für unterstützte Binärdateien kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuskieren. Das Tool hat mehrere Abhängigkeiten.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Und [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **entry point** zu finden, durchsuche die Funktionen nach `::main`, wie hier:

![Einen Rust-entry-point in Ghidra finden, indem nach Funktionsnamen mit doppeltem Doppelpunkt und main gesucht wird](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Wenn du den **Namen** der aufgerufenen **Funktionen** kennst, suche im **Internet** nach ihnen, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binaries werden viele statische Strings nicht als C-Style-Zeiger auf NUL-terminierte Strings referenziert. Ein gängiges `rustc`-Layout ist ein **Zeiger/Längen-Tupel** in **`.data.rel.ro`**, das auf den eigentlichen String-Block in **`.rodata`** verweist:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Zeichenfolgen zusammenführen oder Querverweise vollständig übersehen können.<sup>[[3]](#references)</sup>

Schneller Arbeitsablauf:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Durchlaufe **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen String-Zeiger.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (behalte zum Beispiel Längen zwischen **4** und **100** Bytes bei).
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

Dies ist besonders beim Firmware-Reversing nützlich, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Konfigurationsschlüssel, Command-Handler und Auth-bezogene Logik** offenlegen.

Wenn Ghidra diese Strings nicht erkennt, führe ein benutzerdefiniertes Skript/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners eignen sich als Referenz, um die Idee an andere **Wortgrößen, Byte-Reihenfolgen und Section-Layouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binaries kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du ein Delphi-Binary reversen musst, empfehle ich dir das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi).

Drücke in IDA **Alt+F7**, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dieses Plugin führt das Binary aus und löst die Funktionsnamen zu Beginn des Debuggings dynamisch auf. Drücke nach dem Start des Debuggings erneut auf die Schaltfläche Start (die grüne Schaltfläche oder F9), dann wird am Anfang des echten Codes ein Breakpoint ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche klickst, kann der Debugger in der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Bei gewöhnlichen Go-Binaries kann [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) Laufzeitstrukturen wiederherstellen und Funktionsnamen in IDA verbessern. Lade das Python-Plugin mit **Alt+F7**.

Wenn du ein Golang-Binary reversen musst, empfehle ich dir das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper).

Drücke in IDA **Alt+F7**, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dadurch werden die Funktionsnamen aufgelöst.

### Metadaten ohne Symboltabelle wiederherstellen

Auch ein gestripptes Go-Executable benötigt Laufzeit-Metadaten, um Program Counter Funktionen zuzuordnen. [GoReSym](https://github.com/mandiant/GoReSym) findet und parst mithilfe von Code aus der Go-Runtime Strukturen wie `pclntab` und `moduledata`. So lassen sich Funktionsgrenzen, Namen, Quellcodepfade, Typen und Build-Details wiederherstellen, ohne auf die herkömmliche Symboltabelle angewiesen zu sein.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ein Obfuscator kann diese Strukturen nutzbar lassen und gleichzeitig die wiederhergestellten Namen ersetzen. Garble hasht beispielsweise Bezeichner und Paketpfade und entfernt Build-, Modul- und Debug-Informationen.<sup>[[12]](#references)</sup> Das obfuskierte Paket-Token muss für Funktionen aus diesem Paket konsistent bleiben. Gruppiere Funktionen anhand des wiederholt vorkommenden Tokens, leite aus den aufgerufenen Funktionen, Strings und APIs ein Paket ab und übertrage diese Paketbezeichnung dann auf die gesamte Gruppe.<sup>[[13]](#references)</sup>

### Garble-Namen mit GoResolver wiederherstellen

[GoResolver](https://github.com/volexity/GoResolver) kombiniert die Extraktion von Runtime-Symbolen mit der Generierung sauberer Referenzen und dem Abgleich von Kontrollflussgraphen (CFGs). Gehe dabei wie folgt vor:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler-Version identifizieren.** Prüfe zuerst `BuildInfo` und eingebettete Versions-Strings. Falls der Obfuscator sie entfernt hat, vergleiche Teile der eingebundenen Go-Runtime mit Referenz-Runtimes bestimmter Versionen. In Volexitys Tests reichten etwa `2%` der Runtime aus, um wichtige Go-Versionen voneinander zu unterscheiden. Betrachte dies als empirische Optimierung, nicht als universellen Schwellenwert.<sup>[[13]](#references)</sup>
2. **Passende Referenzen erstellen.** Erzeuge saubere Binaries für die identifizierte Go-Version, Zielarchitektur und wahrscheinlichen Bibliotheken. Ein passender Toolchain reduziert Unterschiede in den vom Compiler generierten CFGs.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Funktionen vergleichen.** GoGrapher gleicht Funktions-CFGs ab und gibt normalisierte Scores von `0.0` bis `1.0` aus. Der Abgleich von Basic Blocks basiert auf einem gewichteten Vergleich ähnlicher Instruktionen. Matches mit hoher Konfidenz ordnen randomisierte Funktionen der sauberen Implementierung zu. Schwächere Matches können dennoch ein Paket oder Modul identifizieren.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validieren und importieren.** Bestätige vorgeschlagene Namen anhand von Aufrufbeziehungen, Konstanten, Strings und Seiteneffekten und importiere dann den JSON-Bericht mit dem GoResolver-Plugin für IDA oder Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Der standardmäßige Schwellenwert für signifikante Übereinstimmungen ist `0.9`. Mit den Schaltern `--extract` und `--graph` lässt sich jeweils eine der beiden Phasen isoliert ausführen. Standardmäßig werden beide ausgeführt, da sich die wiederhergestellten Runtime-Metadaten und die CFG-Belege ergänzen.<sup>[[10]](#references)</sup> CFG-Scores sind heuristisch: Inlining, Build-Flags, Architektur und Unterschiede zwischen Bibliotheksversionen können die Graphstruktur verändern. Bewahre daher nicht aufgelöste Funktionen, statt ihnen Namen mit geringer Konfidenz zuzuweisen.<sup>[[13]](#references)</sup>

### Wiederherstellen der Go-Stringtabelle

Go-Binaries speichern die String-Bytes aller gelinkten Packages in einer zusammenhängenden Tabelle. Die Einträge sind nicht NUL-terminiert, und Runtime-Strukturen geben weder die Basisadresse noch die Größe der Tabelle preis. Der Compiler sortiert die Einträge jedoch unter allen Betriebssystemen und Architekturen zuerst nach Länge und dann alphabetisch. Nachdem ein Eintrag gefunden wurde, kann ein Analyst daher die benachbarten Einträge durchgehen und mithilfe von Daten-Cross-References Strings dem Code zuordnen.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatisiert diesen Workflow in IDA Pro und Ghidra. Lass zuerst die Auto-Analyse abschließen, da das Plugin auf Cross-References im Datensegment angewiesen ist. Der Standard-Anker ist der Runtime-String `entersyscall`. Anschließend kann das Plugin in beide Richtungen suchen, die wiederhergestellten Strings in der Datenbank definieren und ein JSON-Mapping der Strings zu den referenzierenden Funktionen exportieren.<sup>[[14]](#references)</sup>

Filtere den Bericht nach dem Package der referenzierenden Funktion, um Anwendungscode oder Malware-Code von verlinktem Bibliotheksrauschen zu trennen. Mit dieser Technik lassen sich keine Literale wiederherstellen, die durch Obfuskation zerstört wurden, etwa durch Garbles `-literals`-Transformation. Sie kann jedoch weiterhin Runtime-Strings organisieren, die nicht obfuskiert wurden.<sup>[[14]](#references)[[15]](#references)</sup>

### Wiederherstellen von Go-Runtime-Typen

Go enthält Runtime-Typinformationen, die unter anderem für die Garbage Collection verwendet werden. Wenn Build-Informationen entfernt wurden oder der Disassembler diese Metadaten nicht analysiert, können Anweisungen so aussehen, als würden sie beliebige Datenadressen laden, während die Zielregion untypisiert bleibt. Durch das Wiederherstellen der Metadaten werden diese Adressen in lesbare Typreferenzen umgewandelt und die Fähigkeiten der Packages lassen sich leichter nachvollziehen.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kann Symbole extrahieren und Runtime-Typen in einen JSON-Bericht parsen. Die aktuelle CLI verwendet den Unterbefehl `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die Option `-y`/`--types` aktiviert das Parsen von Typen. Importiere den Bericht mit dem IDA-Pro- oder Ghidra-Plugin von GoResolver, um die wiederhergestellten Typen zu definieren und ihre Referenzen in der Analysedatenbank anzuwenden. Im mit diesem Feature eingeführten Berichtsformat sind die Mitglieder für die RTTI-Adresse und die wiederhergestellten Typen null, wenn `-y` weggelassen wird.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver unterstützt PE-, ELF- und Mach-O-Samples für x86, AMD64, ARM und ARM64. Daher gilt derselbe Workflow für Go-Binärdateien von Windows, Linux und macOS.<sup>[[10]](#references)</sup>

## Kompiliertes Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einer kompilierten Python-ELF-/EXE-Binärdatei extrahierst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du die **Binärdatei** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

Unter [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_** sehen, wie die **Tasten** des Game Boy Advance gedrückt werden.

![Konfiguration der no$gba-Steuerung mit den Tastenbelegungen des Game Boy Advance](<../../images/image (581).png>)

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

In dieser Art von Programm ist also **entscheidend, wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** findest du die häufig vorkommende Funktion: **KEYINPUT**.

![Ghidra-Ansicht eines GBA-Binaries mit einem Verweis auf KEYINPUT an Adresse 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild siehst du, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion werden nach einigen Init-Operationen (ohne Bedeutung):

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

Das letzte if prüft, ob **`uVar4`** zu den **letzten Keys** gehört und nicht der aktuelle Key ist. Das entspricht dem Loslassen einer Taste (der aktuelle Key wird in **`uVar1`** gespeichert).

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

- Zuerst wird der Wert mit **4** (der **SELECT**-Taste) verglichen: Bei der Challenge löscht diese Taste den Bildschirm.
- Dann wird der Wert mit **8** (der **START**-Taste) verglichen; in dieser Challenge prüft dieser Pfad, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Sind die Werte gleich, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und erhöht.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

Bei dieser Challenge musste man also die Werte der Tasten kennen und **eine Kombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [archivierter Nostalgia-Challenge-Bericht](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Rust-Strings decodieren - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-gestütztes Reverse Engineering vereiteln – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Ein Ansatz zum Vergleich von Kontrollflussgraphen auf Grundlage des Abgleichs von Basisblöcken](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver-Repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-Obfuskationsmechanismus](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kontrollflussgraph-Ähnlichkeit zum automatischen Deobfuskieren von Golang-Binärdateien nutzen](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor-Repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Aktualisierungen der Golang-Tools von Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Alles reverse engineeren](https://github.com/morluto/rea)
- [17] [REA-Analyse von Managed Code](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA-Anleitung zu CLI und Belegen](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Workflow zum Aufheben der Kontrollfluss-Obfuskation in Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day-Intrusion, Java-Loader, Web-Shell und AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge-README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementierung des IDA-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementierung des Ghidra-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) bindet an die Wildcard-Adresse](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
