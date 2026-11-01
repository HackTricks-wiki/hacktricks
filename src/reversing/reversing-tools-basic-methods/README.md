# Reversing-Tools & grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## ImGui-basierte Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-Automatisierung im User-Mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows-Kontrollfluss durch Ausnahmen

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows-Kernel-Debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm-Dekompilierer / Wat-Compiler

Online:

- Mit [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kannst du von wasm (Binärformat) zu wat (Klartext) **dekompilieren**.
- Mit [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kannst du wat zu wasm **kompilieren**.
- Für die Dekompilierung kannst du auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) ausprobieren.

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

## .NET-Dekompilierer

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Dekompilierer, der mehrere Formate **dekompiliert und untersucht**, darunter **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **ausführbare Dateien** (.exe). Nach der Dekompilierung kann eine Assembly als Visual-Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil: Wenn verlorener Quellcode aus einer älteren Assembly wiederhergestellt werden muss, kann das Zeit sparen. Außerdem ermöglicht dotPeek eine bequeme Navigation durch den dekompilierten Code und ist damit eines der idealen Tools für die **Analyse von Xamarin-Algorithmen.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an deine genauen Anforderungen anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Werfen wir einen Blick auf die zahlreichen Reverse-Engineering-Funktionen dieses Tools:

- Zeigt, wie Daten durch eine Bibliothek oder Komponente fließen
- Gibt Einblick in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, damit du mehr aus den verwendeten APIs und Technologien herausholen kannst.
- Findet Abhängigkeiten und verschiedene Assemblies
- Spürt den genauen Ort von Fehlern in deinem Code, Drittanbieterkomponenten und Bibliotheken auf.
- Ermöglicht das Debuggen im Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es unter jedem Betriebssystem verwenden (du kannst es direkt über VSCode installieren; ein Download von Git ist nicht nötig. Klicke auf **Extensions** und suche nach **ILSpy**).\
Wenn du etwas **dekompilieren**, **ändern** und anschließend erneut **kompilieren** möchtest, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon verwenden: [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### Verwaltete Inspektion ohne Ausführung mit REA

**REA** kann PE/CLI-Metadaten und CIL untersuchen, ohne die Assembly zu laden. Beginne mit der Identität des Artefakts und untersuche anschließend die Member und deklarierten nativen Grenzen. Das ist nützlich, wenn du verdächtige Aufrufe überprüfst, bevor du einen Dekompilierer verwendest oder das Programm ausführst.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Für das Version-Diffing verwendet `compare_managed_members` rohe CIL-/Signatur-Identitäten und Fingerprints dekodierter Instruktionen, statt Metadaten-Tokens als buildübergreifend stabil zu behandeln. Eine P/Invoke-Deklaration beweist nicht, dass nativer Code ausgeführt wurde; `verify_managed_native_boundaries` benötigt einen passenden nativen Export oder Function Evidence, um diese Grenze zu prüfen. Bewahre den Artifact-Digest, die MVID und nicht aufgelöste Zuordnungen zusammen mit dem Ergebnis auf.<sup>[[17]](#references)</sup>

### DNSpy-Logging

Um **DNSpy einige Informationen in einer Datei protokollieren zu lassen**, kannst du dieses Snippet verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy-Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly-Attribute** ändern, die sich auf das **Debugging** beziehen:

![DNSpy Logging - DNSpy Debugging: Zuerst die Assembly-Attribute ändern, die sich auf das Debugging beziehen](<../../images/image (973).png>)

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

Und klicke auf **Kompilieren**:

![DNSpy Logging - DNSpy Debugging: Und klicke auf Kompilieren](<../../images/image (314) (1).png>)

Speichere dann die neue Datei über _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Speichere dann die neue Datei über File Save module](<../../images/image (602).png>)

Das ist notwendig, denn wenn du das nicht machst, werden zur **Laufzeit** mehrere **Optimierungen** auf den Code angewendet. Dadurch kann es passieren, dass beim Debuggen ein **Haltepunkt nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn deine .NET-Anwendung von **IIS** **ausgeführt** wird, kannst du sie anschließend mit folgendem Befehl **neu starten**:

```
iisreset /noforce
```

Dann solltest du zum Starten des Debuggings alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Dann solltest du zum Starten des Debuggings alle geöffneten Dateien schließen und im Debug Tab Attach to Process auswählen](<../../images/image (318).png>)

Wähle anschließend **w3wp.exe** aus, um eine Verbindung zum **IIS server** herzustellen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle anschließend w3wp.exe aus, um eine Verbindung zum IIS server herzustellen, und klicke auf attach](<../../images/image (113).png>)

Da wir nun den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf _Debug >> Break All_ und anschließend auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Da wir nun den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Da wir nun den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (834).png>)

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

![Debugging DLLs - Mit IDA: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Die **Parameter** der Ausführung konfigurieren und dabei den **Pfad zur DLL** sowie die aufzurufende Funktion angeben:

![Debugging DLLs - Mit IDA: Konfiguriere die Parameter der Ausführung und gib dabei den Pfad zur DLL sowie die aufzurufende Funktion an](<../../images/image (704).png>)

Wenn du anschließend mit dem Debugging beginnst, **wird die Ausführung beim Laden jeder DLL angehalten**. Sobald rundll32 deine DLL lädt, wird die Ausführung also angehalten.

Diese Methode hält bei Modul-Ladeereignissen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist jedoch weniger direkt als mit dem unten beschriebenen x64dbg-Workflow.

### Mit x64dbg/x32dbg

- **rundll32 laden** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Die **Command Line** ändern ( _File --> Change Command Line_ ) und den Pfad zur DLL sowie die aufzurufende Funktion angeben, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ ändern und "**DLL Entry**" auswählen.
- Anschließend **die Ausführung starten**. Der Debugger hält bei jedem dll main an. Irgendwann hält er bei **DLL Entry deiner DLL** an. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte, dass du in win64dbg, wenn die Ausführung aus irgendeinem Grund angehalten wurde, **oben im win64dbg-Fenster** sehen kannst, **in welchem Code du dich gerade befindest**:

![Mit IDA - Mit x64dbg/x32dbg: Beachte, dass du in win64dbg, wenn die Ausführung aus irgendeinem Grund angehalten wurde, oben im win64dbg-Fenster sehen kannst, in welchem Code du dich gerade befindest](<../../images/image (842).png>)

Dieser Hinweis bestätigt, dass die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern. Weitere Informationen findest du unter:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Frontend-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das sich auf Spiele konzentriert. Es kann jedoch für alle möglichen Aufgaben im Zusammenhang mit Reverse Engineering verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Frontend für verschiedene Decompiler. Mit diesem Webdienst kannst du die Ausgabe verschiedener Decompiler für kleine ausführbare Dateien vergleichen.

### Godot-PCK-Entschlüsselung und Wiederherstellung von Projekten

Suche bei einem verteilten Godot-Spiel nach der PCK-Datei: Sie kann als eigenständige `.pck` vorliegen, an eine ausführbare Datei angehängt oder darin eingebettet sein oder sich im Verzeichnis `assets` einer APK befinden. [gore](https://github.com/figurophobia/gore) kann das Pack untersuchen und extrahieren. Für die vollständige Wiederherstellung von Skripten und Ressourcen sind jedoch GDRE Tools erforderlich (`gore setup` installiert sie, oder verwende `--gdre`). Für diesen Workflow unterstützt das Tool Godot-4.x-PCK-Formate v2–v4; v1-Header können erkannt werden, für v1 muss jedoch ein Schlüssel angegeben werden.<sup>[[25]](#references)</sup>

Für die automatische Wiederherstellung des Schlüssels ist eine verschlüsselte Dateitabelle erforderlich. Wenn nur die Dateiinhalte verschlüsselt sind, gib stattdessen einen bekannten Schlüssel an. Eine fehlgeschlagene Wiederherstellung beweist nicht, dass ein Pack unverschlüsselt ist.<sup>[[28]](#references)</sup>

Bei der Schlüsselsuche handelt es sich **nicht** um einen AES-256-Keyspace-Angriff. Eine verschlüsselte Dateitabelle enthält den MD5-Hash ihres Klartexts, die Klartextlänge, den IV und den AES-256-CFB-Chiffretext.<sup>[[27]](#references)</sup> `gore` testet 32-Byte-Fenster der ausführbaren Spieldatei oder benachbarter Dateien als mögliche Schlüssel. Es filtert die Kandidaten anhand plausibler entschlüsselter Pfadlängen und -präfixe und bestätigt Treffer beim Durchsuchen von Binärdaten, indem es die gesamte Tabelle entschlüsselt und ihren MD5-Hash überprüft.<sup>[[26]](#references)[[28]](#references)</sup> Zuerst werden initialisierte PE-/ELF-Datensektionen durchsucht; anschließend wird bei Bedarf die gesamte Datei durchsucht. Mit `--scan` werden weitere Kandidatendateien einbezogen.<sup>[[28]](#references)</sup>

Wird kein eingebetteter Schlüssel gefunden, wird eine kurze, integrierte Passwortliste getestet. Mit `--wordlist` lassen sich weitere Kandidaten angeben. Jedes Passwort wird als vom Engine-Passwort abgeleitete Schlüsselrepräsentation, als mit Nullen aufgefülltes Literal oder als Schlüssel mit 64 Hexadezimalzeichen getestet. Anders als Treffer beim Durchsuchen von Binärdaten bestehen Treffer aus der Wortliste in dieser Implementierung lediglich den Filter für die Pfadstruktur. Bestätige sie, indem du das Pack öffnest und die extrahierten Assets überprüfst.<sup>[[26]](#references)[[28]](#references)</sup>

Wenn das Spielartefakt lokal verfügbar ist, wähle den für die Analyse benötigten Schritt. `recover` ruft GDRE auf, um ein Projekt wiederherzustellen, das sich öffnen lässt, während `extract` lediglich die Rohdateien entpackt. `key` gibt einen möglichen Schlüssel aus, der mit einem anderen Tool verwendet werden kann.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Evidenzgestützte native Untersuchung mit REA

**REA** stellt Hopper-, Ghidra- und IDA-Analysen über CLI und MCP bereit. Es benötigt Node.js 22.x (mindestens 22.19), 24.x (mindestens 24.11) oder 26+ sowie npm. Konfiguriere zuerst einen vorhandenen nativen Provider; prüfe `rea providers --json` und wähle explizit einen Provider aus, wenn mehrere das Ziel unterstützen. Verwende unten anstelle von `0x1000` einen beobachteten Funktionsnamen oder eine Adresse aus dem Inventar.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Beginne mit einem Feature-String oder Symbol, folge Referenzen und Aufrufern und untersuche anschließend das Dossier der ausgewählten Funktion sowie den Pseudocode mit `rea decompile`. REA bindet eine Sitzung an den ausgewählten Provider, statt ihn nach einem Fehler stillschweigend zu ersetzen. Für wiederholbare Abfragen verwendet `--snapshot PATH` nur übereinstimmende Artefakt-Bytes, Provider, Einstellungen, Operationen und Parameter erneut. Ein Snapshot ist ein lokaler Cache und keine gespeicherte Provider-Datenbank. Bewahre das zurückgegebene Evidence und explizite Unbekannte auf, statt erschlossene Pfade oder Decompiler-Text als Original-Quellcode zu behandeln.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript-/Electron-Einstiegspunkte, die zu nativen Add-ons führen, findest du unter [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptgesteuerte IDA- und Ghidra-Analyse mit einer lokalen TCP-Bridge

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) läuft innerhalb einer **bereits geöffneten** IDA-Datenbank oder eines Ghidra-CodeBrowser-Programms und ermöglicht einem separaten Skript, diese Analysedatenbank abzufragen und zu ändern. Führe `ID_Server.py` über die Python-CLI von IDA aus (`import ID_Server`) oder `Ghidra_Server.py` über den Script Manager von Ghidra. IDA bindet sich ab Port `5073` an `127.0.0.1` und prüft danach höhere Ports. Das aktuelle Ghidra-Skript beginnt bei Port `5093` und versucht zehn Ports bis einschließlich `5102`; sein Java-Socket bindet sich an die Wildcard-Adresse, nicht nur an Loopback. Prüfe vor dem Verbinden den von der Instanz ausgegebenen Port. Anders als ein Headless Analyzer arbeitet diese Bridge mit dem Programm, das derzeit in der jeweiligen GUI-Instanz geöffnet ist.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Sende **pro Verbindung einen durch einen Zeilenumbruch abgeschlossenen Befehl** und lies die durch einen Zeilenumbruch abgeschlossene Antwort. Das Ergebnis ist normalerweise JSON. Nachdem du beispielsweise eine importierte API gefunden hast, die für einen Eingabepfad relevant ist, ermittelt `IMPORTXREF` deren Aufrufstellen; `DECOMP_XREF` dekompiliert anschließend stapelweise die Aufrufer einer ausgewählten Adresse. `FUNC` untersucht eine Funktion, während `PCODE` die Zwischendarstellung des Decompilers zurückgibt. Verwende die Adresse aus der aktiven Datenbank und keine Adresse aus einer anders rebasierten Binärdatei. Das folgende Beispiel verwendet den Standardport von IDA; für Ghidra verwende den von dessen Skript ausgegebenen Port.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Der gleiche Kanal kann **die Analyse-Datenbank ändern**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` und `PATCH` ändern Namen, Typen, Strukturdefinitionen, Funktionsgrenzen oder gespeicherte Bytes. `PATCH` ist eine Änderung an der Datenbank und **kein** Beleg für einen Patch in einem laufenden Prozess. Keiner der Listener dokumentiert eine Authentifizierung. IDA ist nur an Loopback gebunden, Ghidra kann jedoch über Netzwerkschnittstellen erreichbar sein; schränke den Zugriff auf den Ghidra-Listener ein, wenn du ihn verwendest. `QUIT` stoppt beide Listener, und IDA stellt außerdem `ida_bridge_stop()` bereit.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Einen Shellcode mit blobrunner debuggen

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert Speicher für den **Shellcode**, gibt dessen **Speicheradresse** aus und hält die Ausführung an.\
Binde einen Debugger wie IDA oder x64dbg an, setze einen Breakpoint an der ausgegebenen Adresse und setze die Ausführung fort, um den Shellcode zu debuggen.

Die Releases-Seite auf GitHub enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Eine leicht modifizierte Version von Blobrunner findest du unter dem folgenden Link. Um sie zu kompilieren, musst du lediglich **ein C/C++-Projekt in Visual Studio Code erstellen, den Code kopieren und einfügen und ihn kompilieren**.


{{#ref}}
blobrunner.md
{{#endref}}

### Einen Shellcode mit jmp2it debuggen

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) ähnelt BlobRunner. Es reserviert Speicher für den Shellcode und tritt in eine Endlosschleife ein. Binde den Debugger an, setze die Ausführung für **2–5 Sekunden** fort, halte innerhalb dieser Schleife an und gehe dann schrittweise zum nächsten Aufruf, der die Ausführung an den reservierten Shellcode übergibt.

![Debugger in jmp2its Endlosschleife unmittelbar vor dem Aufruf des reservierten Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it findest du auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode mit Cutter debuggen

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter sowohl „Open File“ als auch „Open Shellcode“ ermöglicht. In meinem Fall dekompilierte Cutter den Shellcode korrekt, wenn ich ihn als Datei öffnete, aber nicht, wenn ich ihn als Shellcode öffnete:

![Cutter zeigt unterschiedliche Analyseergebnisse beim Öffnen derselben Bytes als Datei oder als Shellcode](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen Breakpoint. Offenbar startet Cutter die Emulation dann automatisch an dieser Stelle:

![Breakpoint am gewünschten Shellcode-Einstiegspunkt setzen, bevor die Cutter-Emulation gestartet wird](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Du kannst beispielsweise den Stack in einem Hex-Dump anzeigen:

![Den emulierten Shellcode-Stack im Hex-Dump von Cutter anzeigen](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Damit kannst du beispielsweise herausfinden, **welche Funktionen** der Shellcode verwendet und ob er sich im Speicher **dekodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg verfügt außerdem über einen grafischen Launcher, in dem Sie die gewünschten Optionen auswählen und den Shellcode ausführen können.

![Grafischer Launcher von scDbg zur Auswahl von Shellcode-Emulations- und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der endgültige Shellcode ausgegeben, falls er zur Laufzeit im Speicher verändert wurde (nützlich, um den decodierten Shellcode herunterzuladen). Mit dem **start offset** können Sie den Shellcode ab einem bestimmten Offset starten. Die Option **Debug Shell** ist nützlich, um den Shellcode über das scDbg-Terminal zu debuggen. Ich finde jedoch eine der zuvor erläuterten Optionen dafür besser, da Sie dann Ida oder x64dbg verwenden können.

### Disassemblieren mit CyberChef

Laden Sie Ihre Shellcode-Datei als Eingabe hoch und verwenden Sie das folgende Rezept, um sie zu disassemblieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)**-Obfuscation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten normalerweise nur bei **modularer Arithmetik mit fester Breite** korrekt sind; Überträge und Überläufe spielen daher eine Rolle:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du einen solchen Ausdruck mit allgemeinen algebraischen Werkzeugen vereinfachst, kann leicht ein falsches Ergebnis herauskommen, weil die Semantik der Bitbreite ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite bei**, die aus dem angehobenen Code/IR/Decompiler-Output stammt (`8/16/32/64` Bit).
2. **Klassifiziere den Ausdruck**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
   - **Polynomial**: Produkte kommen vor
   - **Mixed**: Produkte und bitweise Logik sind verschachtelt, oft mit wiederholten Teilausdrücken
3. **Überprüfe jede mögliche Umschreibung** durch zufällige Tests oder einen SMT-Beweis. Wenn sich die Äquivalenz nicht beweisen lässt, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Umgehe abgeflachte Kontrollflüsse mit einem schmalen Ausführungsslice

Die vollständige Rekonstruktion des Kontrollflussgraphen ist oft unnötig. Bei Control-Flow-Flattening, opaque predicates, großen Dispatchern oder MBA-lastigem Code verfolgst du Referenzen von verschlüsselten Blobs und Ausgabepuffern bis zu der kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Data-Flow-Slice oder führe ihn unabhängig aus; der Dispatcher ist nicht Teil der erforderlichen Lösung, wenn sich der relevante Zustand direkt initialisieren lässt.<sup>[[7]](#references)</sup>

Ein praktischer Workflow ist:<sup>[[7]](#references)</sup>

1. Erfasse ausführbare und Datensektionen, Relokationen und Querverweise. Dumpe mögliche Tabellen aus `.rodata` und bewahre dabei ihre Byte-Reihenfolge und Elementbreite.
2. Ermittle die letzte Routine, die den Klartext- oder Ausgabepuffer beschreibt. Notiere ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und den erforderlichen globalen Zustand.
3. Überführe nur diese Operationen in ein Python-Modell mit fester Bitbreite. Wenn der Slice noch von zu viel Zustand abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, statt das gesamte Programm zu emulieren.
4. Überprüfe, ob der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binärdatei ableitet: Entferne stille Fallbacks, suche nach eingebetteten Antworten und teste ihn mit unbekannten Builds, in denen Strings, Schlüssel, Bezeichner, Layouts und Obfuskations-Seeds geändert wurden.

Nützliche Befehle für den ersten Durchlauf sind:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### MBA-Ausdrücke erkennen, die als Konstanten getarnt sind

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann seine Eingabe vollständig aufheben. Nachdem die Tabellen extrahiert wurden, wertet man den Ausdruck über den vollständigen 8-Bit-Wertebereich aus; eine einelementige Ausgabemenge beweist, dass das Byte konstant ist, ohne die umgebende Zustandsmaschine rekonstruieren zu müssen.<sup>[[7]](#references)</sup>

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

Behalte die abschließende Maske bei, da die ursprüngliche Addition einen Wraparound bei Bytebreite aufweist. Für einen größeren Wertebereich kannst du einen SMT solver fragen, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Umgebungsgebundene Decodierung erkennen

Anti-Analyse-Prüfungen müssen weder einen Branch auslösen noch abstürzen. Ein Decoder kann ein Sensorergebnis in ein Schlüsselbit, eine opaque-predicate-Konstante oder den Zustand eines abgeflachten Dispatchers einmischen, normal fortfahren und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehler-Branches zu patchen; verfolge die Datenabhängigkeiten von Umgebungsprüfungen bis in den Decoder-Zustand, vergleiche denselben Slice auf dem echten Gerät und im Emulator und teste, wie das Erzwingen jedes Sensorergebnisses den finalen Buffer verändert.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Simplifier für Malware-Analyse und das Reverse Engineering geschützter Binaries. Er klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, anstatt auf alles denselben generischen Rewrite-Pass anzuwenden.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA wertet den Ausdruck mit Boolean-Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden gegeneinander antreten, etwa Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: Atome mit konstanten Masken werden mithilfe einer bitpartitionierten Rekonstruktion neu aufgebaut, damit maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel für eine gemischte Identität, deren Wiederherstellung sich häufig lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich reduzieren auf:

```c
x * y
```

### Reversing-Notizen

- CoBRA am besten auf **lifted IR-Ausdrücken** oder Decompiler-Ausgaben ausführen, nachdem die genaue Berechnung isoliert wurde.
- `--bitwidth` explizit verwenden, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn ein stärkerer Beweisschritt nötig ist, die lokalen Z3-Notizen hier prüfen:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM-Pass-Plugin** (`libCobraPass.so`) ausgeliefert. Das ist nützlich, wenn MBA-lastiges LLVM IR vor späteren Analyse-Pässen normalisiert werden soll.
- Nicht unterstützte carry-sensitive Residuen aus gemischten Domänen sind ein Hinweis darauf, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell nachzuvollziehen.

## Control-Flow-Flattening mit XOR-Zustand rekonstruieren

Ein OLLVM-artiger Flattener kann den aktuellen Basic-Block-Zustand in zwei 64-Bit-Registern speichern und ihn am Dispatcher mit XOR rekonstruieren. Jeder ursprüngliche Block schreibt das Registerpaar für seinen nächsten Zustand und springt zurück zum Dispatcher. Ein bedingter Block kann `CMOVcc` verwenden, um eine Hälfte des Paars abhängig von den CPU-Flags zu ersetzen. Wer nur sichtbaren Branch-Instruktionen folgt, übersieht daher die beiden Nachfolger. Anders als ein Dispatcher mit indirektem Sprung kann diese Struktur durchgehend direkte Rücksprünge verwenden.<sup>[[19]](#references)[[20]](#references)</sup>

Um den Graphen zu rekonstruieren, den Vergleichsbaum des Dispatchers und die beiden Zustandsregister identifizieren, jeden verglichenen XOR-Zustand seinem Zielblock zuordnen und dann die erreichenden Schreibzugriffe auf das Registerpaar in jedem ursprünglichen Block nachverfolgen. Bei bedingten Schreibzugriffen die flagsetzende Instruktion und beide `CMOVcc`-Ergebnisse einbeziehen. Den Dispatcher-Ausgang jedes Blocks durch seinen aufgelösten direkten Nachfolger oder bedingten Branch ersetzen; danach ist der Dispatcher unerreichbar, ohne die Binärdatei patchen zu müssen. Dies ist ein Ansatz für das gesamte CFG. Wenn nur ein Decoder relevant ist, kann der oben beschriebene [Workflow mit engem Execution-Slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) schneller sein.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatisiert diese Struktur in Binary Ninja. `plugins/DispatchThis` in das Binary-Ninja-Benutzer-Plugin-Verzeichnis kopieren und neu starten. In der betroffenen Funktion **Function Settings** öffnen und `OLLVM_XOR_64` auswählen. Falls die Analyse nicht startet, **Analysis → Reanalyze All Functions** verwenden. Dieser Modus schreibt MLIL-Control-Flow-Kanten um, nicht die Bytes der Datei, und benötigt weder Z3 noch den Resolver für indirekte Sprünge. Er wurde mit Binary Ninja 5.3.9757+ getestet. Die toten Zustands-Schreibzugriffe pro Block werden nicht entfernt; diese daher nicht mit verbleibenden aktiven Übergängen verwechseln.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch `mov`-basierte Instruktionssequenzen und verwendet Signal-/Exception-Handling, um den Control-Flow zu verändern. Weitere Informationen:

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

Um den **entry point** zu finden, suche in den Funktionen nach `::main`, wie hier:

![Einen Rust-entry point in Ghidra finden, indem Funktionsnamen nach doppeltem Doppelpunkt und main durchsucht werden](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Suche im **Internet** nach den **Namen** der aufgerufenen **Funktionen**, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binaries werden viele statische Strings nicht über NUL-terminierte Zeiger im C-Stil referenziert. Ein verbreitetes `rustc`-Layout ist ein **Zeiger-/Längen-Tupel** innerhalb von **`.data.rel.ro`**, das auf den eigentlichen String-Blob in **`.rodata`** verweist:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Das bedeutet, dass `strings` oder die standardmäßige Ghidra-Analyse benachbarte Strings zusammenführen oder Querverweise vollständig übersehen kann.<sup>[[3]](#references)</sup>

Schneller Workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Durchlaufe **`.data.rel.ro`** Wort für Wort.
3. Behandle jeden Wert innerhalb des Adressbereichs von `.rodata` als möglichen String-Zeiger.
4. Behandle das nächste Wort als mögliche Länge.
5. Wende Plausibilitätsfilter an (zum Beispiel nur Längen zwischen **4** und **100** Byte).
6. Lies genau `Länge` Byte aus `.rodata`, anstatt bis `0x00` zu scannen.

Minimale Extraktionslogik:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Dies ist beim Firmware-Reversing besonders nützlich, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Konfigurationsschlüssel, Command-Handler und Authentifizierungslogik** offenlegen.

Wenn Ghidra diese Strings nicht findet, führe ein benutzerdefiniertes Script/Plugin aus, das dieselbe Heuristik anwendet und an den referenzierten `.rodata`-Offsets String-Daten anlegt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **Wortbreiten, Endianness und Abschnittslayouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du eine Delphi-Binärdatei reversen musst, empfehle ich das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi).

Drücke in IDA **Alt+F7**, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dieses Plugin führt die Binärdatei aus und löst zu Beginn des Debuggings dynamisch Funktionsnamen auf. Nachdem du das Debugging gestartet hast, drücke erneut auf die Start-Schaltfläche (die grüne oder f9), und ein Breakpoint wird am Anfang des eigentlichen Codes ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche klickst, kann der Debugger bei der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Für gewöhnliche Go-Binärdateien kann [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) Laufzeitstrukturen wiederherstellen und Funktionsnamen in IDA verbessern. Lade das Python-Plugin mit **Alt+F7**.

Wenn du eine Golang-Binärdatei reversen musst, empfehle ich das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper).

Drücke in IDA **Alt+F7**, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Damit werden die Funktionsnamen aufgelöst.

### Metadaten ohne Symboltabelle wiederherstellen

Auch eine gestrippte Go-Executable benötigt Laufzeitmetadaten, um Program Counter den Funktionen zuzuordnen. [GoReSym](https://github.com/mandiant/GoReSym) findet und parst mithilfe von Code, der von der Go-Laufzeitumgebung abgeleitet wurde, Strukturen wie `pclntab` und `moduledata`. So lassen sich Funktionsgrenzen, Namen, Quellpfade, Typen und Build-Details wiederherstellen, ohne auf die herkömmliche Symboltabelle angewiesen zu sein.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ein Obfuscator kann diese Strukturen nutzbar lassen und gleichzeitig die wiederhergestellten Namen ersetzen. Garble beispielsweise hasht Bezeichner und Paketpfade und entfernt Build-, Modul- und Debug-Informationen.<sup>[[12]](#references)</sup> Das obfuskierte Pakettoken muss für Funktionen aus diesem Paket gleich bleiben. Gruppiere Funktionen anhand des wiederkehrenden Tokens, leite ein Paket aus dessen Callees, Strings und APIs ab und weise dann der gesamten Gruppe dieses Paketlabel zu.<sup>[[13]](#references)</sup>

### Garble-Namen mit GoResolver wiederherstellen

[GoResolver](https://github.com/volexity/GoResolver) kombiniert die Extraktion von Runtime-Symbolen mit der Erzeugung sauberer Referenzen und dem Abgleich von Kontrollflussgraphen (CFGs). Gehe wie folgt vor:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler-Version bestimmen.** Prüfe zuerst `BuildInfo` und eingebettete Versionsstrings. Falls der Obfuscator diese entfernt hat, vergleiche Teile der gebündelten Go-Runtime mit Referenz-Runtimes bestimmter Versionen. In den Tests von Volexity reichten etwa `2%` der Runtime aus, um größere Go-Versionen zu unterscheiden. Betrachte dies als empirische Optimierung, nicht als allgemeingültigen Schwellenwert.<sup>[[13]](#references)</sup>
2. **Passende Referenzen erstellen.** Erzeuge saubere Binaries für die ermittelte Go-Version, die Zielarchitektur und wahrscheinliche Bibliotheken. Ein passendes Toolchain reduziert die Unterschiede zwischen den vom Compiler erzeugten CFGs.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Funktionen vergleichen.** GoGrapher gleicht Funktions-CFGs ab und gibt normalisierte Scores von `0.0` bis `1.0` aus. Der Abgleich der Basic Blocks basiert auf einem gewichteten Vergleich ähnlicher Instruktionen. Matches mit hoher Konfidenz ordnen randomisierte Funktionen der sauberen Implementierung zu. Schwächere Matches können trotzdem ein Paket oder Modul identifizieren.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Der standardmäßige Schwellenwert für signifikante Übereinstimmungen beträgt `0.9`. Mit den Optionen `--extract` und `--graph` lässt sich jeweils eine der beiden Phasen isolieren. Standardmäßig werden beide ausgeführt, da sich die wiederhergestellten Runtime-Metadaten und die CFG-Belege ergänzen.<sup>[[10]](#references)</sup> CFG-Scores sind heuristisch: Inlining, Build-Flags, Architektur und Unterschiede zwischen Bibliotheksversionen können die Graphstruktur verändern. Behalte daher nicht aufgelöste Funktionen bei, statt ihnen Namen mit geringer Konfidenz zuzuweisen.<sup>[[13]](#references)</sup>

### Wiederherstellen der Go-Stringtabelle

Go-Binärdateien enthalten die String-Bytes aller gelinkten Pakete in einer zusammenhängenden Tabelle. Die Einträge sind nicht mit NUL terminiert, und Runtime-Strukturen geben weder die Basisadresse noch die Größe der Tabelle preis. Der Compiler ordnet die Einträge jedoch unter allen Betriebssystemen und Architekturen zuerst nach Länge und dann alphabetisch. Nachdem ein Eintrag gefunden wurde, kann ein Analyst daher benachbarte Einträge durchlaufen und Strings mithilfe von Datenquerverweisen mit Code verknüpfen.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatisiert diesen Workflow in IDA Pro und Ghidra. Warte zunächst, bis die Autoanalyse abgeschlossen ist, da das Plugin auf Querverweisen aus Datensegmenten angewiesen ist. Als standardmäßigen Anker verwendet es den Runtime-String `entersyscall`. Anschließend kann es in beide Richtungen scannen, die wiederhergestellten Strings in der Datenbank definieren und eine JSON-Zuordnung der Strings zu den darauf verweisenden Funktionen exportieren.<sup>[[14]](#references)</sup>

Filtere den Bericht nach dem Paket der verweisenden Funktion, um Anwendungscode oder Malware-Code von nicht relevanten gelinkten Bibliotheken zu trennen. Mit dieser Technik lassen sich Literale nicht wiederherstellen, die durch Obfuskation zerstört wurden, etwa durch Garbles Transformation `-literals`. Sie kann jedoch weiterhin Runtime-Strings organisieren, die nicht obfuskiert wurden.<sup>[[14]](#references)[[15]](#references)</sup>

### Wiederherstellen von Go-Runtime-Typen

Go bettet Runtime-Typinformationen ein, die von Funktionen wie der Garbage Collection verwendet werden. Wenn Build-Informationen entfernt wurden oder der Disassembler diese Metadaten nicht parst, können Anweisungen so wirken, als würden sie beliebige Datenadressen laden, während der Zielbereich untypisiert bleibt. Durch das Wiederherstellen der Metadaten werden diese Adressen zu lesbaren Typreferenzen, wodurch sich die Fähigkeiten der Pakete leichter nachvollziehen lassen.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kann Symbole extrahieren und Runtime-Typen parsen, um einen JSON-Bericht zu erstellen. Die aktuelle CLI verwendet den Unterbefehl `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die Option `-y`/`--types` aktiviert das Parsen von Typen. Importiere den Report mit dem IDA-Pro- oder Ghidra-Plugin von GoResolver, um die wiederhergestellten Typen zu definieren und ihre Referenzen in der Analysedatenbank anzuwenden. Im mit diesem Feature eingeführten Reportformat sind die Mitglieder für die RTTI-Adresse und die wiederhergestellten Typen null, wenn `-y` weggelassen wird.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver unterstützt PE-, ELF- und Mach-O-Samples für x86, AMD64, ARM und ARM64. Daher gilt derselbe Workflow für Go-Binaries unter Windows, Linux und macOS.<sup>[[10]](#references)</sup>

## Kompiliertes Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einem kompilierten Python-Binary im ELF-/EXE-Format extrahierst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du das **Binary** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_** ** sehen, wie du die **Tasten** des Game Boy Advance drückst.

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Jede **Taste hat einen Wert**, der sie identifiziert:

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

In einem solchen Programm ist also **entscheidend, wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** findest du die häufig anzutreffende Funktion: **KEYINPUT**.

![Ghidra-Ansicht einer GBA-Binärdatei mit einem Verweis auf KEYINPUT an der Adresse 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild siehst du, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

Nach einigen Initialisierungsoperationen (ohne Bedeutung) in dieser Funktion:

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

Das letzte if prüft, ob **`uVar4`** zu den zuletzt gedrückten Tasten gehört und nicht der aktuelle Key ist. Das entspricht dem Loslassen einer Taste (der aktuelle Key ist in **`uVar1`** gespeichert).

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

Im vorherigen Code siehst du, dass **uVar1** (die Stelle, an der der **Wert der gedrückten Taste** steht) mit einigen Werten verglichen wird:

- Zuerst wird der Wert mit **4** (der **SELECT**-Taste) verglichen: In der Challenge löscht diese Taste den Bildschirm.
- Dann wird der Wert mit **8** (der **START**-Taste) verglichen. In dieser Challenge wird in diesem Zweig geprüft, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Stimmen die Werte überein, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und erhöht.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

Für diese Challenge musstest du also die Werte der Tasten kennen und **eine Tastenkombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

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
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings decodieren – Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering – rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering – RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia – GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-gestütztes Reverse Engineering vereiteln – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Ein Ansatz zum Vergleich von Kontrollflussgraphen anhand des Abgleichs grundlegender Blöcke](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-Obfuskationsmechanismus](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kontrollflussgraph-Ähnlichkeit nutzen, um Golang-Binärdateien automatisch zu deobfuskieren](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Aktualisierungen der Golang-Tools von Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Alles reverse engineeren](https://github.com/morluto/rea)
- [17] [REA-Analyse von verwaltetem Code](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA-Leitfaden zu CLI und Evidenz](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Workflow zum Auflösen von Kontrollfluss-Obfuskation mit Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut-MF-Zero-Day-Einbruch, Java-Loader, Web-Shell und AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementierung des IDA-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementierung des Ghidra-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle – InetSocketAddress(int) bindet an die Wildcard-Adresse](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot-Reverse-Engineering-Toolkit](https://github.com/figurophobia/gore)
- [26] [Implementierung der Schlüsselwiederherstellung in gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Format verschlüsselter Datenblöcke in gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Implementierung von gore-Befehlen und -Wiederherstellung](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
