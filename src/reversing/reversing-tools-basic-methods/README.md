# Reversing-Tools & grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## ImGui-basierte Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg-Automatisierung im User-Mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows-exceptionsgesteuerter Kontrollfluss

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
- Für die Dekomplilierung kannst du auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) ausprobieren.

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

Der Vorteil dabei: Wenn verlorener Quellcode aus einer Legacy-Assembly wiederhergestellt werden muss, kann das Zeit sparen. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der perfekten Tools für die **Analyse von Xamarin-Algorithmen.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an deine genauen Anforderungen anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die zahlreichen Reverse-Engineering-Funktionen dieses Tools an:

- Gibt Einblick in den Datenfluss durch eine Bibliothek oder Komponente
- Gibt Einblick in die Implementierung und Verwendung von .NET-Sprachen und Frameworks
- Findet undokumentierte und nicht offengelegte Funktionen, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblies
- Ermittelt den genauen Ort von Fehlern in deinem Code, Drittanbieterkomponenten und Bibliotheken.
- Ermöglicht das Debuggen im Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem Betriebssystem verwenden (du kannst es direkt in VSCode installieren, ohne Git herunterladen zu müssen. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du erneut **dekompilieren**, **ändern** und **kompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Methode ändern**, um etwas innerhalb einer Funktion zu ändern).

### Ausführungsfreie verwaltete Inspektion mit REA

**REA** kann PE/CLI-Metadaten und CIL untersuchen, ohne die Assembly zu laden. Beginne mit der Identität des Artefakts und untersuche dann die Member und deklarierten nativen Grenzen. Das ist nützlich, wenn verdächtige Aufrufe geprüft werden, bevor ein Decompiler verwendet oder das Programm ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Beim Versionsvergleich verwendet `compare_managed_members` die unveränderte CIL-/Signaturidentität und Fingerprints dekodierter Instruktionen, statt Metadatentokens als buildübergreifend stabil zu behandeln. Eine P/Invoke-Deklaration beweist nicht, dass nativer Code ausgeführt wurde; `verify_managed_native_boundaries` benötigt einen passenden nativen Export oder Funktionsnachweis, um diese Grenze zu überprüfen. Bewahre den Artefakt-Digest, die MVID und nicht aufgelöste Zuordnungen zusammen mit dem Ergebnis auf.<sup>[[17]](#references)</sup>

### DNSpy-Protokollierung

Um **DNSpy einige Informationen in eine Datei schreiben zu lassen**, kannst du diesen Codeausschnitt verwenden:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy-Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly-Attribute** ändern, die sich auf das **Debugging** beziehen:

![DNSpy Logging - DNSpy-Debugging: Zuerst die Assembly-Attribute ändern, die sich auf das Debugging beziehen](<../../images/image (973).png>)

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

Das ist notwendig, denn wenn du dies nicht tust, werden zur **Laufzeit** mehrere **Optimierungen** auf den Code angewendet. Dadurch kann es passieren, dass beim Debuggen ein **Haltepunkt nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn deine .NET-Anwendung von **IIS** **ausgeführt** wird, kannst du sie anschließend mit diesem Befehl **neu starten**:

```
iisreset /noforce
```

Dann solltest du zum Starten des Debuggings alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Schließe zum Starten des Debuggings alle geöffneten Dateien und wähle im Debug Tab Attach to Process aus](<../../images/image (318).png>)

Wähle anschließend **w3wp.exe** aus, um eine Verbindung zum **IIS server** herzustellen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle w3wp.exe aus, um eine Verbindung zum IIS server herzustellen, und klicke auf attach](<../../images/image (113).png>)

Da wir jetzt den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Da wir jetzt den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Da wir jetzt den Prozess debuggen, müssen wir ihn anhalten und alle Module laden. Klicke zuerst auf Debug Break All und dann auf Debug Windows Modules](<../../images/image (834).png>)

Klicke in **Modules** auf ein beliebiges Modul und wähle **Open All Modules** aus:

![DNSpy Logging - DNSpy Debugging: Klicke in Modules auf ein beliebiges Modul und wähle Open All Modules aus](<../../images/image (922).png>)

Klicke in **Assembly Explorer** mit der rechten Maustaste auf ein beliebiges Modul und dann auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Klicke in Assembly Explorer mit der rechten Maustaste auf ein beliebiges Modul und dann auf Sort Assemblies](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### Mit IDA

- **Lade rundll32** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- Wähle den **Windbg**-Debugger aus
- Wähle "**Suspend on library load/unload**" aus

![Debugging DLLs - Using IDA: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Konfiguriere die **Parameter** der Ausführung, indem du den **Pfad zur DLL** und die aufzurufende Funktion angibst:

![Debugging DLLs - Using IDA: Konfiguriere die Parameter der Ausführung, indem du den Pfad zur DLL und die aufzurufende Funktion angibst](<../../images/image (704).png>)

Wenn du dann mit dem Debugging beginnst, **wird die Ausführung beim Laden jeder DLL angehalten**. Sobald rundll32 deine DLL lädt, wird die Ausführung also angehalten.

Diese Methode hält die Ausführung bei Modul-Ladeereignissen an. Den Einstiegspunkt der geladenen DLL zu erreichen, ist damit jedoch weniger direkt als mit dem folgenden x64dbg-Workflow.

### Mit x64dbg/x32dbg

- **Lade rundll32** (64-Bit-Version unter C:\Windows\System32\rundll32.exe und 32-Bit-Version unter C:\Windows\SysWOW64\rundll32.exe)
- **Ändere die Command Line** ( _File --> Change Command Line_ ) und gib den Pfad zur DLL sowie die aufzurufende Funktion an, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ändere unter _Options --> Settings_ die Einstellung und wähle "**DLL Entry**" aus.
- **Starte dann die Ausführung**. Der Debugger hält bei jedem DLL main an; irgendwann **hält er am Entry deiner DLL an**. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte, dass du in win64dbg **oben im Fenster von win64dbg** sehen kannst, **in welchem Code du dich befindest**, wenn die Ausführung aus irgendeinem Grund angehalten wird:

![Using IDA - Using x64dbg/x32dbg: Beachte, dass du oben im Fenster von win64dbg sehen kannst, in welchem Code du dich befindest, wenn die Ausführung aus irgendeinem Grund angehalten wird](<../../images/image (842).png>)

Diese Anzeige bestätigt, dass die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Anwendungen / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern. Weitere Informationen:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Front-end-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Reverse-Engineering-Aufgaben verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein webbasiertes Front-end für verschiedene Decompiler. Dieser Webdienst ermöglicht es dir, die Ausgaben verschiedener Decompiler für kleine ausführbare Dateien zu vergleichen.

### Godot-PCK-Entschlüsselung und Wiederherstellung von Projekten

Suche bei einem verbreiteten Godot-Spiel nach dessen PCK: in einer eigenständigen `.pck`-Datei, einem angehängten oder eingebetteten ausführbaren Paket oder im Verzeichnis `assets` einer APK. [gore](https://github.com/figurophobia/gore) kann das Paket untersuchen und extrahieren. Für die vollständige Rekonstruktion von Skripten und Ressourcen werden jedoch GDRE Tools benötigt (`gore setup` installiert sie, oder verwende `--gdre`). Für diesen Workflow unterstützt das Tool Godot-4.x-PCK-Formate v2–v4; v1-Header können erkannt werden, für v1 muss aber ein Schlüssel angegeben werden.<sup>[[25]](#references)</sup>

Für die automatische Schlüsselwiederherstellung ist eine verschlüsselte Dateitabelle erforderlich. Wenn nur Dateiinhalte verschlüsselt sind, musst du stattdessen einen bekannten Schlüssel angeben. Eine fehlgeschlagene Wiederherstellung beweist nicht, dass ein Paket unverschlüsselt ist.<sup>[[28]](#references)</sup>

Bei der Schlüsselsuche handelt es sich **nicht** um einen AES-256-Keyspace-Angriff. Eine verschlüsselte Dateitabelle legt den MD5-Hash ihres Klartexts, die Klartextlänge, den IV und den AES-256-CFB-Chiffretext offen.<sup>[[27]](#references)</sup> `gore` testet 32-Byte-Fenster der ausführbaren Spieldatei oder benachbarter Dateien als mögliche Schlüssel. Es filtert Kandidaten anhand plausibler Länge und Präfixe entschlüsselter Pfade und bestätigt Treffer beim Scannen von Binärdateien, indem es die gesamte Tabelle entschlüsselt und ihren MD5-Hash überprüft.<sup>[[26]](#references)[[28]](#references)</sup> Zuerst werden initialisierte PE-/ELF-Datensektionen durchsucht, anschließend wird auf einen Scan der gesamten Datei zurückgegriffen; `--scan` bezieht weitere mögliche Kandidatendateien ein.<sup>[[28]](#references)</sup>

Wird kein eingebetteter Schlüssel gefunden, wird eine kleine integrierte Passwortliste ausprobiert; mit `--wordlist` kannst du weitere Kandidaten angeben. Jedes Passwort wird als vom Engine abgeleitete Schlüsselrepräsentation, als mit Nullen aufgefülltes Literal oder als Schlüssel mit 64 Hexadezimalzeichen getestet. Anders als Treffer beim Scannen von Binärdateien bestehen Treffer aus der Wortliste in dieser Implementierung lediglich den Filter für die Pfadstruktur. Bestätige sie, indem du das Paket öffnest und die extrahierten Assets überprüfst.<sup>[[26]](#references)[[28]](#references)</sup>

Wenn das Spielartefakt lokal verfügbar ist, wähle die für die Analyse benötigte Stufe. `recover` ruft GDRE auf, um ein öffnungsfähiges Projekt wiederherzustellen, während `extract` nur die Rohdateien entpackt. `key` gibt einen möglichen Schlüssel aus, der mit einem anderen Tool verwendet werden kann.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Evidenzgestützte native Untersuchung mit REA

**REA** stellt Hopper-, Ghidra- und IDA-Analysen über CLI und MCP bereit. Erfordert Node.js 22.x (mindestens 22.19), 24.x (mindestens 24.11) oder 26+ sowie npm. Konfigurieren Sie zuerst einen vorhandenen nativen Provider. Prüfen Sie `rea providers --json` und wählen Sie explizit einen Provider aus, wenn mehrere das Ziel unterstützen. Verwenden Sie anstelle von `0x1000` unten einen beobachteten Funktionsnamen oder eine Adresse aus dem Inventar.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Beginne mit einem Feature-String oder Symbol, folge Referenzen und Aufrufern und untersuche dann das ausgewählte Funktionsdossier und den Pseudocode mit `rea decompile`. REA bindet eine Sitzung an den ausgewählten Provider, anstatt ihn nach einem Fehler stillschweigend zu ersetzen. Für wiederholbare Abfragen verwendet `--snapshot PATH` nur übereinstimmende Artefakt-Bytes, Provider, Einstellungen, Operationen und Parameter erneut; ein Snapshot ist ein lokaler Cache und keine gespeicherte Provider-Datenbank. Bewahre die zurückgegebenen Evidence und expliziten Unbekannten auf, statt abgeleitete Pfade oder Decompiler-Text als Original-Quellcode zu behandeln.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript-/Electron-Einstiegspunkte, die zu nativen Add-ons führen, findest du unter [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skriptgesteuerte IDA- und Ghidra-Analyse mit einer lokalen TCP-Bridge

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) läuft innerhalb einer **bereits geöffneten** IDA-Datenbank oder eines Ghidra-CodeBrowser-Programms und ermöglicht einem separaten Skript, diese Analysedatenbank abzufragen und zu ändern. Führe `ID_Server.py` über die Python-CLI von IDA aus (`import ID_Server`) oder `Ghidra_Server.py` über den Script Manager von Ghidra. IDA bindet sich ab Port `5073` an `127.0.0.1` und durchsucht höhere Ports. Das aktuelle Ghidra-Skript startet an Port `5093` und versucht zehn Ports bis einschließlich `5102`; sein Java-Socket bindet sich an die Wildcard-Adresse, nicht nur an Loopback. Prüfe vor dem Verbinden den von der Instanz ausgegebenen Port. Anders als ein Headless Analyzer arbeitet diese Bridge mit dem Programm, das derzeit in der jeweiligen GUI-Instanz geöffnet ist.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Sende **einen mit einem Zeilenumbruch abgeschlossenen Befehl pro Verbindung** und lies die mit einem Zeilenumbruch abgeschlossene Antwort. Das Ergebnis ist normalerweise JSON. Nachdem du beispielsweise eine importierte API gefunden hast, die für einen Eingabepfad relevant ist, ermittelt `IMPORTXREF` deren Aufrufstellen; `DECOMP_XREF` dekompiliert anschließend gesammelt die Aufrufer einer ausgewählten Adresse. `FUNC` untersucht eine Funktion, während `PCODE` die Zwischendarstellung des Decompilers zurückgibt. Verwende die Adresse aus der aktiven Datenbank und keine Adresse, die aus einer anders rebasierten Binärdatei kopiert wurde. Das folgende Beispiel verwendet den Standardport von IDA; für Ghidra verwende den von dessen Skript ausgegebenen Port.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Der gleiche Kanal kann **die Analysedatenbank ändern**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` und `PATCH` ändern Namen, Typen, Strukturdefinitionen, Funktionsgrenzen oder gespeicherte Bytes. `PATCH` ist eine Datenbankänderung, **kein** Beleg für einen Patch in einem laufenden Prozess. Keiner der beiden Listener dokumentiert eine Authentifizierung. IDA ist auf Loopback beschränkt, Ghidra ist möglicherweise über Netzwerkschnittstellen erreichbar; beschränke den Zugriff auf den Ghidra-Listener, wenn du ihn verwendest. `QUIT` beendet beide Listener, und IDA stellt außerdem `ida_bridge_stop()` bereit.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Einen Shellcode mit blobrunner debuggen

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert Speicher für den **Shellcode**, gibt dessen **Speicheradresse** aus und hält die Ausführung an.\
Hänge einen Debugger wie IDA oder x64dbg an, setze einen Breakpoint an der ausgegebenen Adresse und setze die Ausführung fort, um den Shellcode zu debuggen.

Die GitHub-Releases-Seite enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unter folgendem Link findest du eine leicht modifizierte Version von Blobrunner. Um sie zu kompilieren, musst du lediglich **ein C/C++-Projekt in Visual Studio Code erstellen, den Code kopieren und einfügen und ihn dann erstellen**.


{{#ref}}
blobrunner.md
{{#endref}}

### Einen Shellcode mit jmp2it debuggen

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) ähnelt BlobRunner. Es reserviert Speicher für den Shellcode und tritt in eine Endlosschleife ein. Hänge den Debugger an, setze die Ausführung **2–5 Sekunden** lang fort, pausiere innerhalb dieser Schleife und gehe dann bis zum folgenden Aufruf, der die Ausführung an den reservierten Shellcode übergibt.

![Debugger in jmp2its Endlosschleife unmittelbar vor dem Aufruf des reservierten Shellcodes angehalten](<../../images/image (509).png>)

Eine kompilierte Version von [jmp2it kannst du auf der Releases-Seite herunterladen](https://github.com/adamkramer/jmp2it/releases/).

### Shellcode mit Cutter debuggen

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter die Optionen „Open File“ und „Open Shellcode“ bietet. In meinem Fall wurde der Shellcode beim Öffnen als Datei korrekt dekompiliert, als Shellcode jedoch nicht:

![Cutter zeigt unterschiedliche Analyseergebnisse beim Öffnen derselben Bytes als Datei oder als Shellcode](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen bp. Offenbar startet Cutter die Emulation dann automatisch an dieser Stelle:

![Breakpoint am gewünschten Shellcode-Einstiegspunkt setzen, bevor die Cutter-Emulation gestartet wird](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint angehalten](<../../images/image (387).png>)

Du kannst beispielsweise den Stack in einem Hex-Dump anzeigen:

![Den emulierten Shellcode-Stack im Hex-Dump von Cutter anzeigen](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Es zeigt dir unter anderem, **welche Funktionen** der Shellcode verwendet und ob der Shellcode sich im Speicher **dekodiert**.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg verfügt außerdem über einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und den Shellcode ausführen kannst

![Grafischer Launcher von scDbg zum Auswählen von Shellcode-Emulations- und Tracing-Optionen](<../../images/image (258).png>)

Mit der Option **Create Dump** wird der finale Shellcode ausgegeben, wenn zur Laufzeit Änderungen am Shellcode im Speicher vorgenommen wurden (nützlich, um den decodierten Shellcode herunterzuladen). Der **start offset** kann hilfreich sein, um den Shellcode ab einem bestimmten Offset zu starten. Mit der Option **Debug Shell** kannst du den Shellcode über das scDbg-Terminal debuggen. Für diesen Zweck finde ich jedoch eine der zuvor erläuterten Optionen besser, da du dann Ida oder x64dbg verwenden kannst.

### Disassemblieren mit CyberChef

Lade deine Shellcode-Datei als Eingabe hoch und verwende das folgende Rezept, um sie zu disassemblieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuscation von MBA-Obfuskation

Die **Mixed Boolean-Arithmetic (MBA)**-Obfuskation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten meist nur bei **Arithmetik mit fester Bitbreite und Modulo** korrekt sind, sodass Überträge und Überläufe eine Rolle spielen:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Wenn du diesen Ausdruckstyp mit allgemeinen Algebra-Tools vereinfachst, kann leicht ein falsches Ergebnis herauskommen, weil die Bitbreitensemantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite bei**, die aus dem angehobenen Code/der IR/decompiler-Ausgabe stammt (`8/16/32/64` Bits).
2. **Ordne den Ausdruck ein**, bevor du versuchst, ihn zu vereinfachen:
   - **Linear**: gewichtete Summen bitweiser Atome
   - **Semilinear**: linear, ergänzt um konstante Masken wie `x & 0xFF`
   - **Polynomial**: Produkte kommen vor
   - **Gemischt**: Produkte und bitweise Logik sind miteinander verschachtelt, oft mit wiederholten Teilausdrücken
3. **Überprüfe jede mögliche Umschreibung** durch Zufallstests oder einen SMT-Beweis. Wenn sich die Äquivalenz nicht beweisen lässt, behalte den ursprünglichen Ausdruck bei, statt zu raten.

### Flattened Control Flow mit einem schmalen Ausführungsslice umgehen

Den vollständigen Kontrollflussgraphen zu rekonstruieren, ist oft unnötig. Folge bei Control-Flow-Flattening, opaque predicates, großen Dispatchern oder MBA-lastigem Code den Referenzen von verschlüsselten Blobs und Ausgabepuffern bis zur kleinsten Routine, die sie transformiert. Reproduziere dann nur diesen Data-Flow-Slice oder führe ihn unabhängig aus; der Dispatcher ist nicht Teil der erforderlichen Lösung, wenn sich der relevante Zustand direkt initialisieren lässt.<sup>[[7]](#references)</sup>

Ein praktischer Workflow sieht so aus:<sup>[[7]](#references)</sup>

1. Erfasse ausführbare und Daten-Sections, Relocations und Cross-References. Dump candidate tables aus `.rodata` und bewahre dabei Byte-Reihenfolge und Elementbreite.
2. Ermittle die letzte Routine, die den Klartext- oder Ausgabepuffer beschreibt. Notiere ihre Eingaben, referenzierten Tabellen, importierten Aufrufe und den erforderlichen globalen Zustand.
3. Übertrage nur diese Operationen in ein Python-Modell mit fester Bitbreite. Wenn der Slice weiterhin von zu viel Zustand abhängt, rufe die Routine unter Unicorn, QEMU oder einem Debugger auf und hooke irrelevante Imports, statt das ganze Programm zu emulieren.
4. Überprüfe, ob der Extractor seine Ausgabe tatsächlich aus der bereitgestellten Binärdatei ableitet: Entferne stille Fallbacks, durchsuche sie nach eingebetteten Antworten und führe ihn mit unbekannten Builds mit geänderten Strings, Schlüsseln, Identifikatoren, Layouts und Obfuskations-Seeds aus.

Nützliche Befehle für einen ersten Durchgang sind:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### MBA-Ausdrücke erkennen, die als Konstanten getarnt sind

Ein scheinbar eingabeabhängiger Byte-Ausdruck kann seine Eingabe vollständig aufheben. Nachdem seine Tabellen extrahiert wurden, lässt sich der Ausdruck über den vollständigen 8-Bit-Wertebereich auswerten; eine einelementige Ausgabemenge beweist, dass das Byte konstant ist, ohne die umgebende Zustandsmaschine rekonstruieren zu müssen.<sup>[[7]](#references)</sup>

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

Behalte die abschließende Maske bei, da die ursprüngliche Addition bei Bytebreite überläuft. Für einen größeren Wertebereich kannst du einen SMT-Solver fragen, ob `f(x1) != f(x2)` für zwei symbolische Eingaben gleicher Breite erfüllbar ist: `unsat` beweist Invarianz, während `sat` ein Gegenbeispiel liefert und bedeutet, dass die Eingabe nicht verworfen werden kann.<sup>[[7]](#references)</sup>

#### Umgebungsabhängige Decodierung erkennen

Anti-Analyse-Prüfungen müssen weder einen Verzweigungspfad auslösen noch zum Absturz führen. Ein Decoder kann ein Sensorergebnis in ein Schlüsselbit, eine Konstante eines opaque predicate oder den Zustand eines abgeflachten Dispatchers einmischen, normal fortfahren und in einem Emulator plausiblen, aber falschen Klartext erzeugen. Daher reicht es nicht aus, nur sichtbare Fehlerpfade zu patchen. Verfolge stattdessen die Datenabhängigkeiten von Umgebungsprüfungen bis in den Decoderzustand, vergleiche denselben Ausschnitt auf dem authentischen Gerät und im Emulator und teste, wie sich das Erzwingen jedes Sensorergebnisses auf den endgültigen Puffer auswirkt.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Vereinfacher für Malware-Analysen und das Reversing geschützter Binärdateien. Das Tool klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, statt auf alles denselben allgemeinen Rewrite-Durchlauf anzuwenden.<sup>[[2]](#references)</sup>

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

Nützliche Fälle:

- **Linear MBA**: CoBRA wertet den Ausdruck mit booleschen Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden gegeneinander antreten, etwa Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: Konstantenmaskierte Atome werden mit einer bitpartitionierten Rekonstruktion neu aufgebaut, sodass maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel einer gemischten Identität, deren Wiederherstellung sich oft lohnt:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Dies lässt sich zusammenfassen zu:

```c
x * y
```

### Hinweise zum Reverse Engineering

- CoBRA sollte bevorzugt auf **angehobenen IR-Ausdrücken** oder Decompiler-Ausgaben ausgeführt werden, nachdem du die genaue Berechnung isoliert hast.
- Verwende `--bitwidth` explizit, wenn der Ausdruck aus maskierter Arithmetik oder schmalen Registern stammt.
- Wenn du einen stärkeren Beweisschritt benötigst, sieh dir die lokalen Z3-Notizen hier an:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM-Pass-Plugin** (`libCobraPass.so`) ausgeliefert. Das ist nützlich, wenn du MBA-lastige LLVM-IR vor späteren Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte, carry-sensitive Residuen aus gemischten Domänen solltest du als Signal verstehen, den ursprünglichen Ausdruck beizubehalten und den Carry-Pfad manuell zu analysieren.

## XOR-State-Control-Flow-Flattening wiederherstellen

Ein Flattener im OLLVM-Stil kann den aktuellen Basic-Block-State in zwei 64-Bit-Registern speichern und ihn am Dispatcher mit XOR rekonstruieren. Jeder ursprüngliche Block schreibt das Registerpaar für seinen nächsten State und springt zurück zum Dispatcher. Ein bedingter Block kann `CMOVcc` verwenden, um abhängig von den CPU-Flags eine Hälfte des Paars zu ersetzen. Wer nur sichtbaren Branch-Instruktionen folgt, übersieht daher die beiden möglichen Nachfolger. Anders als ein Dispatcher mit indirekten Sprüngen kann diese Form durchgängig direkte Rücksprünge verwenden.<sup>[[19]](#references)[[20]](#references)</sup>

Um den Graphen wiederherzustellen, identifiziere den Vergleichsbaum des Dispatchers und die beiden State-Register, ordne jeden verglichenen XOR-State seinem Zielblock zu und verfolge dann die erreichenden Schreibzugriffe auf das Registerpaar in jedem ursprünglichen Block. Berücksichtige bei bedingten Schreibzugriffen die Flag-setzende Instruktion und beide `CMOVcc`-Ergebnisse. Ersetze den Dispatcher-Ausstieg jedes Blocks durch seinen aufgelösten direkten Nachfolger oder bedingten Branch. Danach ist der Dispatcher unerreichbar, ohne dass die Binary gepatcht werden muss. Das ist ein vollständiger CFG-Ansatz; wenn nur ein Decoder relevant ist, kann der oben beschriebene [Workflow für einen engen Ausführungsslice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) schneller sein.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatisiert diese Form in Binary Ninja. Kopiere `plugins/DispatchThis` in das Benutzer-Plugin-Verzeichnis von Binary Ninja und starte es neu. Öffne bei der betroffenen Funktion **Function Settings** und wähle `OLLVM_XOR_64`. Wenn die Analyse nicht startet, verwende **Analysis → Reanalyze All Functions**. Dieser Modus schreibt MLIL-Control-Flow-Kanten um, nicht die Bytes der Datei, und benötigt weder Z3 noch den Resolver für indirekte Sprünge. Er wurde mit Binary Ninja 5.3.9757+ getestet; die toten State-Schreibzugriffe in den einzelnen Blöcken werden nicht entfernt. Verwechsle sie daher nicht mit weiterhin aktiven Zustandsübergängen.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Programmoperationen durch `mov`-basierte Instruktionssequenzen und verwendet Signal-/Exception-Handling, um den Control Flow zu ändern. Details:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Für unterstützte Binaries kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuskieren. Das Tool hat mehrere Abhängigkeiten.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Und [keystone installieren](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **Einstiegspunkt** zu finden, suche in den Funktionen nach `::main`, wie hier:

![Einen Rust-Einstiegspunkt in Ghidra finden, indem Funktionsnamen nach doppeltem Doppelpunkt und main durchsucht werden](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Suche mit dem **Namen** der aufgerufenen **Funktionen** im **Internet**, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binaries werden viele statische Strings nicht als C-typische, NUL-terminierte Zeiger referenziert. Ein häufiges `rustc`-Layout ist ein **Zeiger-/Längen-Tupel** in **`.data.rel.ro`**, das auf den eigentlichen String-Blob in **`.rodata`** verweist:

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
2. Durchlaufe **`.data.rel.ro`** wortweise.
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

Das ist beim Firmware-Reversing besonders nützlich, da wiederhergestellte Rust-Strings oft **HTTP-Routen, RPC-Namen, Logmeldungen, Assertions, Dateinamen, Konfigurationsschlüssel, Command-Handler und Auth-bezogene Logik** offenlegen.

Wenn Ghidra diese Strings nicht erkennt, führe ein benutzerdefiniertes Skript/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **Wortbreiten, Byte-Reihenfolgen und Section-Layouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für mit Delphi kompilierte Binaries kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du ein Delphi-Binary reversen musst, würde ich dir das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) empfehlen.

Drücke in IDA **Alt+F7**, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dieses Plugin führt das Binary aus und löst die Funktionsnamen zu Beginn des Debuggings dynamisch auf. Drücke nach dem Start des Debuggings erneut auf die Schaltfläche Start (die grüne Schaltfläche oder f9), und ein Breakpoint wird am Anfang des eigentlichen Codes ausgelöst.

Wenn du in der grafischen Anwendung auf eine Schaltfläche klickst, kann der Debugger an der Funktion anhalten, die von dieser Schaltfläche aufgerufen wird.

## Golang

Für gewöhnliche Go-Binaries kann [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) Laufzeitstrukturen wiederherstellen und Funktionsnamen in IDA verbessern. Lade das Python-Plugin mit **Alt+F7**.

Wenn du ein Golang-Binary reversen musst, würde ich dir das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) empfehlen.

Drücke in IDA **Alt+F7**, um ein Python-Plugin zu laden, und wähle dann die Plugin-Datei aus.

Dadurch werden die Funktionsnamen aufgelöst.

### Metadaten ohne die Symboltabelle wiederherstellen

Ein gestripptes Go-Executable benötigt weiterhin Laufzeitmetadaten, um Program Counter den Funktionen zuzuordnen. [GoReSym](https://github.com/mandiant/GoReSym) findet und parst Strukturen wie `pclntab` und `moduledata` mithilfe von Code, der vom Go-Runtime abgeleitet wurde. Dadurch lassen sich Funktionsgrenzen, Namen, Quellpfade, Typen und Build-Details wiederherstellen, ohne sich auf die herkömmliche Symboltabelle zu stützen.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ein Obfuscator kann diese Strukturen nutzbar lassen und gleichzeitig die wiederhergestellten Namen ersetzen. Garble beispielsweise hasht Bezeichner und Paketpfade und entfernt Build-, Modul- und Debug-Informationen.<sup>[[12]](#references)</sup> Das obfuskierte Paket-Token muss für alle Funktionen dieses Pakets konsistent bleiben. Gruppiere Funktionen anhand des wiederkehrenden Tokens, leite aus den aufgerufenen Funktionen, Strings und APIs ein Paket ab und übertrage diese Paketbezeichnung anschließend auf die gesamte Gruppe.<sup>[[13]](#references)</sup>

### Garble-Namen mit GoResolver wiederherstellen

[GoResolver](https://github.com/volexity/GoResolver) kombiniert die Extraktion von Runtime-Symbolen mit der Generierung von Referenzen ohne Obfuscation und dem Abgleich von Kontrollflussgraphen (CFGs). Gehe wie folgt vor:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler-Version ermitteln.** Prüfe zuerst `BuildInfo` und eingebettete Versionsstrings. Falls der Obfuscator sie entfernt hat, vergleiche Teile der gebündelten Go-Runtime mit versionierten Referenz-Runtimes. In den Tests von Volexity reichten etwa `2%` der Runtime aus, um die Go-Hauptversionen zu unterscheiden. Betrachte dies als empirische Optimierung, nicht als universellen Schwellenwert.<sup>[[13]](#references)</sup>
2. **Passende Referenzen erstellen.** Erzeuge unveränderte Binärdateien für die ermittelte Go-Version, die Zielarchitektur und wahrscheinliche Bibliotheken. Ein passender Toolchain reduziert Unterschiede in den vom Compiler erzeugten CFGs.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Funktionen vergleichen.** GoGrapher gleicht Funktions-CFGs ab und gibt normalisierte Werte zwischen `0.0` und `1.0` aus. Der Abgleich der Basisblöcke basiert auf einem gewichteten Vergleich ähnlicher Instruktionen. Zuverlässige Treffer ordnen randomisierte Funktionen der unveränderten Implementierung zu. Weniger zuverlässige Treffer können dennoch ein Paket oder Modul identifizieren.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Der standardmäßige Schwellenwert für signifikante Übereinstimmungen ist `0.9`. Mit den Schaltern `--extract` und `--graph` lässt sich jeweils eine der beiden Phasen isolieren. Standardmäßig werden beide ausgeführt, da sich die wiederhergestellten Runtime-Metadaten und die CFG-Belege ergänzen.<sup>[[10]](#references)</sup> CFG-Scores sind heuristisch: Inlining, Build-Flags, Architektur und Unterschiede zwischen Bibliotheksversionen können die Graphstruktur verändern. Behalte daher nicht aufgelöste Funktionen bei, anstatt ihnen Namen mit geringer Konfidenz zuzuweisen.<sup>[[13]](#references)</sup>

### Go-String-Tabelle wiederherstellen

Go-Binärdateien enthalten die String-Bytes aller gelinkten Pakete in einer zusammenhängenden Tabelle. Die Einträge sind nicht mit NUL terminiert, und Runtime-Strukturen geben weder die Basisadresse noch die Größe der Tabelle preis. Der Compiler ordnet die Einträge jedoch auf allen Betriebssystemen und Architekturen zuerst nach Länge und dann alphabetisch. Nachdem ein Eintrag gefunden wurde, kann ein Analyst daher benachbarte Einträge durchlaufen und Strings mithilfe von Daten-Querverweisen dem Code zuordnen.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatisiert diesen Workflow in IDA Pro und Ghidra. Warte zunächst, bis die Auto-Analyse abgeschlossen ist, da das Plugin auf Querverweisen aus Datensegmenten basiert. Als Standardanker dient der Runtime-String `entersyscall`. Anschließend kann das Plugin in beide Richtungen suchen, die wiederhergestellten Strings in der Datenbank definieren und ein JSON-Mapping von Strings zu referenzierenden Funktionen exportieren.<sup>[[14]](#references)</sup>

Filtere den Bericht nach dem Paket der referenzierenden Funktion, um Anwendungscode oder Malware-Code von verknüpftem Bibliotheksrauschen zu trennen. Mit dieser Technik lassen sich keine Literale wiederherstellen, die durch Obfuskation zerstört wurden, etwa durch Garbles `-literals`-Transformation. Runtime-Strings, die nicht obfuskiert wurden, lassen sich damit dennoch ordnen.<sup>[[14]](#references)[[15]](#references)</sup>

### Go-Runtime-Typen wiederherstellen

Go bettet Runtime-Typinformationen ein, die von Funktionen wie der Garbage Collection verwendet werden. Wenn Build-Informationen entfernt wurden oder der Disassembler diese Metadaten nicht parst, scheinen Instruktionen beliebige Datenadressen zu laden, und die Zielregion bleibt untypisiert. Durch die Wiederherstellung der Metadaten werden diese Adressen zu lesbaren Typreferenzen, sodass sich die Fähigkeiten der Pakete leichter nachvollziehen lassen.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) kann Symbole extrahieren und Runtime-Typen parsen, um einen JSON-Bericht zu erstellen. Die aktuelle CLI verwendet den Unterbefehl `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Die Option `-y`/`--types` aktiviert das Parsen von Typen. Importiere den Bericht mit dem IDA-Pro- oder Ghidra-Plugin von GoResolver, um die wiederhergestellten Typen zu definieren und ihre Referenzen in der Analysedatenbank anzuwenden. Im mit diesem Feature eingeführten Berichtsformat sind die RTTI-Adresse und die Member für wiederhergestellte Typen null, wenn `-y` weggelassen wird.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver unterstützt PE-, ELF- und Mach-O-Dateien für x86, AMD64, ARM und ARM64, sodass derselbe Workflow für Go-Binärdateien von Windows, Linux und macOS gilt.<sup>[[10]](#references)</sup>

## Kompiliertes Python

Auf dieser Seite erfährst du, wie du den Python-Code aus einer kompilierten Python-ELF-/EXE-Binärdatei erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du die **Binärdatei** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug-Version herunterladen_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_** sehen, wie die **Tasten** des Game Boy Advance gedrückt werden

![no$gba-Konfiguration der Steuerung mit den Tastenbelegungen des Game Boy Advance](<../../images/image (581).png>)

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

Bei dieser Art von Programm ist also **entscheidend, wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** finden Sie die häufig vorkommende Funktion: **KEYINPUT**.

![Ghidra-Ansicht einer GBA-Binärdatei mit einem Verweis auf KEYINPUT an Adresse 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild sehen Sie, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion folgen nach einigen Initialisierungsoperationen (ohne Bedeutung):

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

Der letzte if-Ausdruck prüft, ob **`uVar4`** in den **letzten Tasten** enthalten und nicht die aktuelle Taste ist – also, ob eine Taste losgelassen wird (die aktuelle Taste wird in **`uVar1`** gespeichert).

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

Im vorherigen Code sehen Sie, dass wir **uVar1** (die Stelle, an der sich der **Wert der gedrückten Taste** befindet) mit einigen Werten vergleichen:

- Zuerst wird der Wert mit **4** (Taste **SELECT**) verglichen: In dieser Challenge löscht diese Taste den Bildschirm.
- Dann wird der Wert mit **8** (Taste **START**) verglichen; in dieser Challenge prüft dieser Pfad, ob der eingegebene Code gültig ist.
  - In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen. Stimmen die Werte überein, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und erhöht.\
  Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` aufsummiert.

Für diese Challenge mussten Sie also die Tastenwerte kennen und **eine Kombination mit weniger als 8 Tasten drücken, deren Summe 0xf3 ergibt.**

**Quelle für dieses Tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binäre Deobfuskierung)

## References

- [1] [Vereinfachung der MBA-Verschleierung mit CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings entschlüsseln - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [KI-gestütztes Reverse Engineering überwinden – oder es zumindest versuchen](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Ein Ansatz zum Vergleich von Kontrollflussgraphen auf Basis des Abgleichs von Basisblöcken](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble-Verschleierungsmechanismus](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kontrollflussgraph-Ähnlichkeit nutzen, um Golang-Binärdateien automatisch zu deobfuskieren](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Aktualisierungen der Golang-Tools von Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Alles reverse engineeren](https://github.com/morluto/rea)
- [17] [REA-Analyse von verwaltetem Code](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA-CLI- und Nachweisleitfaden](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Workflow zum Aufheben der Kontrollflussverflachung in Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut-MF-Zero-Day-Einbruch, Java-Loader, Web-Shell und AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README von IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementierung des IDA-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementierung des Ghidra-Bridge-Servers](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) bindet an die Wildcard-Adresse](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot-Reverse-Engineering-Toolkit](https://github.com/figurophobia/gore)
- [26] [Implementierung der Schlüsselwiederherstellung in gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Format verschlüsselter Blobs in gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Implementierung von gore-Befehl und -Wiederherstellung](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
