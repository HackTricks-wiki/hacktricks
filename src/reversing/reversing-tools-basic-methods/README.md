# Reversing-Tools und grundlegende Methoden

{{#include ../../banners/hacktricks-training.md}}

## Auf ImGui basierende Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm-Decompiler / Wat-Compiler

Online:

- Verwende [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (binär) nach wat (Klartext) zu **dekompilieren**
- Verwende [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um von wat nach wasm zu **kompilieren**
- Du kannst für die Dekompilierung auch [web-wasmdec](https://wwwg.github.io/web-wasmdec/) ausprobieren.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8-Bytecode im Cache

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET-Decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der **mehrere Formate dekompiliert und untersucht**, darunter **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **ausführbare Dateien** (.exe). Nach der Dekompilierung kann eine Assembly als Visual-Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil besteht darin, dass diese Maßnahme Zeit sparen kann, wenn der verlorene Quellcode aus einer Legacy-Assembly wiederhergestellt werden muss. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der perfekten Tools für die **Xamarin-Algorithmusanalyse.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an deine genauen Anforderungen anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Sehen wir uns die zahlreichen Reverse-Engineering-Funktionen an, die dieses Tool bietet:

- Bietet Einblick darin, wie die Daten durch eine Bibliothek oder Komponente fließen
- Bietet Einblick in die Implementierung und Verwendung von .NET-Sprachen und Frameworks
- Findet nicht dokumentierte und nicht offengelegte Funktionen, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblies
- Ermittelt den genauen Ort von Fehlern in deinem Code, Komponenten von Drittanbietern und Bibliotheken.
- Debuggt den Quellcode des gesamten .NET-Codes, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem OS verwenden (du kannst es direkt aus VSCode installieren, ohne das Git-Repository herunterladen zu müssen. Klicke auf **Extensions** und **suche nach ILSpy**).\
Wenn du **dekompilieren**, **ändern** und anschließend erneut **kompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Modify Method**, um etwas innerhalb einer Funktion zu ändern).

### DNSpy-Logging

Um **DNSpy einige Informationen in eine Datei protokollieren zu lassen**, kannst du dieses Snippet verwenden:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly-Attribute** im Zusammenhang mit dem Debugging ändern:

![DNSpy Logging - DNSpy Debugging: Zuerst die Assembly-Attribute im Zusammenhang mit dem Debugging ändern](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Und auf compile klicken](<../../images/image (314) (1).png>)

Speichern Sie anschließend die neue Datei über _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Anschließend die neue Datei über File Save module speichern](<../../images/image (602).png>)

Dies ist notwendig, da andernfalls zur **runtime** mehrere **optimisations** auf den Code angewendet werden und es möglich wäre, dass beim Debugging ein **break-point nie erreicht wird** oder einige **Variablen nicht existieren**.

Wenn Ihre .NET-Anwendung anschließend von **IIS** **ausgeführt** wird, können Sie sie mit Folgendem **neu starten**:
```
iisreset /noforce
```
Dann solltest du, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Um mit dem Debugging zu beginnen, solltest du alle geöffneten Dateien schließen und im Debug Tab Attach to Process auswählen](<../../images/image (318).png>)

Wähle anschließend **w3wp.exe** aus, um es an den **IIS server** anzuhängen, und klicke auf **attach**:

![DNSpy Logging - DNSpy Debugging: Wähle anschließend w3wp.exe aus, um es an den IIS server anzuhängen, und klicke auf attach](<../../images/image (113).png>)

Da wir den Prozess nun debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf _Debug >> Break All_ und anschließend auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Da wir den Prozess nun debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Da wir den Prozess nun debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf Debug Break All und anschließend auf Debug Windows Modules](<../../images/image (834).png>)

Klicke auf ein beliebiges Modul unter **Modules** und wähle **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Klicke auf ein beliebiges Modul unter Modules und wähle Open All Modules](<../../images/image (922).png>)

Klicke mit der rechten Maustaste auf ein beliebiges Modul im **Assembly Explorer** und klicke auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Klicke mit der rechten Maustaste auf ein beliebiges Modul im Assembly Explorer und klicke auf Sort Assemblies](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debuggen

### Verwendung von IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe und 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Wähle den **Windbg** debugger aus
- Wähle "**Suspend on library load/unload**" aus

![Debugging DLLs - Using IDA: Wähle " Suspend on library load/unload " aus](<../../images/image (868).png>)

- Konfiguriere die **parameters** der Ausführung, indem du den **path to the DLL** und die Funktion angibst, die du aufrufen möchtest:

![Debugging DLLs - Using IDA: Konfiguriere die parameters der Ausführung, indem du den path to the DLL und die Funktion angibst, die du aufrufen möchtest](<../../images/image (704).png>)

Wenn du anschließend mit dem Debugging beginnst, wird **die Ausführung angehalten, sobald jede DLL geladen wird**. Wenn rundll32 also deine DLL lädt, wird die Ausführung angehalten.

Diese Methode hält bei Module-Load-Events an, aber das Erreichen des Entry-Points der geladenen DLL ist weniger direkt als beim folgenden x64dbg-Workflow.

### Verwendung von x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe und 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) und setze den Pfad der dll sowie die Funktion, die du aufrufen möchtest, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ändere _Options --> Settings_ und wähle "**DLL Entry**" aus.
- **Starte anschließend die Ausführung**. Der Debugger hält bei jedem dll main an. Irgendwann wirst du **im dll Entry deiner dll angehalten**. Suche von dort aus einfach nach den Stellen, an denen du einen Breakpoint setzen möchtest.

Beachte, dass du bei win64dbg, wenn die Ausführung aus irgendeinem Grund angehalten wird, **oben im win64dbg-Fenster** sehen kannst, **in welchem Code du dich befindest**:

![Using IDA - Using x64dbg/x32dbg: Beachte, dass du bei win64dbg, wenn die Ausführung aus irgendeinem Grund angehalten wird, oben im win64dbg-Fenster sehen kannst, in welchem Code du dich befindest](<../../images/image (842).png>)

Dieser Indikator bestätigt, dass die Ausführung innerhalb der DLL angehalten wurde, die du debuggen möchtest.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert werden, und sie zu ändern. Weitere Informationen unter:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Front-end-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das auf Spiele ausgerichtet ist. Es kann jedoch für alle möglichen Reverse-Engineering-bezogenen Aufgaben verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Front-end für mehrere Decompiler. Dieser Webservice ermöglicht es dir, die Ausgabe verschiedener Decompiler bei kleinen Executables zu vergleichen.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging eines Shellcodes mit blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserviert den **shellcode**, gibt seine **memory address** aus und pausiert die Ausführung.\
Hänge einen Debugger wie IDA oder x64dbg an, setze einen Breakpoint an der ausgegebenen Adresse und setze die Ausführung fort, um den Shellcode zu debuggen.

Die github-Seite mit den Releases enthält zips mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Eine leicht modifizierte Version von Blobrunner findest du unter folgendem Link. Um sie zu kompilieren, **erstelle einfach ein C/C++-Projekt in Visual Studio Code, kopiere den Code und füge ihn ein und führe den Build aus**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging eines Shellcodes mit jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) ähnelt BlobRunner. Es reserviert den Shellcode und tritt in eine Endlosschleife ein. Hänge den Debugger an, setze die Ausführung für **2–5 Sekunden** fort, pausiere innerhalb dieser Schleife und führe einen Step bis zum nächsten Call aus, der die Ausführung an den reservierten Shellcode überträgt.

![Debugger in jmp2its Endlosschleife unmittelbar vor dem Call zum reservierten Shellcode pausiert](<../../images/image (509).png>)

Du kannst eine kompilierte Version von [jmp2it auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/) herunterladen.

### Debugging von Shellcode mit Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den Shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter **Open File** und **Open Shellcode** ermöglicht. In meinem Fall wurde der Shellcode korrekt dekompiliert, wenn ich ihn als Datei geöffnet habe, aber nicht, wenn ich ihn als Shellcode geöffnet habe:

![Cutter zeigt unterschiedliche Analyseergebnisse beim Öffnen derselben Bytes als Datei oder als Shellcode](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen bp. Offenbar startet Cutter die Emulation dann automatisch an dieser Stelle:

![Breakpoint am gewünschten Shellcode-Einstieg vor dem Start der Cutter-Emulation gesetzt](<../../images/image (589).png>)

![Cutter-Emulator am ausgewählten Shellcode-Breakpoint pausiert](<../../images/image (387).png>)

Du kannst beispielsweise den Stack innerhalb eines hex dump sehen:

![Emulierter Shellcode-Stack im hex dump von Cutter angezeigt](<../../images/image (186).png>)

### Shellcode deobfuskieren und ausgeführte Funktionen ermitteln

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Es zeigt dir Dinge wie **welche Funktionen** der Shellcode verwendet und ob der Shellcode sich selbst im Speicher **decoding**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg verfügt ebenfalls über einen grafischen Launcher, in dem Sie die gewünschten Optionen auswählen und den Shellcode ausführen können.

![Grafischer scDbg-Launcher zur Auswahl von Shellcode-Emulations- und Tracing-Optionen](<../../images/image (258).png>)

Die Option **Create Dump** erstellt einen Dump des finalen Shellcodes, falls der Shellcode dynamisch im Speicher verändert wird (nützlich, um den decodierten Shellcode herunterzuladen). Der **start offset** kann nützlich sein, um den Shellcode an einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den Shellcode über das scDbg-Terminal zu debuggen (ich finde jedoch jede der zuvor erklärten Optionen dafür besser, da Sie Ida oder x64dbg verwenden können).

### Disassemblieren mit CyberChef

Laden Sie Ihre Shellcode-Datei als Eingabe hoch und verwenden Sie das folgende Rezept, um sie zu dekompilieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)**-Obfuscation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische Operatoren (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten normalerweise nur unter **modularer Arithmetik mit fester Breite** korrekt sind, sodass Überträge und Überläufe berücksichtigt werden müssen:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kannst du leicht ein falsches Ergebnis erhalten, weil die Bitbreiten-Semantik ignoriert wurde.<sup>[[1]](#references)</sup>

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite** aus dem gehobenen Code/IR/Decompiler-Output bei (`8/16/32/64` Bit).
2. **Klassifiziere den Ausdruck**, bevor du versuchst, ihn zu vereinfachen:
- **Linear**: gewichtete Summen bitweiser Atome
- **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
- **Polynomial**: Produkte kommen vor
- **Mixed**: Produkte und bitweise Logik sind verschachtelt, häufig mit wiederholten Teilausdrücken
3. **Überprüfe jede mögliche Umformung** durch zufällige Tests oder einen SMT-Beweis. Wenn die Äquivalenz nicht bewiesen werden kann, behalte den ursprünglichen Ausdruck bei, anstatt zu raten.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Simplifier für Malware-Analyse und das Reversing geschützter Binaries. Es klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, anstatt auf alles einen generischen Rewrite-Pass anzuwenden.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA wertet den Ausdruck mit booleschen Eingaben aus, leitet eine Signatur ab und lässt mehrere Wiederherstellungsmethoden wie pattern matching, ANF conversion und coefficient interpolation gegeneinander antreten.
- **Semilinear MBA**: constant-masked atoms werden mit bit-partitioned reconstruction neu aufgebaut, sodass maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Kerne zerlegt, und wiederholte Teilausdrücke können vor der Vereinfachung der äußeren Relation in temporäre Variablen ausgelagert werden.

Beispiel für eine gemischte Identität, deren Wiederherstellung sich häufig lohnt:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dies lässt sich zusammenfassen zu:
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

- CoBRA wird auch als **LLVM pass plugin** (`libCobraPass.so`) ausgeliefert. Das ist nützlich, wenn du MBA-lastige LLVM-IR vor späteren Analyse-Pässen normalisieren möchtest.
- Nicht unterstützte carry-sensitive mixed-domain residuals sollten als Signal behandelt werden, den ursprünglichen Ausdruck beizubehalten und den carry path manuell zu analysieren.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator ersetzt Program operationen durch `mov`-based instruction sequences und verwendet Signal-/Exception-Handling, um den control flow zu verändern. Details:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Bei unterstützten Binaries kann [demovfuscator](https://github.com/kirschju/demovfuscator) das Ergebnis deobfuscaten. Es hat mehrere Dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Und [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, kann dieser Workaround zum Finden der Flag** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **entry point** zu finden, durchsuche die Funktionen nach `::main`, wie in:

![Einen Rust-entry point in Ghidra finden, indem Funktionsnamen nach doppeltem Doppelpunkt und main durchsucht werden](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, daher ist ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Wenn du den **Namen** der aufgerufenen **Funktionen** kennst, suche im **Internet** nach ihnen, um mehr über ihre **Inputs** und **Outputs** zu erfahren.

### Rust-Strings aus ELF-Firmware wiederherstellen

In **Rust-ELF**-Binaries werden viele statische Strings nicht als C-Style-Zeiger mit NUL-Terminierung referenziert. Ein häufiges `rustc`-Layout ist ein **Pointer/Length-Tupel** innerhalb von **`.data.rel.ro`**, das auf den tatsächlichen String-Blob verweist, der in **`.rodata`** gespeichert ist:
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
5. Wende Plausibilitätsfilter an (behalte beispielsweise Längen zwischen **4** und **100** Bytes).
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
Dies ist beim Firmware-Reversing besonders nützlich, da wiederhergestellte Rust-Strings häufig **HTTP-Routen, RPC-Namen, Log-Meldungen, Assertions, Dateinamen, Konfigurationsschlüssel, Command-Handler und Auth-bezogene Logik** offenlegen.

Wenn Ghidra diese Strings nicht erkennt, führe ein benutzerdefiniertes Script/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um diese Idee an andere **Wortbreiten, Endianness und Section-Layouts** anzupassen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Für kompilierte Delphi-Binaries kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du ein Delphi-Binary reverse musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) zu verwenden.

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle anschließend die Plugin-Datei aus.

Dieses Plugin führt das Binary aus und löst die Funktionsnamen zu Beginn des Debuggings dynamisch auf. Nachdem du das Debugging gestartet hast, drücke erneut die Start-Schaltfläche (die grüne Schaltfläche oder F9), woraufhin ein Breakpoint am Anfang des eigentlichen Codes ausgelöst wird.

Wenn du in der grafischen Anwendung eine Schaltfläche drückst, kann der Debugger in der von dieser Schaltfläche aufgerufenen Funktion anhalten.

## Golang

Wenn du ein Golang-Binary reverse musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) zu verwenden.

Drücke **Alt+F7** in IDA, um ein Python-Plugin zu laden, und wähle anschließend die Plugin-Datei aus.

Dadurch werden die Namen der Funktionen aufgelöst.

## Compiled Python

Auf dieser Seite findest du Informationen dazu, wie du den Python-Code aus einem kompilierten Python-Binary im ELF-/EXE-Format extrahierst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Wenn du das **Binary** eines GBA-Spiels erhältst, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Benutzeroberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), unter _**Options --> Emulation Setup --> Controls**_** ** kannst du sehen, wie die Game-Boy-Advance-**Tasten** gedrückt werden.

![no$gba-Konfiguration der Steuerung mit den Tastenbelegungen des Game Boy Advance](<../../images/image (581).png>)

Beim Drücken erhält jede **Taste einen Wert**, durch den sie identifiziert wird:
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
In dieser Art von Programm wird der interessante Teil darin bestehen, **wie das Programm die Benutzereingabe verarbeitet**. An der Adresse **0x4000130** finden Sie die häufig vorkommende Funktion: **KEYINPUT**.

![Ghidra-Ansicht eines GBA-Binaries mit Verweis auf KEYINPUT an der Adresse 0x4000130](<../../images/image (447).png>)

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
Das letzte if prüft, ob **`uVar4`** in den **letzten Keys** enthalten ist und nicht der aktuelle Key ist – auch als Loslassen einer Taste bezeichnet (der aktuelle Key wird in **`uVar1`** gespeichert).
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
Im vorherigen Code können Sie sehen, dass wir **uVar1** (die Stelle, an der sich der **Wert des gedrückten Buttons** befindet) mit einigen Werten vergleichen:

- Zuerst wird es mit dem **Wert 4** (dem **SELECT**-Button) verglichen: In der Herausforderung löscht dieser Button den Bildschirm.
- Danach wird der Wert mit **8** (dem **START**-Button) verglichen; in dieser Herausforderung prüft dieser Pfad, ob der eingegebene Code gültig ist.
- In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen, und wenn der Wert übereinstimmt, wird bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) geprüft und inkrementiert.\
Solange der Zähler kleiner als 8 ist, werden die Werte der gedrückten Tasten in `DAT_030000d8` akkumuliert.

In dieser Herausforderung mussten Sie also, nachdem Sie die Werte der Buttons kannten, **eine Kombination mit einer Länge von weniger als 8 drücken, deren resultierende Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [archivierter Nostalgia-Herausforderungsbericht](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binär-Deobfuskation)

## References

- [1] [Vereinfachung von MBA-Obfuskation mit CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [CoBRA-Repository von Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Rust-Strings decodieren - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust-Strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA-Reversing-Tutorial (archiviert)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
