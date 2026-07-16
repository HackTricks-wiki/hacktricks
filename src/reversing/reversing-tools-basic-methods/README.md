# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der **mehrere Formate dekompiliert und untersucht**, einschließlich **Bibliotheken** (.dll), **Windows metadata file**s (.winmd) und **Executables** (.exe). Nach dem Dekompilieren kann ein Assembly als Visual Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil dabei ist, dass diese Maßnahme Zeit sparen kann, wenn aus einem Legacy-Assembly verlorener Source Code wiederhergestellt werden muss. Außerdem bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist damit eines der perfekten Tools für **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an deine genauen Bedürfnisse anpasst, spart .NET reflector Zeit und vereinfacht die Entwicklung. Werfen wir einen Blick auf die Vielzahl an reverse engineering-Diensten, die dieses Tool bietet:

- Bietet Einblick darin, wie die Daten durch eine Library oder Komponente fließen
- Bietet Einblick in die Implementierung und Nutzung von .NET-Sprachen und Frameworks
- Findet undokumentierte und nicht offengelegte Funktionalität, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblies
- Spürt den genauen Ort von Fehlern in deinem Code, Drittanbieterkomponenten und Libraries auf.
- Debuggt in den Source von all dem .NET-Code, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem OS haben (du kannst es direkt aus VSCode installieren, kein Download des git nötig. Klicke auf **Extensions** und suche nach **ILSpy**).\
Wenn du **dekompilieren**, **modifizieren** und erneut **recompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Right Click -> Modify Method** um etwas innerhalb einer function zu ändern).

### DNSpy Logging

Um **DNSpy so zu konfigurieren, dass es einige Informationen in eine Datei loggt**, könntest du diesen Snippet verwenden:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly attributes** ändern, die sich auf **debugging** beziehen:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
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

Dann speichere die neue Datei über _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Das ist notwendig, weil andernfalls zur **runtime** mehrere **optimisations** auf den Code angewendet werden und es möglich sein könnte, dass beim Debugging ein **break-point is never hit** oder einige **variables don't exist**.

Dann, wenn deine .NET-Anwendung von **IIS** **run** wird, kannst du sie mit **restart**:
```
iisreset /noforce
```
Dann solltest du zum Starten des Debuggens alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Dann **w3wp.exe** auswählen, um dich an den **IIS server** anzuhängen, und auf **attach** klicken:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Jetzt, da wir den Prozess debuggen, ist es Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Klicke auf ein beliebiges Modul unter **Modules** und wähle **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Mache einen Rechtsklick auf ein beliebiges Modul im **Assembly Explorer** und klicke auf **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Konfiguriere die **Parameter** der Ausführung, indem du den **Pfad zur DLL** und die Funktion angibst, die du aufrufen möchtest:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Dann wird, wenn du das Debugging startest, **die Ausführung bei jedem geladenen DLL angehalten**; sobald rundll32 deine DLL lädt, wird die Ausführung angehalten.

Aber wie kannst du zum Code der geladenen DLL gelangen? Mit dieser Methode weiß ich es nicht.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ändere _Options --> Settings_ und wähle "**DLL Entry**".
- Dann **start the execution**, der Debugger hält bei jedem dll main an; irgendwann wirst du **im dll Entry deiner dll anhalten**. Von dort aus suchst du einfach nach den Stellen, an denen du einen breakpoint setzen willst.

Beachte, dass du, wenn die Ausführung aus irgendeinem Grund in win64dbg angehalten wird, sehen kannst, **in welchem Code du dich befindest**, indem du oben im **win64dbg window** nachsiehst:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Dann kannst du daran erkennen, wann die Ausführung in der DLL angehalten wurde, die du debuggen möchtest.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um zu finden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern. Mehr Infos in:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Frontend-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), mit Fokus auf Spiele. Es kann jedoch für alles rund um Reverse Engineering verwendet werden

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Frontend für eine Reihe von Decompilern. Dieser Webservice ermöglicht dir, die Ausgabe verschiedener Decompiler bei kleinen Executables zu vergleichen.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) wird den **shellcode** in einem Speicherbereich **allozieren**, dir die **memory address** **anzeigen**, an der der shellcode allokiert wurde, und die Ausführung **anhalten**.\
Dann musst du einen **debugger anhängen** (Ida oder x64dbg) an den Prozess und einen **breakpoint an der angegebenen memory address** setzen und die Ausführung **fortsetzen**. Auf diese Weise debugst du den shellcode.

Die Releases-GitHub-Seite enthält ZIP-Dateien mit den kompilierten Releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unter dem folgenden Link findest du eine leicht modifizierte Version von Blobrunner. Um sie zu kompilieren, **erstell einfach ein C/C++ project in Visual Studio Code, kopiere den Code hinein und baue es**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)ist sehr ähnlich zu blobrunner. Es wird den **shellcode** in einem Speicherbereich **allozieren** und eine **ewige Schleife** starten. Danach musst du den **debugger anhängen** an den Prozess, **starten, 2-5 Sekunden warten und stoppen**, und du befindest dich in der **ewigen Schleife**. Spring zum nächsten Befehl der ewigen Schleife, da es ein Call zum shellcode sein wird, und schließlich wirst du den shellcode ausführen.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

Du kannst eine kompilierte Version von [jmp2it auf der releases page](https://github.com/adamkramer/jmp2it/releases/) herunterladen.

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter kannst du den shellcode emulieren und dynamisch untersuchen.

Beachte, dass Cutter dir erlaubt, "Open File" und "Open Shellcode" zu wählen. In meinem Fall wurde der shellcode korrekt dekompiliert, wenn ich ihn als Datei geöffnet habe, aber nicht, wenn ich ihn als shellcode geöffnet habe:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

Um die Emulation an der gewünschten Stelle zu starten, setze dort einen bp, und offenbar startet Cutter die Emulation dann automatisch von dort:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

Du kannst zum Beispiel den Stack innerhalb eines Hex-Dumps sehen:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Du solltest [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Es sagt dir Dinge wie **welche Funktionen** der shellcode verwendet und ob der shellcode sich im Speicher **selbst decodiert**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg hat außerdem einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und den Shellcode ausführen kannst

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Die Option **Create Dump** speichert den finalen Shellcode ab, falls der Shellcode während der Laufzeit im Speicher dynamisch verändert wird (nützlich, um den dekodierten Shellcode herunterzuladen). Die Option **start offset** kann nützlich sein, um den Shellcode an einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den Shellcode mit dem scDbg-Terminal zu debuggen (ich finde jedoch, dass die zuvor erklärten Optionen dafür besser geeignet sind, da du dann Ida oder x64dbg verwenden kannst).

### Disassembling using CyberChef

Lade deine Shellcode-Datei als Input hoch und verwende das folgende Recipe, um sie zu decompilieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)**-Obfuscation versteckt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Wichtig ist, dass diese Identitäten normalerweise nur unter **fixed-width modular arithmetic** korrekt sind, daher zählen Carries und Overflows:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kannst du leicht ein falsches Ergebnis erhalten, weil die Bit-Breite-Semantik ignoriert wurde.

### Praktischer Workflow

1. **Behalte die ursprüngliche Bit-Breite** aus dem gelifteten Code/IR/Decompiler-Output (`8/16/32/64` Bits).
2. **Klassifiziere den Ausdruck** bevor du versuchst, ihn zu vereinfachen:
- **Linear**: gewichtete Summen von bitwise Atomen
- **Semilinear**: linear plus konstante Masken wie `x & 0xFF`
- **Polynomial**: Produkte treten auf
- **Mixed**: Produkte und bitwise-Logik sind ineinander verschachtelt, oft mit wiederholten Teilausdrücken
3. **Verifiziere jede Kandidaten-Umschreibung** mit Random-Testing oder einem SMT-Beweis. Wenn die Äquivalenz nicht bewiesen werden kann, behalte den ursprünglichen Ausdruck statt zu raten.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Simplifier für Malware-Analyse und Protected-Binary-Reversing. Es klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines statt einen generischen Rewrite-Pass auf alles anzuwenden.

Quick usage:
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

- **Linear MBA**: CoBRA wertet den Ausdruck auf Boolean-Inputs aus, leitet eine Signatur ab und startet mehrere Recovery-Methoden parallel, wie pattern matching, ANF-Konvertierung und Koeffizienteninterpolation.
- **Semilinear MBA**: constant-masked Atome werden mit bit-partitionierter reconstruction aufgebaut, sodass maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in cores zerlegt und wiederholte Teil-Ausdrücke können in temporaries gehoben werden, bevor die äußere Relation vereinfacht wird.

Beispiel für eine gemischte Identität, deren Recovery sich oft lohnt:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dies kann sich zusammenfassen zu:
```c
x * y
```
### Reversing notes

- Preferiere, CoBRA auf **lifted IR expressions** oder decompiler output zu verwenden, nachdem du die exakte Berechnung isoliert hast.
- Verwende `--bitwidth` explizit, wenn die expression aus masked arithmetic oder narrow registers stammt.
- Wenn du einen stärkeren proof step brauchst, prüfe die lokalen Z3-Notizen hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA wird auch als **LLVM pass plugin** (`libCobraPass.so`) ausgeliefert, was nützlich ist, wenn du vor späteren analysis passes stark MBA-lastige LLVM IR normalisieren willst.
- Unsupported carry-sensitive mixed-domain residuals sollten als Signal behandelt werden, die originale expression beizubehalten und den carry path manuell zu analysieren.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser obfuscator **modifiziert alle instructions zu `mov`** (ja, wirklich cool). Er nutzt außerdem interruptions, um executions flows zu ändern. Für mehr Informationen darüber, wie es funktioniert:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Wenn du Glück hast, wird [demovfuscator](https://github.com/kirschju/demovfuscator) das binary deofuscate. Es hat mehrere dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Und [installiere keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du einen **CTF** spielst, kann dieser Workaround zum Finden der Flag sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **Entry Point** zu finden, suche die Funktionen nach `::main` wie in:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, daher ist es ziemlich offensichtlich, dass dies die interessante main-Funktion ist.\
Mit dem **Namen** der aufgerufenen **Funktionen** kannst du im **Internet** nach ihnen suchen, um ihre **Inputs** und **Outputs** zu lernen.

### Recovering Rust strings from ELF firmware

In **Rust ELF**-Binaries werden viele statische Strings nicht als C-Style NUL-terminierte Pointer referenziert. Ein typisches `rustc`-Layout ist ein **Pointer/Längen-Tupel** innerhalb von **`.data.rel.ro`**, das auf den echten String-Blob in **`.rodata`** zeigt:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Das bedeutet, dass `strings` oder die Standardanalyse von Ghidra benachbarte Strings zusammenführen oder Cross-References vollständig übersehen können.

Schneller Workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Ermittle die virtuelle Adresse und Größe von **`.rodata`**.
2. Enumeriere **`.data.rel.ro`** wortweise.
3. Behandle jeden Wert innerhalb des `.rodata`-Adressbereichs als potenziellen String-Pointer.
4. Behandle das nächste Wort als potenzielle Länge.
5. Wende Plausibilitätsfilter an (zum Beispiel Längen zwischen **4** und **100** Bytes beibehalten).
6. Lese genau `length` Bytes aus `.rodata` statt bis `0x00` zu scannen.

Minimaler Extraktor-Logik:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Dies ist besonders nützlich beim Firmware-Reversing, weil wiederhergestellte Rust-Strings oft **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers und auth-related logic** offenlegen.

Wenn Ghidra diese Strings verpasst, führe ein benutzerdefiniertes Script/Plugin aus, das dieselbe Heuristik anwendet und String-Daten an den referenzierten `.rodata`-Offsets erstellt. Die veröffentlichten Tools `rust-strings` und `RustStrings.py` von Pen Test Partners sind gute Referenzen, um die Idee an andere **word sizes, endianness und section layouts** anzupassen.

## **Delphi**

Für Delphi-kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden

Wenn du eine Delphi-Binärdatei reversen musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) zu verwenden

Drücke einfach **ATL+f7** (python plugin in IDA importieren) und wähle das python plugin aus.

Dieses Plugin führt die Binärdatei aus und löst Funktionsnamen dynamisch zu Beginn des Debuggings auf. Nachdem das Debugging gestartet wurde, drücke erneut den Start-Button (den grünen oder f9), und ein Breakpoint wird am Anfang des echten Codes ausgelöst.

Es ist auch sehr interessant, weil der Debugger anhält, wenn du in der grafischen Anwendung eine Schaltfläche drückst, in der Funktion, die von diesem bottom ausgeführt wird.

## Golang

Wenn du eine Golang-Binärdatei reversen musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) zu verwenden

Drücke einfach **ATL+f7** (python plugin in IDA importieren) und wähle das python plugin aus.

Dies wird die Namen der Funktionen auflösen.

## Compiled Python

Auf dieser Seite findest du, wie du den Python-Code aus einer ELF/EXE-kompilierten Python-Binärdatei erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Wenn du die **binary** eines GBA-Spiels bekommst, kannst du verschiedene Tools verwenden, um sie zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Enthält einen Debugger mit Oberfläche
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), unter _**Options --> Emulation Setup --> Controls**_** ** kannst du sehen, wie du die Game Boy Advance **buttons** drückst

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Wenn sie gedrückt werden, hat jede **key einen Wert**, um sie zu identifizieren:
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
Also, in dieser Art von Programm ist der interessante Teil, **wie das Programm die Benutzereingabe behandelt**. An der Adresse **0x4000130** findest du die häufig vorkommende Funktion: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Im vorherigen Bild kannst du sehen, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion, nach einigen Init-Operationen (ohne jede Bedeutung):
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
Das letzte if prüft, ob **`uVar4`** in den **last Keys** liegt und nicht der aktuelle key ist; das wird auch als Loslassen eines Buttons bezeichnet (der aktuelle key ist in **`uVar1`** gespeichert).
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
Im vorherigen Code kannst du sehen, dass wir **uVar1** (der Ort, an dem der **Wert des gedrückten Buttons** steht) mit einigen Werten vergleichen:

- Zuerst wird es mit dem **Wert 4** (**SELECT** button) verglichen: In der Challenge löscht dieser button den Bildschirm
- Dann wird es mit dem **Wert 8** (**START** button) verglichen: In der Challenge prüft das, ob der code gültig ist, um die flag zu bekommen.
- In diesem Fall wird die var **`DAT_030000d8`** mit 0xf3 verglichen und wenn der Wert derselbe ist, wird etwas code ausgeführt.
- In allen anderen Fällen wird ein cont (**`DAT_030000d4`**) geprüft. Es ist ein cont, weil direkt nach dem Eintreten in den code 1 addiert wird.\
**W**enn weniger als 8, wird etwas gemacht, das das **Addieren** von Werten zu **`DAT_030000d8`** beinhaltet (im Grunde werden die Werte der gedrückten keys in diese variable addiert, solange der cont kleiner als 8 ist).

Also musstest du in dieser Challenge, wenn du die Werte der buttons kennst, **eine Kombination mit einer Länge kleiner als 8 drücken, sodass die resultierende Summe 0xf3 ist.**

**Referenz für dieses tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
