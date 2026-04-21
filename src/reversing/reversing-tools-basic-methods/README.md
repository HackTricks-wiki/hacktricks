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

dotPeek ist ein Decompiler, der **mehrere Formate dekompiliert und untersucht**, einschließlich **Libraries** (.dll), **Windows-Metadatendateien** (.winmd) und **Executables** (.exe). Nach der Dekompilierung kann eine Assembly als Visual-Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil hierbei ist, dass diese Aktion Zeit sparen kann, wenn verlorener Source Code aus einer Legacy-Assembly wiederhergestellt werden muss. Außerdem bietet dotPeek eine praktische Navigation im dekompilierten Code und ist damit eines der perfekten Tools für die **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-in-Modell und einer API, die das Tool an deine genauen Bedürfnisse anpasst, spart .NET reflector Zeit und vereinfacht die Entwicklung. Werfen wir einen Blick auf die Vielzahl an Reverse-Engineering-Services, die dieses Tool bietet:

- Bietet Einblick darin, wie die Daten durch eine Library oder Komponente fließen
- Bietet Einblick in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
- Findet undokumentierte und nicht offengelegte Funktionalität, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblies
- Verfolgt den genauen Ort von Fehlern in deinem Code, Komponenten von Drittanbietern und Libraries.
- Debuggt in den Source aller .NET-Code, mit dem du arbeitest.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Du kannst es auf jedem OS haben (du kannst es direkt aus VSCode installieren, kein Download von git nötig. Klicke auf **Extensions** und **search ILSpy**).\
Wenn du **decompilieren**, **modifizieren** und erneut **recompilieren** musst, kannst du [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Right Click -> Modify Method** um etwas innerhalb einer Funktion zu ändern).

### DNSpy Logging

Um **DNSpy einige Informationen in eine Datei loggen zu lassen**, könntest du dieses Snippet verwenden:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Um Code mit DNSpy zu debuggen, musst du:

Zuerst die **Assembly attributes** ändern, die mit **debugging** zusammenhängen:

![](<../../images/image (973).png>)

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

![](<../../images/image (314) (1).png>)

Speichere dann die neue Datei über _**File >> Save module...**_:

![](<../../images/image (602).png>)

Das ist notwendig, weil, wenn du das nicht tust, zur **Laufzeit** mehrere **optimisations** auf den Code angewendet werden und es möglich wäre, dass beim Debugging ein **break-point nicht erreicht wird** oder einige **variables nicht existieren**.

Wenn deine .NET-Anwendung dann von **IIS** **run** wird, kannst du sie mit folgendem Befehl **restart**:
```
iisreset /noforce
```
Dann solltest du, um mit dem Debugging zu beginnen, alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![](<../../images/image (318).png>)

Dann **w3wp.exe** auswählen, um dich an den **IIS server** anzuhängen, und auf **attach** klicken:

![](<../../images/image (113).png>)

Jetzt, da wir den Prozess debuggen, ist es Zeit, ihn anzuhalten und alle Module zu laden. Klicke zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Klicke auf ein beliebiges Modul unter **Modules** und wähle **Open All Modules**:

![](<../../images/image (922).png>)

Klicke mit der rechten Maustaste auf ein beliebiges Modul im **Assembly Explorer** und klicke auf **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![](<../../images/image (704).png>)

Dann wird beim Start des Debuggings **die Ausführung bei jedem Laden einer DLL angehalten**, und sobald rundll32 deine DLL lädt, wird die Ausführung angehalten.

Aber wie kommst du zum Code der DLL, die geladen wurde? Mit dieser Methode weiß ich es nicht.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Beachte, dass du bei jedem beliebigen Stopp der Ausführung in win64dbg sehen kannst, **in welchem Code du dich befindest**, indem du oben im **Fenster von win64dbg** schaust:

![](<../../images/image (842).png>)

Dann kannst du daran erkennen, wann die Ausführung in der DLL gestoppt wurde, die du debuggen willst.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg verfügt auch über einen grafischen Launcher, in dem du die gewünschten Optionen auswählen und die Shellcode ausführen kannst

![](<../../images/image (258).png>)

Die Option **Create Dump** speichert den finalen Shellcode, wenn der Shellcode im Speicher dynamisch verändert wird (nützlich, um den dekodierten Shellcode herunterzuladen). Der **start offset** kann nützlich sein, um den Shellcode an einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den Shellcode mit dem scDbg-Terminal zu debuggen (ich finde jedoch, dass die zuvor erklärten Optionen dafür besser geeignet sind, da du Ida oder x64dbg verwenden kannst).

### Disassembling using CyberChef

Lade deine Shellcode-Datei als Input hoch und verwende das folgende Recipe, um sie zu decompilieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)**-Obfuscation verbirgt einfache Ausdrücke wie `x + y` hinter Formeln, die arithmetische (`+`, `-`, `*`) und bitweise Operatoren (`&`, `|`, `^`, `~`, Shifts) kombinieren. Der wichtige Punkt ist, dass diese Identitäten normalerweise nur unter **fixed-width modular arithmetic** korrekt sind, sodass Carries und Overflows eine Rolle spielen:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Wenn du diese Art von Ausdruck mit generischen Algebra-Tools vereinfachst, kannst du leicht ein falsches Ergebnis bekommen, weil die Bitbreiten-Semantik ignoriert wurde.

### Praktischer Workflow

1. **Behalte die ursprüngliche Bitbreite** aus dem gehobenen Code/IR/Decompiler-Output (`8/16/32/64` bits).
2. **Klassifiziere den Ausdruck** bevor du versuchst, ihn zu vereinfachen:
- **Linear**: gewichtete Summen von bitwise Atomen
- **Semilinear**: linear plus konstante Masks wie `x & 0xFF`
- **Polynomial**: Produkte treten auf
- **Mixed**: Produkte und bitwise logic sind miteinander verflochten, oft mit wiederholten Teilausdrücken
3. **Verifiziere jede Kandidaten-Umschreibung** mit zufälligen Tests oder einem SMT-Beweis. Wenn die Äquivalenz nicht bewiesen werden kann, behalte den ursprünglichen Ausdruck statt zu raten.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ist ein praktischer MBA-Simplifier für Malware-Analyse und protected-binary reversing. Er klassifiziert den Ausdruck und leitet ihn durch spezialisierte Pipelines, statt auf alles einen generischen Rewrite-Pass anzuwenden.

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

- **Linear MBA**: CoBRA evaluiert den Ausdruck auf Boolean-Inputs, leitet eine Signatur ab und testet mehrere Recovery-Methoden wie Pattern Matching, ANF-Konvertierung und Koeffizienteninterpolation parallel.
- **Semilinear MBA**: constant-masked Atoms werden mit bit-partitionierter Reconstruction wieder aufgebaut, sodass maskierte Bereiche korrekt bleiben.
- **Polynomial/Mixed MBA**: Produkte werden in Cores zerlegt, und wiederholte Subexpressions können vor der Vereinfachung der äußeren Relation in temporaries ausgelagert werden.

Beispiel für eine gemischte Identity, deren Recovery sich oft lohnt:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dies kann reduziert werden zu:
```c
x * y
```
### Reversing notes

- Preferiere es, CoBRA auf **lifted IR expressions** oder decompiler output auszuführen, nachdem du die exakte Berechnung isoliert hast.
- Verwende `--bitwidth` explizit, wenn die expression aus maskierten arithmetic oder schmalen registers stammt.
- Wenn du einen stärkeren Beweisschritt brauchst, prüfe hier die lokalen Z3-Notizen:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA gibt es auch als **LLVM pass plugin** (`libCobraPass.so`), was nützlich ist, wenn du vor späteren analysis passes MBA-heavy LLVM IR normalisieren willst.
- Nicht unterstützte carry-sensitive mixed-domain residuals sollten als Signal behandelt werden, das original expression beizubehalten und den carry path manuell zu begründen.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Und [keystone installieren](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du einen **CTF** spielst, kann dieser Workaround, um die Flag zu finden, sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **entry point** zu finden, suche die Funktionen nach `::main` wie in:

![](<../../images/image (1080).png>)

In diesem Fall hieß das Binary authenticator, also ist es ziemlich offensichtlich, dass dies die interessante main function ist.\
Wenn du den **Namen** der aufgerufenen **functions** hast, suche sie im **Internet**, um mehr über ihre **inputs** und **outputs** zu erfahren.

## **Delphi**

Für mit Delphi kompilierte Binaries kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden

Wenn du ein Delphi-Binary reverse-engineeren musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) zu verwenden

Drücke einfach **ATL+f7** (python plugin in IDA importieren) und wähle das python plugin aus.

Dieses Plugin führt das Binary aus und löst Funktionsnamen dynamisch am Anfang des Debuggings auf. Nach dem Starten des Debuggings drücke erneut den Start-Button (den grünen oder f9) und ein breakpoint wird am Anfang des echten Codes getroffen.

Es ist auch sehr interessant, weil der Debugger, wenn du in der grafischen Anwendung einen Button drückst, in der Funktion anhält, die von diesem button ausgeführt wird.

## Golang

Wenn du ein Golang-Binary reverse-engineeren musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) zu verwenden

Drücke einfach **ATL+f7** (python plugin in IDA importieren) und wähle das python plugin aus.

Dadurch werden die Namen der Funktionen aufgelöst.

## Compiled Python

Auf dieser Seite findest du heraus, wie du den python code aus einem ELF/EXE python compilierten Binary erhältst:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Wenn du das **binary** eines GBA-Spiels bekommst, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Enthält einen Debugger mit Interface
- [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** kannst du sehen, wie du die Game Boy Advance **buttons** drückst

![](<../../images/image (581).png>)

Wenn gedrückt, hat jede **key** einen Wert zur Identifizierung:
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
Also, in dieser Art von Programm wird der interessante Teil **sein, wie das Programm die User Input behandelt**. In der Adresse **0x4000130** findest du die häufig vorkommende Funktion: **KEYINPUT**.

![](<../../images/image (447).png>)

Im vorherigen Bild kannst du sehen, dass die Funktion aus **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion, nach einigen Init-Operationen (ohne jegliche Bedeutung):
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
Das letzte if prüft, ob **`uVar4`** in den **letzten Keys** ist und nicht der aktuelle Key; das wird auch als Loslassen einer Taste bezeichnet (der aktuelle Key ist in **`uVar1`** gespeichert).
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
Im vorherigen Code kannst du sehen, dass wir **uVar1** (die Stelle, an der sich der **Wert des gedrückten Buttons** befindet) mit einigen Werten vergleichen:

- Zuerst wird es mit dem **Wert 4** verglichen (**SELECT** button): In der Challenge löscht dieser button den Bildschirm
- Dann wird es mit dem **Wert 8** verglichen (**START** button): In der Challenge prüft das, ob der Code gültig ist, um die flag zu bekommen.
- In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen, und wenn der Wert gleich ist, wird etwas Code ausgeführt.
- In allen anderen Fällen wird ein cont (`DAT_030000d4`) geprüft. Es ist ein cont, weil direkt nach dem Eintritt in den Code 1 addiert wird.\
**I**st er kleiner als 8, wird etwas ausgeführt, das das **Addieren** von Werten zu **`DAT_030000d8`** beinhaltet (im Grunde werden die Werte der gedrückten keys zu dieser Variable addiert, solange der cont kleiner als 8 ist).

Also musstest du in dieser Challenge, wenn du die Werte der buttons kennst, **eine Kombination mit einer Länge kleiner als 8 drücken, deren resultierende Summe 0xf3 ergibt.**

**Referenz für dieses Tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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

{{#include ../../banners/hacktricks-training.md}}
