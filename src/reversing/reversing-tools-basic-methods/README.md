# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Basierte Reversing-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm Decompiler / Wat Compiler

Online:

- Verwenden Sie [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (binär) nach wat (klarer Text) zu **dekompilieren**
- Verwenden Sie [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um von wat nach wasm zu **kompilieren**
- Sie können auch versuchen, [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) zu verwenden, um zu dekompilieren

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET Decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der **mehrere Formate dekompiliert und untersucht**, einschließlich **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **ausführbaren Dateien** (.exe). Nach der Dekompilierung kann ein Assembly als Visual Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil hier ist, dass, wenn ein verlorener Quellcode aus einem Legacy-Assembly wiederhergestellt werden muss, diese Aktion Zeit sparen kann. Darüber hinaus bietet dotPeek eine praktische Navigation durch den dekompilierten Code, was es zu einem der perfekten Werkzeuge für die **Xamarin-Algorithmusanalyse** macht.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-In-Modell und einer API, die das Tool an Ihre genauen Bedürfnisse anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Werfen wir einen Blick auf die Vielzahl von Reverse-Engineering-Diensten, die dieses Tool bietet:

- Bietet Einblicke, wie die Daten durch eine Bibliothek oder Komponente fließen
- Bietet Einblicke in die Implementierung und Nutzung von .NET-Sprachen und -Frameworks
- Findet undocumented und unexposed Funktionalitäten, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblies
- Verfolgt den genauen Standort von Fehlern in Ihrem Code, Drittanbieterkomponenten und Bibliotheken.
- Debuggt in die Quelle des gesamten .NET-Codes, mit dem Sie arbeiten.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Sie können es auf jedem Betriebssystem haben (Sie können es direkt von VSCode installieren, es ist nicht notwendig, das Git-Repository herunterzuladen. Klicken Sie auf **Erweiterungen** und **suchen Sie nach ILSpy**).\
Wenn Sie **dekompilieren**, **modifizieren** und **wieder kompilieren** müssen, können Sie [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder einen aktiv gepflegten Fork davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Methode ändern**, um etwas innerhalb einer Funktion zu ändern).

### DNSpy Protokollierung

Um **DNSpy einige Informationen in einer Datei protokollieren zu lassen**, können Sie diesen Snippet verwenden:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Um Code mit DNSpy zu debuggen, müssen Sie:

Zuerst die **Assembly-Attribute** im Zusammenhang mit **Debugging** ändern:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Um:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Und klicken Sie auf **compile**:

![](<../../images/image (314) (1).png>)

Dann speichern Sie die neue Datei über _**File >> Save module...**_:

![](<../../images/image (602).png>)

Dies ist notwendig, da, wenn Sie dies nicht tun, zur **Laufzeit** mehrere **Optimierungen** auf den Code angewendet werden und es möglich sein könnte, dass beim Debuggen ein **Break-Point niemals erreicht wird** oder einige **Variablen nicht existieren**.

Wenn Ihre .NET-Anwendung von **IIS** **ausgeführt** wird, können Sie sie mit **neustarten**:
```
iisreset /noforce
```
Dann sollten Sie, um mit dem Debuggen zu beginnen, alle geöffneten Dateien schließen und im **Debug Tab** **Attach to Process...** auswählen:

![](<../../images/image (318).png>)

Wählen Sie dann **w3wp.exe** aus, um sich mit dem **IIS-Server** zu verbinden, und klicken Sie auf **attach**:

![](<../../images/image (113).png>)

Jetzt, da wir den Prozess debuggen, ist es Zeit, ihn zu stoppen und alle Module zu laden. Klicken Sie zuerst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Klicken Sie auf ein beliebiges Modul in **Modules** und wählen Sie **Open All Modules**:

![](<../../images/image (922).png>)

Klicken Sie mit der rechten Maustaste auf ein beliebiges Modul im **Assembly Explorer** und klicken Sie auf **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging von DLLs

### Verwendung von IDA

- **Laden Sie rundll32** (64-Bit in C:\Windows\System32\rundll32.exe und 32-Bit in C:\Windows\SysWOW64\rundll32.exe)
- Wählen Sie den **Windbg**-Debugger
- Wählen Sie "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Konfigurieren Sie die **Parameter** der Ausführung, indem Sie den **Pfad zur DLL** und die Funktion, die Sie aufrufen möchten, angeben:

![](<../../images/image (704).png>)

Wenn Sie dann mit dem Debuggen beginnen, **wird die Ausführung gestoppt, wenn jede DLL geladen wird**. Wenn rundll32 Ihre DLL lädt, wird die Ausführung gestoppt.

Aber wie gelangen Sie zum Code der geladenen DLL? Mit dieser Methode weiß ich es nicht.

### Verwendung von x64dbg/x32dbg

- **Laden Sie rundll32** (64-Bit in C:\Windows\System32\rundll32.exe und 32-Bit in C:\Windows\SysWOW64\rundll32.exe)
- **Ändern Sie die Befehlszeile** (_Datei --> Befehlszeile ändern_) und setzen Sie den Pfad der DLL und die Funktion, die Sie aufrufen möchten, zum Beispiel: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ändern Sie _Optionen --> Einstellungen_ und wählen Sie "**DLL Entry**".
- Starten Sie dann die Ausführung, der Debugger wird an jedem DLL-Hauptpunkt anhalten, irgendwann werden Sie **im DLL-Eintrag Ihrer DLL anhalten**. Von dort aus suchen Sie einfach nach den Punkten, an denen Sie einen Haltepunkt setzen möchten.

Beachten Sie, dass Sie, wenn die Ausführung aus irgendeinem Grund in win64dbg gestoppt wird, **sehen können, in welchem Code Sie sich befinden**, indem Sie oben im win64dbg-Fenster nachsehen:

![](<../../images/image (842).png>)

Dann können Sie sehen, wann die Ausführung in der DLL gestoppt wurde, die Sie debuggen möchten.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und um sie zu ändern. Weitere Informationen in:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ist ein Front-End-/Reverse-Engineering-Tool für den GNU Project Debugger (GDB), das sich auf Spiele konzentriert. Es kann jedoch für alle reverse-engineeringbezogenen Dinge verwendet werden.

[**Decompiler Explorer**](https://dogbolt.org/) ist ein Web-Frontend für eine Reihe von Decompilern. Dieser Webdienst ermöglicht es Ihnen, die Ausgaben verschiedener Decompiler bei kleinen ausführbaren Dateien zu vergleichen.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Debugging eines Shellcodes mit Blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) wird den **Shellcode** in einem Speicherbereich **allokieren**, Ihnen die **Speicheradresse** anzeigen, an der der Shellcode allokiert wurde, und die Ausführung **stoppen**.\
Dann müssen Sie einen **Debugger** (Ida oder x64dbg) an den Prozess anhängen und einen **Haltepunkt an der angegebenen Speicheradresse** setzen und die Ausführung **fortsetzen**. Auf diese Weise debuggen Sie den Shellcode.

Die Veröffentlichungsseite auf GitHub enthält ZIP-Dateien mit den kompilierten Versionen: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Sie finden eine leicht modifizierte Version von Blobrunner unter dem folgenden Link. Um es zu kompilieren, **erstellen Sie einfach ein C/C++-Projekt in Visual Studio Code, kopieren Sie den Code und bauen Sie es**.

{{#ref}}
blobrunner.md
{{#endref}}

### Debugging eines Shellcodes mit jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) ist sehr ähnlich wie Blobrunner. Es wird den **Shellcode** in einem Speicherbereich **allokieren** und eine **ewige Schleife** starten. Sie müssen dann den **Debugger** an den Prozess anhängen, **spielen Sie Start, warten Sie 2-5 Sekunden und drücken Sie Stop**, und Sie werden sich in der **ewigen Schleife** wiederfinden. Springen Sie zur nächsten Anweisung der ewigen Schleife, da es ein Aufruf zum Shellcode sein wird, und schließlich werden Sie den Shellcode ausführen.

![](<../../images/image (509).png>)

Sie können eine kompilierte Version von [jmp2it auf der Veröffentlichungsseite herunterladen](https://github.com/adamkramer/jmp2it/releases/).

### Debugging von Shellcode mit Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter können Sie den Shellcode emulieren und dynamisch inspizieren.

Beachten Sie, dass Cutter Ihnen erlaubt, "Datei öffnen" und "Shellcode öffnen". In meinem Fall, als ich den Shellcode als Datei öffnete, wurde er korrekt dekompiliert, aber als ich ihn als Shellcode öffnete, nicht:

![](<../../images/image (562).png>)

Um die Emulation an dem Ort zu starten, an dem Sie möchten, setzen Sie dort einen Haltepunkt, und anscheinend wird Cutter die Emulation automatisch von dort aus starten:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Sie können den Stack beispielsweise in einem Hexdump sehen:

![](<../../images/image (186).png>)

### Deobfuscating Shellcode und Abrufen ausgeführter Funktionen

Sie sollten [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) ausprobieren.\
Es wird Ihnen Dinge sagen wie **welche Funktionen** der Shellcode verwendet und ob der Shellcode sich **im Speicher dekodiert**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg verfügt auch über einen grafischen Launcher, in dem Sie die gewünschten Optionen auswählen und den Shellcode ausführen können.

![](<../../images/image (258).png>)

Die **Create Dump**-Option erstellt einen Dump des finalen Shellcodes, wenn Änderungen am Shellcode dynamisch im Speicher vorgenommen werden (nützlich, um den dekodierten Shellcode herunterzuladen). Der **start offset** kann nützlich sein, um den Shellcode an einem bestimmten Offset zu starten. Die **Debug Shell**-Option ist nützlich, um den Shellcode mit dem scDbg-Terminal zu debuggen (ich finde jedoch, dass die zuvor erklärten Optionen besser dafür geeignet sind, da Sie Ida oder x64dbg verwenden können).

### Disassemblierung mit CyberChef

Laden Sie Ihre Shellcode-Datei als Eingabe hoch und verwenden Sie das folgende Rezept, um sie zu dekompilieren: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator **modifiziert alle Anweisungen für `mov`** (ja, wirklich cool). Er verwendet auch Unterbrechungen, um die Ausführungsflüsse zu ändern. Für weitere Informationen darüber, wie es funktioniert:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Wenn Sie Glück haben, wird [demovfuscator](https://github.com/kirschju/demovfuscator) die Binärdatei deobfuskieren. Es hat mehrere Abhängigkeiten.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Und [installiere keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, könnte dieser Workaround, um die Flagge zu finden**, sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **Einstiegspunkt** zu finden, suche die Funktionen nach `::main` wie in:

![](<../../images/image (1080).png>)

In diesem Fall hieß die Binärdatei authenticator, daher ist es ziemlich offensichtlich, dass dies die interessante Hauptfunktion ist.\
Hast du den **Namen** der **aufgerufenen Funktionen**, suche sie im **Internet**, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

## **Delphi**

Für in Delphi kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du eine Delphi-Binärdatei zurückverfolgen musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) zu verwenden.

Drücke einfach **ATL+f7** (Python-Plugin in IDA importieren) und wähle das Python-Plugin aus.

Dieses Plugin führt die Binärdatei aus und löst die Funktionsnamen dynamisch zu Beginn des Debuggings auf. Nach dem Start des Debuggings drücke erneut die Starttaste (die grüne oder f9) und ein Haltepunkt wird am Anfang des echten Codes erreicht.

Es ist auch sehr interessant, weil der Debugger stoppt, wenn du einen Knopf in der grafischen Anwendung drückst, in der Funktion, die von diesem Knopf ausgeführt wird.

## Golang

Wenn du eine Golang-Binärdatei zurückverfolgen musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) zu verwenden.

Drücke einfach **ATL+f7** (Python-Plugin in IDA importieren) und wähle das Python-Plugin aus.

Dies wird die Namen der Funktionen auflösen.

## Kompilierte Python

Auf dieser Seite kannst du finden, wie du den Python-Code aus einer ELF/EXE Python-kompilierten Binärdatei erhältst:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Wenn du die **Binärdatei** eines GBA-Spiels erhältst, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Schnittstelle
- [**mgba** ](https://mgba.io) - Enthält einen CLI-Debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_\*\* \*\* kannst du sehen, wie du die Game Boy Advance **Tasten** drückst.

![](<../../images/image (581).png>)

Wenn gedrückt, hat jede **Taste einen Wert**, um sie zu identifizieren:
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
In diesem Programm wird der interessante Teil sein, **wie das Programm die Benutzereingabe behandelt**. An der Adresse **0x4000130** finden Sie die häufig vorkommende Funktion: **KEYINPUT**.

![](<../../images/image (447).png>)

In dem vorherigen Bild sehen Sie, dass die Funktion von **FUN_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion, nach einigen Initialisierungsoperationen (ohne jegliche Bedeutung):
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
Es wurde dieser Code gefunden:
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
Die letzte Bedingung überprüft, ob **`uVar4`** in den **letzten Tasten** ist und nicht die aktuelle Taste ist, die auch als Loslassen einer Taste bezeichnet wird (die aktuelle Taste ist in **`uVar1`** gespeichert).
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
Im vorherigen Code sehen Sie, dass wir **uVar1** (der Ort, an dem der **Wert des gedrückten Buttons** ist) mit einigen Werten vergleichen:

- Zuerst wird er mit dem **Wert 4** (**SELECT**-Taste) verglichen: In der Herausforderung löscht dieser Button den Bildschirm.
- Dann wird er mit dem **Wert 8** (**START**-Taste) verglichen: In der Herausforderung wird überprüft, ob der Code gültig ist, um die Flagge zu erhalten.
- In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen, und wenn der Wert gleich ist, wird ein bestimmter Code ausgeführt.
- In allen anderen Fällen wird ein Zähler (`DAT_030000d4`) überprüft. Es ist ein Zähler, weil er direkt nach dem Betreten des Codes um 1 erhöht wird.\
**Wenn** weniger als 8, wird etwas gemacht, das **Werte** zu \*\*`DAT_030000d8` \*\* hinzufügt (grundsätzlich werden die Werte der gedrückten Tasten in dieser Variablen addiert, solange der Zähler weniger als 8 ist).

In dieser Herausforderung mussten Sie also, wissend um die Werte der Tasten, eine **Kombination mit einer Länge kleiner als 8 drücken, deren resultierende Addition 0xf3 ist.**

**Referenz für dieses Tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kurse

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary Deobfuscation)

{{#include ../../banners/hacktricks-training.md}}
