# Omgekeerde Ingenieursgereedskap & Basiese Metodes

{{#include ../../banners/hacktricks-training.md}}

## ImGui-gebaseerde omgekeerde ingenieursgereedskap

Sagteware:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm-dekompileerder / Wat-kompieleerder

Aanlyn:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om te **decompileer** van wasm (binary) na wat (duidelike teks)
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om te **compileer** van wat na wasm
- jy kan ook probeer om [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) te gebruik om te decompileer

Sagteware:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET-dekompileerder

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n dekompileerder wat **meervoudige formate dekompileer en ondersoek**, insluitend **biblioteke** (.dll), **Windows metadata-lêers** (.winmd), en **uitvoerbare lêers** (.exe). Sodra dit gedecompileer is, kan 'n assembly as 'n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hier is dat as verlore bronkode van 'n verouderde assembly herstel moet word, hierdie aksie tyd kan bespaar. Verder bied dotPeek handige navigasie regdeur die gedecompileerde kode, wat dit een van die perfekte gereedskap vir **Xamarin algorithm analysis** maak.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende add-in-model en 'n API wat die tool uitbrei om by jou presiese behoeftes te pas, bespaar .NET reflector tyd en vereenvoudig ontwikkeling. Kom ons kyk na die verskeidenheid reverse engineering-dienste wat hierdie tool bied:

- Bied insig in hoe die data deur 'n biblioteek of komponent vloei
- Bied insig in die implementering en gebruik van .NET tale en frameworks
- Vind ongedokumenteerde en onblootgestelde funksionaliteit om meer uit die APIs en tegnologieë wat gebruik word te kry.
- Vind afhanklikhede en verskillende assemblies
- Spoor die presiese ligging van foute in jou kode, derdeparty-komponente en biblioteke op.
- Ontfout in die bron van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige OS hê (jy kan dit direk vanaf VSCode installeer, geen behoefte om die git af te laai nie. Klik op **Extensions** en **search ILSpy**).\
As jy weer **decompileer**, **wysig** en **recompileer** moet, kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) gebruik of 'n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** om iets binne-in 'n funksie te verander).

### DNSpy Logging

Om **DNSpy** te laat **some information in a file** log, kan jy hierdie snippet gebruik:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Om kode met DNSpy te debug, moet jy:

Eerstens, verander die **Assembly attributes** wat verband hou met **debugging**:

![](<../../images/image (973).png>)

Van:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Aan:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
En klik op **compile**:

![](<../../images/image (314) (1).png>)

Stoor dan die nuwe lêer via _**File >> Save module...**_:

![](<../../images/image (602).png>)

Dit is nodig, want as jy dit nie doen nie, sal daar tydens **runtime** verskeie **optimisations** op die kode toegepas word en dit kan moontlik wees dat terwyl jy debug ’n **break-point nooit getref word** of sommige **variables nie bestaan nie**.

As jou .NET-toepassing deur **IIS** **run** word, kan jy dit dan **restart** met:
```
iisreset /noforce
```
Dan, om met debug te begin moet jy al die oopgemaakte lêers sluit en binne die **Debug Tab** kies **Attach to Process...**:

![](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![](<../../images/image (113).png>)

Nou dat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Klik enige module in **Modules** en kies **Open All Modules**:

![](<../../images/image (922).png>)

Regskliek enige module in **Assembly Explorer** en klik **Sort Assemblies**:

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

Dan, wanneer jy begin debug, **sal die uitvoering gestop word wanneer elke DLL gelaai word**, dan, wanneer rundll32 jou DLL laai, sal die uitvoering gestop word.

Maar, hoe kan jy by die kode van die DLL kom wat gelaai is? Met hierdie metode, weet ek nie hoe nie.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Let op dat wanneer die uitvoering om enige rede in win64dbg gestop word, jy kan sien **in which code you are** deur te kyk na die **top of the win64dbg window**:

![](<../../images/image (842).png>)

Dan, deur hierna te kyk, kan jy sien wanneer die uitvoering gestop is in die dll wat jy wil debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes in die geheue van 'n lopende speletjie gestoor word en dit te verander. Meer info in:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n front-end/reverse engineering tool vir die GNU Project Debugger (GDB), gefokus op games. Dit kan egter vir enige reverse-engineering verwante goed gebruik word

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web front-end na 'n aantal decompilers. Hierdie webdiens laat jou toe om die uitvoer van verskillende decompilers op klein uitvoerbare lêers te vergelyk.

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
scDbg het ook ’n grafiese launcher waar jy die opsies kan kies wat jy wil en die shellcode kan uitvoer

![](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode dump as enige verandering dinamies in geheue aan die shellcode gemaak word (nuttig om die decoded shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode vanaf ’n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode te debug met behulp van die scDbg terminal (ek vind egter enige van die vorige opsies beter vir hierdie doel, aangesien jy Ida of x64dbg sal kan gebruik).

### Disassembling using CyberChef

Laai jou shellcode-lêer op as input en gebruik die volgende recipe om dit te decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation verberg eenvoudige uitdrukkings soos `x + y` agter formules wat arithmetic (`+`, `-`, `*`) en bitwise operators (`&`, `|`, `^`, `~`, shifts) meng. Die belangrike deel is dat hierdie identiteite gewoonlik net korrek is onder **fixed-width modular arithmetic**, so carries en overflows maak saak:
```c
(x ^ y) + 2 * (x & y) == x + y
```
As jy hierdie soort uitdrukking met generiese algebra-gereedskap vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bit-width semantics geïgnoreer is.

### Practical workflow

1. **Hou die oorspronklike bit-width** van die gelifte kode/IR/decompiler-uitvoer (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy probeer om dit te vereenvoudig:
- **Linear**: gewogen somme van bitwise atoms
- **Semilinear**: linear plus konstante masks soos `x & 0xFF`
- **Polynomial**: products verskyn
- **Mixed**: products en bitwise logic is verweef, dikwels met herhaalde subexpressions
3. **Verifieer elke kandidaat-rewrite** met random testing of ’n SMT-proof. As die equivalence nie bewys kan word nie, hou eerder die oorspronklike uitdrukking as om te raai.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA simplifier vir malware analysis en protected-binary reversing. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pipelines in plaas daarvan om een generiese rewrite-pass op alles toe te pas.

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
Nuttige gevalle:

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolean invoere, lei ’n signature af, en laat verskeie recovery-metodes meeding soos pattern matching, ANF conversion, en coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms word herbou met bit-partitioned reconstruction sodat gemaskerde areas korrek bly.
- **Polynomial/Mixed MBA**: products word ontbind in cores en herhaalde subexpressions kan in temporaries opgelig word voordat die outer relation vereenvoudig word.

Voorbeeld van ’n mixed identity wat dikwels die moeite werd is om te probeer recover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dit kan saamval tot:
```c
x * y
```
### Reversing notes

- Verkies om CoBRA op **lifted IR expressions** of decompiler-uitvoer te laat loop nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` eksplisiet wanneer die expression uit gemaskerde arithmetic of narrow registers kom.
- As jy ’n sterker proof step nodig het, kyk die plaaslike Z3 notes hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA word ook gelewer as ’n **LLVM pass plugin** (`libCobraPass.so`), wat nuttig is wanneer jy MBA-heavy LLVM IR wil normaliseer voor latere analysis passes.
- Unsupported carry-sensitive mixed-domain residuals moet behandel word as ’n sein om die oorspronklike expression te hou en oor die carry path handmatig te reason.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator **modifies all the instructions for `mov`**(ja, regtig cool). Dit gebruik ook interruptions om executions flows te verander. Vir meer information oor hoe dit werk:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

As jy gelukkig is, sal [demovfuscator](https://github.com/kirschju/demovfuscator) die binary deofuscate. Dit het verskeie dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
En [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy 'n **CTF** speel, kan hierdie workaround om die flag te vind baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **entry point** te vind, soek die functions by `::main` soos in:

![](<../../images/image (1080).png>)

In hierdie geval is die binary authenticator genoem, so dit is redelik duidelik dat dit die interessante main function is.\
Met die **name** van die **functions** wat geroep word, soek hulle op die **Internet** om meer te leer oor hul **inputs** en **outputs**.

## **Delphi**

Vir Delphi compiled binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik

As jy 'n Delphi binary moet reverse, sou ek voorstel dat jy die IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik

Druk net **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Hierdie plugin sal die binary execute en function names dinamies oplos aan die begin van die debugging. Nadat jy die debugging begin het, druk weer die Start button (die groen een of f9) en 'n breakpoint sal tref aan die begin van die real code.

Dit is ook baie interessant omdat as jy 'n button in die graphic application druk, sal die debugger stop in die function wat deur daardie bottom execute word.

## Golang

As jy 'n Golang binary moet reverse, sou ek voorstel dat jy die IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik

Druk net **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Dit sal die names van die functions resolve.

## Compiled Python

Op hierdie page kan jy vind hoe om die python code uit 'n ELF/EXE python compiled binary te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

As jy die **binary** van 'n GBA game kry, kan jy verskillende tools gebruik om dit te **emulate** en te **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Bevat 'n debugger met interface
- [**mgba** ](https://mgba.io)- Bevat 'n CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance **buttons** te druk

![](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **key 'n waarde** om dit te identifiseer:
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
So, in hierdie soort program sal die interessante deel **hoe die program die gebruiker-invoer hanteer** wees. In die adres **0x4000130** sal jy die algemeen voorkomende funksie vind: **KEYINPUT**.

![](<../../images/image (447).png>)

In die vorige beeld kan jy sien dat die funksie vanaf **FUN_080015a8** geroep word (adresse: _0x080015fa_ en _0x080017ac_).

In daardie funksie, na sommige init-operasies (sonder enige belang):
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
Dis die kode gevind:
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
Die laaste if kontroleer of **`uVar4`** in die **laaste Keys** is en nie die huidige key is nie, ook genoem dat ’n button losgelaat word (die huidige key word in **`uVar1`** gestoor).
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
In die vorige kode kan jy sien dat ons **uVar1** vergelyk (die plek waar die **waarde van die ingedrukte knoppie** is) met sekere waardes:

- Eerstens word dit vergelyk met die **waarde 4** (**SELECT**-knoppie): In die challenge maak hierdie knoppie die skerm skoon
- Dan word dit vergelyk met die **waarde 8** (**START**-knoppie): In die challenge kyk dit of die code geldig is om die flag te kry.
- In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk, en as die waarde dieselfde is, word sekere code uitgevoer.
- In enige ander gevalle word ’n cont (**`DAT_030000d4`**) nagegaan. Dit is ’n cont omdat dit 1 byvoeg net nadat jy in die code ingegaan het.\
**A**s dit minder as 8 is, word iets gedoen wat behels dat waardes by **`DAT_030000d8`** gevoeg word (basies voeg dit die waardes van die sleutels wat in hierdie var gedruk word by, solank die cont minder as 8 is).

So, in hierdie challenge, met die waardes van die knoppies in gedagte, moes jy **’n kombinasie met ’n lengte kleiner as 8 druk waarvan die resultante optelling 0xf3 is.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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
