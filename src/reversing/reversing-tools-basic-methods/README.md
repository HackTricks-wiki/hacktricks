# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binary) na wat (clear text) te **decompile**
- Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **compile**
- jy kan ook probeer om [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) te gebruik om te decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n decompiler wat **decompile en multiple formats ondersoek**, insluitend **libraries** (.dll), **Windows metadata file**s (.winmd), en **executables** (.exe). Sodra dit gedecompileer is, kan 'n assembly as 'n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hier is dat as verlore bronkode herstel moet word vanaf 'n legacy assembly, hierdie aksie tyd kan bespaar. Verder bied dotPeek handige navigasie regdeur die gedecompileerde kode, wat dit een van die perfekte tools vir **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende add-in model en 'n API wat die tool uitbrei om by jou presiese behoeftes te pas, bespaar .NET reflector tyd en vereenvoudig ontwikkeling. Kom ons kyk na die oorvloed van reverse engineering-dienste wat hierdie tool bied:

- Bied insig in hoe die data deur 'n library of component vloei
- Bied insig in die implementering en gebruik van .NET languages en frameworks
- Vind undocumented en unexposed funksionaliteit om meer uit die APIs en technologies used te kry.
- Vind dependencies en verskillende assemblies
- Spoor die presiese ligging van errors in jou code, third-party components, en libraries op.
- Debug in die source van al die .NET code waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit op enige OS hê (jy kan dit direk vanaf VSCode installeer, geen behoefte om die git af te laai nie. Klik op **Extensions** en **search ILSpy**).\
As jy moet **decompile**, **modify** en weer **recompile** kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) of 'n aktief onderhoude fork daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), gebruik. (**Right Click -> Modify Method** om iets binne 'n function te verander).

### DNSpy Logging

Om **DNSpy** te laat log sommige information in 'n file, kan jy hierdie snippet gebruik:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Ontfouting

Om kode met DNSpy te ontfout, moet jy:

Eers, verander die **Assembly attributes** wat verband hou met **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Stoor dan die nuwe lêer via _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Dit is nodig omdat as jy dit nie doen nie, sal verskeie **optimerings** by **runtime** op die kode toegepas word en dit moontlik kan wees dat terwyl jy debug, ’n **break-point** nooit getref word nie of sommige **variables** nie bestaan nie.

Dan, as jou .NET application deur **IIS** **run** word, kan jy dit **restart** met:
```
iisreset /noforce
```
Then, om te begin debug, moet jy al die oop lêers sluit en binne die **Debug Tab** **Attach to Process...** kies:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS server** te koppel en klik **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Nou dat ons die proses debug, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en klik dan op _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Klik enige module in **Modules** en kies **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Regsklik op enige module in **Assembly Explorer** en klik **Sort Assemblies**:

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

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Dan, wanneer jy begin debug, **sal die uitvoering gestop word wanneer elke DLL gelaai word**, dan, wanneer rundll32 jou DLL laai, sal die uitvoering gestop word.

Maar hoe kan jy by die kode van die DLL kom wat gelaai is? Deur hierdie metode, weet ek nie hoe nie.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Let op dat wanneer die uitvoering om enige rede in win64dbg gestop word, kan jy sien **in watter code jy is** deur te kyk na die **bokant van die win64dbg venster**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Dan, deur na hierdie ca te kyk, sien jy wanneer die uitvoering gestop is in die dll wat jy wil debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes in die geheue van 'n lopende game gestoor word en dit te verander. Meer info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n front-end/reverse engineering tool vir die GNU Project Debugger (GDB), gefokus op games. Dit kan egter gebruik word vir enige reverse-engineering verwante goed

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web front-end vir 'n aantal decompilers. Hierdie webdiens laat jou toe om die uitset van verskillende decompilers op klein uitvoerbare lêers te vergelyk.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) sal die **shellcode** binne 'n stukkie geheue **allokeer**, sal jou die **memory address** **aandui** waar die shellcode geallokeer is en sal die uitvoering **stop**.\
Dan moet jy 'n **debugger aanheg** (Ida of x64dbg) aan die proses en 'n **breakpoint by die aangeduide memory address** plaas en die uitvoering **hervat**. Op hierdie manier sal jy die shellcode debug.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is baie soortgelyk aan blobrunner. Dit sal die **shellcode** binne 'n geheuespasie **allokeer**, en 'n **ewigdurende lus** begin. Jy moet dan die **debugger aanheg** aan die proses, **start speel, wag 2-5 sekondes en druk stop** en jy sal jouself in die **ewigdurende lus** bevind. Spring na die volgende instruksie van die ewigdurende lus, want dit sal 'n call na die shellcode wees, en uiteindelik sal jy vind dat jy die shellcode uitvoer.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Deur cutter te gebruik kan jy die shellcode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te gebruik. In my geval, toe ek die shellcode as 'n lêer oopgemaak het, het dit dit korrek gedecompileer, maar toe ek dit as 'n shellcode oopgemaak het, het dit nie:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

Om die emulasie te begin op die plek waar jy wil, stel daar 'n bp en blykbaar sal cutter die emulasie outomaties van daar af begin:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

Jy kan byvoorbeeld die stack binne 'n hex dump sien:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Jy moet [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) probeer.\
Dit sal vir jou dinge sê soos **which functions** die shellcode gebruik en of die shellcode homself in die geheue **decoding**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg kom ook met 'n grafiese launcher waar jy die opsies kan kies wat jy wil en die shellcode uitvoer

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Die **Create Dump**-opsie sal die finale shellcode uitgooi as enige verandering dinamies in geheue aan die shellcode gedoen word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode by 'n spesifieke offset te begin. Die **Debug Shell**-opsie is nuttig om die shellcode te debug met die scDbg-terminal (ek vind egter enige van die opsies wat vroeër verduidelik is beter vir hierdie doel, aangesien jy Ida of x64dbg sal kan gebruik).

### Disassembling using CyberChef

Laai jou shellcode-lêer op as invoer en gebruik die volgende recipe om dit te decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation verberg eenvoudige uitdrukkings soos `x + y` agter formules wat rekenkunde (`+`, `-`, `*`) en bitwyse operateurs (`&`, `|`, `^`, `~`, shifts) meng. Die belangrike deel is dat hierdie identiteite gewoonlik net korrek is onder **vaste-breedte modulêre rekenkunde**, so carries en oorspoelings maak saak:
```c
(x ^ y) + 2 * (x & y) == x + y
```
As jy hierdie soort uitdrukking met generiese algebra-instrumente vereenvoudig, kan jy maklik ’n verkeerde resultaat kry omdat die bit-width semantiek geïgnoreer is.

### Praktiese werkvloei

1. **Behou die oorspronklike bit-width** van die opgeligte kode/IR/dekompiler-uitset (`8/16/32/64` bits).
2. **Klassifiseer die uitdrukking** voordat jy dit probeer vereenvoudig:
- **Lineêr**: geweegde somme van bitwise atome
- **Semilineêr**: lineêr plus konstante masks soos `x & 0xFF`
- **Polinomial**: produkte kom voor
- **Gemeng**: produkte en bitwise logic is verweef, dikwels met herhaalde subuitdrukkings
3. **Verifieer elke kandidaat-herskryf** met ewekansige toetsing of ’n SMT-bewys. As die ekwivalensie nie bewys kan word nie, behou eerder die oorspronklike uitdrukking as om te raai.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is ’n praktiese MBA simplifier vir malware analysis en protected-binary reversing. Dit klassifiseer die uitdrukking en stuur dit deur gespesialiseerde pipelines eerder as om een generiese rewrite pass op alles toe te pas.

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

- **Linear MBA**: CoBRA evalueer die uitdrukking op Boolean-insette, lei ’n signature af, en laat verskeie recovery methods teen mekaar wed, soos pattern matching, ANF conversion, en coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms word herbou met bit-partitioned reconstruction sodat masked regions korrek bly.
- **Polynomial/Mixed MBA**: products word ontbind in cores en repeated subexpressions kan na temporaries gelig word voordat die outer relation vereenvoudig word.

Voorbeeld van ’n mixed identity wat gewoonlik die moeite werd is om te probeer recover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Dit kan saamval tot:
```c
x * y
```
### Reversing notes

- Verkies om CoBRA op **lifted IR expressions** of decompiler-uitvoer te laat loop nadat jy die presiese berekening geïsoleer het.
- Gebruik `--bitwidth` eksplisiet wanneer die expression uit gemaskeerde arithmetic of smal registers kom.
- As jy ’n sterker bewysstap nodig het, kyk na die plaaslike Z3 notes hier:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA kom ook as ’n **LLVM pass plugin** (`libCobraPass.so`), wat nuttig is wanneer jy MBA-heavy LLVM IR voor latere analysis passes wil normaliseer.
- Unsupported carry-sensitive mixed-domain residuals moet as ’n sein behandel word om die oorspronklike expression te behou en oor die carry path handmatig te redeneer.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

To find the **entry point** search the functions by `::main` like in:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

In this case the binary was called authenticator, so it's pretty obvious that this is the interesting main function.\
Having the **name** of the **functions** being called, search for them on the **Internet** to learn about their **inputs** and **outputs**.

### Herstel Rust strings from ELF firmware

In **Rust ELF** binaries, many static strings are not referenced as C-style NUL-terminated pointers. A common `rustc` layout is a **pointer/length tuple** inside **`.data.rel.ro`** pointing into the real string blob stored in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Dit beteken dat `strings` of die verstek Ghidra-analise aangrensende stringe kan saamvoeg of kruisverwysings heeltemal mis.

Vinnige werkvloei:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Kry die virtuele adres en grootte van **`.rodata`**.
2. Lys **`.data.rel.ro`** een woord op ’n slag.
3. Behandel enige waarde binne die `.rodata`-adresreeks as ’n kandidaat-stringwyser.
4. Behandel die volgende woord as die kandidaat-lengte.
5. Pas gesondheidsfilters toe (byvoorbeeld, hou lengtes tussen **4** en **100** grepe).
6. Lees presies `length` grepe uit `.rodata` in plaas daarvan om tot `0x00` te skandeer.

Minimum onttrekker-logika:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Dit is veral nuttig in firmware reversing omdat herwinde Rust strings dikwels **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, en auth-related logic** openbaar.

As Ghidra daardie strings mis, hardloop ’n custom script/plugin wat dieselfde heuristic toepas en string data skep by die verwysde `.rodata` offsets. Die gepubliseerde `rust-strings` en `RustStrings.py` tools van Pen Test Partners is goeie verwysings om die idee aan te pas vir ander **word sizes, endianness, en section layouts**.

## **Delphi**

Vir Delphi compiled binaries kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik

As jy ’n Delphi binary moet reverse, sal ek voorstel dat jy die IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik

Druk net **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Hierdie plugin sal die binary execute en function names dinamies oplos aan die begin van die debugging. Nadat debugging begin het, druk weer die Start button (die groen een of f9) en ’n breakpoint sal in die begin van die werklike code getref word.

Dit is ook baie interessant omdat as jy ’n button in die graphic application druk, sal die debugger stop in die function wat deur daardie button executed word.

## Golang

As jy ’n Golang binary moet reverse, sal ek voorstel dat jy die IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik

Druk net **ATL+f7** (import python plugin in IDA) en kies die python plugin.

Dit sal die names van die functions oplos.

## Compiled Python

Op hierdie page kan jy sien hoe om die python code uit ’n ELF/EXE python compiled binary te kry:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

As jy die **binary** van ’n GBA game kry, kan jy verskillende tools gebruik om dit te **emulate** en **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Bevat ’n debugger met interface
- [**mgba** ](https://mgba.io)- Bevat ’n CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** kan jy sien hoe om die Game Boy Advance **buttons** te druk

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Wanneer dit gedruk word, het elke **key ’n value** om dit te identifiseer:
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
So, in hierdie soort program sal die interessante deel wees **hoe die program die gebruiker-invoer hanteer**. In die adres **0x4000130** sal jy die algemeen-gevonde funksie vind: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

In die vorige beeld kan jy sien dat die funksie vanaf **FUN_080015a8** geroep word (adresse: _0x080015fa_ en _0x080017ac_).

In daardie funksie, ná sommige init-operasies (sonder enige belangrikheid):
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
Dit vind hierdie kode:
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
Die laaste if kontroleer of **`uVar4`** in die **laaste Keys** is en nie die huidige key nie; dit word ook die loslaat van ’n button genoem (huidige key word in **`uVar1`** gestoor).
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
In die vorige code kan jy sien dat ons **uVar1** (die plek waar die **waarde van die gedrukkte knoppie** is) vergelyk met sommige waardes:

- Eerstens word dit vergelyk met die **waarde 4** (**SELECT** button): In die challenge maak hierdie button die skerm skoon
- Dan word dit vergelyk met die **waarde 8** (**START** button): In die challenge kontroleer dit of die code geldig is om die flag te kry.
- In hierdie geval word die var **`DAT_030000d8`** met 0xf3 vergelyk en as die waarde dieselfde is, word some code uitgevoer.
- In enige ander gevalle word some cont (**`DAT_030000d4`**) gekontroleer. Dit is 'n cont omdat dit 1 byvoeg net nadat dit in die code ingaan.\
**A**s minder as 8, word iets wat **adding** values to **`DAT_030000d8`** behels, gedoen (basies voeg dit die waardes van the keys pressed in hierdie variable by solank as die cont minder as 8 is).

So, in hierdie challenge, met kennis van the values of the buttons, moes jy **'n kombinasie met 'n lengte kleiner as 8 druk waarvan die resulting addition 0xf3 is.**

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
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
