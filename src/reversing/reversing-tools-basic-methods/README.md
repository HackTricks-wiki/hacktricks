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

dotPeek ni decompiler inayoweza **kudekompaila na kuchunguza miundo mingi**, ikijumuisha **libraries** (.dll), **Windows metadata file**s (.winmd), na **executables** (.exe). Baada ya kudekompailiwa, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida hapa ni kwamba ikiwa source code iliyopotea inahitaji kurejeshwa kutoka kwenye legacy assembly, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa urambazaji rahisi ndani ya code iliyodekompailiwa, na kuifanya kuwa mojawapo ya zana bora kabisa za **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kwa add-in model kamili na API inayopanua tool ili ilingane na mahitaji yako halisi, .NET reflector huokoa muda na kurahisisha development. Hebu tuangalie wingi wa reverse engineering services ambazo tool hii hutoa:

- Hutoa ufahamu wa jinsi data inavyopita kupitia library au component
- Hutoa ufahamu kuhusu implementation na usage ya lugha na frameworks za .NET
- Hupata functionality isiyoandikwa na isiyoonyeshwa wazi ili kupata zaidi kutoka kwa APIs na technologies zinazotumiwa.
- Hupata dependencies na assemblies tofauti
- Hufuatilia eneo halisi la errors kwenye code yako, third-party components, na libraries.
- Hufanya debugging hadi kwenye source ya code yote ya .NET unayofanya nayo kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuwa nayo kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bonyeza **Extensions** na **search ILSpy**).\
Ikiwa unahitaji **decompile**, **modify** na **recompile** tena unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** kubadilisha kitu ndani ya function).

### DNSpy Logging

Ili kufanya **DNSpy iandike baadhi ya information kwenye file**, unaweza kutumia snippet hii:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Ili kufanya debug ya code kwa kutumia DNSpy unahitaji:

Kwanza, badilisha **Assembly attributes** zinazohusiana na **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

Kutoka:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Kwa:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Na bofya **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Kisha hifadhi faili jipya kupitia _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Hii ni muhimu kwa sababu usipofanya hivi, wakati wa **runtime** **optimisations** kadhaa zitatumika kwenye code na huenda ikawezekana kwamba wakati wa debugging **break-point is never hit** au baadhi ya **variables don't exist**.

Kisha, ikiwa application yako ya .NET inakuwa **run** na **IIS** unaweza kui**restart** kwa:
```
iisreset /noforce
```
Then, ili kuanza debugging unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Debug Tab** chagua **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuattach kwenye **IIS server** na bofya **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Sasa kwa kuwa tuna-debug process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_ kisha bofya _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules** na chagua **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote ndani ya **Assembly Explorer** na bofya **Sort Assemblies**:

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

Kisha, unapoanza debugging **utekelezaji utasimamishwa kila DLL inapopakiwa**, kisha, rundll32 inapopakia DLL yako uekelezaji utasimamishwa.

Lakini, unawezaje kufika kwenye code ya DLL iliyopakiwa? Kwa njia hii, sijui jinsi.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali thamani muhimu zimehifadhiwa ndani ya memory ya game inayoendeshwa na kuzibadilisha. Taarifa zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/reverse engineering tool ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa chochote kinachohusiana na reverse-engineering

[**Decompiler Explorer**](https://dogbolt.org/) ni web front-end kwa decompilers kadhaa. Hii web service hukuwezesha kulinganisha output ya decompilers tofauti kwenye executables ndogo.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) itatenga **shellcode** ndani ya space ya memory, itakuonyesha **memory address** ambapo shellcode ilitengwa na itasimamisha **utekelezaji**.\
Kisha, unahitaji **kuattach debugger** (Ida au x64dbg) kwenye process na kuweka **breakpoint kwenye memory address iliyoonyeshwa** kisha **kuendelea** na uekelezaji. Kwa njia hii utakuwa una-debug shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)inafanana sana na blobrunner. Itatenga **shellcode** ndani ya space ya memory, na kuanza **eternal loop**. Kisha unahitaji **kuattach debugger** kwenye process, **bonyeza start, subiri sekunde 2-5 na bonyeza stop** na utajikuta ndani ya **eternal loop**. Ruka hadi instruction inayofuata ya eternal loop kwa kuwa itakuwa ni call kwa shellcode, na mwishowe utajikuta una-execute shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

Unaweza kupakua version iliyocompile ya [jmp2it ndani ya releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia cutter unaweza ku-emulate shellcode na kuichunguza dynamically.

Kumbuka kwamba Cutter inaruhusu "Open File" na "Open Shellcode". Kwangu nilipofungua shellcode kama file ili-decompile kwa usahihi, lakini nilipofungua kama shellcode haikufanya hivyo:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo na inaonekana cutter ita-start emulation kiotomatiki kutoka hapo:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

Unaweza kuona stack, kwa mfano, ndani ya hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia vitu kama **functions gani** shellcode inatumia na kama shellcode inajitumia **decoding** yenyewe ndani ya memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg pia ina launcher ya graphical ambapo unaweza kuchagua options unazotaka na execute shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Option ya **Create Dump** itadump shellcode ya mwisho ikiwa mabadiliko yoyote yanafanywa kwenye shellcode dynamically in memory (inasaidia kupakua decoded shellcode). Option ya **start offset** inaweza kuwa muhimu kuanza shellcode kwenye offset maalum. Option ya **Debug Shell** ni muhimu kwa debug shellcode kwa kutumia scDbg terminal (hata hivyo ninaona options zozote zilizoelezwa hapo awali ni bora zaidi kwa hili kwa sababu utaweza kutumia Ida au x64dbg).

### Disassembling using CyberChef

Upload file yako ya shellcode kama input na tumia recipe ifuatayo ku-decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama `x + y` nyuma ya formulas zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Sehemu muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, hivyo carries na overflows ni muhimu:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ikiwa unarahisisha aina hii ya usemi kwa kutumia generic algebra tooling unaweza kupata matokeo mabaya kwa urahisi kwa sababu semantics za bit-width zilipuuzwa.

### Practical workflow

1. **Hifadhi bit-width ya awali** kutoka kwenye code/IR/decompiler output iliyoinuliwa (`8/16/32/64` bits).
2. **Panga usemi** kabla ya kujaribu kuurahisisha:
- **Linear**: weighted sums za bitwise atoms
- **Semilinear**: linear pamoja na constant masks kama `x & 0xFF`
- **Polynomial**: products zinaonekana
- **Mixed**: products na bitwise logic zimechanganywa, mara nyingi zikiwa na repeated subexpressions
3. **Thibitisha kila candidate rewrite** kwa random testing au SMT proof. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi usemi wa awali badala ya kubahatisha.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni practical MBA simplifier kwa malware analysis na protected-binary reversing. Hu-classify usemi na kuuelekeza kupitia specialized pipelines badala ya kutumia one generic rewrite pass kwa kila kitu.

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
Matumizi muhimu:

- **Linear MBA**: CoBRA hutathmini usemi kwenye Boolean inputs, hutengeneza signature, na hujaribu kwa wakati mmoja mbinu kadhaa za recovery kama pattern matching, ANF conversion, na coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms hujengwa upya kwa bit-partitioned reconstruction ili maeneo yaliyofunikwa na mask yabaki sahihi.
- **Polynomial/Mixed MBA**: bidhaa hugawanywa kuwa cores na repeated subexpressions zinaweza kuhamishwa hadi temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa mixed identity ambao mara nyingi inafaa kujaribu kurecover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Hii inaweza kupunguzwa hadi:
```c
x * y
```
### Reversing notes

- Prefer running CoBRA on **lifted IR expressions** or decompiler output after you isolated the exact computation.
- Use `--bitwidth` explicitly when the expression came from masked arithmetic or narrow registers.
- If you need a stronger proof step, check the local Z3 notes here:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA also ships as an **LLVM pass plugin** (`libCobraPass.so`), which is useful when you want to normalize MBA-heavy LLVM IR before later analysis passes.
- Unsupported carry-sensitive mixed-domain residuals should be treated as a signal to keep the original expression and reason about the carry path manually.

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

### Recovering Rust strings from ELF firmware

In **Rust ELF** binaries, many static strings are not referenced as C-style NUL-terminated pointers. A common `rustc` layout is a **pointer/length tuple** inside **`.data.rel.ro**` pointing into the real string blob stored in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Hii inamaanisha `strings` au uchambuzi wa kawaida wa Ghidra unaweza kuunganisha strings zilizo karibu au kukosa cross-references kabisa.

Mtiririko wa kazi wa haraka:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Pata anwani ya virtual na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya anuwai ya anwani ya `.rodata` kama pointer ya string inayowezekana.
4. Chukulia neno linalofuata kama urefu unaowezekana.
5. Tekeleza vichujio vya usalama wa akili (kwa mfano, weka urefu kati ya **4** na **100** bytes).
6. Soma bytes `length` hasa kutoka `.rodata` badala ya kuchanganua hadi `0x00`.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Hii ni muhimu sana katika firmware reversing kwa sababu strings za Rust zilizorecovered mara nyingi huonyesha **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, na auth-related logic**.

Ikiwa Ghidra inakosa hizo strings, endesha custom script/plugin inayotumia heuristic ileile na kuunda string data kwenye referenced `.rodata` offsets. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeo mazuri ya kubadilisha wazo hili kwa **word sizes, endianness, na section layouts** nyingine.

## **Delphi**

Kwa Delphi compiled binaries unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unalazimika reverse binary ya Delphi ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza tu **ATL+f7** (import python plugin in IDA) kisha chagua python plugin.

Plugin hii itatekeleza binary na kuresolve majina ya function kwa dynamic wakati wa mwanzo wa debugging. Baada ya kuanza debugging bonyeza tena Start button (ile ya kijani au f9) na breakpoint itagonga mwanzo wa real code.

Pia ni ya kuvutia sana kwa sababu ukibonyeza button kwenye graphic application debugger itasimama kwenye function inayotekelezwa na hiyo bottom.

## Golang

Ikiwa unalazimika reverse binary ya Golang ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza tu **ATL+f7** (import python plugin in IDA) kisha chagua python plugin.

Hii itaresolve majina ya function.

## Compiled Python

Kwenye ukurasa huu unaweza kupata jinsi ya kupata python code kutoka kwenye ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Ukipata **binary** ya mchezo wa GBA unaweza kutumia tools tofauti ku **emulate** na ku **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **buttons** za Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Zinapobonyezwa, kila **key ina value** ya kuitambulisha:
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
Kwa hivyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia user input**. Katika address **0x4000130** utafind function inayopatikana kwa kawaida: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Katika picha ya awali unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (addresses: _0x080015fa_ and _0x080017ac_).

Katika function hiyo, baada ya some init operations (bila umuhimu wowote):
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
Imepatikana msimbo huu:
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
The last if inachunguza ikiwa **`uVar4`** iko katika **last Keys** na si key ya sasa, pia huitwa kuachia kitufe (current key imehifadhiwa katika **`uVar1`**).
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
Katika code ya awali unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **thamani ya button iliyobanwa** iko) na baadhi ya values:

- Kwanza, inaliganishwa na **thamani 4** (**SELECT** button): Katika challenge button hii inafuta screen
- Kisha, inalinganisha na **thamani 8** (**START** button): Katika challenge hii inakagua kama code ni valid kupata flag.
- Katika case hii var **`DAT_030000d8`** inaliganishwa na 0xf3 na kama value ni ileile baadhi ya code inatekelezwa.
- Katika cases zingine zote, some cont (**`DAT_030000d4`**) inakaguliwa. Ni cont kwa sababu inaongeza 1 mara tu baada ya kuingia kwenye code.\
**K**ama ni chini ya 8, kitu kinachohusisha **kuongeza** values kwenye **`DAT_030000d8`** kinafanyika (kimsingi inaongeza values za keys zilizobanwa kwenye variable hii ilimradi cont ni chini ya 8).

Kwa hiyo, katika challenge hii, ukijua values za buttons, ulilazimika **kubonyeza combination yenye length ndogo kuliko 8 ambayo jumla yake inayotokana na kuongezwa ni 0xf3.**

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
