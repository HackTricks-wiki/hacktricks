# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za Reversing zenye Msingi wa ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kufanya **decompile** kutoka wasm (binary) hadi wat (maandishi wazi)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kufanya **compile** kutoka wat hadi wasm
- unaweza pia kujaribu kutumia [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kufanya decompile

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler ambayo **hufanya decompile na kuchunguza formats nyingi**, zikiwemo **libraries** (.dll), **Windows metadata file**s (.winmd), na **executables** (.exe). Baada ya kufanyiwa decompile, assembly inaweza kuhifadhiwa kama Visual Studio project (.csproj).

Faida hapa ni kwamba ikiwa source code iliyopotea inahitaji kurejeshwa kutoka kwenye legacy assembly, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa navigation rahisi katika code iliyofanyiwa decompile, na kuifanya kuwa mojawapo ya zana bora kwa **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na add-in model pana na API inayopanua tool ili kukidhi mahitaji yako halisi, .NET reflector huokoa muda na kurahisisha development. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na tool hii:

- Hutoa ufahamu wa jinsi data inavyopita kupitia library au component
- Hutoa ufahamu wa implementation na matumizi ya .NET languages na frameworks
- Hupata functionality ambayo haijaandikwa documentation na ambayo haijawekwa wazi, ili kupata zaidi kutoka kwenye APIs na technologies zinazotumika.
- Hupata dependencies na assemblies tofauti
- Hufuatilia eneo kamili la errors katika code yako, third-party components, na libraries.
- Hufanya debug kwenye source ya .NET code yote unayofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kui-install moja kwa moja kutoka VSCode, hakuna haja ya ku-download git. Bonyeza **Extensions** na **search ILSpy**).\
Ikiwa unahitaji kufanya **decompile**, **modify** na **recompile** tena, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayotunzwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### DNSpy Logging

Ili kufanya **DNSpy iandike baadhi ya taarifa kwenye file**, unaweza kutumia snippet hii:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Ili kufanya debugging ya code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **sifa za Assembly** zinazohusiana na **debugging**:

![DNSpy Logging - DNSpy Debugging: Kwanza, badilisha sifa za Assembly zinazohusiana na debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Bofya compile](<../../images/image (314) (1).png>)

Kisha hifadhi faili jipya kupitia _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Kisha hifadhi faili jipya kupitia File Save module](<../../images/image (602).png>)

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** **optimisations** kadhaa zitatumika kwenye code, na huenda wakati wa debugging **break-point is never hit** au baadhi ya **variables don't exist**.

Kisha, ikiwa application yako ya .NET inaendeshwa na **IIS**, unaweza **restart** kwa:
```
iisreset /noforce
```
Kisha, ili kuanza debugging unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging unapaswa kufunga faili zote zilizofunguliwa na ndani ya Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuunganisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuunganisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha bofya _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha bofya Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha bofya Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote kwenye **Assembly Explorer** na ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote kwenye Assembly Explorer na ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Chagua **Windbg** debugger
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za execution kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Using IDA: Sanidi parameters za execution kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **execution itasimamishwa kila DLL inapopakiwa**, hivyo rundll32 inapopakia DLL yako, execution itasimamishwa.

Lakini unawezaje kufikia code ya DLL iliyopakiwa? Kwa kutumia method hii, sijui jinsi ya kufanya hivyo.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza execution**, debugger itasimama kwenye kila dll main; wakati fulani **itasimama kwenye dll Entry ya dll yako**. Kuanzia hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba execution inaposimamishwa kwa sababu yoyote kwenye win64dbg, unaweza kuona **uko kwenye code ipi** kwa kuangalia **sehemu ya juu ya dirisha la win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Kumbuka kwamba execution inaposimamishwa kwa sababu yoyote kwenye win64dbg unaweza kuona uko kwenye code ipi kwa kuangalia sehemu ya juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kisha, ukiangalia sehemu hii, unaweza kuona execution iliposimamishwa kwenye dll unayotaka kufanya debugging.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni program muhimu ya kutafuta mahali ambapo values muhimu zimehifadhiwa ndani ya memory ya game inayoendelea na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/reverse engineering tool ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa mambo yoyote yanayohusiana na reverse-engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni web front-end ya decompilers kadhaa. Web service hii hukuruhusu kulinganisha output ya decompilers tofauti kwenye executables ndogo.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) ita **allocate** **shellcode** ndani ya nafasi ya memory, **itakuonyesha** **memory address** ambayo shellcode iliwekwa na **itasimamisha** execution.\
Kisha unahitaji **ku-attach debugger** (Ida au x64dbg) kwenye process na kuweka **breakpoint kwenye memory address iliyoonyeshwa**, kisha **uendeleze** execution. Kwa njia hii utafanya debugging ya shellcode.

Ukurasa wa releases wa github una zips zenye releases zilizocompile: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata version iliyorekebishwa kidogo ya Blobrunner kwenye link ifuatayo. Ili kuicompile, **create C/C++ project katika Visual Studio Code, copy na paste code, kisha i-build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)inafanana sana na blobrunner. Ita **allocate** **shellcode** ndani ya nafasi ya memory na kuanzisha **infinite loop**. Kisha unahitaji **ku-attach debugger** kwenye process, **bonyeza start, subiri sekunde 2-5, kisha bonyeza stop**, na utajikuta ndani ya **infinite loop**. Ruka hadi instruction inayofuata ya infinite loop, kwa kuwa itakuwa call kwenda kwenye shellcode; hatimaye utajikuta uki-execute shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it inafanana sana na blobrunner. Ita allocate shellcode ndani ya nafasi ya memory na kuanzisha infinite loop...](<../../images/image (509).png>)

Unaweza kupakua version iliyocompile ya [jmp2it kwenye releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia cutter unaweza ku-emulate shellcode na kuichunguza dynamically.

Kumbuka kwamba Cutter inakuruhusu kutumia "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama file ili-decompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Kumbuka kwamba Cutter inakuruhusu kutumia "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama file ili...](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo; inaonekana cutter itaanza emulation automatically kutoka hapo:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Ili kuanza emulation mahali unapotaka, weka bp hapo; inaonekana cutter itaanza emulation automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Ili kuanza emulation mahali unapotaka, weka bp hapo; inaonekana cutter itaanza emulation automatically...](<../../images/image (387).png>)

Unaweza kuona stack, kwa mfano, ndani ya hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Unaweza kuona stack, kwa mfano, ndani ya hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama **functions zipi** shellcode inatumia na kama shellcode **inaji-decode** yenyewe kwenye memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg pia ina graphical launcher ambapo unaweza kuchagua options unazotaka na ku-execute shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg pia ina graphical launcher ambapo unaweza kuchagua options unazotaka na ku...](<../../images/image (258).png>)

Option ya **Create Dump** itadump shellcode ya mwisho ikiwa mabadiliko yoyote yamefanywa kwenye shellcode dynamically kwenye memory (ni muhimu kwa kudownload shellcode iliyodecodewa). **start offset** inaweza kuwa muhimu kuanzisha shellcode kwenye offset maalum. Option ya **Debug Shell** ni muhimu kwa kudebug shellcode ukitumia scDbg terminal (hata hivyo, naona options zozote zilizoelezwa awali ni bora zaidi kwa suala hili kwa sababu utaweza kutumia Ida au x64dbg).

### Disassembling using CyberChef

Upload file yako ya shellcode kama input na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama `x + y` nyuma ya formulas zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, hivyo carries na overflows zina umuhimu:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ukirahisisha aina hii ya expression kwa kutumia generic algebra tooling, unaweza kupata kwa urahisi matokeo yasiyo sahihi kwa sababu semantics za bit-width zilipuuzwa.<sup>[[1]](#references)</sup>

### Workflow ya vitendo

1. **Hifadhi bit-width ya awali** kutoka kwenye lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Classify expression** kabla ya kujaribu kuirahisisha:
- **Linear**: weighted sums za bitwise atoms
- **Semilinear**: linear pamoja na constant masks kama vile `x & 0xFF`
- **Polynomial**: bidhaa zinaonekana
- **Mixed**: bidhaa na bitwise logic zimechanganyika, mara nyingi zikiwa na repeated subexpressions
3. **Verify kila candidate rewrite** kwa random testing au SMT proof. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi expression ya awali badala ya kukisia.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa malware analysis na protected-binary reversing. Hu-classify expression na kuipeleka kupitia specialized pipelines badala ya kutumia generic rewrite pass moja kwa kila kitu.<sup>[[2]](#references)</sup>

Matumizi ya haraka:
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
Kesi muhimu:

- **Linear MBA**: CoBRA hutathmini expression kwa kutumia Boolean inputs, hutengeneza signature, na huendesha kwa wakati mmoja recovery methods kadhaa kama pattern matching, ANF conversion, na coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms hujengwa upya kwa bit-partitioned reconstruction ili masked regions zibaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa kuwa cores, na repeated subexpressions zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha outer relation.

Mfano wa mixed identity ambao kwa kawaida unafaa kujaribu kuurejesha:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Hii inaweza kurahisishwa kuwa:
```c
x * y
```
### Vidokezo vya Reversing

- Pendelea kuendesha CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga computation halisi.
- Tumia `--bitwidth` waziwazi wakati expression ilitokana na masked arithmetic au registers zenye upana mdogo.
- Ikiwa unahitaji hatua yenye proof imara zaidi, angalia maelezo ya hapa ya Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia husambazwa kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka ku-normalize LLVM IR yenye MBA nyingi kabla ya analysis passes zinazofuata.
- Mixed-domain residuals zisizotumika zenye kutegemea carry zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression ya awali na kufikiri kuhusu carry path manually.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii **hubadilisha instructions zote kuwa `mov`** (ndiyo, ni nzuri sana). Pia hutumia interruptions kubadilisha execution flows. Kwa maelezo zaidi kuhusu jinsi inavyofanya kazi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Ukiwa na bahati, [demovfuscator](https://github.com/kirschju/demovfuscator) ita-deofuscate binary. Ina dependencies kadhaa.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Na [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, workaround hii ya kupata flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa `::main` kama ilivyo katika:

![Movfuscator - Rust: Ili kupata entry point, tafuta functions kwa ::main kama ilivyo katika](<../../images/image (1080).png>)

Katika hali hii binary iliitwa authenticator, kwa hiyo ni wazi kabisa kwamba hii ndiyo main function inayohusika.\
Ukiwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili kujifunza kuhusu **inputs** na **outputs** zao.

### Kurejesha Rust strings kutoka ELF firmware

Katika binaries za **Rust ELF**, static strings nyingi hazirejelewi kama pointers za C-style zilizo na NUL termination. Mpangilio wa kawaida wa `rustc` ni **pointer/length tuple** ndani ya **`.data.rel.ro`** inayoelekeza kwenye string blob halisi iliyohifadhiwa ndani ya **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Hii ina maana kwamba `strings` au uchanganuzi wa kawaida wa Ghidra unaweza kuunganisha strings zilizo karibu au kukosa cross-references kabisa.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer ya string inayowezekana.
4. Chukulia word inayofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya sanity (kwa mfano, hifadhi urefu wa kati ya **4** na **100** bytes).
6. Soma byte `length` haswa kutoka `.rodata` badala ya kuscan hadi `0x00`.

Mantiki ndogo ya extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Hii ni muhimu hasa katika firmware reversing kwa sababu Rust strings zilizorejeshwa mara nyingi hufichua **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, na auth-related logic**.

Ikiwa Ghidra itakosa strings hizo, endesha custom script/plugin inayotumia heuristic hiyo hiyo na kuunda string data kwenye `.rodata` offsets zilizoelekezwa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hili kwa **word sizes, endianness, na section layouts** nyingine.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizocompiliwa za Delphi unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unapaswa kureverse Delphi binary, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza tu **ATL+f7** (import python plugin katika IDA) na uchague python plugin.

Plugin hii itaendesha binary na kutatua function names dynamically mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena Start button (ile ya kijani au f9), kisha breakpoint itagonga mwanzoni mwa real code.

Hii pia inavutia kwa sababu ukibonyeza button katika graphic application, debugger itasimama kwenye function iliyotekelezwa na button hiyo.

## Golang

Ikiwa unapaswa kureverse Golang binary, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza tu **ATL+f7** (import python plugin katika IDA) na uchague python plugin.

Hii itatatua names za functions.

## Compiled Python

Katika ukurasa huu unaweza kupata jinsi ya kupata python code kutoka kwenye ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Ukipata **binary** ya game ya GBA unaweza kutumia tools mbalimbali za **ku-emulate** na **ku-debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Katika [**no$gba**](https://problemkaputt.de/gba.htm), katika _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **buttons** za Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Inapobonyezwa, kila **key ina value** ya kuitambua:
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
Kwa hiyo, katika aina hii ya program, sehemu ya kuvutia itakuwa **jinsi program inavyoshughulikia user input**. Katika anwani **0x4000130** utapata function inayopatikana mara kwa mara: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA inayorejelea KEYINPUT katika anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kwamba function inaitwa kutoka kwa **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya baadhi ya init operations (zisizo na umuhimu):
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
Msimbo huu umepatikana:
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
The last if inakagua **`uVar4`** iko kwenye **last Keys** na si key ya sasa, pia huitwa kuachilia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).
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
Katika code ya awali unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **value of the pressed button** iko) na values fulani:

- Kwanza, inalinganishwa na **value 4** (button ya **SELECT**): Katika challenge, button hii inafuta screen
- Kisha, inalinganishwa na **value 8** (button ya **START**): Katika challenge, hii hukagua kama code ni valid ili kupata flag.
- Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3, na ikiwa value ni sawa, code fulani inatekelezwa.
- Katika hali nyingine zote, cont fulani (**`DAT_030000d4`**) hukaguliwa. Ni cont kwa sababu inaongezwa 1 mara tu baada ya kuanza kuingiza code.\
**I**kiwa ni chini ya 8, kitu kinachohusisha **kuongeza** values kwenye **`DAT_030000d8`** hufanyika (kimsingi inaongeza values za keys zilizobonyezwa kwenye var hii mradi cont iwe chini ya 8).

Kwa hiyo, katika challenge hii, ukijua values za buttons, ulihitaji **kubonyeza combination yenye length chini ya 8 ambapo jumla inayotokana ni 0xf3.**

**Reference ya tutorial hii:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
