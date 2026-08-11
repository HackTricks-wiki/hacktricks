# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za Reversing Zinazotumia ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kufanya **decompile** kutoka wasm (binary) hadi wat (clear text)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kufanya **compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa decompilation.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler inayofanya **decompile na kuchunguza formats nyingi**, ikijumuisha **libraries** (.dll), **Windows metadata file**s (.winmd), na **executables** (.exe). Baada ya kufanyiwa decompile, assembly inaweza kuhifadhiwa kama Visual Studio project (.csproj).

Faida hapa ni kwamba ikiwa source code iliyopotea inahitaji kurejeshwa kutoka kwenye legacy assembly, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa navigation rahisi katika decompiled code, na kuifanya kuwa mojawapo ya zana bora za **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na add-in model pana na API inayopanua tool ili kukidhi mahitaji yako mahususi, .NET reflector huokoa muda na kurahisisha development. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na tool hii:

- Hutoa ufahamu kuhusu jinsi data inavyopita kupitia library au component
- Hutoa ufahamu kuhusu implementation na matumizi ya .NET languages na frameworks
- Hupata functionality ambayo haijaandikwa kwenye documentation na ambayo haijawekwa wazi, ili kupata zaidi kutoka kwenye APIs na technologies zinazotumika.
- Hupata dependencies na assemblies tofauti
- Hufuatilia mahali halisi pa errors katika code yako, third-party components, na libraries.
- Hufanya debug kwenye source ya .NET code yote unayofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kui-install moja kwa moja kutoka VSCode, hakuna haja ya ku-download git. Bonyeza **Extensions** kisha **search ILSpy**).\
Ikiwa unahitaji kufanya **decompile**, **modify** na **recompile** tena, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### DNSpy Logging

Ili kufanya **DNSpy i-log taarifa fulani kwenye file**, unaweza kutumia snippet hii:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Ili kufanya debugging ya code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **Assembly attributes** zinazohusiana na **debugging**:

![DNSpy Logging - DNSpy Debugging: Kwanza, badilisha Assembly attributes zinazohusiana na debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Na bofya compile](<../../images/image (314) (1).png>)

Kisha hifadhi faili mpya kupitia _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Kisha hifadhi faili mpya kupitia File Save module](<../../images/image (602).png>)

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** **optimisations** kadhaa zitatumika kwenye code na kuna uwezekano kwamba wakati wa debugging **break-point haitawahi kugongwa** au baadhi ya **variables hazitakuwepo**.

Kisha, ikiwa application yako ya .NET inaendeshwa na **IIS**, unaweza **kuianzisha upya** kwa:
```
iisreset /noforce
```
Kisha, ili kuanza debugging unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging unapaswa kufunga faili zote zilizofunguliwa na ndani ya Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuunganisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuunganisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Sasa kwa kuwa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha bofya _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sasa kwa kuwa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha bofya Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sasa kwa kuwa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha bofya Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote ndani ya **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote ndani ya Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote ndani ya **Assembly Explorer** na uchague **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote ndani ya Assembly Explorer na uchague Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Kutumia IDA

- **Load rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- Chagua **Windbg** debugger
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za execution kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Sanidi parameters za execution kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **execution itasimamishwa kila DLL inapopakiwa**, hivyo rundll32 inapopakia DLL yako, execution itasimamishwa.

Njia hii husimama kwenye matukio ya module-load, lakini kufikia entry point ya DLL iliyopakiwa si rahisi moja kwa moja kama ilivyo kwenye workflow ya x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Load rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza execution**, debugger itasimama kwenye kila dll main; wakati fulani **itasimama kwenye dll Entry ya dll yako**. Kuanzia hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba execution inaposimamishwa kwa sababu yoyote katika win64dbg, unaweza kuona **uko kwenye code ipi** kwa kuangalia **juu ya dirisha la win64dbg**:

![Using IDA - Kutumia x64dbg/x32dbg: Kumbuka kwamba execution inaposimamishwa kwa sababu yoyote katika win64dbg, unaweza kuona uko kwenye code ipi kwa kuangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha wakati execution imesimamishwa ndani ya DLL unayotaka ku-debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo values muhimu zimehifadhiwa ndani ya memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/reverse engineering tool ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse-engineering

[**Decompiler Explorer**](https://dogbolt.org/) ni web front-end ya decompilers kadhaa. Web service hii hukuwezesha kulinganisha output ya decompilers tofauti kwenye executables ndogo.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode with blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **memory address** yake, na kusitisha execution.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye address iliyochapishwa, kisha endeleza execution ili ku-debug shellcode.

Ukurasa wa releases wa github una zips zilizo na releases zilizocompile: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililobadilishwa kidogo la Blobrunner kwenye link ifuatayo. Ili kulicompile, **unda C/C++ project katika Visual Studio Code, copy na paste code, kisha build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode with jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye infinite loop. Ambatisha debugger, endeleza execution kwa **sekunde 2–5**, isimamishe ndani ya loop hiyo, kisha step hadi kwenye call inayofuata inayohamisha execution kwenda kwenye shellcode iliyotengwa.

![Debugger ikiwa imesimama kwenye infinite loop ya jmp2it mara tu kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililocompile la [jmp2it kwenye releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza ku-emulate shellcode na kuichunguza dynamically.

Kumbuka kwamba Cutter inakuruhusu kutumia "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama file ili-decompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya analysis wakati bytes zilezile zinafunguliwa kama file au kama shellcode](<../../images/image (562).png>)

Ili kuanza emulation katika sehemu unayotaka, weka bp hapo na inaonekana Cutter itaanza emulation moja kwa moja kutoka hapo:

![Kuweka breakpoint kwenye shellcode entry inayotakiwa kabla ya kuanza Cutter emulation](<../../images/image (589).png>)

![Cutter emulator ikiwa imesimama kwenye shellcode breakpoint iliyochaguliwa](<../../images/image (387).png>)

Unaweza kuona stack, kwa mfano ndani ya hex dump:

![Kuangalia stack ya shellcode iliyo-emulate kwenye Cutter's hex dump](<../../images/image (186).png>)

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
scDbg pia ina graphical launcher ambapo unaweza kuchagua options unazotaka na kutekeleza shellcode

![scDbg graphical launcher for selecting shellcode emulation and tracing options](<../../images/image (258).png>)

Option ya **Create Dump** itadump shellcode ya mwisho ikiwa kuna mabadiliko yaliyofanywa kwa shellcode dynamically kwenye memory (ni muhimu kwa kupakua shellcode iliyodecodewa). **start offset** inaweza kuwa muhimu kuanzisha shellcode kwenye offset maalum. Option ya **Debug Shell** ni muhimu kwa ajili ya ku-debug shellcode kwa kutumia scDbg terminal (hata hivyo, naona options zozote zilizoelezwa awali zinafaa zaidi kwa jambo hili kwa sababu utaweza kutumia Ida au x64dbg).

### Disassembling using CyberChef

Pakia faili yako ya shellcode kama input na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama vile `x + y` nyuma ya formulas zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, kwa hivyo carries na overflows ni muhimu:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ukirahisisha aina hii ya expression kwa kutumia zana za jumla za algebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za bit-width zilipuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi bit-width ya awali** kutoka kwenye lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Classify expression** kabla ya kujaribu kuirahisisha:
- **Linear**: weighted sums za bitwise atoms
- **Semilinear**: linear pamoja na constant masks kama `x & 0xFF`
- **Polynomial**: products zinatokea
- **Mixed**: products na bitwise logic zimechanganywa, mara nyingi zikiwa na repeated subexpressions
3. **Thibitisha kila candidate rewrite** kwa random testing au SMT proof. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi expression ya awali badala ya kubashiri.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa malware analysis na protected-binary reversing. Huainisha expression na kuipeleka kupitia specialized pipelines badala ya kutumia generic rewrite pass moja kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini expression kwenye Boolean inputs, hutengeneza signature, na kuendesha kwa wakati mmoja recovery methods kadhaa kama pattern matching, ANF conversion, na coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms hujengwa upya kwa bit-partitioned reconstruction ili masked regions zibaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa kuwa cores, na repeated subexpressions zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha outer relation.

Mfano wa mixed identity ambayo mara nyingi inafaa kujaribu kuirecover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Hii inaweza kurahisishwa kuwa:
```c
x * y
```
### Maelezo ya Reversing

- Pendelea kuendesha CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga computation halisi.
- Tumia `--bitwidth` wazi wakati expression ilitokana na **masked arithmetic** au registers nyembamba.
- Ikiwa unahitaji hatua thabiti zaidi ya proof, angalia maelezo ya Z3 hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inasambazwa kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kunormalize LLVM IR yenye MBA nyingi kabla ya **analysis passes** zinazofuata.
- **Unsupported carry-sensitive mixed-domain residuals** zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression ya awali na kuchanganua carry path mwenyewe.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa instruction sequences zinazotumia `mov`, na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kufanya deobfuscate ya matokeo. Ina dependencies kadhaa.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Na [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, workaround hii ya kutafuta flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa kutumia `::main` kama ilivyo kwenye:

![Kupata Rust entry point katika Ghidra kwa kutafuta majina ya functions kwa double-colon main](<../../images/image (1080).png>)

Katika hali hii binary iliitwa authenticator, kwa hiyo ni rahisi kutambua kwamba hii ndiyo main function inayovutia.\
Ukiwa na **name** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **inputs** na **outputs** zake.

### Kurejesha Rust strings kutoka ELF firmware

Katika binaries za **Rust ELF**, strings nyingi tuli hazirejelewi kama pointers za C-style zilizo NUL-terminated. Muundo wa kawaida wa `rustc` ni **pointer/length tuple** ndani ya **`.data.rel.ro`** inayoelekeza kwenye string blob halisi iliyohifadhiwa kwenye **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Hii inamaanisha kuwa `strings` au uchanganuzi chaguomsingi wa Ghidra unaweza kuunganisha strings zilizo karibu au kukosa kabisa cross-references.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Hesabu **`.data.rel.ro`** neno moja kwa wakati mmoja.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer ya string inayoweza kuwa sahihi.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya sanity (kwa mfano, hifadhi urefu ulio kati ya **4** na **100** bytes).
6. Soma bytes `length` hasa kutoka `.rodata` badala ya kuendelea kuscan hadi `0x00`.

Mantiki ndogo ya extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Hii ni muhimu hasa katika firmware reversing kwa sababu Rust strings zilizopatikana mara nyingi hufichua **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, na auth-related logic**.

Ikiwa Ghidra itakosa strings hizo, endesha custom script/plugin inayotumia heuristic hiyo hiyo na kuunda string data kwenye `.rodata` offsets zilizorejelewa. Zana za `rust-strings` na `RustStrings.py` zilizochapishwa na Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hili kwa **word sizes, endianness, na section layouts** nyingine.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa Delphi compiled binaries unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kureverse Delphi binary, ninapendekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague plugin file.

Plugin hii itaendesha binary na kutatua function names dynamically mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itagonga mwanzoni mwa real code.

Ukibonyeza kitufe katika graphical application, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Ikiwa unahitaji kureverse Golang binary, ninapendekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague plugin file.

Hii itatatua names za functions.

## Python Iliyocompiliwa

Katika ukurasa huu unaweza kupata jinsi ya kupata Python code kutoka kwenye ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali za **ku-emulate** na **ku-debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua debug version_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **buttons** za Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Zinapobonyezwa, kila **key ina value** ya kuitambua:
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
Kwa hiyo, katika aina hii ya program, sehemu ya kuvutia itakuwa **jinsi program inavyoshughulikia user input**. Katika anwani **0x4000130** utapata function inayopatikana mara nyingi: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA inayorejelea KEYINPUT kwenye anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya init operations kadhaa (zisizo na umuhimu):
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
Imepata code hii:
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
`if` ya mwisho inakagua ikiwa **`uVar4`** iko kwenye **Keys** za mwisho na si key ya sasa; hii pia huitwa kuachilia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).
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
Katika msimbo uliotangulia unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **value ya kitufe kilichobonyezwa** ipo) na baadhi ya values:

- Kwanza, inalinganishwa na **value 4** (kitufe cha **SELECT**): Katika challenge, kitufe hiki husafisha screen
- Kisha inalinganisha value hiyo na **8** (kitufe cha **START**); katika challenge hii, njia hiyo hukagua ikiwa code iliyoingizwa ni halali.
- Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3, na ikiwa value ni sawa, code fulani hutekelezwa.
- Katika hali nyingine zote, counter (`DAT_030000d4`) hukaguliwa na kuongezwa.\
Counter ikiwa chini ya 8, values za vitufe vilivyobonyezwa hukusanywa katika `DAT_030000d8`.

Kwa hiyo, katika challenge hii, kwa kujua values za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu wa chini ya 8 ambao jumla yake ni 0xf3.**

**Reference ya tutorial hii:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Kurahisisha MBA obfuscation kwa kutumia CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kudecode Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
