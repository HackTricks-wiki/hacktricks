# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za reversing zinazotumia ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) **kudecompile** kutoka wasm (binary) hadi wat (clear text)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) **kucompile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa ajili ya decompilation.

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler inayofanya **decompile na kuchunguza formats mbalimbali**, zikiwemo **libraries** (.dll), **Windows metadata file**s (.winmd), na **executables** (.exe). Baada ya kufanyiwa decompile, assembly inaweza kuhifadhiwa kama Visual Studio project (.csproj).

Faida hapa ni kwamba ikiwa source code iliyopotea inahitaji kurejeshwa kutoka kwenye legacy assembly, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa navigation rahisi katika code iliyofanyiwa decompile, na kuifanya kuwa mojawapo ya zana bora kwa **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na add-in model pana na API inayopanua zana ili kukidhi mahitaji yako halisi, .NET Reflector huokoa muda na kurahisisha development. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa ufahamu kuhusu jinsi data inavyopita kupitia library au component
- Hutoa ufahamu kuhusu implementation na matumizi ya lugha na frameworks za .NET
- Hupata functionality isiyoandikwa kwenye documentation na isiyowekwa wazi ili kupata zaidi kutoka kwenye APIs na technologies zinazotumika.
- Hupata dependencies na assemblies mbalimbali
- Hufuatilia eneo kamili la errors katika code yako, third-party components, na libraries.
- Hufanya debugging hadi kwenye source ya code yote ya .NET unayofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuwa nayo kwenye OS yoyote (unaweza kuiinstall moja kwa moja kutoka VSCode, bila kuhitaji kudownload git. Bofya kwenye **Extensions** na **search ILSpy**).\
Ikiwa unahitaji **kudecompile**, **kurekebisha** na **kucompile tena** unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayotunzwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### DNSpy Logging

Ili kufanya **DNSpy iandike baadhi ya taarifa kwenye file**, unaweza kutumia snippet hii:
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
Na ubofye **compile**:

![DNSpy Logging - DNSpy Debugging: Na ubofye compile](<../../images/image (314) (1).png>)

Kisha hifadhi faili jipya kupitia _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Kisha hifadhi faili jipya kupitia File Save module](<../../images/image (602).png>)

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** **optimisations** kadhaa zitatumika kwenye code na huenda wakati wa debugging **break-point is never hit** au baadhi ya **variables don't exist**.

Kisha, ikiwa application yako ya .NET **run** inafanywa na **IIS**, unaweza kuiwasha upya kwa:
```
iisreset /noforce
```
Kisha, ili kuanza debugging unapaswa kufunga mafaili yote yaliyofunguliwa na ndani ya **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging unapaswa kufunga mafaili yote yaliyofunguliwa na ndani ya Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili ku-attach kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili ku-attach kwenye IIS server na ubofye attach](<../../images/image (113).png>)

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

### Kutumia IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Chagua **Windbg** debugger
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Weka **parameters** za execution kwa kuweka **path to the DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Weka parameters za execution kwa kuweka path to the DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **execution itasimamishwa kila DLL inapopakiwa**, hivyo rundll32 inapopakia DLL yako execution itasimamishwa.

Njia hii husimama kwenye matukio ya module-load, lakini kufikia entry point ya DLL iliyopakiwa si ya moja kwa moja kama ilivyo kwenye x64dbg workflow iliyo hapa chini.

### Kutumia x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza execution**, debugger itasimama kwenye kila dll main; wakati fulani **itasimama kwenye dll Entry ya dll yako**. Kutoka hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba execution inaposimamishwa kwa sababu yoyote katika win64dbg, unaweza kuona **uko kwenye code gani** kwa kuangalia **juu ya win64dbg window**:

![Using IDA - Kutumia x64dbg/x32dbg: Kumbuka kwamba execution inaposimamishwa kwa sababu yoyote katika win64dbg, unaweza kuona uko kwenye code gani kwa kuangalia juu ya win64dbg window](<../../images/image (842).png>)

Kiashiria hiki huthibitisha execution inaposimamishwa ndani ya DLL unayotaka kufanya debugging.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni program muhimu ya kutafuta mahali ambapo values muhimu zimehifadhiwa ndani ya memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi katika:


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

### Kufanya debugging ya shellcode kwa blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hu-allocate **shellcode**, huchapisha **memory address** yake, na husitisha execution.\
Attach debugger kama IDA au x64dbg, weka breakpoint kwenye address iliyochapishwa, kisha endeleza execution ili kufanya debugging ya shellcode.

Github page ya releases ina zips zenye releases zilizocompile: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililorekebishwa kidogo la Blobrunner kwenye link ifuatayo. Ili kuicompile, **tengeneza C/C++ project katika Visual Studio Code, copy na paste code hiyo, kisha i-build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kufanya debugging ya shellcode kwa jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hu-allocate shellcode na kuingia kwenye infinite loop. Attach debugger, endeleza execution kwa **sekunde 2–5**, isimamishe ndani ya loop hiyo, kisha songa hadi kwenye call inayofuata inayohamisha execution kwenda kwenye shellcode iliyotengwa.

![Debugger ikiwa imesimamishwa kwenye infinite loop ya jmp2it mara moja kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililocompile la [jmp2it kwenye releases page](https://github.com/adamkramer/jmp2it/releases/).

### Kufanya debugging ya shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia cutter unaweza ku-emulate shellcode na kuichunguza dynamically.

Kumbuka kwamba Cutter inaruhusu "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama file ili-decompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya analysis wakati bytes zilezile zinapofunguliwa kama file au shellcode](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo; inaonekana cutter itaanza emulation automatically kutoka hapo:

![Kuweka breakpoint kwenye shellcode entry inayotakiwa kabla ya kuanza Cutter emulation](<../../images/image (589).png>)

![Cutter emulator ikiwa imesimamishwa kwenye shellcode breakpoint iliyochaguliwa](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode iliyo-emulate kwenye Cutter's hex dump](<../../images/image (186).png>)

### Ku-deobfuscate shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama **ni functions zipi** shellcode inatumia na ikiwa shellcode **inajidecode** yenyewe kwenye memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg pia ina graphical launcher ambapo unaweza kuchagua options unazotaka na kutekeleza shellcode

![graphical launcher ya scDbg ya kuchagua options za shellcode emulation na tracing](<../../images/image (258).png>)

Option ya **Create Dump** ita-dump shellcode ya mwisho ikiwa mabadiliko yoyote yamefanywa kwenye shellcode kwa dynamically kwenye memory (ni muhimu kwa kupakua shellcode iliyodecode). **start offset** inaweza kuwa muhimu kuanzisha shellcode kwenye offset maalum. Option ya **Debug Shell** ni muhimu kwa ku-debug shellcode kwa kutumia terminal ya scDbg (hata hivyo, ninaona options zozote zilizoelezwa hapo awali kuwa bora zaidi kwa jambo hili kwa sababu utaweza kutumia Ida au x64dbg).

### Disassembling kwa kutumia CyberChef

Upload faili yako ya shellcode kama input na utumie recipe ifuatayo ku-decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Uondoaji wa MBA obfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama vile `x + y` nyuma ya formulas zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, hivyo carries na overflows ni muhimu:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ukirahisisha aina hii ya expression kwa kutumia generic algebra tooling, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantics za bit-width zilipuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi bit-width ya awali** kutoka kwenye lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Panga expression katika kundi** kabla ya kujaribu kuirahisisha:
- **Linear**: weighted sums za bitwise atoms
- **Semilinear**: linear pamoja na constant masks kama `x & 0xFF`
- **Polynomial**: products zinatokea
- **Mixed**: products na bitwise logic zimechanganywa, mara nyingi zikiwa na repeated subexpressions
3. **Thibitisha kila rewrite inayowezekana** kwa random testing au SMT proof. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi expression ya awali badala ya kukisia.

### Bypass flattened control flow kwa kutumia narrow execution slice

Kurejesha control-flow graph kamili mara nyingi si lazima. Kwa control-flow flattening, opaque predicates, large dispatchers, au code yenye MBA nyingi, fuata references kutoka kwenye encrypted blobs na output buffers hadi kwenye routine ndogo inayozibadilisha. Kisha tengeneza upya data-flow slice hiyo pekee, au i-execute kwa kujitegemea; dispatcher si sehemu ya suluhisho linalohitajika ikiwa state husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha executable na data sections, relocations, na cross-references. Dump candidate tables kutoka `.rodata` huku ukihifadhi byte order na element width zake.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, tables zinazorejelewa, imported calls, na global state inayohitajika.
3. Lift operations hizo pekee ziingie kwenye fixed-width Python model. Ikiwa slice bado inategemea state nyingi, invoke routine hiyo chini ya Unicorn, QEMU, au debugger na hook irrelevant imports badala ya ku-emulate program nzima.
4. Thibitisha kwamba extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa silent fallbacks, itafute kwa embedded answers, na iendeshe dhidi ya builds ambazo haijawahi kuona zikiwa na strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Commands muhimu za first-pass ni:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Tambua MBA expressions zilizojificha kama constants

Expression ya byte inayoonekana kutegemea input inaweza kufuta input yake kabisa. Baada ya kutoa tables zake, evaluate expression hiyo katika domain kamili ya 8-bit; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo ni constant bila kurejesha state machine inayohusika.<sup>[[7]](#references)</sup>
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
Weka mask ya mwisho kwa sababu addition ya awali ina byte-width wraparound. Kwa domain pana zaidi, muulize SMT solver kama `f(x1) != f(x2)` inaweza kutimizwa kwa inputs mbili za symbolic zenye width sawa: `unsat` inathibitisha invariance, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kuondolewa.<sup>[[7]](#references)</sup>

#### Tambua decoding inayofungamana na mazingira

Anti-analysis checks si lazima ziwe na branch au zisababishe crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye key bit, constant ya opaque-predicate, au hali ya flattened-dispatcher, ikaendelea kawaida, na kutoa plaintext inayoonekana sahihi lakini ya uongo kwenye emulator. Kwa hivyo, ku-patch failure branches zinazoonekana pekee hakutoshi; fuatilia data dependencies kutoka environment probes hadi decoder state, linganisha slice hiyo hiyo kwenye authentic device na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa malware analysis na protected-binary reversing. Huainisha expression na kuipitisha kwenye specialized pipelines badala ya kutumia generic rewrite pass moja kwa kila kitu.<sup>[[2]](#references)</sup>

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
Matukio muhimu:

- **Linear MBA**: CoBRA hutathmini expression kwenye inputs za Boolean, hutengeneza signature, na huendesha kwa wakati mmoja mbinu kadhaa za recovery kama vile pattern matching, ANF conversion, na coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms hujengwa upya kwa kutumia bit-partitioned reconstruction ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa katika cores, na repeated subexpressions zinaweza kuinuliwa kuwa temporaries kabla ya kurahisisha outer relation.

Mfano wa mixed identity ambayo kwa kawaida inafaa kujaribu kuirecover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Hili linaweza kurahisishwa kuwa:
```c
x * y
```
### Maelezo ya Reversing

- Pendelea kutumia CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga computation halisi.
- Tumia `--bitwidth` waziwazi wakati expression ilitokana na masked arithmetic au registers zenye upana mdogo.
- Ikiwa unahitaji hatua thabiti zaidi ya proof, angalia maelezo ya Z3 ya hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia huja kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kunormalize LLVM IR yenye MBA nyingi kabla ya analysis passes za baadaye.
- Unsupported carry-sensitive mixed-domain residuals zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression ya awali na kufikiri kuhusu carry path manually.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za program kuwa instruction sequences zinazotegemea `mov`, na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazoungwa mkono, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kufanya deobfuscate ya matokeo. Ina dependencies kadhaa.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Na [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, mbinu hii ya muda ya kutafuta flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa `::main` kama ilivyo kwenye:

![Kupata Rust entry point katika Ghidra kwa kutafuta majina ya functions kwa main yenye double-colon](<../../images/image (1080).png>)

Katika hali hii binary iliitwa authenticator, kwa hiyo ni dhahiri kwamba hii ndiyo main function inayovutia.\
Ukitambua **name** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **inputs** na **outputs** zake.

### Kurejesha Rust strings kutoka ELF firmware

Katika binary za **Rust ELF**, static strings nyingi hazirejelewi kama pointers za C-style zenye NUL termination. Mpangilio wa kawaida wa `rustc` ni **tuple ya pointer/length** ndani ya **`.data.rel.ro`**, inayoelekeza kwenye string blob halisi iliyohifadhiwa katika **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Hii inamaanisha kuwa `strings` au uchanganuzi chaguomsingi wa Ghidra unaweza kuunganisha strings zilizo karibu au kukosa kabisa marejeleo mtambuka.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kama pointer ya string candidate.
4. Chukulia neno linalofuata kuwa urefu candidate.
5. Tumia vichujio vya uthibitishaji (kwa mfano, hifadhi urefu kati ya **4** na **100** bytes).
6. Soma bytes `length` hasa kutoka `.rodata` badala ya kuendelea kusoma hadi `0x00`.

Mantiki ya msingi ya extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Hii ni muhimu sana katika firmware reversing kwa sababu Rust strings zilizorejeshwa mara nyingi hufichua **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, na auth-related logic**.

Ikiwa Ghidra haitambui strings hizo, endesha custom script/plugin inayotumia heuristic hiyo hiyo na kuunda string data kwenye `.rodata` offsets zilizoonyeshwa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hili kwa **word sizes, endianness, na section layouts** tofauti.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa Delphi compiled binaries unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kufanya reverse ya Delphi binary, ninapendekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague plugin file.

Plugin hii ita-execute binary na kutatua function names dynamically mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), kisha breakpoint itafikiwa mwanzoni mwa real code.

Ukibonyeza kitufe katika graphical application, debugger inaweza kusimama kwenye function iliyoalikwa na kitufe hicho.

## Golang

Ikiwa unahitaji kufanya reverse ya Golang binary, ninapendekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague plugin file.

Hii itatatua majina ya functions.

## Compiled Python

Katika ukurasa huu unaweza kupata jinsi ya kupata Python code kutoka kwenye ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA unaweza kutumia zana mbalimbali ku-**emulate** na ku-**debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua debug version_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **buttons** za Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Inapobonyezwa, kila **key ina value** ya kuitambulisha:
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
Kwa hiyo, katika aina hii ya programu, sehemu muhimu itakuwa **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Katika anwani **0x4000130** utapata function inayopatikana kwa kawaida: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA inayorejelea KEYINPUT katika anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya operesheni kadhaa za init (zisizo na umuhimu):
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
Imepatikana code hii:
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
If ya mwisho inaangalia ikiwa **`uVar4`** iko kwenye **last Keys** na si key ya sasa, pia huitwa kuachilia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).
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
Katika code ya awali unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **value ya button iliyobonyezwa** ipo) na values fulani:

- Kwanza, inalinganishwa na **value 4** (button ya **SELECT**): Katika challenge, button hii husafisha screen
- Kisha inalinganisha value hiyo na **8** (button ya **START**); katika challenge hii, njia hiyo hukagua ikiwa code iliyoingizwa ni valid.
- Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3, na ikiwa value ni sawa, code fulani hutekelezwa.
- Katika kila hali nyingine, counter (`DAT_030000d4`) hukaguliwa na kuongezwa.\
Wakati counter iko chini ya 8, values za keys zilizobonyezwa hukusanywa katika `DAT_030000d8`.

Kwa hiyo, katika challenge hii, ukijua values za buttons, ulihitaji **kubonyeza combination yenye urefu wa chini ya 8 ambayo jumla yake ni 0xf3.**

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
- [6] [Nostalgia - GBA reversing tutorial (iliyohifadhiwa)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering Inayosaidiwa na AI, au Angalau Kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
