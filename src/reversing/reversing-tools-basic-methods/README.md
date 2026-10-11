# Zana za Reverse Engineering na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za Reverse Engineering za ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Utatuzi wa hitilafu kwenye Windows kernel

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasimbuaji wa Wasm / Wakusanyaji wa Wat

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) ili **decompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) ili **compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa decompilation.

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode iliyohifadhiwa kwenye cache ya Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Decompiler ya .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler ambayo **hufanya decompile na kuchunguza miundo mingi**, ikijumuisha **libraries** (.dll), **faili za metadata za Windows** (.winmd), na **executables** (.exe). Baada ya kufanya decompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwenye assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hurahisisha kuvinjari msimbo uliofanyiwa decompile, na kuifanya kuwa mojawapo ya zana bora kwa **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na mfumo mpana wa add-in na API inayoweza kupanua zana ili kukidhi mahitaji yako hasa, .NET Reflector huokoa muda na kurahisisha uundaji wa programu. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa mwonekano wa jinsi data inavyopita kwenye library au component
- Hutoa mwonekano wa utekelezaji na matumizi ya lugha na frameworks za .NET
- Hutafuta utendaji usioandikwa kwenye nyaraka na usiofichuliwa ili kupata manufaa zaidi kutoka kwa API na teknolojia zinazotumika.
- Hutafuta dependencies na assemblies mbalimbali
- Hufuatilia eneo halisi la makosa kwenye msimbo wako, components za wahusika wengine na libraries.
- Hufanya debug kwenye chanzo cha msimbo wote wa .NET unaoufanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ya ILSpy ya Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode; hakuna haja ya kupakua git. Bofya **Extensions** kisha **tafuta ILSpy**).\
Ikiwa unahitaji **kufanya decompile**, **kurekebisha** na **kucompile upya**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### Uwekaji wa kumbukumbu wa DNSpy

Ili kufanya **DNSpy irekodi taarifa fulani kwenye faili**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Ili kufanya debug ya code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **sifa za Assembly** zinazohusiana na **debugging**:

![Logging ya DNSpy - Debugging ya DNSpy: Kwanza, badilisha sifa za Assembly zinazohusiana na debugging](<../../images/image (973).png>)

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

Hili ni muhimu kwa sababu usipofanya hivi, wakati wa **runtime** msimbo utaboreshwa kwa **optimisations** kadhaa, na huenda **break-point isiwahi kufikiwa** wakati wa debugging au **baadhi ya variables zisiwepo**.

Kisha, ikiwa application yako ya .NET inaendeshwa na **IIS**, unaweza kuianzisha upya kwa kutumia:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na kwenye **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na kwenye Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuambatisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuambatisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_ kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules** kisha uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules kisha uchague Open All Modules](<../../images/image (922).png>)

Bofya-kulia module yoyote kwenye **Assembly Explorer** kisha ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya-kulia module yoyote kwenye Assembly Explorer kisha ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Kutumia IDA

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimama kila DLL inapopakiwa**. Hivyo, rundll32 itakapopakia DLL yako, utekelezaji utasimama.

Njia hii husimama kwenye matukio ya module kupakiwa, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye workflow ya x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya DLL na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ kisha uchague "**DLL Entry**".
- Kisha **anza utekelezaji**; debugger itasimama kwenye kila dll main, na wakati fulani **utasimama kwenye DLL Entry ya DLL yako**. Kutoka hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba utekelezaji unaposimama kwa sababu yoyote kwenye win64dbg, unaweza kuona **uko kwenye code gani** kwa kuangalia **juu ya dirisha la win64dbg**:

![Kutumia IDA - Kutumia x64dbg/x32dbg: Kumbuka kwamba utekelezaji unaposimama kwa sababu yoyote kwenye win64dbg, unaweza kuona uko kwenye code gani kwa kuangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki huthibitisha kwamba utekelezaji umesimama ndani ya DLL unayotaka kufanya debugging yake.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa kwenye memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/tool ya reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti inayotoa ufikiaji wa decompilers kadhaa. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executable ndogo.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kufanya debugging ya shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **memory address** yake, na kusitisha utekelezaji.\
Ambatisha debugger kama vile IDA au x64dbg, weka breakpoint kwenye address iliyochapishwa, kisha endeleza utekelezaji ili kufanya debugging ya shellcode.

Ukurasa wa releases github una zip zilizo na releases zilizocompile: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo la Blobrunner lililorekebishwa kidogo kwenye kiungo kifuatacho. Ili kulicompile, **tengeneza C/C++ project katika Visual Studio Code, nakili na ubandike code kisha uibuild**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kufanya debugging ya shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye infinite loop. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha ndani ya loop hiyo, kisha songa hadi kwenye call inayofuata inayohamisha utekelezaji kwenye shellcode iliyotengwa.

![Debugger ikiwa imesitishwa kwenye infinite loop ya jmp2it, kabla tu ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililocompile la [jmp2it kwenye ukurasa wa releases](https://github.com/adamkramer/jmp2it/releases/).

### Kufanya debugging ya shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuemulate shellcode na kuikagua dynamically.

Kumbuka kwamba Cutter hukuruhusu kuchagua "Open File" na "Open Shellcode". Kwa upande wangu, nilipofungua shellcode kama faili, iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya analysis wakati bytes zilezile zinafunguliwa kama faili au shellcode](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo na inaonekana Cutter itaanza emulation yenyewe kutoka hapo:

![Kuweka breakpoint kwenye shellcode entry unayotaka kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Cutter emulator ikiwa imesitishwa kwenye breakpoint ya shellcode iliyochaguliwa](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode iliyoemulate kwenye hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama vile **functions zipi** shellcode inatumia na ikiwa shellcode **inajidecode** yenyewe kwenye memory.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg pia huja na kizindua cha picha kinachokuwezesha kuchagua chaguo unazotaka na kutekeleza shellcode

![Kizindua cha picha cha scDbg cha kuchagua emulation ya shellcode na chaguo za kufuatilia](<../../images/image (258).png>)

Chaguo la **Create Dump** litadump shellcode ya mwisho ikiwa mabadiliko yoyote yatafanywa kwa shellcode moja kwa moja kwenye memory (ni muhimu kwa kupakua shellcode iliyodecodewa). **start offset** inaweza kuwa muhimu kwa kuanzisha shellcode kwenye offset mahususi. Chaguo la **Debug Shell** ni muhimu kwa kudebug shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona chaguo lolote kati ya yale yaliyoelezwa awali linafaa zaidi kwa hili, kwa kuwa utaweza kutumia Ida au x64dbg).

### Kutenganisha maagizo kwa kutumia CyberChef

Pakia faili yako ya shellcode kama ingizo na utumie recipe ifuatayo kuitenganisha: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Kuondoa obfuscation ya MBA

Obfuscation ya **Mixed Boolean-Arithmetic (MBA)** huficha expressions rahisi kama `x + y` nyuma ya fomula zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu katika **modular arithmetic yenye upana usiobadilika**, kwa hiyo carries na overflows ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya expression kwa kutumia zana za jumla za algebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantics za bit-width hazikuzingatiwa.<sup>[[1]](#references)</sup>

### Mchakato wa kazi wa vitendo

1. **Hifadhi bit-width ya awali** kutoka kwenye code/IR/decompiler output iliyoinuliwa (`8/16/32/64` bits).
2. **Ainisha expression** kabla ya kujaribu kurahisisha:
   - **Linear**: jumla zenye uzani za bitwise atoms
   - **Semilinear**: linear pamoja na constant masks kama `x & 0xFF`
   - **Polynomial**: bidhaa zinaonekana
   - **Mixed**: bidhaa na bitwise logic zimechanganyika, mara nyingi zikiwa na subexpressions zinazorudiwa
3. **Thibitisha kila rewrite inayowezekana** kwa kutumia random testing au SMT proof. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi expression ya awali badala ya kubahatisha.

### Bypass control flow iliyosawazishwa kwa kutumia execution slice finyu

Mara nyingi si lazima kurejesha control-flow graph nzima. Ukiwa na control-flow flattening, opaque predicates, dispatchers kubwa, au code yenye MBA nyingi, fuatilia references kutoka kwenye encrypted blobs na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha rudia data-flow slice hiyo pekee, au iendeshe kivyake; dispatcher haihitajiki kwenye suluhisho ikiwa state husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mchakato wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha executable na data sections, relocations, na cross-references. Dump candidate tables kutoka `.rodata` huku ukihifadhi mpangilio wa bytes na upana wa kila element.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, tables inazorejelea, imported calls, na global state inayohitajika.
3. Inua operations hizo pekee kwenye fixed-width Python model. Ikiwa slice bado inategemea state nyingi sana, ita routine hiyo kwa kutumia Unicorn, QEMU, au debugger na hook imports zisizohusika badala ya kuiga program nzima.
4. Thibitisha kwamba extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa silent fallbacks, itafute majibu yaliyopachikwa ndani yake, na iendeshe kwenye builds ambazo haijawahi kuona zenye strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za hatua ya kwanza ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua misemo ya MBA iliyofichwa kama thamani zisizobadilika

Usemi wa byte unaoonekana kutegemea ingizo unaweza kufuta kabisa ingizo lake. Baada ya kutoa jedwali zake, tathmini usemi huo katika kikoa kizima cha biti 8; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo ni thabiti bila kurejesha state machine inayoizunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu addition ya awali huzunguka kwenye upana wa byte. Kwa domain pana zaidi, iulize SMT solver ikiwa `f(x1) != f(x2)` inaridhishika kwa inputs mbili za symbolic zenye upana sawa: `unsat` huthibitisha invariance, ilhali `sat` hutoa counterexample na kumaanisha kuwa input haiwezi kutupiliwa mbali.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis si lazima usababishe branch au crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye bit ya key, constant ya opaque predicate, au state ya flattened-dispatcher, kuendelea kawaida, na kutoa plaintext inayokubalika lakini si sahihi kwenye emulator. Kwa hiyo, kupatch failure branches zinazoonekana pekee hakutoshi; fuatilia data dependencies kutoka environment probes hadi decoder state, linganisha slice ileile kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier inayofaa kwa malware analysis na reversing ya protected binaries. Huainisha expression na kuielekeza kwenye pipeline maalumu badala ya kutumia rewrite pass moja ya jumla kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini usemi kwa ingizo za Boolean, hupata signature, na huendesha kwa wakati mmoja mbinu kadhaa za urejeshaji kama vile pattern matching, ubadilishaji wa ANF, na coefficient interpolation.
- **Semilinear MBA**: atoms zilizofichwa kwa constants hujengwa upya kwa kutumia bit-partitioned reconstruction ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: bidhaa hugawanywa katika cores na subexpressions zinazojirudia zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa mixed identity ambayo mara nyingi inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hii inaweza kurahisishwa kuwa:

```c
x * y
```

### Vidokezo vya reversing

- Pendelea kuendesha CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga computation halisi.
- Tumia `--bitwidth` moja kwa moja ikiwa expression ilitokana na masked arithmetic au narrow registers.
- Ikiwa unahitaji hatua ya uthibitisho iliyo imara zaidi, angalia dokezo za Z3 hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inapatikana kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kunormalize LLVM IR yenye MBA nyingi kabla ya kuendesha analysis passes nyingine.
- Residuals mchanganyiko wa domains zinazotegemea carry na ambazo hazitumiki zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression asili na kuchanganua carry path mwenyewe.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa instruction sequences zinazotumia `mov`, na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation kwenye matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na pia [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, workaround hii ya kupata flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa kutumia `::main` kama ilivyo hapa:

![Kupata entry point ya Rust katika Ghidra kwa kutafuta majina ya functions yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni dhahiri kabisa kuwa hii ndiyo main function inayovutia.\
Kwa kuwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **inputs** na **outputs** zake.

### Kurejesha strings za Rust kutoka firmware ya ELF

Katika binaries za **Rust ELF**, strings nyingi tuli hazirejelewi kama pointers za mtindo wa C zinazotamatishwa na NUL. Mpangilio wa kawaida wa `rustc` ni **pointer/length tuple** ndani ya **`.data.rel.ro`** inayoelekeza kwenye string blob halisi iliyohifadhiwa ndani ya **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Hii inamaanisha kuwa `strings` au uchanganuzi chaguomsingi wa Ghidra unaweza kuunganisha strings zilizo karibu au kukosa kabisa marejeleo mtambuko.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa kielekezi cha mfuatano kinachowezekana.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya uhalali (kwa mfano, weka urefu kati ya **4** na **100** baiti).
6. Soma baiti `length` pekee kutoka `.rodata` badala ya kuchanganua hadi `0x00`.

Mantiki ya chini kabisa ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hii ni muhimu hasa katika firmware reversing kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, majina ya RPC, ujumbe wa log, assertions, majina ya faili, config keys, command handlers, na logic inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda string data kwenye offsets za `.rodata` zilizorejelewa. Zana za `rust-strings` na `RustStrings.py` zilizochapishwa na Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hili ili litumike na **ukubwa mwingine wa word, endianness, na mipangilio ya section**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizokompailiwa na Delphi unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kureverse binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itaendesha binary na kutatua majina ya functions dynamically mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9) na breakpoint itasita mwanzoni mwa code halisi.

Ukibonyeza kitufe kwenye programu ya picha, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Ikiwa unahitaji kureverse binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya functions.

## Compiled Python

Katika ukurasa huu unaweza kupata maelekezo ya kupata code ya python kutoka kwa binary iliyokompailiwa ya python ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali ku **emulate** na **debug** mchezo huo:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Unapobonyezwa, kila **key ina thamani** ya kuitambua:

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

Kwa hiyo, katika aina hii ya program, sehemu ya kuvutia itakuwa **jinsi program inavyoshughulikia ingizo la mtumiaji**. Kwenye anwani **0x4000130** utapata function inayopatikana mara nyingi: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA unaorejelea KEYINPUT kwenye anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kuwa function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Kwenye function hiyo, baada ya baadhi ya shughuli za init (zisizo na umuhimu wowote):

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

If ya mwisho inakagua kama **`uVar4`** iko kwenye **Keys za mwisho** na si ufunguo wa sasa; hii pia huitwa kuachia kitufe (ufunguo wa sasa huhifadhiwa kwenye **`uVar1`**).

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

Katika msimbo uliotangulia, unaweza kuona kwamba tunalinganisha **uVar1** (mahali palipo na **thamani ya kitufe kilichobonyezwa**) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto hii, kitufe hiki husafisha skrini.
- Kisha thamani inalinganishwa na **8** (kitufe cha **START**); katika changamoto hii, njia hiyo hukagua kama msimbo ulioingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3, na ikiwa thamani zinafanana, msimbo fulani hutekelezwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Kaunta ikiwa chini ya 8, thamani za vitufe vilivyobonyezwa hujumlishwa katika `DAT_030000d8`.

Kwa hiyo, katika changamoto hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu chini ya 8 ambao jumla yake ni 0xf3.**

**Marejeo ya mafunzo haya:** [maelezo ya changamoto ya Nostalgia yaliyohifadhiwa](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Kurahisisha MBA obfuscation kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hifadhi ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kuchambua strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering inayosaidiwa na AI, au angalau kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
