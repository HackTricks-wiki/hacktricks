# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za reversing zinazotumia ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows kernel debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kufanya **decompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kufanya **compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa ajili ya decompilation.

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 bytecode iliyohifadhiwa kwenye cache

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads zilizovirtualishwa na VM maalum

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler inayofanya **decompile na kuchunguza miundo mingi**, ikijumuisha **libraries** (.dll), **faili za metadata za Windows** (.winmd), na **executables** (.exe). Baada ya kufanyiwa decompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwenye assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa urambazaji rahisi katika msimbo uliofanyiwa decompile, na hivyo kuifanya kuwa mojawapo ya zana bora za **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na modeli pana ya add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha uendelezaji. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa ufahamu kuhusu mtiririko wa data ndani ya library au component
- Hutoa ufahamu kuhusu utekelezaji na matumizi ya lugha na frameworks za .NET
- Hupata utendaji usioandikwa kwenye nyaraka na ambao haujawekwa wazi, ili uweze kunufaika zaidi na API na teknolojia zinazotumika.
- Hupata dependencies na assemblies tofauti
- Hufuatilia eneo halisi la makosa kwenye msimbo wako, components za wahusika wengine, na libraries.
- Hufanya debug ndani ya chanzo cha msimbo wote wa .NET unaofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bofya **Extensions** kisha **tafuta ILSpy**).\
Ikiwa unahitaji kufanya **decompile**, **modify** na **compile tena**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### DNSpy Logging

Ili kufanya **DNSpy iandike taarifa fulani kwenye faili ya log**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Ili kutatua hitilafu za code kwa kutumia DNSpy, unahitaji:

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Kisha hifadhi faili jipya kupitia _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** marekebisho kadhaa ya **optimisations** yatatumika kwenye msimbo, na huenda wakati wa debugging **break-point is never hit** au **variables don't exist**.

Kisha, ikiwa programu yako ya .NET **inaendeshwa** na **IIS**, unaweza **kuianzisha upya** kwa kutumia:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na ndani ya Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuambatisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuambatisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote kwenye **Assembly Explorer** kisha ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote kwenye Assembly Explorer kisha ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Kutumia IDA

- **Pakia rundll32** (64-bit iko kwenye C:\Windows\System32\rundll32.exe na 32-bit iko kwenye C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimama kila DLL inapopakiwa**. Kwa hiyo, rundll32 itakapopakia DLL yako, utekelezaji utasimama.

Njia hii husimamisha utekelezaji kwenye matukio ya kupakia module, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye workflow ya x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Pakia rundll32** (64-bit iko kwenye C:\Windows\System32\rundll32.exe na 32-bit iko kwenye C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**; debugger itasimama kwenye kila dll main. Wakati fulani **utasimama kwenye DLL Entry ya dll yako**. Kuanzia hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kuwa utekelezaji ukisimama kwa sababu yoyote kwenye win64dbg, unaweza kuona **uko kwenye code gani** kwa kuangalia **juu ya dirisha la win64dbg**:

![Kutumia IDA - Kutumia x64dbg/x32dbg: Kumbuka kuwa utekelezaji ukisimama kwa sababu yoyote kwenye win64dbg, unaweza kuona uko kwenye code gani kwa kuangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha kuwa utekelezaji umesimama ndani ya DLL unayotaka kufanya debugging yake.

## Programu za GUI / Michezo ya video

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali thamani muhimu zimehifadhiwa ndani ya memory ya mchezo unaoendeshwa na kuzibadilisha. Maelezo zaidi kwenye:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni zana ya front-end/reverse engineering ya GNU Project Debugger (GDB), inayolenga michezo. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti inayotoa ufikiaji wa decompilers mbalimbali. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kufanya debugging ya shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **memory address** yake, na kusitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye address iliyochapishwa, kisha endeleza utekelezaji ili kufanya debugging ya shellcode.

Ukurasa wa GitHub releases una zip zenye releases zilizocompiliwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililorekebishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kulicompile, **unda C/C++ project kwenye Visual Studio Code, nakili na ubandike code, kisha uijenge**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kufanya debugging ya shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) ni sawa na BlobRunner. Hutenga shellcode na kuingia kwenye infinite loop. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha ndani ya loop hiyo, kisha songa hadi call inayofuata inayohamishia utekelezaji kwenye shellcode iliyotengwa.

![Debugger ikiwa imesitishwa ndani ya infinite loop ya jmp2it, kabla tu ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililocompiliwa la [jmp2it kwenye ukurasa wa releases](https://github.com/adamkramer/jmp2it/releases/).

### Kufanya debugging ya shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuiga utekelezaji wa shellcode na kuikagua inapotekelezwa.

Kumbuka kuwa Cutter hukuruhusu kuchagua "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama faili, iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi wa bytes zilezile zilipofunguliwa kama faili au shellcode](<../../images/image (562).png>)

Ili kuanza emulation kwenye sehemu unayotaka, weka bp hapo; inaonekana Cutter itaanza emulation moja kwa moja kutoka hapo:

![Kuweka breakpoint kwenye entry point inayotakiwa ya shellcode kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Emulator ya Cutter ikiwa imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode inayoigwa ndani ya hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama **functions zipi** shellcode inatumia na kama shellcode **inajidecode** kwenye memory.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg pia ina launcher ya picha inayokuwezesha kuchagua chaguo unazotaka na kutekeleza shellcode

![Launcher ya picha ya scDbg kwa kuchagua chaguo za emulation na tracing za shellcode](<../../images/image (258).png>)

Chaguo la **Create Dump** litahifadhi shellcode ya mwisho ikiwa mabadiliko yoyote yamefanywa kwenye shellcode moja kwa moja kwenye memory (ni muhimu kwa kupakua shellcode iliyofichuliwa). **start offset** inaweza kuwa muhimu kwa kuanzisha shellcode kwenye offset maalum. Chaguo la **Debug Shell** ni muhimu kwa kutatua hitilafu za shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona chaguo lolote kati ya yale yaliyoelezwa awali linafaa zaidi kwa hili, kwa kuwa utaweza kutumia Ida au x64dbg).

### Kutenganisha kwa kutumia CyberChef

Pakia faili yako ya shellcode kama input na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama `x + y` nyuma ya fomula zinazochanganya operators za arithmetic (`+`, `-`, `*`) na bitwise (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, kwa hiyo carries na overflows ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya kauli kwa kutumia zana za jumla za aljebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za upana wa biti zilipuuzwa.<sup>[[1]](#references)</sup>

### Utaratibu wa vitendo

1. **Hifadhi upana wa biti asilia** kutoka kwenye code/IR iliyoinuliwa au matokeo ya decompiler (`8/16/32/64` biti).
2. **Panga kauli katika aina** kabla ya kujaribu kuirahisisha:
   - **Linear**: jumla zenye uzani za vipengele vya bitwise
   - **Semilinear**: kauli za linear pamoja na masks zisizobadilika kama `x & 0xFF`
   - **Polynomial**: kuna bidhaa
   - **Mixed**: bidhaa na mantiki ya bitwise zimechanganywa, mara nyingi zikiwa na subexpressions zinazorudiwa
3. **Thibitisha kila rewrite inayowezekana** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi kauli asilia badala ya kubahatisha.

### Bypass control flow iliyoflatteniwa kwa kutumia execution slice finyu

Mara nyingi si lazima kurejesha control-flow graph nzima. Katika hali za control-flow flattening, opaque predicates, dispatchers kubwa, au code yenye MBA nyingi, fuata marejeo kutoka kwenye blobs zilizosimbwa na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha rudia data-flow slice hiyo pekee, au iendeshe kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa state husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Utaratibu wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha executable na data sections, relocations, na cross-references. Dump jedwali zinazowezekana kutoka `.rodata` huku ukihifadhi mpangilio wake wa bytes na upana wa elementi.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, jedwali inazorejelea, imported calls, na global state inayohitajika.
3. Lift operations hizo pekee kwenye modeli ya Python yenye upana usiobadilika. Ikiwa slice bado inategemea state nyingi mno, endesha routine hiyo kwa kutumia Unicorn, QEMU, au debugger, na hook imports zisizohusika badala ya ku-emulate programu nzima.
4. Thibitisha kuwa extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa fallback zisizoonekana, itafute majibu yaliyopachikwa, na iendeshe dhidi ya builds ambazo haijawahi kuona, zikiwa na strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za awali ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Gundua misemo ya MBA iliyojificha kama constants

Usemi wa byte unaoonekana kutegemea ingizo unaweza kufuta kabisa athari ya ingizo hilo. Baada ya kutoa majedwali yake, tathmini usemi katika eneo lote la biti 8; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo ni constant bila kuhitaji kurejesha state machine inayoizunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu addition ya awali huzunguka inapofikia upana wa byte. Kwa domain pana zaidi, iulize SMT solver ikiwa `f(x1) != f(x2)` inaweza kuridhishwa kwa symbolic inputs mbili zenye upana sawa: `unsat` huthibitisha invariance, ilhali `sat` hutoa counterexample na kumaanisha kuwa input haiwezi kutupwa.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis si lazima usababishe branch au crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye key bit, constant ya opaque-predicate, au hali ya flattened-dispatcher, kuendelea kawaida, na kutoa plaintext inayoonekana kuaminika lakini isiyo sahihi ndani ya emulator. Kwa hiyo, kupatch failure branches zinazoonekana pekee hakutoshi; fuatilia data dependencies kutoka kwa environment probes hadi kwenye hali ya decoder, linganisha slice hiyo hiyo kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa ajili ya malware analysis na reversing ya protected-binary. Huainisha expression na kuielekeza kupitia pipelines maalum badala ya kutumia generic rewrite pass moja kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini expression kwa pembejeo za Boolean, hupata signature, na huendesha kwa wakati mmoja mbinu kadhaa za recovery kama pattern matching, ANF conversion, na coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms hujengwa upya kwa bit-partitioned reconstruction ili maeneo yaliyofunikwa na mask yabaki sahihi.
- **Polynomial/Mixed MBA**: bidhaa hugawanywa katika cores, na subexpressions zinazojirudia zinaweza kuinuliwa kuwa temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa mixed identity ambayo kwa kawaida inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hili linaweza kurahisishwa kuwa:

```c
x * y
```

### Vidokezo vya reversing

- Pendelea kuendesha CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga hesabu mahususi.
- Tumia `--bitwidth` waziwazi ikiwa expression imetokana na masked arithmetic au narrow registers.
- Ikiwa unahitaji hatua ya uthibitisho imara zaidi, angalia maelezo ya Z3 ya hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia huja kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kurekebisha LLVM IR yenye MBA nyingi kabla ya passes nyingine za uchanganuzi.
- Residuals za mixed-domain zisizotumika ambazo zinategemea carry zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression asilia na kuchanganua carry path kwa mkono.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa mfuatano wa instructions zinazotumia `mov`, na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation kwenye matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unashiriki kwenye **CTF, njia hii ya muda ya kupata flag** inaweza kuwa na manufaa sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta vitendaji kwa kutumia `::main` kama ilivyo hapa:

![Kupata entry point ya Rust katika Ghidra kwa kutafuta majina ya vitendaji yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii binary iliitwa authenticator, kwa hiyo ni wazi kabisa kwamba hiki ndicho kitendaji kikuu kinachovutia.\
Ukiwa na **majina** ya **vitendaji** vinavyoitwa, vitafute kwenye **Internet** ili kujifunza kuhusu **inputs** na **outputs** zake.

### Kurejesha strings za Rust kutoka kwenye firmware ya ELF

Katika binary za **Rust ELF**, strings nyingi tuli hazirejelewi kwa kutumia pointers zinazotamatishwa na NUL kama ilivyo katika C. Mpangilio wa kawaida wa `rustc` ni **tuple ya pointer/urefu** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa kwenye **`.rodata`**:

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
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer inayoweza kuelekeza kwenye string.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya busara (kwa mfano, hifadhi urefu kati ya **4** na **100** byte).
6. Soma byte `length` haswa kutoka `.rodata` badala ya kusoma hadi `0x00`.

Mantiki ndogo ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hili lina manufaa hasa katika kufanya reverse engineering ya firmware, kwa sababu string za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, majina ya RPC, ujumbe wa log, assertions, majina ya faili, config keys, command handlers na mantiki inayohusiana na auth**.

Ghidra ikikosa string hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda data ya string kwenye offsets za `.rodata` zilizorejelewa. Zana za `rust-strings` na `RustStrings.py` zilizochapishwa na Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hilo ili litumike kwa **ukubwa tofauti wa word, endianness na mpangilio wa sehemu**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizocompiliwa za Delphi, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kufanya reverse engineering ya binary ya Delphi, ningependekeza utumie plugin ya IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia plugin ya Python, kisha uchague faili ya plugin.

Plugin hii itaendesha binary na kutatua majina ya functions kwa njia ya dinamiki wakati debugging inaanza. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itasimama mwanzoni mwa code halisi.

Ukibonyeza kitufe kwenye programu ya picha, debugger inaweza kusimama kwenye function inayoitwa na kitufe hicho.

## Golang

Kwa binaries za kawaida za Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya functions katika IDA. Pakia plugin yake ya Python kwa **Alt+F7**.

### Rejesha metadata bila symbol table

Executable ya Go iliyo-stripped bado inahitaji runtime metadata ili kuoanisha program counters na functions. [GoReSym](https://github.com/mandiant/GoReSym) hutafuta na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya functions, majina, source paths, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikiwa bado inaweza kutumika huku ikibadilisha majina yaliyorejeshwa. Garble, kwa mfano, hutengeneza hash za identifiers na package paths na kuondoa taarifa za build, module na debug.<sup>[[12]](#references)</sup> Token ya package iliyofichwa lazima ibaki ileile katika functions zote za package hiyo. Panga functions kwa token inayojirudia, bainisha package moja kwa kutumia callees, strings na APIs zake, kisha tumia lebo hiyo ya package kwa kundi zima.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huunganisha uchimbaji wa runtime symbols na utengenezaji wa marejeo safi pamoja na ulinganishaji wa control-flow graph (CFG). Tumia mfuatano huu:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator imeziondoa, linganisha sehemu za Go runtime iliyojumuishwa na reference runtimes za matoleo mbalimbali. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Chukulia hili kama uboreshaji uliothibitishwa kwa majaribio, si kizingiti cha jumla.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeo yanayolingana.** Tengeneza binaries safi kwa toleo la Go lililotambuliwa, target architecture na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazotokana na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama sanifu kutoka `0.0` hadi `1.0`. Ulinganishaji wake wa basic blocks unategemea ulinganisho wenye uzani wa instructions zinazofanana. Matches zenye uhakika mkubwa huunganisha functions zenye majina yaliyobadilishwa nasibu na implementation safi. Matches dhaifu bado zinaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia uhusiano wa calls, constants, strings na side effects, kisha ingiza ripoti ya JSON kwa kutumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Sakinisha toolchain na uendeshe extractor na graph matcher pamoja:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenga mojawapo ya hatua hizo, ilhali kwa chaguomsingi zote mbili hutekelezwa kwa sababu metadata ya runtime iliyopatikana na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kimkakati: inline, build flags, usanifu na tofauti za matoleo ya library zinaweza kubadilisha umbo la grafu, kwa hivyo hifadhi functions ambazo hazijatatuliwa badala ya kulazimisha majina yasiyo na uhakika wa kutosha.<sup>[[13]](#references)</sup>

## Python Iliyokusanywa

Katika ukurasa huu unaweza kupata jinsi ya kupata msimbo wa python kutoka kwa binary ya ELF/EXE iliyokusanywa kwa python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali kuufanya **emulate** na kuufanyia **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Kila **kitufe kina thamani** ya kukitambua kinapobonyezwa:

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

Kwa hiyo, katika aina hii ya programu, sehemu ya kuvutia ni **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Kwenye anwani **0x4000130** utapata function inayopatikana mara nyingi: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya operesheni za init (zisizo na umuhimu wowote):

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

if ya mwisho inakagua kama **`uVar4`** iko kwenye Keys za awali na si key ya sasa, yaani kuachia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).

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

Katika code iliyotangulia unaweza kuona kwamba tunalinganisha **uVar1** (mahali palipo na **thamani ya kitufe kilichobonyezwa**) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto, kitufe hiki husafisha skrini
- Kisha inalinganisha thamani na **8** (kitufe cha **START**); katika changamoto hii, njia hiyo hukagua kama code iliyoingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3 na ikiwa thamani ni sawa, code fulani hutekelezwa.
- Katika hali nyingine zote, counter (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Counter ikiwa chini ya 8, thamani za vitufe vilivyobonyezwa hujumlishwa kwenye `DAT_030000d8`.

Kwa hiyo, katika changamoto hii, ukijua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu wa chini ya 8 ambao jumla yake ni 0xf3.**

**Rejeo la mafunzo haya:** [maelezo ya changamoto ya Nostalgia yaliyohifadhiwa kwenye archive](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Kusimbua strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - strings za Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa kwenye archive)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering inayosaidiwa na AI, au angalau kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya kulinganisha Control Flow Graphs kwa kutumia Basic Block Matching](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Utaratibu wa obfuscation wa Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia ufanano wa Control-Flow Graph ili kuondoa obfuscation kiotomatiki kwenye binaries za Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
