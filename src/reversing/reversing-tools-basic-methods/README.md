# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za Reversing zinazotumia ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Uendeshaji otomatiki wa WinDbg katika user mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Utatuzi wa kernel ya Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) **ku-decompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) **ku-compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa decompilation.

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode iliyohifadhiwa kwenye cache ya Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payload zilizovirtualize na VM maalum

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Decompiler ya .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler ambayo **hu-decompile na kuchunguza miundo mbalimbali**, ikiwemo **libraries** (.dll), **faili za metadata za Windows** (.winmd), na **executables** (.exe). Baada ya ku-decompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwenye assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hurahisisha urambazaji ndani ya msimbo uliodecompilewa, na kuifanya kuwa mojawapo ya zana bora za **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na modeli pana ya add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha uundaji wa programu. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Huonyesha jinsi data inavyopita kwenye library au component
- Hutoa maarifa kuhusu utekelezaji na matumizi ya lugha na frameworks za .NET
- Hupata utendaji usioandikwa kwenye nyaraka na usiofichuliwa ili kupata manufaa zaidi kutoka kwa API na teknolojia zinazotumika.
- Hupata dependencies na assemblies mbalimbali
- Hufuatilia mahali halisi pa makosa katika msimbo wako, components za wahusika wengine, na libraries.
- Hufanya debug kwenye source ya msimbo wote wa .NET unaofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ya ILSpy ya Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bofya **Extensions** kisha **tafuta ILSpy**).\
Ikiwa unahitaji **ku-decompile**, **kurekebisha** na **ku-compile tena**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Bofya kulia -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed bila kutekeleza, kwa kutumia REA

**REA** inaweza kukagua metadata ya PE/CLI na CIL bila kupakia assembly. Anza kwa kutambua utambulisho wa artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii ni muhimu unapochunguza calls zinazotiliwa shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa kulinganisha matoleo, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na fingerprint za maagizo yaliyodekodiwa badala ya kuchukulia metadata tokens kuwa thabiti katika builds mbalimbali. Tamko la P/Invoke si uthibitisho kwamba native code ilitekelezwa; `verify_managed_native_boundaries` inahitaji native export au function Evidence inayolingana ili kukagua mpaka huo. Hifadhi artifact digest, MVID na mappings ambazo hazijatatuliwa pamoja na matokeo.<sup>[[17]](#references)</sup>

### Kuweka Kumbukumbu kwenye DNSpy

Ili kufanya **DNSpy irekodi taarifa fulani kwenye faili**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Ili ku-debug code kwa kutumia DNSpy, unahitaji:

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

Hili ni muhimu kwa sababu usipofanya hivyo, **optimisations** kadhaa zitatumika kwenye code wakati wa **runtime**, na huenda **breakpoint** isifikiwe kamwe wakati wa debugging au baadhi ya **variables** zisiwepo.

Kisha, ikiwa programu yako ya .NET inaendeshwa na **IIS**, unaweza kuiwasha upya kwa:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na uchague **Attach to Process...** ndani ya **Debug Tab**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na uchague Attach to Process ndani ya Debug Tab](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuunganisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuunganisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Sasa kwa kuwa tuna-debug process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sasa kwa kuwa tuna-debug process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sasa kwa kuwa tuna-debug process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote katika **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote katika Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote katika **Assembly Explorer** kisha ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote katika Assembly Explorer kisha ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Kutumia IDA

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za execution kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Sanidi parameters za execution kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **execution itasimama kila DLL inapopakiwa**. Kwa hiyo, rundll32 itakapopakia DLL yako, execution itasimama.

Njia hii husimamisha execution kwenye matukio ya module-load, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama kwa workflow ya x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza execution**; debugger itasimama kwenye kila dll main. Wakati fulani **utasimama kwenye DLL Entry ya dll yako**. Kutoka hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba execution ikisimama kwa sababu yoyote katika win64dbg, unaweza kuona **code unayochunguza** juu ya dirisha la win64dbg:

![Using IDA - Kutumia x64dbg/x32dbg: Kumbuka kwamba execution ikisimama kwa sababu yoyote katika win64dbg, unaweza kuona code unayochunguza juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha kwamba execution imesimama ndani ya DLL unayotaka ku-debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa kwenye memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/zana ya reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti ya decompilers kadhaa. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

## Uchunguzi wa native unaoungwa mkono na ushahidi kwa kutumia REA

**REA** hutoa uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Sanidi kwanza provider ya native iliyopo; angalia `rea providers --json` na uchague provider mahususi ikiwa zaidi ya mmoja anaunga mkono target. Tumia jina la function au anwani uliyoona kwenye inventory badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza kwa string au symbol ya feature, fuata marejeo na callers, kisha kagua dossier na pseudocode ya function iliyochaguliwa kwa kutumia `rea decompile`. REA hufunga session kwenye provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena bytes za artifact, provider, settings, operation na parameters zinazolingana pekee; snapshot ni cache ya ndani, si database ya provider iliyohifadhiwa. Hifadhi Evidence na unknowns zilizo wazi zilizorejeshwa badala ya kuchukulia paths zilizokisiwa au maandishi ya decompiler kuwa source asilia.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekea kwenye native add-ons, angalia [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **memory address** yake, na kusitisha execution.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye address iliyochapishwa, kisha endeleza execution ili kufanya debug ya shellcode.

Ukurasa wa releases wa GitHub una ZIP zenye releases zilizokompailiwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililorekebishwa kidogo la Blobrunner kwenye link ifuatayo. Ili kulikompaili, **unda tu C/C++ project katika Visual Studio Code, nakili na ubandike code, kisha build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye infinite loop. Ambatisha debugger, endeleza execution kwa **sekunde 2–5**, sitisha ndani ya loop hiyo, kisha step hadi kwenye call inayofuata inayohamishia execution kwenye shellcode iliyotengwa.

![Debugger ikiwa imesitishwa kwenye infinite loop ya jmp2it mara moja kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokompailiwa la [jmp2it kwenye ukurasa wa releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuiga shellcode na kuikagua dynamically.

Kumbuka kwamba Cutter inaruhusu "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama file iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya analysis ilipofungua bytes zilezile kama file au shellcode](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo na inaonekana Cutter itaanza emulation yenyewe kutoka hapo:

![Kuweka breakpoint kwenye entry ya shellcode inayotakiwa kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Emulator ya Cutter ikiwa imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode inayoigwa kwenye hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama vile **functions zipi** shellcode inatumia na kama shellcode inajidecode yenyewe kwenye memory.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg pia ina launcher ya picha ambapo unaweza kuchagua chaguo unazotaka na kutekeleza shellcode

![Launcher ya picha ya scDbg ya kuchagua chaguo za kuiga na kufuatilia shellcode](<../../images/image (258).png>)

Chaguo la **Create Dump** litadump shellcode ya mwisho ikiwa kuna mabadiliko yoyote yaliyofanywa kwenye shellcode kwa nguvu kwenye memory (ni muhimu kwa kupakua shellcode iliyodecode). **start offset** inaweza kutumika kuanzisha shellcode kwenye offset maalum. Chaguo la **Debug Shell** ni muhimu kwa kutatua hitilafu kwenye shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona chaguo lolote kati ya yale yaliyoelezwa awali ni bora zaidi kwa jambo hili, kwa kuwa utaweza kutumia Ida au x64dbg).

### Kudisassemble kwa kutumia CyberChef

Pakia faili yako ya shellcode kama input, kisha utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Kuondoa obfuscation ya MBA

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama `x + y` nyuma ya fomula zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, kwa hiyo carries na overflows ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya usemi kwa kutumia zana za jumla za aljebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za bit-width zilipuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi bit-width ya awali** kutoka kwenye msimbo/IR/decompiler output iliyoinuliwa (`8/16/32/64` bits).
2. **Ainisha usemi** kabla ya kujaribu kuurahisisha:
   - **Linear**: jumla zenye uzani za vipengele vya bitwise
   - **Semilinear**: linear pamoja na masks zisizobadilika kama `x & 0xFF`
   - **Polynomial**: bidhaa zinatokea
   - **Mixed**: bidhaa na mantiki ya bitwise zimechanganywa, mara nyingi pamoja na subexpressions zinazorudiwa
3. **Thibitisha kila rewrite unayopendekeza** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa ulinganifu hauwezi kuthibitishwa, hifadhi usemi wa awali badala ya kubashiri.

### Epuka control flow iliyosawazishwa kwa kutumia execution slice nyembamba

Mara nyingi si lazima kurejesha control-flow graph nzima. Katika hali ya control-flow flattening, opaque predicates, dispatchers kubwa, au msimbo wenye MBA nyingi, fuatilia marejeleo kutoka kwenye encrypted blobs na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha zalisha upya data-flow slice hiyo pekee, au iendeshe kivyake; dispatcher haihitajiki kwa suluhisho ikiwa hali husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha executable na data sections, relocations, na cross-references. Dampo meza zinazoweza kuhusika kutoka `.rodata` huku ukihifadhi mpangilio wa byte na upana wa elementi.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, meza inazorejelea, imported calls, na global state inayohitajika.
3. Hamishia operations hizo pekee kwenye modeli ya Python yenye upana usiobadilika. Ikiwa slice bado inategemea hali nyingi mno, iite routine hiyo chini ya Unicorn, QEMU, au debugger na uweke hook kwenye imports zisizo muhimu badala ya kuiga programu nzima.
4. Thibitisha kwamba extractor inapata matokeo yake kutoka kwenye binary iliyotolewa: ondoa fallbacks zisizoonekana, itafute majibu yaliyopachikwa ndani yake, na iendeshe dhidi ya builds ambazo haijawahi kuona zenye strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za ukaguzi wa awali ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua misemo ya MBA iliyofichwa kama thamani zisizobadilika

Usemi wa baiti unaoonekana kutegemea ingizo unaweza kulifuta kabisa ingizo lake. Baada ya kutoa jedwali zake, tathmini usemi huo katika kikoa kizima cha biti 8; seti ya matokeo yenye thamani moja inathibitisha kuwa baiti hiyo haibadiliki bila kuhitaji kurejesha mashine ya hali inayouzunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu addition ya awali ina wraparound ya upana wa byte. Kwa domain pana zaidi, uliza SMT solver ikiwa `f(x1) != f(x2)` inaweza kutimizwa kwa symbolic inputs mbili zenye upana sawa: `unsat` inathibitisha invariance, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kuondolewa.<sup>[[7]](#references)</sup>

#### Tambua decoding inayofungamana na mazingira

Ukaguzi wa Anti-analysis si lazima ufanye branch au crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye key bit, constant ya opaque-predicate, au state ya flattened-dispatcher, ikaendelea kawaida, na kutoa plaintext inayoonekana kuwa sahihi lakini si ya kweli kwenye emulator. Kwa hivyo, kupatch failure branches zinazoonekana pekee hakutoshi; fuatilia data dependencies kutoka environment probes hadi decoder state, linganisha slice ileile kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa malware analysis na reversing ya protected binaries. Huainisha expression na kuielekeza kupitia pipelines maalum badala ya kutumia rewrite pass moja ya jumla kwa kila kitu.<sup>[[2]](#references)</sup>

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

Hali muhimu:

- **Linear MBA**: CoBRA hutathmini expression kwa Boolean inputs, hupata signature, na huendesha kwa wakati mmoja mbinu kadhaa za recovery kama pattern matching, ubadilishaji wa ANF, na coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms hujengwa upya kwa reconstruction iliyogawanywa kwa bit ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa kuwa cores, na repeated subexpressions zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa mixed identity ambayo kwa kawaida inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hii inaweza kufupishwa kuwa:

```c
x * y
```

### Vidokezo vya reversing

- Pendelea kuendesha CoBRA kwenye **misemo ya IR iliyoinuliwa** au matokeo ya decompiler baada ya kutenga hesabu husika.
- Tumia `--bitwidth` waziwazi ikiwa usemi umetokana na hesabu iliyofanyiwa masking au rejista nyembamba.
- Ikiwa unahitaji hatua madhubuti zaidi ya uthibitisho, angalia maelezo ya Z3 ya hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia husambazwa kama **plugin ya LLVM pass** (`libCobraPass.so`), inayofaa unapotaka kurekebisha LLVM IR yenye MBA nyingi kabla ya passes nyingine za uchanganuzi.
- Residuals mchanganyiko wa domain zisizotumika, ambazo zinategemea carry, zinapaswa kuchukuliwa kama ishara ya kubakiza usemi wa awali na kuchambua njia ya carry kwa mikono.

## Kurejesha control-flow flattening ya XOR-state

Flattener ya mtindo wa OLLVM inaweza kuhifadhi hali ya basic block ya sasa kwenye rejista mbili za biti 64 na kuijenga upya kwa XOR kwenye dispatcher. Kila block asili huandika jozi ya hali ya hali inayofuata na kuruka kurudi kwenye dispatcher. Block yenye masharti inaweza kutumia `CMOVcc` kubadilisha nusu moja ya jozi kulingana na flags za CPU, hivyo kufuata maagizo ya matawi yanayoonekana pekee hukosa successors wawili. Tofauti na dispatcher ya indirect-jump, muundo huu unaweza kutumia back-edges za moja kwa moja kila mahali.<sup>[[19]](#references)[[20]](#references)</sup>

Ili kurejesha graph, tambua mti wa ulinganishaji wa dispatcher na rejista mbili za hali, linganisha kila hali ya XOR inayolinganishwa na block lengwa lake, kisha fuatilia writes zinazofikia jozi ya rejista katika kila block asili. Kwa writes zenye masharti, jumuisha agizo linaloweka flags na matokeo yote mawili ya `CMOVcc`. Badilisha exit ya dispatcher ya kila block iwe successor yake ya moja kwa moja iliyotatuliwa au tawi lenye masharti; dispatcher basi haitafikiwa tena bila kurekebisha binary. Hii ni mbinu ya full-CFG; ikiwa decoder moja tu ndiyo muhimu, [workflow finyu ya execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hapo juu inaweza kuwa ya haraka zaidi.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) huendesha mchakato huu kiotomatiki katika Binary Ninja. Nakili `plugins/DispatchThis` kwenye saraka ya plugin za mtumiaji ya Binary Ninja na uanzishe upya. Kwenye function iliyoathiriwa, fungua **Function Settings** na uchague `OLLVM_XOR_64`; ikiwa uchanganuzi hautaanza, tumia **Analysis → Reanalyze All Functions**. Hali hii huandika upya kingo za control-flow za MLIL, si baiti za faili, na haihitaji Z3 wala indirect-jump resolver. Imejaribiwa kwenye Binary Ninja 5.3.9757+; haiondoi writes za hali zilizokufa za kila block, kwa hiyo usizichukulie kimakosa kuwa transitions hai zilizobaki.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operesheni za programu kuwa mfuatano wa maagizo yanayotumia `mov` na hutumia utunzaji wa signal/exception kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binary zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation kwenye matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, njia hii ya kutafuta flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa `::main` kama ilivyo hapa:

![Kupata entry point ya Rust katika Ghidra kwa kutafuta majina ya functions yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni wazi kabisa kwamba hii ndiyo main function inayovutia.\
Kwa kuwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili kujifunza kuhusu **inputs** na **outputs** zake.

### Kurejesha strings za Rust kutoka firmware ya ELF

Katika binary za **Rust ELF**, strings nyingi tuli hazirejelewi kwa pointers zinazomalizika kwa NUL za mtindo wa C. Muundo wa kawaida wa `rustc` ni **tuple ya pointer/urefu** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa katika **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Hii ina maana kwamba `strings` au uchanganuzi chaguomsingi wa Ghidra unaweza kuunganisha strings zilizo karibu au kukosa kabisa marejeleo mtambuka.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja la mashine kwa wakati mmoja.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer inayoweza kuelekeza kwenye string.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya ukaguzi wa uhalali (kwa mfano, hifadhi urefu ulio kati ya baiti **4** na **100**).
6. Soma baiti `length` kamili kutoka `.rodata` badala ya kuendelea kusoma hadi `0x00`.

Mantiki ya msingi ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hii ni muhimu hasa katika firmware reversing kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, majina ya RPC, ujumbe wa log, assertions, majina ya faili, config keys, command handlers, na mantiki inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic ileile na kuunda string data kwenye offsets za `.rodata` zilizorejelewa. Zana za `rust-strings` na `RustStrings.py` zilizochapishwa na Pen Test Partners ni marejeleo mazuri ya kurekebisha wazo hilo kwa **word sizes, endianness, na mipangilio ya sections** mingine.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizokompailiwa za Delphi unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kureverse binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itatekeleza binary na kutatua majina ya functions kwa nguvu mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itasimama mwanzoni mwa code halisi.

Ukibonyeza kitufe katika programu ya graphical, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Kwa Go binaries za kawaida, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya functions katika IDA. Pakia Python plugin yake kwa kutumia **Alt+F7**.

Ikiwa unahitaji kureverse binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya functions.

### Rejesha metadata bila symbol table

Go executable iliyovuliwa bado inahitaji runtime metadata ili kuoanisha program counters na functions. [GoReSym](https://github.com/mandiant/GoReSym) hupata na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya functions, majina, source paths, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikiwa inatumika huku ikibadilisha majina yaliyorejeshwa. Kwa mfano, Garble huhash vitambulishi na njia za package na huondoa taarifa za build, module na debug.<sup>[[12]](#references)</sup> Tokeni ya package iliyofichwa lazima ibaki thabiti kwenye functions za package hiyo. Panga functions kulingana na tokeni inayojirudia, kadiria package moja kutokana na callees, strings na APIs zake, kisha sambaza lebo hiyo ya package kwa kundi lote.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble ukitumia GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huunganisha uchimbaji wa runtime-symbol na uundaji wa marejeleo safi pamoja na ulinganishaji wa control-flow-graph (CFG). Tumia hatua hizi kwa mpangilio:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator iliziondoa, linganisha sehemu za Go runtime iliyojumuishwa na runtime za marejeleo zenye matoleo maalum. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Chukulia hili kama uboreshaji uliothibitishwa kwa majaribio, si kizingiti kinachotumika kila mahali.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeleo yanayolingana.** Tengeneza binaries safi kwa toleo la Go lililotambuliwa, architecture lengwa na maktaba zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazozalishwa na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama zilizosanifishwa kuanzia `0.0` hadi `1.0`. Ulinganishaji wake wa basic-block unategemea ulinganisho wenye uzani wa instructions zinazofanana. Ulinganishaji wenye uhakika mkubwa huunganisha functions zenye majina yaliyobadilishwa bila mpangilio na implementation safi. Ulinganishaji dhaifu bado unaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia uhusiano wa calls, constants, strings na athari za pembeni, kisha ingiza ripoti ya JSON ukitumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenganisha hatua hizo, huku utekelezaji chaguomsingi ukifanya zote mbili kwa sababu metadata ya runtime iliyopatikana na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kimkakati: inlining, build flags, usanifu na tofauti za matoleo ya library zinaweza kubadilisha umbo la graph, kwa hiyo hifadhi functions ambazo hazijatatuliwa badala ya kuzilazimishia majina yenye confidence ndogo.<sup>[[13]](#references)</sup>

### Kurejesha jedwali la string za Go

Binaries za Go huweka bytes za string kutoka kwa packages zote zilizounganishwa kwenye jedwali moja linaloendelea. Entries hazina kikomo cha NUL, na miundo ya runtime haionyeshi msingi au ukubwa wa jedwali. Hata hivyo, compiler hupanga entries kwanza kulingana na urefu, kisha alfabeti, katika mifumo ya uendeshaji na usanifu mbalimbali. Baada ya kupata entry moja, mchambuzi anaweza kutembea kwenye entries zilizo karibu na kutumia data cross-references kuhusisha strings na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha workflow hii kiotomatiki katika IDA Pro na Ghidra. Acha auto-analysis ikamilike kwanza kwa sababu plugin hutegemea data-segment cross-references. Anchor yake chaguomsingi ni string ya runtime `entersyscall`; baada ya hapo inaweza kuchanganua upande wowote, kufafanua strings zilizopatikana kwenye database, na kutoa JSON mapping ya strings kwa functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa package ya function inayorejelea string ili kutenganisha code ya programu au malware na kelele ya library zilizounganishwa. Mbinu hii haiwezi kurejesha literals zilizoharibiwa na obfuscation kama vile mabadiliko ya `-literals` ya Garble. Bado inaweza kupanga strings za runtime ambazo hazijafichwa kwa obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za runtime za Go

Go hujumuisha taarifa za aina za runtime zinazotumiwa na vipengele kama garbage collection. Build information inapoondolewa au disassembler inaposhindwa kuchanganua metadata hii, maagizo yanaweza kuonekana kana kwamba yanapakia anwani za data kiholela na eneo lengwa hubaki bila aina. Kurejesha metadata hubadilisha anwani hizo kuwa marejeleo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua aina za runtime kuwa ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwasha uchanganuzi wa aina (`type parsing`). Ingiza report hiyo ukitumia plugin ya IDA Pro au Ghidra ya GoResolver ili kufafanua aina zilizorejeshwa na kutumia marejeleo yake kwenye database ya uchanganuzi. Katika fomati ya report iliyoletwa na kipengele hiki, usipotumia `-y`, sehemu za anwani ya RTTI na aina zilizorejeshwa hubaki null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia samples za PE, ELF na Mach-O za x86, AMD64, ARM na ARM64, kwa hivyo workflow ileile inatumika kwa Go binaries za Windows, Linux na macOS.<sup>[[10]](#references)</sup>

## Python Iliyocompiliwa

Katika ukurasa huu unaweza kupata maelekezo ya jinsi ya kupata Python code kutoka kwenye binary ya Python iliyocompiliwa ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia tools mbalimbali kuufanyia **emulate** na **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![Usanidi wa controls za no$gba unaoonyesha ulinganifu wa vitufe vya Game Boy Advance](<../../images/image (581).png>)

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

Kwa hiyo, katika aina hii ya program, sehemu ya kuvutia itakuwa **jinsi program inavyoshughulikia ingizo la mtumiaji**. Katika anwani **0x4000130** utapata function inayopatikana mara nyingi: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA inayorejelea KEYINPUT kwenye anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kuwa function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya baadhi ya shughuli za init (zisizo na umuhimu):

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

if ya mwisho inakagua kwamba **`uVar4`** imo kwenye **Keys** za awali na si ufunguo wa sasa, yaani kitendo cha kuachia kitufe (ufunguo wa sasa umehifadhiwa kwenye **`uVar1`**).

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

Katika msimbo uliotangulia, unaweza kuona kwamba tunalinganisha **uVar1** (mahali palipo **thamani ya kitufe kilichobonyezwa**) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto hii, kitufe hiki hufuta skrini.
- Kisha inalinganisha thamani na **8** (kitufe cha **START**); katika changamoto hii, njia hiyo hukagua ikiwa msimbo ulioingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3 na ikiwa thamani zinafanana, baadhi ya msimbo hutekelezwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Mradi kaunta iko chini ya 8, thamani za vitufe vilivyobonyezwa hujumlishwa katika `DAT_030000d8`.

Kwa hiyo, katika changamoto hii, ukijua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu wa chini ya 8 ili jumla yake iwe 0xf3.**

**Rejeo la mafunzo haya:** [maelezo ya changamoto ya Nostalgia yaliyohifadhiwa kwenye kumbukumbu](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Kuondoa obfuscation kwenye binary)

## References

- [1] [Kurahisisha obfuscation ya MBA kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hazina ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kufasiri strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - strings za Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya reversing ya GBA (yaliyohifadhiwa kwenye kumbukumbu)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering inayosaidiwa na AI, au angalau kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya kulinganisha Control Flow Graphs kwa kutumia ulinganishaji wa Basic Blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Hazina ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mbinu ya obfuscation ya Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia ufanano wa Control-Flow Graph ili kuondoa obfuscation kwenye binaries za Golang kiotomatiki](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Hazina ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Maboresho ya zana za Golang za Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa CLI na Evidence wa REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Mtiririko wa kazi wa kuondoa control-flow flattening katika Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Uvamizi wa PaperCut MF Zero-Day, Java Loader, Web Shell, na AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
{{#include ../../banners/hacktricks-training.md}}
