# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za Reversing Zinazotumia ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Uendeshaji otomatiki wa WinDbg user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Utatuzi wa hitilafu kwenye Windows kernel

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kufanya **decompile** kutoka wasm (binary) hadi wat (maandishi wazi)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kufanya **compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kufanya decompilation.

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode iliyohifadhiwa kwenye cache ya Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads zilizowekwa kwenye virtual machine na VM maalum

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Decompiler ya .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler ambayo **hufanya decompile na kukagua miundo mingi**, ikijumuisha **libraries** (.dll), **faili za metadata za Windows** (.winmd), na **executables** (.exe). Baada ya kufanyiwa decompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo chanzo uliopotea unahitaji kurejeshwa kutoka kwa assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hurahisisha urambazaji ndani ya msimbo uliofanyiwa decompile, na kuifanya kuwa mojawapo ya zana bora kwa **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na mfumo kamili wa add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha uendelezaji. Hebu tuangalie huduma mbalimbali za reverse engineering zinazotolewa na zana hii:

- Hutoa mwonekano wa jinsi data inavyopita kwenye library au component
- Hutoa mwonekano wa utekelezaji na matumizi ya lugha na frameworks za .NET
- Hupata utendaji usioandikwa kwenye nyaraka na usiofichuliwa, ili kupata manufaa zaidi kutoka kwa API na teknolojia zinazotumika.
- Hupata dependencies na assemblies tofauti
- Hufuatilia mahali halisi pa makosa kwenye msimbo wako, components za wahusika wengine, na libraries.
- Hutatua hitilafu ndani ya chanzo cha msimbo wote wa .NET unaotumia.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode; huhitaji kupakua git. Bofya **Extensions** kisha **search ILSpy**).\
Ikiwa unahitaji kufanya **decompile**, **modify** na **recompile** tena, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed code bila kuitekeleza kwa kutumia REA

**REA** inaweza kukagua metadata ya PE/CLI na CIL bila kupakia assembly. Anza kwa kutambua artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii ni muhimu unapokagua calls zinazotiliwa shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa kulinganisha matoleo, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na alama za vidole za maagizo yaliyofasiriwa badala ya kuchukulia metadata tokens kuwa thabiti kati ya builds. Tamko la P/Invoke halithibitishi kwamba native code iliendeshwa; `verify_managed_native_boundaries` inahitaji export ya native au Evidence ya function inayolingana ili kukagua mpaka huo. Hifadhi artifact digest, MVID na mappings ambazo hazijatatuliwa pamoja na matokeo.<sup>[[17]](#references)</sup>

### Uwekaji wa Kumbukumbu wa DNSpy

Ili **DNSpy iandike taarifa fulani kwenye faili**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Utatuzi wa hitilafu kwa DNSpy

Ili kutatua hitilafu kwenye code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **sifa za Assembly** zinazohusiana na **utatuzi wa hitilafu**:

![DNSpy Logging - Utatuzi wa hitilafu kwa DNSpy: Kwanza, badilisha sifa za Assembly zinazohusiana na utatuzi wa hitilafu](<../../images/image (973).png>)

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

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** marekebisho kadhaa ya **optimisations** yatatumika kwenye code, na huenda wakati wa debugging **break-point isifikiwe kamwe** au baadhi ya **variables zisiwepo**.

Kisha, ikiwa programu yako ya .NET inaendeshwa na **IIS**, unaweza kuianzisha upya kwa kutumia:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, funga faili zote zilizofunguliwa na uchague **Attach to Process...** ndani ya **Debug Tab**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, funga faili zote zilizofunguliwa na uchague Attach to Process ndani ya Debug Tab](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuunganisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuunganisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya-kulia module yoyote kwenye **Assembly Explorer** na ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya-kulia module yoyote kwenye Assembly Explorer na ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Kutumia IDA

- **Pakia rundll32** (64bits iko kwenye C:\Windows\System32\rundll32.exe na 32 bits iko kwenye C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimamishwa kila DLL inapopakiwa**; hivyo, rundll32 itakapopakia DLL yako, utekelezaji utasimamishwa.

Njia hii husimamisha utekelezaji wakati wa matukio ya kupakia module, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye workflow ya x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Pakia rundll32** (64bits iko kwenye C:\Windows\System32\rundll32.exe na 32 bits iko kwenye C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**; debugger itasimama kwenye kila dll main, na wakati fulani **utasimama kwenye DLL Entry ya dll yako**. Kutoka hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba utekelezaji unaposimamishwa kwa sababu yoyote kwenye win64dbg, unaweza kuona **uko kwenye code gani** kwa kuangalia **juu ya dirisha la win64dbg**:

![Kutumia IDA - Kutumia x64dbg/x32dbg: Kumbuka kwamba utekelezaji unaposimamishwa kwa sababu yoyote kwenye win64dbg, unaweza kuona uko kwenye code gani kwa kuangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki huthibitisha utekelezaji unaposimama ndani ya DLL unayotaka kufanya debugging.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa kwenye memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi kwenye:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni zana ya front-end/reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti inayotumia decompilers mbalimbali. Huduma hii ya wavuti hukuruhusu kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

## Uchunguzi wa native unaoungwa mkono na ushahidi kwa kutumia REA

**REA** huwezesha kutumia uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Sanidi provider iliyopo ya native kwanza; angalia `rea providers --json` na uchague provider waziwazi iwapo zaidi ya mmoja anaunga mkono target. Tumia jina au anwani ya function iliyobainika kwenye inventory badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza na feature string au symbol, fuata references na callers, kisha kagua dossier na pseudocode ya function iliyochaguliwa kwa `rea decompile`. REA huunganisha session na provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena bytes za artifact zinazolingana tu, provider, settings, operation na parameters; snapshot ni cache ya ndani, si database ya provider iliyohifadhiwa. Hifadhi Evidence iliyorudishwa pamoja na mambo yasiyojulikana yaliyoelezwa wazi, badala ya kuchukulia paths zilizokisiwa au maandishi ya decompiler kuwa source ya awali.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekeza kwenye native add-ons, angalia [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kudebug shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **anwani yake ya memory**, na kusitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye anwani iliyochapishwa, kisha endeleza utekelezaji ili kudebug shellcode.

Ukurasa wa releases wa GitHub una zips zenye releases zilizokompailiwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo la BlobRunner lililorekebishwa kidogo kwenye link ifuatayo. Ili kulikompaili, **unda tu C/C++ project katika Visual Studio Code, nakili na ubandike code, kisha uijenge**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kudebug shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye infinite loop. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha ndani ya loop hiyo, kisha step hadi kwenye call inayofuata inayohamisha utekelezaji kwenda kwenye shellcode iliyotengwa.

![Debugger ikiwa imesitishwa ndani ya infinite loop ya jmp2it, mara moja kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokompailiwa la [jmp2it kwenye ukurasa wa releases](https://github.com/adamkramer/jmp2it/releases/).

### Kudebug shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuemulate shellcode na kuikagua wakati wa utekelezaji.

Kumbuka kuwa Cutter inaruhusu "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama file iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi wakati bytes zilezile zinafunguliwa kama file au shellcode](<../../images/image (562).png>)

Ili kuanzisha emulation mahali unapotaka, weka bp hapo; inaonekana Cutter itaanzisha emulation yenyewe kutoka hapo:

![Kuweka breakpoint kwenye entry point inayotakiwa ya shellcode kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Emulator ya Cutter ikiwa imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Unaweza kuona stack, kwa mfano, ndani ya hex dump:

![Kuangalia stack ya shellcode iliyoemulatewa kwenye hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama vile shellcode inatumia **functions zipi** na kama shellcode **inajidecode** kwenye memory.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg pia ina launcher ya picha inayokuwezesha kuchagua chaguo unazotaka na kutekeleza shellcode

![scDbg graphical launcher for selecting shellcode emulation and tracing options](<../../images/image (258).png>)

Chaguo la **Create Dump** litahifadhi shellcode ya mwisho ikiwa kuna mabadiliko yoyote yaliyofanywa kwa shellcode hiyo wakati wa utekelezaji kwenye memory (ni muhimu kwa kupakua shellcode iliyodecodeiwa). **start offset** inaweza kusaidia kuanzisha shellcode kwenye offset maalum. Chaguo la **Debug Shell** linafaa kwa kudebug shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona chaguo lolote kati ya yaliyoelezwa hapo awali linafaa zaidi kwa hili, kwa kuwa utaweza kutumia Ida au x64dbg).

### Kutenganisha maagizo kwa kutumia CyberChef

Pakia faili yako ya shellcode kama ingizo na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Uondoaji wa obfuscation ya MBA

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha misemo rahisi kama `x + y` nyuma ya fomula zinazochanganya hesabu (`+`, `-`, `*`) na waendeshaji wa bitwise (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba utambulisho huu kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, kwa hiyo carry na overflow ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya usemi kwa kutumia zana za kawaida za aljebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za upana wa biti zimepuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi upana asilia wa biti** kutoka kwenye msimbo/IR/decompiler uliokuzwa (`8/16/32/64` bits).
2. **Panga usemi katika kundi** kabla ya kujaribu kuurahisisha:
   - **Linear**: jumla zenye uzani za atomi za bitwise
   - **Semilinear**: linear pamoja na masks za kudumu kama `x & 0xFF`
   - **Polynomial**: kuna bidhaa
   - **Mixed**: bidhaa na mantiki ya bitwise zimechanganyika, mara nyingi zikiwa na misemi midogo inayojirudia
3. **Thibitisha kila mabadiliko yanayopendekezwa** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa ulinganifu hauwezi kuthibitishwa, hifadhi usemi asilia badala ya kubahatisha.

### Epuka control flow iliyosawazishwa kwa kutumia kipande finyu cha utekelezaji

Mara nyingi si lazima kurejesha grafu kamili ya control-flow. Kukiwa na control-flow flattening, opaque predicates, dispatchers kubwa, au msimbo mwingi wa MBA, fuata marejeleo kutoka kwenye blobs zilizosimbwa na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha tengeneza upya kipande hicho tu cha mtiririko wa data, au kitekeleze kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa hali husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha sehemu zinazotekelezeka na za data, relocations, na cross-references. Dampo jedwali zinazoweza kufaa kutoka `.rodata` huku ukihifadhi mpangilio wake wa byte na upana wa elementi.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, jedwali inazorejelea, miito ya nje iliyoingizwa, na hali ya kimataifa inayohitajika.
3. Inua shughuli hizo pekee kwenye modeli ya Python yenye upana wa biti usiobadilika. Ikiwa kipande hicho bado kinategemea hali nyingi mno, iite routine hiyo chini ya Unicorn, QEMU, au debugger, na weka hooks kwa imports zisizohusika badala ya kuiga programu nzima.
4. Thibitisha kuwa extractor inapata matokeo yake kweli kutoka kwenye binary iliyotolewa: ondoa njia mbadala zinazotumika kimyakimya, itafute ili kuona kama majibu yamepachikwa ndani yake, na iendeshe dhidi ya builds ambazo haijawahi kuona zenye strings, keys, identifiers, layouts na obfuscation seeds zilizobadilishwa.

Amri muhimu za ukaguzi wa awali ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua expressions za MBA zilizofichwa kama constants

Expression ya byte inayoonekana kutegemea input inaweza kufuta kabisa athari ya input yake. Baada ya kutoa tables zake, tathmini expression hiyo katika domain nzima ya 8-bit; seti ya matokeo yenye kipengele kimoja inathibitisha kuwa byte hiyo ni constant bila kuhitaji kurejesha state machine inayoizunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu addition ya awali ina wraparound ya upana wa byte. Kwa domain pana zaidi, uliza SMT solver ikiwa `f(x1) != f(x2)` inaridhishika kwa inputs mbili za symbolic zenye upana sawa: `unsat` huthibitisha invariance, ilhali `sat` hutoa counterexample na humaanisha kuwa input haiwezi kutupiliwa mbali.<sup>[[7]](#references)</sup>

#### Tambua decoding inayofungamana na mazingira

Ukaguzi wa anti-analysis si lazima usababishe branch au crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye bit ya key, constant ya opaque-predicate, au state ya flattened-dispatcher, kuendelea kawaida, na kutoa plaintext inayokubalika lakini ya uongo kwenye emulator. Kwa hiyo, kupatch branches za failure zinazoonekana pekee haitoshi; fuatilia data dependencies kutoka kwa environment probes hadi kwenye state ya decoder, linganisha slice hiyo hiyo kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa malware analysis na protected-binary reversing. Huainisha expression na kuielekeza kwenye pipelines maalum badala ya kutumia rewrite pass moja ya jumla kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini usemi kwa ingizo za Boolean, hutoa saini, na kujaribu mbinu kadhaa za urejeshaji, kama vile pattern matching, ubadilishaji wa ANF, na interpolation ya coefficient.
- **Semilinear MBA**: atomu zilizofichwa kwa constant hujengwa upya kwa kutumia bit-partitioned reconstruction ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: bidhaa hugawanywa katika cores, na subexpressions zinazorudiwa zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa mixed identity ambayo kwa kawaida inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hili linaweza kurahisishwa kuwa:

```c
x * y
```

### Vidokezo vya reversing

- Pendelea kuendesha CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga hesabu husika.
- Tumia `--bitwidth` moja kwa moja ikiwa expression imetokana na masked arithmetic au narrow registers.
- Ikiwa unahitaji hatua thabiti zaidi ya uthibitisho, angalia vidokezo vya Z3 vya hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inapatikana kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kunormalize LLVM IR yenye MBA nyingi kabla ya kutumia analysis passes za baadaye.
- Residuals mchanganyiko wa domains zisizotumika ambazo ni nyeti kwa carry zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression asili na kuchanganua carry path kwa mkono.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa instruction sequences zinazotumia `mov`, na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation kwenye matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, workaround hii ya kupata flag** inaweza kuwa na manufaa sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa kutumia `::main` kama ilivyo hapa:

![Kutafuta entry point ya Rust katika Ghidra kwa kutafuta majina ya functions yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni wazi kabisa kuwa hii ndiyo main function inayovutia.\
Ukiwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **inputs** na **outputs** zake.

### Kurejesha strings za Rust kutoka kwenye firmware ya ELF

Katika binaries za **Rust ELF**, strings nyingi tuli hazirejelewi kama pointers zenye NUL mwisho kwa mtindo wa C. Mpangilio wa kawaida wa `rustc` ni **pointer/length tuple** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa kwenye **`.rodata`**:

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
4. Chukulia neno linalofuata kuwa length inayowezekana.
5. Tumia vichujio vya sanity (kwa mfano, hifadhi lengths zilizo kati ya **4** na **100** bytes).
6. Soma bytes `length` haswa kutoka `.rodata` badala ya kuchanganua hadi ufikie `0x00`.

Mantiki ndogo ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hili ni muhimu hasa katika firmware reversing kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, majina ya RPC, ujumbe wa log, assertions, majina ya faili, config keys, command handlers, na mantiki inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda data ya string kwenye offsets za `.rodata` zilizorejelewa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hilo ili litumike kwa **ukubwa tofauti wa word, endianness, na mpangilio tofauti wa sehemu**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizocompiliwa za Delphi, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kufanya reverse engineering ya binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itaendesha binary na kutatua majina ya functions kwa nguvu mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itasimama mwanzoni mwa code halisi.

Ukibonyeza kitufe katika programu ya picha, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Kwa Go binaries za kawaida, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya functions katika IDA. Pakia Python plugin yake kwa **Alt+F7**.

Ikiwa unahitaji kufanya reverse engineering ya binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya functions.

### Rejesha metadata bila symbol table

Go executable iliyofanyiwa stripping bado inahitaji runtime metadata ili kuoanisha program counters na functions. [GoReSym](https://github.com/mandiant/GoReSym) hutafuta na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya functions, majina, source paths, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikitumika huku ikibadilisha majina yaliyorejeshwa. Kwa mfano, Garble huhash vitambulishi na njia za package na kuondoa taarifa za build, module na debug.<sup>[[12]](#references)</sup> Tokeni ya package iliyofichwa lazima ibaki ileile katika functions kutoka package hiyo. Panga functions kwa tokeni inayojirudia, tambua package moja kutokana na callees, strings na APIs zake, kisha tumia lebo hiyo ya package kwa kundi lote.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huchanganya uchimbaji wa runtime symbols na uundaji wa marejeleo safi pamoja na ulinganishaji wa control-flow-graph (CFG). Tumia mfuatano huu:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator imeziondoa, linganisha sehemu za Go runtime iliyojumuishwa na runtime za marejeleo zenye matoleo mahususi. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Ichukulie hii kama uboreshaji uliothibitishwa kwa majaribio, si kizingiti cha jumla.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeleo yanayolingana.** Tengeneza binaries safi za toleo la Go lililotambuliwa, target architecture na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazozalishwa na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama zilizosanifishwa kuanzia `0.0` hadi `1.0`. Ulinganishaji wa basic-blocks unategemea ulinganishaji wenye uzani wa instructions zinazofanana. Ulinganishaji wenye uhakika mkubwa huunganisha functions zilizobadilishiwa majina nasibu na implementation safi. Ulinganishaji dhaifu zaidi bado unaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia mahusiano ya calls, constants, strings na side effects, kisha ingiza ripoti ya JSON kwa kutumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Sakinisha toolchain na uendeshe extractor na graph matcher kwa pamoja:<sup>[[10]](#references)</sup>

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

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenganisha hatua mojawapo, ilhali chaguo-msingi huendesha zote mbili kwa sababu metadata ya runtime iliyopatikana na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za heuristic: inlining, build flags, architecture na tofauti za matoleo ya library zinaweza kubadilisha umbo la graph, kwa hivyo hifadhi functions ambazo hazijatatuliwa badala ya kuzilazimishia majina yasiyo na uhakika wa kutosha.<sup>[[13]](#references)</sup>

### Kurejesha Go string table

Go binaries huweka bytes za string kutoka kila package iliyounganishwa kwenye table moja mfululizo. Entries hazina kikomo cha NUL, na runtime structures hazionyeshi base au ukubwa wa table. Hata hivyo, compiler hupanga entries kwanza kwa urefu, kisha kwa alfabeti katika operating systems na architectures zote. Kwa hiyo, baada ya kupata entry moja, mchambuzi anaweza kupitia entries zilizo karibu na kutumia data cross-references kuhusisha strings na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha workflow hii kiotomatiki katika IDA Pro na Ghidra. Acha auto-analysis ikamilike kwanza, kwa sababu plugin hutegemea data-segment cross-references. Anchor yake chaguomsingi ni runtime string `entersyscall`; kisha inaweza kuchanganua katika mwelekeo wowote, kufafanua strings zilizopatikana kwenye database, na kuhamisha JSON mapping ya strings na functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa package ya function inayorejelea string ili kutenganisha application au malware code na kelele ya library zilizounganishwa. Mbinu hii haiwezi kurejesha literals zilizoharibiwa na obfuscation kama vile mabadiliko ya Garble ya `-literals`. Bado inaweza kupanga runtime strings ambazo hazijaobfuscate.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za Go runtime

Go hujumuisha runtime type information inayotumiwa na vipengele kama garbage collection. Build information inapofutwa au disassembler inaposhindwa kuchanganua metadata hii, instructions zinaweza kuonekana kana kwamba zinapakia data addresses zisizohusiana, huku eneo lengwa likibaki bila aina iliyobainishwa. Kurejesha metadata hubadilisha addresses hizo kuwa marejeleo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua runtime types na kutoa ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwasha uchanganuzi wa aina. Leta ripoti kwa kutumia plugin ya IDA Pro au Ghidra ya GoResolver ili kufafanua aina zilizorejeshwa na kutumia marejeleo yake kwenye hifadhidata ya uchanganuzi. Katika umbizo la ripoti lililoanzishwa na kipengele hiki, kuacha `-y` husababisha washiriki wa anwani ya RTTI na aina zilizorejeshwa kuwa null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia sampuli za PE, ELF na Mach-O za x86, AMD64, ARM na ARM64, kwa hivyo mtiririko huohuo wa kazi hutumika kwa binaries za Go za Windows, Linux na macOS.<sup>[[10]](#references)</sup>

## Python Iliyokusanywa

Katika ukurasa huu unaweza kujifunza jinsi ya kupata msimbo wa python kutoka kwenye binary iliyokusanywa ya python ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali ku-**emulate** na ku-**debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye kiolesura
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![Usanidi wa vidhibiti vya no$gba unaoonyesha ulinganifu wa vitufe vya Game Boy Advance](<../../images/image (581).png>)

Unapobonyeza, kila **ufunguo una thamani** ya kuutambua:

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

Kwa hiyo, katika aina hii ya programu, sehemu ya kuvutia ni **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Katika anwani **0x4000130** utapata function inayopatikana kwa kawaida: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya baadhi ya operesheni za init (zisizo na umuhimu):

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

if ya mwisho inakagua kuwa **`uVar4`** iko kwenye **Keys za mwisho** na si key ya sasa; yaani kitufe kinaachiliwa (key ya sasa imehifadhiwa kwenye **`uVar1`**).

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

Katika msimbo uliotangulia, unaweza kuona kwamba tunalinganisha **uVar1** (mahali ilipo **thamani ya kitufe kilichobonyezwa**) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto hii, kitufe hiki husafisha skrini.
- Kisha, thamani inalinganishwa na **8** (kitufe cha **START**); katika changamoto hii, njia hiyo hukagua ikiwa msimbo ulioingizwa ni halali.
  - Katika hali hii, kigezo **`DAT_030000d8`** hulinganishwa na 0xf3, na ikiwa thamani inalingana, msimbo fulani hutekelezwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Kaunta ikiwa chini ya 8, thamani za vitufe vilivyobonyezwa hukusanywa katika `DAT_030000d8`.

Kwa hiyo, katika changamoto hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu chini ya 8 ili jumla yake iwe 0xf3.**

**Marejeleo ya mafunzo haya:** [maelezo ya changamoto ya Nostalgia yaliyohifadhiwa kwenye kumbukumbu](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Kuondoa obfuscation ya binary)

## References

- [1] [Kurahisisha MBA obfuscation kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hifadhi ya CoBRA ya Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Kudecode strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa kwenye kumbukumbu)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering inayosaidiwa na AI, au angalau kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya kulinganisha Control Flow Graphs kwa kutumia ulinganishaji wa Basic Blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Hifadhi ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Utaratibu wa obfuscation wa Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia ufanano wa Control-Flow Graph ili kuondoa obfuscation kiotomatiki kwenye binaries za Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Hifadhi ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Maboresho ya zana za Volexity za Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa CLI na Evidence wa REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
