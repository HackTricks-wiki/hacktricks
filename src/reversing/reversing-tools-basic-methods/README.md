# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za reversing zinazotegemea ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows kernel debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) **ku-decompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) **ku-compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwwg.github.io/web-wasmdec/) kwa decompilation.

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 bytecode iliyohifadhiwa kwenye cache

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads zilizovirtualishwa na VMs maalum

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler ambayo **hu-decompile na kuchunguza fomati nyingi**, zikiwemo **libraries** (.dll), **Windows metadata file**s (.winmd), na **executables** (.exe). Baada ya ku-decompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwa assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa urambazaji rahisi ndani ya msimbo uliodecompile, na kuifanya kuwa mojawapo ya zana bora kwa **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kwa mfumo mpana wa add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha uendelezaji. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa mwonekano wa jinsi data inavyopita kupitia library au component
- Hutoa mwonekano wa utekelezaji na matumizi ya lugha na framework za .NET
- Hupata utendaji usioandikwa nyaraka na usiofichuliwa ili kupata manufaa zaidi kutoka kwa API na teknolojia zinazotumika.
- Hupata dependencies na assemblies tofauti
- Hufuatilia eneo halisi la makosa katika msimbo wako, components za wahusika wengine, na libraries.
- Hufanya debugging kwenye chanzo cha msimbo wote wa .NET unaofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bofya **Extensions** kisha **tafuta ILSpy**).\
Ikiwa unahitaji **ku-decompile**, **kurekebisha** na **ku-compile upya**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed code bila kuitekeleza kwa kutumia REA

**REA** inaweza kukagua PE/CLI metadata na CIL bila kupakia assembly. Anza kwa kubaini utambulisho wa artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii ni muhimu unapochunguza calls zinazotia shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa ulinganishaji wa matoleo, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na fingerprint za maelekezo yaliyodecodeiwa badala ya kuchukulia metadata tokens kuwa thabiti kati ya builds. Tamko la P/Invoke si uthibitisho kwamba native code iliendeshwa; `verify_managed_native_boundaries` inahitaji native export au function Evidence inayolingana ili kukagua mpaka huo. Hifadhi artifact digest, MVID na mappings ambazo hazijatatuliwa pamoja na matokeo.<sup>[[17]](#references)</sup>

### Kuweka Logging kwenye DNSpy

Ili kufanya **DNSpy iandike taarifa fulani kwenye faili**, unaweza kutumia kipande hiki:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Utatuzi wa hitilafu wa DNSpy

Ili kutatua hitilafu za code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **sifa za Assembly** zinazohusiana na **utatuzi wa hitilafu**:

![Uwekaji kumbukumbu wa DNSpy - Utatuzi wa hitilafu wa DNSpy: Kwanza, badilisha sifa za Assembly zinazohusiana na utatuzi wa hitilafu](<../../images/image (973).png>)

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

Hili ni muhimu kwa sababu usipofanya hivyo, **optimisations** kadhaa zitatumika kwenye code wakati wa **runtime**, na inawezekana kwamba wakati wa debugging **break-point haitafikiwa kamwe** au baadhi ya **variables hazitakuwepo**.

Kisha, ikiwa application yako ya .NET inaendeshwa na **IIS**, unaweza kuianzisha upya kwa:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na ndani ya Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuambatisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuambatisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Sasa kwa kuwa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sasa kwa kuwa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sasa kwa kuwa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote katika **Assembly Explorer** na ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote katika Assembly Explorer na ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Using IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimamishwa kila DLL inapopakiwa**. Kwa hiyo, rundll32 inapopakia DLL yako, utekelezaji utasimamishwa.

Njia hii husimamisha utekelezaji kwenye matukio ya kupakia module, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama kwa workflow ya x64dbg iliyo hapa chini.

### Using x64dbg/x32dbg

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**; debugger itasimama kwenye kila dll main. Wakati fulani, **utasimama kwenye DLL Entry ya dll yako**. Kutoka hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba utekelezaji unaposimamishwa kwa sababu yoyote katika win64dbg, unaweza kuona **uko kwenye code gani** kwa kuangalia **juu ya dirisha la win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Kumbuka kwamba utekelezaji unaposimamishwa kwa sababu yoyote katika win64dbg, unaweza kuona uko kwenye code gani kwa kuangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha utekelezaji unaposimama ndani ya DLL unayotaka kufanya debugging yake.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali thamani muhimu zinapohifadhiwa kwenye memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni zana ya front-end/reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti inayotoa ufikiaji wa decompilers kadhaa. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

## Uchunguzi wa native unaotegemea ushahidi kwa kutumia REA

**REA** hutoa uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Kwanza sanidi native provider iliyopo; angalia `rea providers --json` na uchague provider wazi ikiwa zaidi ya mmoja anaunga mkono target. Tumia jina la function lililoonekana au anwani kutoka kwenye inventory badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza na mfuatano wa kipengele au alama, fuatilia marejeleo na wapigaji, kisha kagua faili ya maelezo ya function iliyochaguliwa na pseudocode kwa kutumia `rea decompile`. REA hufunga session kwenye provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena tu byte za artifact, provider, settings, operation na parameters zinazolingana; snapshot ni cache ya ndani, si database ya provider iliyohifadhiwa. Hifadhi Evidence iliyorudishwa na mambo yasiyojulikana yaliyoelezwa wazi badala ya kuchukulia paths zilizokisiwa au maandishi ya decompiler kama source ya awali.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekea kwenye native add-ons, tazama [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kutatua hitilafu za shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **anwani yake ya memory**, na kusitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye anwani iliyochapishwa, kisha endelea na utekelezaji ili kutatua hitilafu za shellcode.

Ukurasa wa matoleo wa github una zips zenye matoleo yaliyokompailiwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililorekebishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kulikompaili, **tengeneza tu C/C++ project katika Visual Studio Code, nakili na ubandike code hiyo, kisha uijenge**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kutatua hitilafu za shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye infinite loop. Ambatisha debugger, endelea kwa **sekunde 2–5**, sitisha ukiwa ndani ya loop hiyo, kisha songa hadi kwenye call inayofuata inayohamishia utekelezaji kwenye shellcode iliyotengwa.

![Debugger ikiwa imesitishwa kwenye infinite loop ya jmp2it mara moja kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokompailiwa la [jmp2it kwenye ukurasa wa matoleo](https://github.com/adamkramer/jmp2it/releases/).

### Kutatua hitilafu za shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia cutter unaweza kuemulate shellcode na kuichunguza kwa nguvu.

Kumbuka kuwa Cutter hukuruhusu "Open File" na "Open Shellcode". Kwa upande wangu, nilipofungua shellcode kama faili iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi wakati byte zilezile zinafunguliwa kama faili au shellcode](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo na inaonekana cutter itaanza emulation kiotomatiki kutoka hapo:

![Kuweka breakpoint kwenye entry ya shellcode inayotakiwa kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Emulator ya Cutter ikiwa imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Unaweza kuona stack, kwa mfano, ndani ya hex dump:

![Kuangalia stack ya shellcode iliyoemulatewa kwenye hex dump ya Cutter](<../../images/image (186).png>)

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

scDbg pia huja na kizindua cha picha kinachokuwezesha kuchagua chaguo unazotaka na kutekeleza shellcode

![Kizindua cha picha cha scDbg cha kuchagua chaguo za kuiga shellcode na kufuatilia](<../../images/image (258).png>)

Chaguo la **Create Dump** litadump shellcode ya mwisho ikiwa mabadiliko yoyote yamefanywa kwa shellcode hiyo wakati wa utekelezaji ndani ya memory (ni muhimu kwa kupakua shellcode iliyodecodewa). **start offset** inaweza kuwa muhimu ili kuanzisha shellcode kwenye offset maalum. Chaguo la **Debug Shell** ni muhimu kwa kutatua hitilafu za shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona chaguo zozote kati ya zilizoelezwa awali ni bora zaidi kwa jambo hili, kwa kuwa utaweza kutumia Ida au x64dbg).

### Kutenganisha maagizo kwa kutumia CyberChef

Pakia faili yako ya shellcode kama ingizo na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Kuondoa MBA obfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha vielezi rahisi kama vile `x + y` nyuma ya fomula zinazochanganya waendeshaji wa kihesabu (`+`, `-`, `*`) na wa bitwise (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba utambulisho huu kwa kawaida huwa sahihi tu chini ya **hesabu ya modular yenye upana maalum wa biti**, kwa hiyo carry na overflow ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya usemi kwa kutumia zana za aljebra za jumla, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za upana wa biti zilipuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi upana wa biti wa asili** kutoka kwenye msimbo/IR/decompiler iliyoinuliwa (`8/16/32/64` bits).
2. **Panga usemi katika aina yake** kabla ya kujaribu kuurahisisha:
   - **Wa mstari**: jumla zenye uzani wa atomi za bitwise
   - **Nusu-mstari**: wa mstari pamoja na masks za kudumu kama `x & 0xFF`
   - **Wa polinomu**: bidhaa zinajitokeza
   - **Mchanganyiko**: bidhaa na mantiki ya bitwise zimechanganywa, mara nyingi zikiwa na misemo midogo inayojirudia
3. **Thibitisha kila uandikaji upya unaowezekana** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa ulinganifu hauwezi kuthibitishwa, hifadhi usemi wa asili badala ya kukisia.

### Epuka mtiririko bapa wa udhibiti kwa kutumia sehemu finyu ya utekelezaji

Mara nyingi si lazima kurejesha grafu kamili ya mtiririko wa udhibiti. Katika hali za control-flow flattening, opaque predicates, dispatchers kubwa, au msimbo wenye MBA nyingi, fuatilia marejeleo kutoka kwa data fiche iliyosimbwa na bafa za matokeo hadi kwenye utaratibu mdogo zaidi unaozibadilisha. Kisha zalisha upya sehemu hiyo tu ya mtiririko wa data, au iendeshe kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa hali husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha sehemu zinazotekelezeka na za data, relocations, na marejeleo mtambuka. Dump jedwali teule kutoka `.rodata` huku ukihifadhi mpangilio wake wa baiti na upana wa vipengele.
2. Tambua utaratibu wa mwisho unaoandika maandishi ya wazi au bafa ya matokeo. Rekodi ingizo zake, jedwali inazorejelea, miito iliyoingizwa, na hali ya kimataifa inayohitajika.
3. Inua shughuli hizo pekee kwenye modeli ya Python yenye upana wa biti usiobadilika. Ikiwa sehemu hiyo bado inategemea hali nyingi mno, iite utaratibu huo chini ya Unicorn, QEMU, au debugger na uweke hooks kwenye imports zisizo muhimu badala ya kuiga programu nzima.
4. Thibitisha kuwa extractor inapata matokeo yake kutoka kwenye binary iliyotolewa: ondoa njia mbadala zilizofichwa, itafute majibu yaliyopachikwa, na iendeshe dhidi ya build ambazo haijaziona zenye strings, keys, identifiers, layouts, na mbegu za obfuscation zilizobadilishwa.

Amri muhimu za ukaguzi wa awali ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua expressions za MBA zinazoficha constants

Expression ya byte inayoonekana kutegemea input inaweza kufuta kabisa athari ya input. Baada ya kutoa tables zake, tathmini expression hiyo katika domain nzima ya 8-bit; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo ni constant bila kuhitaji kurejesha state machine inayoizunguka.<sup>[[7]](#references)</sup>

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

Keep mask ya mwisho kwa sababu addition ya awali huzunguka inapofikia upana wa byte. Kwa domain pana zaidi, uliza SMT solver ikiwa `f(x1) != f(x2)` inaweza kuridhishwa kwa symbolic inputs mbili zenye upana sawa: `unsat` huthibitisha invariance, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kutupwa.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis si lazima usababishe branch au crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye key bit, constant ya opaque-predicate, au hali ya flattened-dispatcher, ikaendelea kawaida, na kutoa plaintext inayoonekana kuwa ya kweli lakini si sahihi ndani ya emulator. Kwa hiyo, kupatch matawi ya failure yanayoonekana pekee hakutoshi; fuatilia data dependencies kutoka environment probes hadi kwenye hali ya decoder, linganisha slice ileile kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa uchanganuzi wa malware na reversing ya binaries zilizolindwa. Huainisha expression na kuipitisha kwenye pipelines maalum badala ya kutumia rewrite pass moja ya jumla kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini usemi kwa ingizo za Boolean, hutoa signature, na kujaribu mbinu kadhaa za urejeshaji kwa wakati mmoja, kama vile pattern matching, ubadilishaji wa ANF, na coefficient interpolation.
- **Semilinear MBA**: atomu zilizofichwa kwa constants hujengwa upya kwa kutumia bit-partitioned reconstruction ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: bidhaa hugawanywa katika cores, na subexpression zinazojirudia zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa identity mchanganyiko ambayo mara nyingi inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hii inaweza kurahisishwa kuwa:

```c
x * y
```

### Vidokezo vya reverse engineering

- Pendelea kuendesha CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga hesabu halisi.
- Tumia `--bitwidth` waziwazi ikiwa expression imetokana na masked arithmetic au registers nyembamba.
- Ikiwa unahitaji hatua ya uthibitisho yenye nguvu zaidi, angalia vidokezo vya Z3 vya hapa:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inapatikana kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kunormalize LLVM IR yenye MBA nyingi kabla ya kutumia analysis passes zinazofuata.
- Residuals zisizotumika zinazohitaji kuzingatia carry katika mixed-domain zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression ya awali na kufanyia uchanganuzi wa carry path mwenyewe.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa instruction sequences zinazotumia `mov`, na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation kwenye matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unashiriki **CTF, workaround hii ya kupata flag** inaweza kuwa na manufaa sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa `::main` kama hapa:

![Finding a Rust entry point in Ghidra by searching function names for double-colon main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni dhahiri kabisa kwamba hii ndiyo main function inayovutia.\
Ukiwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **inputs** na **outputs** zake.

### Kurejesha strings za Rust kutoka firmware ya ELF

Katika binaries za **Rust ELF**, strings nyingi tuli hazirejelewi kama pointers za C-style zilizokatishwa kwa NUL. Mpangilio wa kawaida wa `rustc` ni **tuple ya pointer/length** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa ndani ya **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Hii inamaanisha kuwa `strings` au uchanganuzi chaguomsingi wa Ghidra unaweza kuunganisha mifuatano ya maandishi iliyo jirani au kukosa kabisa marejeo mtambuka.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer ya string inayowezekana.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya sanity (kwa mfano, hifadhi urefu wa kati ya **baiti 4** na **baiti 100**).
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

Hii ni muhimu sana katika firmware reversing kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, majina ya RPC, ujumbe wa log, assertions, majina ya faili, config keys, command handlers, na logic inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda string data kwenye offsets za `.rodata` zilizorejelewa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeleo mazuri ya kurekebisha wazo hili ili litumike kwa **word sizes, endianness, na mpangilio wa sehemu** tofauti.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizocompiliwa za Delphi, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kureverse binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itatekeleza binary na kutatua majina ya functions kwa nguvu mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9) na breakpoint itasimama mwanzoni mwa code halisi.

Ukibonyeza kitufe katika application ya picha, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Kwa Go binaries za kawaida, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya functions katika IDA. Pakia Python plugin yake kwa kutumia **Alt+F7**.

Ikiwa unahitaji kureverse binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya functions.

### Rejesha metadata bila symbol table

Go executable iliyovuliwa bado inahitaji runtime metadata ili kuoanisha program counters na functions. [GoReSym](https://github.com/mandiant/GoReSym) hutafuta na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya functions, majina, njia za source, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikiwa inatumika huku ikibadilisha majina yaliyorejeshwa. Kwa mfano, Garble huhash vitambulishi na njia za package na huondoa taarifa za build, module na debug.<sup>[[12]](#references)</sup> Tokeni ya package iliyofichwa lazima ibaki ileile katika functions za package hiyo. Panga functions kulingana na tokeni inayojirudia, kadiria package moja kutokana na callees, strings na APIs zake, kisha tumia lebo hiyo ya package kwa kundi lote.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huunganisha uchimbaji wa runtime-symbol na utengenezaji wa marejeo safi pamoja na ulinganishaji wa control-flow-graph (CFG). Tumia hatua hizi kwa mpangilio:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator iliziondoa, linganisha sehemu za Go runtime iliyojumuishwa na runtime za marejeo zenye matoleo maalum. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Ichukulie hii kama uboreshaji uliothibitishwa kwa majaribio, si kizingiti cha jumla.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeo yanayolingana.** Tengeneza binaries safi za toleo la Go lililotambuliwa, usanifu lengwa na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazozalishwa na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama sanifu kutoka `0.0` hadi `1.0`. Ulinganishaji wake wa basic-block hutegemea ulinganisho wenye uzani wa instructions zinazofanana. Ulinganishaji wenye uhakika wa juu huhusisha functions zenye majina yaliyobadilishwa nasibu na implementation safi. Ulinganishaji dhaifu bado unaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia uhusiano wa calls, constants, strings na side effects, kisha ingiza ripoti ya JSON kwa kutumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenga hatua yoyote kati ya hizo, ilhali kwa chaguomsingi zote mbili hutumika kwa sababu metadata ya runtime iliyorejeshwa na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kihisabati: inlining, build flags, usanifu na tofauti za matoleo ya maktaba zinaweza kubadilisha umbo la grafu, kwa hivyo hifadhi functions ambazo hazijatatuliwa badala ya kulazimisha majina yasiyo na uhakika mkubwa.<sup>[[13]](#references)</sup>

### Kurejesha jedwali la string za Go

Binaries za Go huweka byte za string kutoka kila kifurushi kilichounganishwa katika jedwali moja linalofuatana. Vipengee havina kikomo cha NUL, na miundo ya runtime haionyeshi msingi wala ukubwa wa jedwali. Hata hivyo, compiler hupanga vipengee kwanza kwa urefu, kisha kwa alfabeti, katika mifumo ya uendeshaji na usanifu mbalimbali. Kwa hiyo, baada ya kupata kipengee kimoja, mchambuzi anaweza kupitia vipengee vilivyo karibu na kutumia marejeleo mtambuka ya data kuhusisha string na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha mchakato huu kiotomatiki katika IDA Pro na Ghidra. Acha auto-analysis imalize kwanza kwa sababu plugin hutegemea marejeleo mtambuka ya sehemu ya data. Anchor yake chaguomsingi ni string ya runtime `entersyscall`; kisha inaweza kuchanganua kuelekea upande wowote, kufafanua string zilizorejeshwa kwenye database, na kuhamisha ramani ya JSON inayohusisha string na functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa kifurushi cha function inayorejelea ili kutenganisha code ya application au malware na kelele za maktaba zilizounganishwa. Mbinu hii haiwezi kurejesha literal zilizoharibiwa na obfuscation, kama vile mabadiliko ya `-literals` ya Garble. Hata hivyo, inaweza kupanga string za runtime ambazo hazijafichwa kwa obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za Go runtime

Go hupachika maelezo ya aina za runtime yanayotumiwa na vipengele kama garbage collection. Build information inapofutwa au disassembler inaposhindwa kuchanganua metadata hii, maagizo yanaweza kuonekana kana kwamba yanapakia anwani za data zisizo na mpangilio, na eneo lengwa hubaki bila aina iliyobainishwa. Kurejesha metadata hubadilisha anwani hizo kuwa marejeleo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa kifurushi.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua aina za runtime kuwa ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwezesha uchanganuzi wa aina. Leta ripoti kwa kutumia plugin ya GoResolver ya IDA Pro au Ghidra ili kufafanua aina zilizorejeshwa na kutumia marejeleo yake katika hifadhidata ya uchanganuzi. Katika umbizo la ripoti lililoanzishwa na kipengele hiki, kutotumia `-y` huacha anwani ya RTTI na washiriki wa aina zilizorejeshwa wakiwa null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia sampuli za PE, ELF, na Mach-O za x86, AMD64, ARM, na ARM64, kwa hivyo mtiririko huo wa kazi unatumika pia kwa binary za Go za Windows, Linux, na macOS.<sup>[[10]](#references)</sup>

## Python Iliyokusanywa

Katika ukurasa huu unaweza kupata maelezo ya jinsi ya kupata msimbo wa python kutoka kwa binary ya python iliyokusanywa ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali ku**emulate** na **debug** mchezo huo:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye kiolesura
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![Usanidi wa vidhibiti vya no$gba unaoonyesha upangaji wa vitufe vya Game Boy Advance](<../../images/image (581).png>)

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

Kwa hiyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Katika anwani **0x4000130** utapata kazi inayopatikana kwa kawaida: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA inayorejelea KEYINPUT kwenye anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kuwa kazi hiyo inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika kazi hiyo, baada ya baadhi ya shughuli za uanzishaji (zisizo na umuhimu):

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

if ya mwisho inakagua kama **`uVar4`** imo kwenye **last Keys** na si ufunguo wa sasa; hali hii pia huitwa kuachia kitufe (ufunguo wa sasa umehifadhiwa kwenye **`uVar1`**).

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

Katika msimbo uliotangulia unaweza kuona kwamba tunalinganisha **uVar1** (mahali palipo **thamani ya kitufe kilichobonyezwa**) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika challenge, kitufe hiki husafisha skrini
- Kisha inalinganisha thamani hiyo na **8** (kitufe cha **START**); katika challenge hii, njia hiyo hukagua ikiwa msimbo ulioingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3, na thamani zikilingana, msimbo fulani hutekelezwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Kaunta ikiwa chini ya 8, thamani za vitufe vilivyobonyezwa hujumlishwa katika `DAT_030000d8`.

Kwa hiyo, katika challenge hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu wa chini ya 8 ambao jumla yake ni 0xf3.**

**Marejeleo ya mafunzo haya:** [maelezo ya challenge ya Nostalgia yaliyohifadhiwa kwenye kumbukumbu](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Uondoaji wa ufichaji wa binary)

## References

- [1] [Kurahisisha ufichaji wa MBA kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kufumbua strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa kwenye kumbukumbu)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering inayosaidiwa na AI, au angalau kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya kulinganisha Control Flow Graphs kwa kutumia ulinganishaji wa Basic Block](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repository ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mbinu ya ufichaji ya Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia ufanano wa Control-Flow Graph ili kuondoa ufichaji wa binary za Golang kiotomatiki](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repository ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Maboresho ya zana za Golang za Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Fanya Reverse Engineering kwa Kitu Chochote](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed-code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa CLI na Evidence wa REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
