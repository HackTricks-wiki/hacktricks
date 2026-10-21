# Zana za Reverse Engineering na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za reversing zinazotumia ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Uendeshaji otomatiki wa WinDbg katika user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Utatuzi wa kernel ya Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Online:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) ili **decompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) ili **compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa decompilation.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode iliyohifadhiwa kwenye cache ya Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads zilizovirtualishwa na VM maalum

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler inayofanya **decompile na kuchunguza fomati mbalimbali**, ikijumuisha **libraries** (.dll), **Windows metadata file**s (.winmd), na **executables** (.exe). Baada ya kufanyiwa decompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwa assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hurahisisha urambazaji ndani ya msimbo uliofanyiwa decompile, na kuifanya kuwa mojawapo ya zana bora za **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na modeli pana ya add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha uendelezaji. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa mwanga kuhusu jinsi data inavyopita kwenye library au component
- Hutoa mwanga kuhusu utekelezaji na matumizi ya lugha na framework za .NET
- Hupata utendaji usioandikwa kwenye nyaraka na usiofichuliwa ili uweze kutumia zaidi API na teknolojia husika.
- Hupata dependencies na assemblies mbalimbali
- Hufuatilia eneo halisi la hitilafu katika msimbo wako, components za wahusika wengine, na libraries.
- Hufanya debug kwenye chanzo cha msimbo wote wa .NET unaofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode; hakuna haja ya kupakua git. Bofya **Extensions** na **utafute ILSpy**).\
Ikiwa unahitaji **decompile**, **kurekebisha** na **kucompile upya**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed bila kutekeleza programu kwa kutumia REA

**REA** inaweza kukagua metadata ya PE/CLI na CIL bila kupakia assembly. Anza kwa kutambua utambulisho wa artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii ni muhimu unapochunguza miito inayotia shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa kulinganisha tofauti za matoleo, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na alama za vidole za maagizo yaliyofafanuliwa badala ya kuchukulia tokeni za metadata kuwa thabiti katika miundo mbalimbali. Tamko la P/Invoke si uthibitisho kwamba msimbo wa native uliendeshwa; `verify_managed_native_boundaries` inahitaji export ya native au Evidence ya function inayolingana ili kuthibitisha mpaka huo. Hifadhi digest ya artifact, MVID na mapangilio ambayo hayajatatuliwa pamoja na matokeo.<sup>[[17]](#references)</sup>

### Kuweka Kumbukumbu kwa DNSpy

Ili **kurekodi taarifa fulani kwenye faili kwa kutumia DNSpy**, unaweza kutumia kipande hiki cha msimbo:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Utatuzi wa hitilafu wa DNSpy

Ili kutatua hitilafu za code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **sifa za Assembly** zinazohusiana na **utatuzi wa hitilafu**:

![DNSpy Logging - Utatuzi wa hitilafu wa DNSpy: Kwanza, badilisha sifa za Assembly zinazohusiana na utatuzi wa hitilafu](<../../images/image (973).png>)

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

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** marekebisho kadhaa ya **optimisations** yatatumika kwenye code, na huenda **break-point isiwahi kufikiwa** wakati wa debugging au **variables zisiwepo**.

Kisha, ikiwa application yako ya .NET inaendeshwa na **IIS**, unaweza **restart** kwa kutumia:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, funga faili zote zilizofunguliwa, halafu kwenye **Debug Tab** chagua **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, funga faili zote zilizofunguliwa, halafu kwenye Debug Tab chagua Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuambatisha kwenye **IIS server**, halafu ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuambatisha kwenye IIS server, halafu ubofye attach](<../../images/image (113).png>)

Sasa tunafanya debugging ya process; wakati umefika kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Sasa tunafanya debugging ya process; wakati umefika kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Sasa tunafanya debugging ya process; wakati umefika kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules**, kisha uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules, kisha uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote kwenye **Assembly Explorer**, kisha ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote kwenye Assembly Explorer, kisha ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Kutumia IDA

- **Pakia rundll32** (64bits kwenye C:\Windows\System32\rundll32.exe na 32 bits kwenye C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimama kila DLL inapopakiwa**. Kwa hiyo, rundll32 itakapopakia DLL yako, utekelezaji utasimama.

Njia hii husimamisha utekelezaji kwenye matukio ya kupakia module, lakini kufika kwenye entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye workflow ya x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Pakia rundll32** (64bits kwenye C:\Windows\System32\rundll32.exe na 32 bits kwenye C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya DLL na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**. Debugger itasimama kwenye kila dll main; wakati fulani **utasimama kwenye DLL Entry ya DLL yako**. Kutoka hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kuwa utekelezaji unaposimamishwa kwa sababu yoyote kwenye win64dbg, unaweza kuona **uko kwenye code gani** kwa kuangalia **juu ya dirisha la win64dbg**:

![Kutumia IDA - Kutumia x64dbg/x32dbg: Kumbuka kuwa utekelezaji unaposimamishwa kwa sababu yoyote kwenye win64dbg, unaweza kuona uko kwenye code gani kwa kuangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha kuwa utekelezaji umesimama ndani ya DLL unayotaka kufanya debugging yake.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa kwenye memory ya game inayoendeshwa, na kuzibadilisha. Maelezo zaidi kwenye:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/tool ya reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti inayotumia decompilers mbalimbali. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

## Uchunguzi wa native unaotegemea ushahidi kwa kutumia REA

**REA** hutoa uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Sanidi kwanza provider iliyopo ya native; kagua `rea providers --json` na uchague provider wazi ikiwa zaidi ya mmoja anaweza kutumia target. Tumia jina au anwani ya function iliyoonekana kwenye inventory badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza na string au symbol ya kipengele, fuatilia marejeleo na callers, kisha kagua dossier na pseudocode za function iliyochaguliwa kwa `rea decompile`. REA hufunga session kwenye provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena tu bytes za artifact, provider, settings, operation na parameters zinazolingana; snapshot ni cache ya ndani, si database ya provider iliyohifadhiwa. Hifadhi Evidence iliyorudishwa na unknowns zilizo wazi badala ya kuchukulia njia zilizokisiwa au maandishi ya decompiler kama source asilia.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekea kwenye native add-ons, tazama [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Uchambuzi wa IDA na Ghidra kwa script kupitia local TCP bridge

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) huendeshwa ndani ya database ya IDA au program ya Ghidra CodeBrowser ambayo **tayari imefunguliwa**, na huruhusu script tofauti kuuliza na kurekebisha database hiyo ya uchambuzi. Endesha `ID_Server.py` kutoka IDA Python CLI (`import ID_Server`) au `Ghidra_Server.py` kutoka Ghidra Script Manager. IDA hufungamana na `127.0.0.1` kuanzia port `5073` na hukagua ports za juu zaidi. Script ya sasa ya Ghidra huanza port `5093` na hujaribu ports kumi hadi `5102`; Java socket yake hufungamana na wildcard address, si loopback pekee. Kagua port iliyochapishwa na instance kabla ya kuunganisha. Tofauti na headless analyzer, bridge hii hufanya kazi kwenye program iliyofunguliwa kwa sasa katika GUI instance hiyo.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Tuma **command moja inayoishia kwa newline kwa kila connection** na usome response inayoishia kwa newline. Matokeo kwa kawaida huwa JSON. Kwa mfano, baada ya kupata imported API inayohusiana na input path, `IMPORTXREF` hupata call sites zake; kisha `DECOMP_XREF` hufanya batch-decompile callers za address iliyochaguliwa. `FUNC` hukagua function, huku `PCODE` ikirudisha intermediate representation ya decompiler. Tumia address kutoka kwenye database inayotumika sasa, si address iliyonakiliwa kutoka kwenye binary iliyorebasewa tofauti. Mfano ulio hapa chini unatumia port chaguomsingi ya IDA; kwa Ghidra, tumia port iliyochapishwa na script yake.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Kituo hicho hicho kinaweza **kubadilisha hifadhidata ya uchanganuzi**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC`, na `PATCH` hubadilisha majina, aina, ufafanuzi wa miundo, mipaka ya functions, au bytes zilizohifadhiwa. `PATCH` ni uhariri wa hifadhidata, **si** ushahidi wa patch kwenye mchakato unaoendelea. Hakuna kati ya listener hizo inayoeleza kuhusu uthibitishaji. IDA husikiliza kwenye loopback pekee, lakini Ghidra inaweza kufikiwa kupitia interfaces za mtandao; zuia ufikiaji wa listener ya Ghidra unapoitumia. `QUIT` husimamisha listener yoyote kati ya hizo, na IDA pia hutoa `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kutatua shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **anwani yake ya kumbukumbu**, kisha husitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye anwani iliyochapishwa, kisha endeleza utekelezaji ili kutatua shellcode.

Ukurasa wa releases wa GitHub una faili za zip zenye matoleo yaliyokusanywa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililobadilishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kulikusanya, **tengeneza mradi wa C/C++ katika Visual Studio Code, nakili na ubandike code, kisha ujenge mradi huo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kutatua shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye kitanzi kisicho na mwisho. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha ndani ya kitanzi hicho, kisha songa hadi kwenye call inayofuata inayohamisha utekelezaji kwenda kwenye shellcode iliyotengwa.

![Debugger ikiwa imesitishwa ndani ya kitanzi kisicho na mwisho cha jmp2it, mara moja kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokusanywa la [jmp2it kwenye ukurasa wa releases](https://github.com/adamkramer/jmp2it/releases/).

### Kutatua shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuiga shellcode na kuichunguza wakati wa utekelezaji.

Kumbuka kuwa Cutter hukuruhusu kuchagua "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama faili, ili-decompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi wakati bytes zilezile zinafunguliwa kama faili au kama shellcode](<../../images/image (562).png>)

Ili kuanza uigaji mahali unapotaka, weka bp hapo; inaonekana Cutter itaanza uigaji moja kwa moja kutoka hapo:

![Kuweka breakpoint kwenye ingizo linalotakiwa la shellcode kabla ya kuanza uigaji wa Cutter](<../../images/image (589).png>)

![Emulator ya Cutter ikiwa imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Unaweza kuona stack, kwa mfano, ndani ya hex dump:

![Kuangalia stack ya shellcode iliyoigwa kwenye hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama vile shellcode inatumia **functions zipi** na kama shellcode **inajidecode** yenyewe kwenye kumbukumbu.

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

Chaguo la **Create Dump** litaondoa nakala ya mwisho ya shellcode ikiwa mabadiliko yoyote yatafanywa kwenye shellcode wakati inabadilika ndani ya memory (ni muhimu kwa kupakua shellcode iliyofumbuliwa). **start offset** inaweza kusaidia kuanzisha shellcode kwenye offset maalum. Chaguo la **Debug Shell** ni muhimu kwa kutatua hitilafu za shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona chaguo lolote kati ya yale yaliyoelezwa awali linafaa zaidi kwa hili, kwa kuwa utaweza kutumia Ida au x64dbg).

### Kutenganisha maagizo kwa kutumia CyberChef

Pakia faili yako ya shellcode kama ingizo na utumie recipe ifuatayo ili kuitenganisha: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Kuondoa obfuscation ya MBA

Obfuscation ya **Mixed Boolean-Arithmetic (MBA)** huficha expressions rahisi kama `x + y` nyuma ya fomula zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba utambulisho huu kwa kawaida huwa sahihi tu chini ya **hesabu ya moduli yenye upana usiobadilika**, kwa hiyo carry na overflow ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya usemi kwa kutumia zana za jumla za aljebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za upana wa biti zimepuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi upana wa biti wa asili** kutoka kwenye matokeo ya code/IR/decompiler iliyoinuliwa (`8/16/32/64` biti).
2. **ainisha usemi** kabla ya kujaribu kuurahisisha:
   - **Linear**: jumla zenye uzani za vipengele vya biti
   - **Semilinear**: linear pamoja na masks za kudumu kama `x & 0xFF`
   - **Polynomial**: kuna bidhaa
   - **Mixed**: bidhaa na mantiki ya biti zimechanganywa, mara nyingi kwa kutumia subexpressions zinazojirudia
3. **Thibitisha kila rewrite inayowezekana** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa usawa hauwezi kuthibitishwa, hifadhi usemi wa asili badala ya kubahatisha.

### Epuka control flow iliyoflatteniwa kwa kutumia kipande finyu cha utekelezaji

Mara nyingi si lazima kurejesha control-flow graph kamili. Katika hali za control-flow flattening, opaque predicates, dispatchers kubwa, au code yenye MBA nyingi, fuata marejeo kutoka kwenye blobs zilizosimbwa kwa njia fiche na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha zalisha upya kipande hicho cha data-flow pekee, au kitekeleze kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa hali husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha executable na data sections, relocations, na cross-references. Dump candidate tables kutoka `.rodata` huku ukihifadhi mpangilio wake wa byte na upana wa kila element.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, tables zinazorejelewa, imported calls, na hali ya global inayohitajika.
3. Inua operations hizo pekee kuwa fixed-width Python model. Ikiwa kipande bado kinategemea hali nyingi mno, iite routine hiyo chini ya Unicorn, QEMU, au debugger, na hook imports zisizohusika badala ya kuiga programu nzima.
4. Thibitisha kuwa extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa fallbacks zisizoonekana, itafute majibu yaliyopachikwa ndani yake, na iendeshe dhidi ya builds ambazo haijaziona zenye strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za hatua ya kwanza ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua expressions za MBA zilizofichwa kama constants

Expression ya byte inayoonekana kutegemea input inaweza kufuta kabisa athari ya input hiyo. Baada ya kutoa tables zake, tathmini expression hiyo katika domain nzima ya 8-bit; seti ya outputs yenye thamani moja inathibitisha kuwa byte hiyo ni constant, bila kuhitaji kurejesha state machine inayoizunguka.<sup>[[7]](#references)</sup>

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

Weka mask ya mwisho kwa sababu jumlisha ya awali huzunguka inapofikia upana wa byte. Kwa domain pana zaidi, iulize SMT solver ikiwa `f(x1) != f(x2)` inaweza kuwa kweli kwa inputs mbili za kimfano zenye upana sawa: `unsat` huthibitisha kutobadilika, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kutupiliwa mbali.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis hauhitaji kuwa na matawi au kusababisha crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye biti ya key, constant ya opaque-predicate, au state ya flattened-dispatcher, ikaendelea kama kawaida, na kutoa plaintext inayoonekana kuwa sahihi lakini si ya kweli ndani ya emulator. Kwa hiyo, kurekebisha matawi ya kushindwa yanayoonekana pekee hakutoshi; fuatilia utegemezi wa data kutoka kwa uchunguzi wa mazingira hadi kwenye state ya decoder, linganisha slice ileile kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni zana ya vitendo ya kurahisisha MBA kwa uchanganuzi wa malware na reversing ya binaries zilizolindwa. Huainisha expression na kuipitisha kwenye pipelines maalum badala ya kutumia pass moja ya jumla ya rewrite kwa kila kitu.<sup>[[2]](#references)</sup>

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

Matumizi yanayofaa:

- **Linear MBA**: CoBRA hutathmini expression kwa Boolean inputs, hupata signature, kisha huendesha kwa wakati mmoja mbinu kadhaa za recovery kama pattern matching, ANF conversion, na coefficient interpolation.
- **Semilinear MBA**: atoms zilizofunikwa kwa constant hujengwa upya kwa bit-partitioned reconstruction ili maeneo yaliyofunikwa yabaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa katika cores na subexpressions zinazorudiwa zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha outer relation.

Mfano wa mixed identity ambayo kwa kawaida inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hii inaweza kurahisishwa kuwa:

```c
x * y
```

### Vidokezo vya reverse engineering

- Pendelea kuendesha CoBRA kwenye **misemo ya IR iliyoinuliwa** au matokeo ya decompiler baada ya kutenga hesabu halisi.
- Tumia `--bitwidth` moja kwa moja ikiwa msemo ulitokana na masked arithmetic au registers nyembamba.
- Ikiwa unahitaji hatua madhubuti zaidi ya uthibitisho, angalia madokezo ya Z3 hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inapatikana kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kurekebisha LLVM IR yenye MBA nyingi kabla ya passes za uchanganuzi zinazofuata.
- Residuals mchanganyiko wa domains zisizotumika na zinazotegemea carry zichukulie kama ishara ya kuhifadhi msemo asilia na kuchunguza carry path mwenyewe.

## Kurejesha control-flow flattening ya XOR-state

Flattener ya mtindo wa OLLVM inaweza kuhifadhi state ya basic block ya sasa kwenye registers mbili za 64-bit na kuijenga upya kwa XOR kwenye dispatcher. Kila block asilia huandika jozi ya state kwa ajili ya state inayofuata kisha huruka kurudi kwenye dispatcher. Block yenye masharti inaweza kutumia `CMOVcc` kubadilisha nusu moja ya jozi kulingana na flags za CPU, kwa hiyo kufuata maagizo ya branch yanayoonekana pekee hukosa successors wawili. Tofauti na indirect-jump dispatcher, muundo huu unaweza kutumia direct back-edges kila mahali.<sup>[[19]](#references)[[20]](#references)</sup>

Ili kurejesha graph, tambua mti wa ulinganishaji wa dispatcher na registers mbili za state, unganisha kila XOR state iliyolinganishwa na block yake lengwa, kisha fuatilia maandishi yanayofika kwenye jozi ya registers katika kila block asilia. Kwa maandishi yenye masharti, jumuisha maagizo yanayoweka flags na matokeo yote mawili ya `CMOVcc`. Andika upya exit ya dispatcher ya kila block iwe direct successor yake iliyotatuliwa au conditional branch; dispatcher haitafikiwa tena bila kurekebisha binary. Hii ni mbinu ya full-CFG; ikiwa decoder moja tu ndiyo muhimu, [narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hapo juu inaweza kuwa ya haraka zaidi.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) huendesha mchakato huu kiotomatiki katika Binary Ninja. Nakili `plugins/DispatchThis` kwenye saraka ya plugins za mtumiaji ya Binary Ninja kisha uanzishe upya. Kwenye function iliyoathiriwa, fungua **Function Settings** na uchague `OLLVM_XOR_64`; ikiwa uchanganuzi hautaanza, tumia **Analysis → Reanalyze All Functions**. Hali hii huandika upya control-flow edges za MLIL, si bytes za faili, na haihitaji Z3 wala indirect-jump resolver. Imejaribiwa kwenye Binary Ninja 5.3.9757+; haiondoi maandishi ya dead per-block state, kwa hiyo usiyachanganye na transitions hai zilizosalia.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa mfuatano wa maagizo yanayotegemea `mov` na hutumia ushughulikiaji wa signal/exception kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation kwenye matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unashiriki kwenye **CTF, njia hii ya kutafuta flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta vitendaji kwa kutumia `::main` kama ilivyo hapa:

![Kupata entry point ya Rust katika Ghidra kwa kutafuta majina ya vitendaji yenye alama mbili za koloni kabla ya main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni wazi kabisa kwamba hiki ndicho kitendaji kikuu kinachovutia.\
Baada ya kupata **majina** ya **vitendaji** vinavyoitwa, vitafute kwenye **Internet** ili ujifunze kuhusu **ingizo** na **matokeo** yake.

### Kurejesha mifuatano ya Rust kutoka kwenye firmware ya ELF

Katika binary za **Rust ELF**, mifuatano mingi tuli hairejelewi kupitia viashiria vilivyokatishwa na NUL kama ilivyo katika C. Mpangilio wa kawaida wa `rustc` ni **jozi ya pointer/urefu** ndani ya **`.data.rel.ro`** inayoelekeza kwenye bloku halisi ya mfuatano iliyohifadhiwa katika **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Hii inamaanisha kuwa `strings` au uchanganuzi wa kawaida wa Ghidra unaweza kuunganisha mifuatano iliyo karibu au kukosa kabisa marejeleo mtambuka.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer inayoweza kuelekeza kwenye string.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya uthibitishaji wa mantiki (kwa mfano, hifadhi urefu kati ya **4** na **100** bytes).
6. Soma bytes `length` pekee kutoka `.rodata` badala ya kusoma hadi `0x00`.

Mantiki ya chini kabisa ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hii ni muhimu hasa katika firmware reversing kwa sababu Rust strings zilizorejeshwa mara nyingi hufichua **HTTP routes, majina ya RPC, ujumbe wa log, assertions, majina ya faili, config keys, command handlers, na mantiki inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda string data kwenye offsets za `.rodata` zilizorejelewa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hilo kwa **ukubwa mwingine wa neno, endianness, na mipangilio ya section**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binary zilizokompailiwa za Delphi, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kufanya reverse ya binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itatekeleza binary na kutatua majina ya function kwa nguvu mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itasimama mwanzoni mwa code halisi.

Ukibonyeza kitufe katika programu ya picha, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Kwa binary za kawaida za Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya function katika IDA. Pakia Python plugin yake kwa kubonyeza **Alt+F7**.

Ikiwa unahitaji kufanya reverse ya binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya function.

### Rejesha metadata bila symbol table

Go executable iliyovuliwa bado inahitaji runtime metadata ili kuoanisha program counters na function. [GoReSym](https://github.com/mandiant/GoReSym) hupata na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya function, majina, source paths, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikiwa inatumika huku ikibadilisha majina yaliyorejeshwa. Kwa mfano, Garble huhash vitambulishi na njia za package, na kuondoa taarifa za build, module na debug.<sup>[[12]](#references)</sup> Token ya package iliyofichwa lazima ibaki thabiti katika functions za package hiyo. Panga functions kwa token inayojirudia, tambua package moja kupitia callees, strings na APIs zake, kisha sambaza lebo hiyo ya package kwa kundi zima.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huchanganya uchimbaji wa runtime-symbol na uundaji wa marejeo safi pamoja na ulinganishaji wa control-flow-graph (CFG). Tumia mfuatano huu:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na version strings zilizopachikwa kwanza. Ikiwa obfuscator iliziondoa, linganisha sehemu za Go runtime iliyounganishwa na reference runtimes za matoleo tofauti. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Ichukulie hii kama uboreshaji uliothibitishwa kwa majaribio, si kiwango cha jumla.<sup>[[13]](#references)</sup>
2. **Tengeneza references zinazolingana.** Zalisha binaries safi kwa toleo la Go lililotambuliwa, target architecture na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazotokana na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama zilizosanifishwa kutoka `0.0` hadi `1.0`. Ulinganishaji wake wa basic-block unategemea ulinganishaji wenye uzani wa instructions zinazofanana. Ulinganishaji wenye uhakika mkubwa huunganisha functions zilizobadilishiwa majina nasibu na implementation safi. Ulinganishaji dhaifu bado unaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Switchi za `--extract` na `--graph` zinaweza kutenganisha hatua yoyote kati ya hizo, huku chaguo-msingi likiendesha zote mbili kwa sababu metadata ya runtime iliyorejeshwa na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kihisabati: inlining, build flags, usanifu na tofauti za matoleo ya library zinaweza kubadilisha umbo la graph, kwa hivyo hifadhi functions ambazo hazijatatuliwa badala ya kuzipa majina yasiyo na uhakika wa kutosha.<sup>[[13]](#references)</sup>

### Kurejesha jedwali la string la Go

Binaries za Go huweka byte za string kutoka kila package iliyounganishwa kwenye jedwali moja linaloendelea. Entries hazina kikomo cha NUL, na miundo ya runtime haionyeshi base au ukubwa wa jedwali. Hata hivyo, compiler hupanga entries kwanza kwa urefu na kisha kwa alfabeti, katika mifumo yote ya uendeshaji na usanifu. Kwa hiyo, baada ya kupata entry moja, mchambuzi anaweza kupitia entries zilizo karibu na kutumia marejeleo ya data ili kuhusisha strings na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha workflow hii kiotomatiki katika IDA Pro na Ghidra. Acha uchanganuzi otomatiki ukamilike kwanza kwa sababu plugin hutegemea cross-references za segmenti ya data. Anchor yake chaguomsingi ni string ya runtime `entersyscall`; kisha inaweza kuchanganua katika mwelekeo wowote, kufafanua strings zilizorejeshwa kwenye database, na kuhamisha JSON inayohusisha strings na functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa package ya function inayorejelea string ili kutenganisha code ya application au malware na kelele ya library zilizounganishwa. Mbinu hii haiwezi kurejesha literals zilizoharibiwa na obfuscation kama vile mabadiliko ya `-literals` ya Garble. Hata hivyo, inaweza kupanga strings za runtime ambazo hazijafichwa kwa obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za runtime za Go

Go hujumuisha taarifa za aina za runtime zinazotumiwa na vipengele kama vile garbage collection. Build information inapofutwa au disassembler isipokuwa metadata hii, maagizo yanaweza kuonekana kana kwamba yanapakia anwani za data zisizohusiana na eneo lengwa hubaki bila aina. Kurejesha metadata hubadilisha anwani hizo kuwa marejeleo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua aina za runtime kuwa ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwasha uchanganuzi wa types. Ingiza ripoti kwa kutumia plugin ya IDA Pro au Ghidra ya GoResolver ili kufafanua types zilizorejeshwa na kutumia marejeleo yake kwenye hifadhidata ya uchanganuzi. Katika muundo wa ripoti ulioanzishwa na kipengele hiki, ukiacha `-y`, anwani ya RTTI na sehemu za types zilizorejeshwa zitakuwa null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia sampuli za PE, ELF, na Mach-O za x86, AMD64, ARM, na ARM64, kwa hivyo mtiririko huo huo wa kazi hutumika kwa binaries za Go kutoka Windows, Linux, na macOS.<sup>[[10]](#references)</sup>

## Python iliyokusanywa

Katika ukurasa huu unaweza kupata maelezo ya jinsi ya kupata msimbo wa python kutoka kwenye binary ya python iliyokusanywa ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana tofauti **kuiga** na **ku-debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye kiolesura
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![Mipangilio ya vidhibiti vya no$gba inayoonyesha ulinganifu wa vitufe vya Game Boy Advance](<../../images/image (581).png>)

Vinapobonyezwa, kila **kitufe huwa na thamani** ya kukitambulisha:

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

Kwa hiyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Katika anwani **0x4000130** utapata function inayopatikana kwa kawaida: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA unaorejelea KEYINPUT katika anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya baadhi ya shughuli za init (zisizo na umuhimu wowote):

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

if ya mwisho inakagua kama **`uVar4`** imo kwenye Keys za awali na si key ya sasa, hali inayojulikana pia kama kuachia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).

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

Katika code iliyotangulia, unaweza kuona kwamba tunalinganisha **uVar1** (mahali ilipo **thamani ya kitufe kilichobonyezwa**) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto hii, kitufe hiki hufuta skrini
- Kisha thamani hiyo inalinganishwa na **8** (kitufe cha **START**); katika changamoto hii, njia hiyo hukagua kama code iliyoingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3, na ikiwa thamani hizo zinafanana, code fulani huendeshwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Kaunta ikiwa chini ya 8, thamani za funguo zilizobonyezwa hujumlishwa kwenye `DAT_030000d8`.

Kwa hiyo, katika changamoto hii, ukijua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu chini ya 8 ambao jumla yake ni 0xf3.**

**Rejeleo la mafunzo haya:** [maelezo ya changamoto ya Nostalgia yaliyohifadhiwa kwenye kumbukumbu](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Kurahisisha obfuscation ya MBA kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hifadhi ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kusimbua string za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa kwenye kumbukumbu)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering Inayosaidiwa na AI, au Angalau Kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya Kulinganisha Control Flow Graphs kwa Kutumia Ulinganishaji wa Basic Blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Hifadhi ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Utaratibu wa obfuscation wa Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia Ufanano wa Control-Flow Graph ili Kuondoa Obfuscation kwenye Binaries za Golang Kiotomatiki](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Hifadhi ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Maboresho ya Volexity Golang Tooling](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Chochote](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa REA CLI na Evidence](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Mtiririko wa kazi wa Binary Ninja wa kuondoa control-flow flattening](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Uvamizi wa PaperCut MF wa Zero-Day, Java Loader, Web Shell na AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README ya IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Utekelezaji wa IDA bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Utekelezaji wa Ghidra bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) hufunga kwenye anwani ya wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
