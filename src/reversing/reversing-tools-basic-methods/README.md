# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za reversing zinazotumia ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Uendeshaji wa WinDbg katika user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Control flow ya Windows inayoendeshwa na exceptions

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Utatuzi wa Windows kernel

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Online:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kufanya **decompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kufanya **compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa ajili ya decompilation.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode ya Node.js / V8 iliyo kwenye cache

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads zilizovirtualize na VMs maalum

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler inayofanya **decompile na kuchunguza formats mbalimbali**, ikiwemo **libraries** (.dll), **Windows metadata files** (.winmd), na **executables** (.exe). Baada ya kufanya decompile, assembly inaweza kuhifadhiwa kama project ya Visual Studio (.csproj).

Faida yake ni kwamba, ikiwa source code iliyopotea inahitaji kurejeshwa kutoka kwa assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hurahisisha kuvinjari code iliyofanyiwa decompile, na kuifanya kuwa mojawapo ya zana bora za **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na mfumo mpana wa add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha development. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa ufahamu kuhusu jinsi data inavyopita kwenye library au component
- Hutoa ufahamu kuhusu utekelezaji na matumizi ya lugha na frameworks za .NET
- Hupata functionality isiyoandikwa kwenye nyaraka na isiyoonyeshwa, ili kufaidika zaidi na APIs na technologies zinazotumika.
- Hupata dependencies na assemblies mbalimbali
- Hufuatilia mahali hasa pa makosa kwenye code yako, third-party components, na libraries.
- Hufanya debug kwenye source ya code yote ya .NET unayotumia.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin ya Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bofya **Extensions** na **utafute ILSpy**).\
Ikiwa unahitaji kufanya **decompile**, **modify** na **compile tena**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayotunzwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed code bila kuiendesha kwa kutumia REA

**REA** inaweza kukagua PE/CLI metadata na CIL bila kupakia assembly. Anza kwa kutambua artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii ni muhimu unapokagua calls zinazotiliwa shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa version diffing, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na alama za vidole za decoded-instruction badala ya kuchukulia metadata tokens kuwa thabiti kati ya builds. P/Invoke declaration si uthibitisho kwamba native code iliendeshwa; `verify_managed_native_boundaries` inahitaji native export au function Evidence inayolingana ili kukagua mpaka huo. Hifadhi artifact digest, MVID na unresolved mappings pamoja na matokeo.<sup>[[17]](#references)</sup>

### DNSpy Logging

Ili kufanya **DNSpy irekodi taarifa fulani kwenye faili**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Utatuzi wa hitilafu kwa DNSpy

Ili kutatua hitilafu katika code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **sifa za Assembly** zinazohusiana na **utatuzi wa hitilafu**:

![Kuweka kumbukumbu katika DNSpy - Utatuzi wa hitilafu kwa DNSpy: Kwanza, badilisha sifa za Assembly zinazohusiana na utatuzi wa hitilafu](<../../images/image (973).png>)

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

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** msimbo utaboreshwa kwa kutumia **optimisations** kadhaa, na huenda **breakpoint** isiwahi kufikiwa unapofanya **debugging**, au baadhi ya **variables** zisiwepo.

Kisha, ikiwa programu yako ya .NET inaendeshwa na **IIS**, unaweza kuianzisha upya kwa kutumia:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na uchague **Attach to Process...** ndani ya **Debug Tab**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa na uchague Attach to Process ndani ya Debug Tab](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuambatisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuambatisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote katika **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote katika Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote katika **Assembly Explorer** na ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote katika Assembly Explorer na ubofye Sort Assemblies](<../../images/image (339).png>)

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

Kisha, unapoanza debugging, **utekelezaji utasimama kila DLL inapopakiwa**; kwa hiyo, rundll32 inapopakia DLL yako, utekelezaji utasimama.

Njia hii husimamisha utekelezaji kwenye matukio ya kupakiwa kwa module, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye workflow ya x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**; debugger itasimama kwenye kila dll main, na wakati fulani **utasimama kwenye DLL Entry ya dll yako**. Kuanzia hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba utekelezaji unaposimama kwa sababu yoyote katika win64dbg, unaweza kuona **uko kwenye code gani** kwa kuangalia **juu ya dirisha la win64dbg**:

![Kutumia IDA - Kutumia x64dbg/x32dbg: Kumbuka kwamba utekelezaji unaposimama kwa sababu yoyote katika win64dbg, unaweza kuona uko kwenye code gani kwa kuangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki huthibitisha kwamba utekelezaji umesimama ndani ya DLL unayotaka kufanya debugging yake.

## Programu za GUI / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa kwenye memory ya game inayoendeshwa, na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni zana ya front-end/reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti kwa decompilers kadhaa. Huduma hii ya wavuti hukuruhusu kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

## Uchunguzi wa native unaoungwa mkono na ushahidi kwa kutumia REA

**REA** hutoa uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Sanidi kwanza provider iliyopo ya native; angalia `rea providers --json` na uchague provider mahususi ikiwa zaidi ya mmoja anaunga mkono target. Tumia jina la function au address iliyoonekana kwenye inventory badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza na feature string au symbol, fuata references na callers, kisha kagua function dossier na pseudocode ya function iliyochaguliwa ukitumia `rea decompile`. REA hufunga session kwenye provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena bytes za artifact, provider, settings, operation na parameters zinazolingana pekee; snapshot ni cache ya ndani, si database ya provider iliyohifadhiwa. Hifadhi Evidence iliyorejeshwa na unknowns zilizo wazi badala ya kuchukulia paths zilizokisiwa au maandishi ya decompiler kuwa source asilia.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekea kwenye native add-ons, angalia [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Uchambuzi wa IDA na Ghidra kwa script kupitia daraja la TCP la ndani

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) huendeshwa ndani ya database ya IDA au programu ya Ghidra CodeBrowser ambayo **tayari imefunguliwa**, na huruhusu script tofauti kutuma queries na kufanya marekebisho kwenye database hiyo ya uchambuzi. Endesha `ID_Server.py` kutoka IDA Python CLI (`import ID_Server`) au `Ghidra_Server.py` kutoka Ghidra Script Manager. IDA hufunga kwenye `127.0.0.1` ikianzia port `5073` na hukagua port za juu zaidi. Script ya sasa ya Ghidra huanzia port `5093` na hujaribu port kumi hadi `5102`; socket yake ya Java hufunga kwenye wildcard address, si loopback pekee. Angalia port iliyochapishwa na instance kabla ya kuunganisha. Tofauti na headless analyzer, daraja hili hufanya kazi kwenye program iliyofunguliwa kwa sasa katika instance hiyo ya GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Tuma **command moja inayoishia kwa newline kwa kila connection**, kisha soma response inayoishia kwa newline. Matokeo kwa kawaida huwa JSON. Kwa mfano, baada ya kupata API iliyoimportiwa inayohusiana na input path, `IMPORTXREF` hupata call sites zake; kisha `DECOMP_XREF` hufanya decompile kwa batch ya callers wa address iliyochaguliwa. `FUNC` hukagua function, huku `PCODE` ikirejesha intermediate representation ya decompiler. Tumia address kutoka kwenye database inayotumika, si address iliyonakiliwa kutoka kwenye binary iliyorebase kwa namna tofauti. Mfano ulio hapa chini unatumia port chaguomsingi ya IDA; kwa Ghidra, tumia port iliyochapishwa na script yake.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Chaneli hiyo hiyo inaweza **kubadilisha hifadhidata ya uchanganuzi**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC`, na `PATCH` hubadilisha majina, aina, ufafanuzi wa miundo, mipaka ya functions, au baiti zilizohifadhiwa. `PATCH` ni mabadiliko ya hifadhidata, **si** ushahidi wa patch kwenye mchakato unaoendelea. Hakuna listener inayoeleza kuhusu authentication. IDA husikiliza kwenye loopback pekee, lakini Ghidra inaweza kufikiwa kupitia interfaces za mtandao; zuia ufikiaji wa listener ya Ghidra unapoitumia. `QUIT` husimamisha listener yoyote kati ya hizo, na IDA pia hutoa `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kudebug shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **anwani yake ya kumbukumbu**, kisha husitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye anwani iliyochapishwa, kisha endeleza utekelezaji ili kudebug shellcode.

Ukurasa wa GitHub wa releases una faili za zip zenye matoleo yaliyokompailiwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililorekebishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kulikompaili, **unda tu mradi wa C/C++ kwenye Visual Studio Code, nakili na ubandike code, kisha uijenge**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kudebug shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye kitanzi kisichoisha. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha ndani ya kitanzi hicho, kisha piga hatua hadi kwenye call inayofuata inayohamisha utekelezaji kwenye shellcode iliyotengwa.

![Debugger imesitishwa ndani ya kitanzi kisichoisha cha jmp2it, kabla tu ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokompailiwa la [jmp2it kwenye ukurasa wa releases](https://github.com/adamkramer/jmp2it/releases/).

### Kudebug shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuemulate shellcode na kuichunguza inapotekelezwa.

Kumbuka kwamba Cutter inaruhusu kuchagua "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama faili, iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi inapofungua baiti zilezile kama faili au shellcode](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo; inaonekana Cutter itaanza emulation moja kwa moja kutoka hapo:

![Kuweka breakpoint kwenye sehemu inayotakiwa ya kuanzia ya shellcode kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Emulator ya Cutter imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode inayoemulatewa ndani ya hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama vile **ni functions zipi** zinazotumiwa na shellcode na kama shellcode **inajidecode** yenyewe kwenye kumbukumbu.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg pia ina launcher ya picha ambapo unaweza kuchagua options unazotaka na kutekeleza shellcode

![scDbg graphical launcher for selecting shellcode emulation and tracing options](<../../images/image (258).png>)

Option ya **Create Dump** itadump shellcode ya mwisho ikiwa kuna mabadiliko yaliyofanywa kwa shellcode kwenye memory wakati wa utekelezaji (ni muhimu kwa kupakua shellcode iliyodecodeiwa). **start offset** inaweza kusaidia kuanzisha shellcode kutoka offset maalum. Option ya **Debug Shell** ni muhimu kwa kudebug shellcode ukitumia terminal ya scDbg (hata hivyo, naona options zilizoelezwa hapo awali ni bora zaidi kwa kazi hii kwa sababu utaweza kutumia Ida au x64dbg).

### Ku-disassemble kwa kutumia CyberChef

Pakia faili yako ya shellcode kama input na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama `x + y` ndani ya formulas zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, kwa hiyo carries na overflows ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukiirahisisha aina hii ya usemi kwa kutumia zana za jumla za aljebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za bit-width zimepuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi bit-width ya awali** kutoka kwenye msimbo/IR/decompiler output iliyoinuliwa (`8/16/32/64` bits).
2. **Panga usemi katika kundi** kabla ya kujaribu kuurahisisha:
   - **Linear**: jumla zenye uzani za atoms za bitwise
   - **Semilinear**: linear pamoja na masks zisizobadilika kama `x & 0xFF`
   - **Polynomial**: kuna bidhaa
   - **Mixed**: bidhaa na mantiki ya bitwise zimechanganywa, mara nyingi zikiwa na subexpressions zinazojirudia
3. **Thibitisha kila rewrite inayowezekana** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi usemi wa awali badala ya kubashiri.

### Bypass control flow iliyolainishwa kwa kutumia kipande chembamba cha utekelezaji

Mara nyingi si lazima kurejesha control-flow graph nzima. Katika hali za control-flow flattening, opaque predicates, dispatchers kubwa, au msimbo mzito wa MBA, fuatilia marejeleo kutoka kwenye blobs zilizosimbwa kwa njia fiche na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha nakili tu kipande hicho cha data-flow, au kitekeleze kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa hali husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha sehemu za executable na data, relocations, na cross-references. Dump candidate tables kutoka `.rodata` huku ukihifadhi mpangilio wa bytes na upana wa kila element.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, tables inazorejelea, imported calls, na global state inayohitajika.
3. Inua operations hizo pekee kwenye fixed-width Python model. Ikiwa kipande hicho bado kinategemea state nyingi mno, iite routine hiyo chini ya Unicorn, QEMU, au debugger na hook imports zisizo muhimu badala ya kuiga programu nzima.
4. Thibitisha kuwa extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa silent fallbacks, itafute majibu yaliyopachikwa ndani yake, na iendeshe dhidi ya builds ambazo haijaziona zenye strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za ukaguzi wa awali ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua expressions za MBA zilizofichwa kama constants

Expression ya byte inayoonekana kutegemea input inaweza kufuta kabisa input hiyo. Baada ya kutoa tables zake, tathmini expression hiyo katika domain kamili ya 8-bit; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo ni constant bila kurejesha state machine inayoizunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu addition ya awali ina wraparound ya upana wa byte. Kwa domain pana zaidi, iulize SMT solver ikiwa `f(x1) != f(x2)` inaweza kutimizwa kwa symbolic inputs mbili zenye upana sawa: `unsat` inathibitisha invariance, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kutupiliwa mbali.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis si lazima ufanye branch au kusababisha crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye key bit, constant ya opaque-predicate, au state ya flattened-dispatcher, ikaendelea kama kawaida, na kutoa plaintext inayowezekana lakini isiyo sahihi kwenye emulator. Kwa hiyo, kupatch visible failure branches pekee hakutoshi; fuatilia data dependencies kutoka environment probes hadi decoder state, linganisha slice ileile kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa malware analysis na reversing ya protected binaries. Huainisha expression na kuipitisha kwenye pipelines maalum badala ya kutumia generic rewrite pass moja kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini usemi kwa thamani za Boolean, hupata signature, na hushindanisha mbinu kadhaa za recovery kama pattern matching, ubadilishaji wa ANF, na coefficient interpolation.
- **Semilinear MBA**: atomu zilizofunikwa na constant hujengwa upya kwa kutumia bit-partitioned reconstruction ili maeneo yaliyofunikwa yabaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa kuwa cores, na subexpressions zinazorudiwa zinaweza kuhamishwa kwenye temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa identity mchanganyiko ambayo mara nyingi inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hii inaweza kufupishwa kuwa:

```c
x * y
```

### Vidokezo vya reversing

- Pendelea kutumia CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kutenga hesabu husika.
- Tumia `--bitwidth` waziwazi ikiwa expression imetokana na masked arithmetic au narrow registers.
- Ikiwa unahitaji hatua ya uthibitisho imara zaidi, angalia notes za Z3 hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia husambazwa kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kunormalize LLVM IR yenye MBA nyingi kabla ya kutumia analysis passes za baadaye.
- Residuals mchanganyiko wa domains ambazo hazitumiki na ambazo zinategemea carry zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression ya awali na kuchanganua njia ya carry kwa mikono.

## Kurejesha control-flow flattening ya XOR-state

Flattener ya mtindo wa OLLVM inaweza kuhifadhi hali ya basic block ya sasa katika registers mbili za biti 64 na kuijenga upya kwa kutumia XOR kwenye dispatcher. Kila block ya awali huandika jozi ya hali ya state inayofuata na kuruka kurudi kwenye dispatcher. Block ya masharti inaweza kutumia `CMOVcc` kubadilisha nusu moja ya jozi kulingana na CPU flags, kwa hiyo kufuata maagizo ya branch yanayoonekana pekee kutakufanya ukose successors wawili. Tofauti na dispatcher ya indirect-jump, muundo huu unaweza kutumia back-edges za moja kwa moja kila mahali.<sup>[[19]](#references)[[20]](#references)</sup>

Ili kurejesha graph, tambua mti wa ulinganishaji wa dispatcher na registers mbili za state, linganisha kila XOR state inayolinganishwa na block inayolengwa, kisha fuatilia writes zinazofikia jozi ya registers katika kila block ya awali. Kwa conditional writes, jumuisha maagizo yanayoweka flags na matokeo yote mawili ya `CMOVcc`. Andika upya kutoka kwa kila block kwenda kwa dispatcher kuwa successor yake ya moja kwa moja iliyobainishwa au conditional branch; hivyo dispatcher haitafikiwa tena bila kurekebisha binary. Hii ni mbinu ya full-CFG; ikiwa decoder moja tu ndiyo muhimu, workflow ya [narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hapo juu inaweza kuwa ya haraka zaidi.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) hufanya automation ya muundo huu katika Binary Ninja. Nakili `plugins/DispatchThis` kwenye saraka ya user plugin ya Binary Ninja kisha uwashe upya. Kwenye function iliyoathirika, fungua **Function Settings** na uchague `OLLVM_XOR_64`; ikiwa analysis haianzi, tumia **Analysis → Reanalyze All Functions**. Hali hii huandika upya control-flow edges za MLIL, si byte za faili, na haihitaji Z3 wala indirect-jump resolver. Imejaribiwa kwenye Binary Ninja 5.3.9757+; haiondoi state writes zilizokufa kwa kila block, kwa hiyo usizichukulie kimakosa kama transitions zinazoendelea kutumika.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa mfuatano wa maagizo yanayotumia `mov` na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation ya matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unashiriki kwenye **CTF, njia hii ya mkato ya kupata flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa kutumia `::main` kama ilivyo hapa:

![Kupata entry point ya Rust kwenye Ghidra kwa kutafuta majina ya functions yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni wazi kabisa kuwa hii ndiyo main function inayovutia.\
Ukiwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **pembejeo** na **matokeo** yake.

### Kurejesha strings za Rust kutoka kwenye firmware ya ELF

Katika binaries za **Rust ELF**, strings nyingi tuli hazirejelewi kwa kutumia pointers zinazomalizika kwa NUL kama ilivyo kwa C. Muundo wa kawaida wa `rustc` ni **tuple ya pointer/urefu** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa ndani ya **`.rodata`**:

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
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer inayoweza kuelekeza kwenye string.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya kukagua uhalali (kwa mfano, hifadhi urefu wa kati ya **baiti 4** na **100**).
6. Soma baiti `length` pekee kutoka `.rodata` badala ya kusoma hadi `0x00`.

Mantiki ndogo ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hili ni muhimu hasa katika reverse engineering ya firmware, kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, RPC names, ujumbe wa logi, assertions, majina ya faili, config keys, command handlers na mantiki inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda string data kwenye offsets za `.rodata` zilizorejelewa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hilo kwa **word sizes, endianness na miundo ya sections** tofauti.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries za Delphi zilizocompile, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kufanya reverse engineering ya binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itaendesha binary na kutatua majina ya functions kwa nguvu mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itafikiwa mwanzoni mwa code halisi.

Ukibonyeza kitufe kwenye programu ya picha, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Kwa binaries za kawaida za Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya functions katika IDA. Pakia Python plugin yake kwa **Alt+F7**.

Ikiwa unahitaji kufanya reverse engineering ya binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya functions.

### Rejesha metadata bila symbol table

Executable ya Go iliyovuliwa symbols bado huhitaji runtime metadata ili kuoanisha program counters na functions. [GoReSym](https://github.com/mandiant/GoReSym) hutafuta na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya functions, majina, source paths, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

An obfuscator inaweza kuacha miundo hiyo ikiwa inatumika huku ikibadilisha majina yaliyorejeshwa. Kwa mfano, Garble huhash vitambulishi na njia za package na huondoa maelezo ya build, module na debug.<sup>[[12]](#references)</sup> Tokeni iliyofichwa ya package lazima ibaki ileile katika functions kutoka package hiyo. Panga functions kwa tokeni inayojirudia, kadiria package moja kutokana na callees, strings na APIs zake, kisha tumia lebo ya package hiyo kwa kundi zima.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huunganisha utoaji wa alama za runtime na utengenezaji wa marejeleo safi pamoja na ulinganishaji wa control-flow graph (CFG). Tumia mfuatano huu:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator imeziondoa, linganisha sehemu za Go runtime iliyojumuishwa na reference runtimes zenye matoleo maalum. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Ichukulie hii kama uboreshaji uliotokana na majaribio, si kiwango kinachotumika kila mahali.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeleo yanayolingana.** Tengeneza binaries safi za toleo la Go lililotambuliwa, architecture lengwa na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazozalishwa na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama zilizosanifishwa kutoka `0.0` hadi `1.0`. Ulinganishaji wa basic-blocks unategemea ulinganishaji wenye uzani wa instructions zinazofanana. Matches zenye uhakika mkubwa huunganisha functions zenye majina yaliyobadilishwa nasibu na implementation safi. Matches dhaifu bado zinaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia mahusiano ya calls, constants, strings na side effects, kisha uingize ripoti ya JSON kwa kutumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenga hatua mojawapo, huku chaguomsingi ikiendesha zote mbili kwa sababu metadata ya runtime iliyorejeshwa na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kihisia: inlining, build flags, usanifu na tofauti za matoleo ya library zinaweza kubadilisha umbo la grafu, kwa hiyo hifadhi functions ambazo hazijatatuliwa badala ya kulazimisha majina yasiyo na uhakika mkubwa.<sup>[[13]](#references)</sup>

### Kurejesha jedwali la string za Go

Binaries za Go huweka bytes za string kutoka kila package iliyounganishwa katika jedwali moja linaloendelea. Entries hazimalizwi kwa NUL na miundo ya runtime haionyeshi msingi au ukubwa wa jedwali. Hata hivyo, compiler hupanga entries kwanza kwa urefu, kisha kialfabeti katika mifumo ya uendeshaji na usanifu mbalimbali. Baada ya kupata entry moja, mchambuzi anaweza kutembea kwenye entries zilizo karibu na kutumia marejeleo mtambuka ya data kuhusisha strings na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha workflow hii kiotomatiki katika IDA Pro na Ghidra. Kwanza subiri uchanganuzi otomatiki ukamilike kwa sababu plugin hutegemea marejeleo mtambuka ya segment ya data. Anchor yake chaguomsingi ni string ya runtime `entersyscall`; kisha inaweza kuchanganua upande wowote, kufafanua strings zilizorejeshwa kwenye database na kuhamisha ramani ya JSON inayoonyesha strings na functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa package ya function inayorejelea ili kutenganisha code ya application au malware na kelele za library zilizounganishwa. Mbinu hii haiwezi kurejesha literals zilizoharibiwa na obfuscation kama vile mabadiliko ya Garble ya `-literals`. Bado inaweza kupanga strings za runtime ambazo hazijafichwa kwa obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za runtime za Go

Go hujumuisha maelezo ya aina ya runtime yanayotumiwa na vipengele kama vile garbage collection. Build information inapoondolewa au disassembler inaposhindwa kuchanganua metadata hii, maagizo yanaweza kuonekana kana kwamba yanapakia anwani za data zisizohusiana na eneo lengwa hubaki bila aina. Kurejesha metadata hubadilisha anwani hizo kuwa marejeleo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua aina za runtime kuwa ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwasha uchanganuzi wa aina. Leta ripoti kwa kutumia plugin ya IDA Pro au Ghidra ya GoResolver ili kufafanua aina zilizopatikana na kutumia marejeleo yake kwenye hifadhidata ya uchanganuzi. Katika muundo wa ripoti ulioanzishwa na kipengele hiki, ukiacha `-y`, sehemu za anwani ya RTTI na aina zilizopatikana huwa null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia sampuli za PE, ELF, na Mach-O za x86, AMD64, ARM, na ARM64, kwa hivyo mchakato huohuo hutumika kwa binary za Go kutoka Windows, Linux, na macOS.<sup>[[10]](#references)</sup>

## Python Iliyokompailiwa

Katika ukurasa huu unaweza kupata jinsi ya kupata msimbo wa Python kutoka kwenye binary ya Python iliyokompailiwa ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali kuiga na kufanya **debug** yake:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye kiolesura
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![Usanidi wa vidhibiti vya no$gba unaoonyesha mpangilio wa vitufe vya Game Boy Advance](<../../images/image (581).png>)

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

Kwa hiyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Kwenye anwani **0x4000130** utapata function inayopatikana kwa kawaida: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA inayorejelea KEYINPUT kwenye anwani 0x4000130](<../../images/image (447).png>)

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

Imepata msimbo huu:

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

`if` ya mwisho inakagua ikiwa **`uVar4`** iko kwenye **Keys** za awali na si key ya sasa; hii pia huitwa kuachia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).

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

Katika code iliyotangulia unaweza kuona kwamba tunalinganisha **uVar1** (mahali palipo **thamani ya kitufe kilichobonyezwa**) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika challenge, kitufe hiki husafisha skrini.
- Kisha thamani inalinganishwa na **8** (kitufe cha **START**); katika challenge hii, njia hiyo hukagua kama code iliyoingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3 na ikiwa thamani ni sawa, code fulani hutekelezwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Wakati kaunta iko chini ya 8, thamani za vitufe vilivyobonyezwa hukusanywa katika `DAT_030000d8`.

Kwa hiyo, katika challenge hii, ukijua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu chini ya 8 ambao jumla yake ni 0xf3.**

**Marejeleo ya mafunzo haya:** [maelezo ya challenge ya Nostalgia yaliyohifadhiwa](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Uondoaji wa ufichaji wa binary)

## References

- [1] [Kurahisisha ufichaji wa MBA kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hazina ya CoBRA ya Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Kutatua strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - strings za Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda reverse engineering inayosaidiwa na AI, au angalau kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya kulinganisha grafu za mtiririko wa udhibiti kwa kutumia ulinganishaji wa basic blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Hazina ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mbinu ya ufichaji ya Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia ufanano wa grafu za mtiririko wa udhibiti kuondoa ufichaji wa binary za Golang kiotomatiki](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Hazina ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Maboresho ya zana za Golang za Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Chochote](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa CLI na Evidence wa REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Mtiririko wa kazi wa Binary Ninja wa kuondoa control-flow flattening](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Uvamizi wa PaperCut MF Zero-Day, Java Loader, Web Shell na AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README ya IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Utekelezaji wa seva ya IDA bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Utekelezaji wa seva ya Ghidra bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) hufunga kwenye anwani ya wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
