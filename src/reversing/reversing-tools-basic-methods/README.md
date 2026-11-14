# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za reversing zinazotegemea ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Uendeshaji otomatiki wa WinDbg user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Mtiririko wa udhibiti wa Windows unaoendeshwa na exceptions

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Utatuzi wa hitilafu za Windows kernel

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kufanya **decompile** kutoka wasm (binary) hadi wat (maandishi ya kawaida)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kufanya **compile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa ajili ya decompilation.

Programu:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode iliyohifadhiwa kwenye cache ya Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads zilizovirtualishwa na VMs maalum

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler inayofanya **decompile na kuchunguza miundo mbalimbali**, ikijumuisha **libraries** (.dll), **faili za metadata za Windows** (.winmd), na **executables** (.exe). Baada ya kufanyiwa decompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo chanzo uliopotea unahitaji kurejeshwa kutoka kwenye assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hurahisisha urambazaji kwenye msimbo uliofanyiwa decompile, na kuifanya kuwa mojawapo ya zana bora kwa **uchanganuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na modeli pana ya add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha uendelezaji. Hebu tuangalie huduma nyingi za reverse engineering ambazo zana hii hutoa:

- Hutoa mwanga kuhusu jinsi data inavyopita kwenye library au component
- Hutoa mwanga kuhusu utekelezaji na matumizi ya lugha na frameworks za .NET
- Hupata utendakazi usioandikwa kwenye nyaraka na usiofichuliwa ili kunufaika zaidi na APIs na teknolojia zinazotumika.
- Hupata dependencies na assemblies mbalimbali
- Hufuatilia eneo halisi la makosa kwenye msimbo wako, components za watu wengine na libraries.
- Hufanya debug kwenye source ya msimbo wote wa .NET unaofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) na [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode; huhitaji kupakua git. Bofya **Extensions** na **utafute ILSpy**).\
Ikiwa unahitaji kufanya **decompile**, **modify** na kufanya **recompile** tena, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Bofya kulia -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed bila kutekeleza msimbo kwa kutumia REA

**REA** inaweza kukagua metadata ya PE/CLI na CIL bila kupakia assembly. Anza kwa kutambua artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii husaidia unapokagua calls zinazotiliwa shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa kulinganisha tofauti za matoleo, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na alama za vidole za decoded instructions, badala ya kuchukulia metadata tokens kuwa thabiti katika builds. Tangazo la P/Invoke si uthibitisho kwamba native code iliendeshwa; `verify_managed_native_boundaries` inahitaji native export au function Evidence inayolingana ili kukagua mpaka huo. Hifadhi artifact digest, MVID na mappings ambazo hazijatatuliwa pamoja na matokeo.<sup>[[17]](#references)</sup>

### Uwekaji wa kumbukumbu katika DNSpy

Ili **DNSpy iandike taarifa fulani kwenye faili**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugging kwa DNSpy

Ili kutatua hitilafu kwenye code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **Assembly attributes** zinazohusiana na **debugging**:

![DNSpy Logging - Debugging kwa DNSpy: Kwanza, badilisha Assembly attributes zinazohusiana na debugging](<../../images/image (973).png>)

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

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** **optimisations** kadhaa zitatumika kwenye code, na huenda wakati wa debugging **break-point isiwahi kufikiwa** au **variables** fulani zisiwepo.

Kisha, ikiwa application yako ya .NET inaendeshwa na **IIS**, unaweza kuiwasha upya kwa:

```
iisreset /noforce
```

Kisha, ili kuanza kufanya debugging, funga faili zote zilizo wazi na kwenye **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza kufanya debugging, funga faili zote zilizo wazi na kwenye Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuambatisha kwenye **IIS server** na ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuambatisha kwenye IIS server na ubofye attach](<../../images/image (113).png>)

Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules** na uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules na uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote kwenye **Assembly Explorer** na ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote kwenye Assembly Explorer na ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Kwa kutumia IDA

- **Pakia rundll32** (64bits kwenye C:\Windows\System32\rundll32.exe na 32 bits kwenye C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kwa kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kwa kutumia IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimamishwa kila DLL inapopakiwa**. Kwa hiyo, rundll32 itakapopakia DLL yako, utekelezaji utasimamishwa.

Njia hii husimamisha utekelezaji kwenye matukio ya kupakiwa kwa module, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye mtiririko wa kazi wa x64dbg hapa chini.

### Kwa kutumia x64dbg/x32dbg

- **Pakia rundll32** (64bits kwenye C:\Windows\System32\rundll32.exe na 32 bits kwenye C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**; debugger itasimama kwenye kila dll main. Wakati fulani **utasimama kwenye Entry ya dll yako**. Kuanzia hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba utekelezaji unaposimama kwa sababu yoyote kwenye win64dbg, unaweza kuona **code unayoiangalia** juu ya **dirisha la win64dbg**:

![Kwa kutumia IDA - Kwa kutumia x64dbg/x32dbg: Kumbuka kwamba utekelezaji unaposimama kwa sababu yoyote kwenye win64dbg, unaweza kuona code unayoiangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha kwamba utekelezaji umesimama ndani ya DLL unayotaka kufanya debugging.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta sehemu ambazo thamani muhimu zimehifadhiwa kwenye memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi kwenye:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni zana ya front-end/reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti ya decompilers kadhaa. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

### Usimbuaji wa Godot PCK na urejeshaji wa project

Kwa game ya Godot inayosambazwa, tafuta PCK yake kwenye `.pck` inayojitegemea, kwenye executable pack iliyoambatishwa au kupachikwa, au kwenye directory ya `assets` ya APK. [gore](https://github.com/figurophobia/gore) inaweza kukagua na kutoa yaliyomo kwenye pack, huku ujenzi kamili wa scripts na resources ukihitaji GDRE Tools (`gore setup` huisakinisha, au tumia `--gdre`). Zana hii inasaidia miundo ya Godot 4.x PCK v2–v4 kwa mtiririko huu wa kazi; inaweza kutambua vichwa vya v1 lakini inahitaji ufunguo uliotolewa kwa v1.<sup>[[25]](#references)</sup>

Urejeshaji wa ufunguo kiotomatiki unahitaji jedwali la faili lililosimbwa; ikiwa yaliyomo kwenye faili pekee ndiyo yaliyosimbwa, toa ufunguo unaojulikana badala yake. Kushindwa kwa urejeshaji hakuthibitishi kwamba pack haijasimbwa.<sup>[[28]](#references)</sup>

Utafutaji wa ufunguo **si shambulio la keyspace ya AES-256**. Jedwali la faili lililosimbwa hufichua MD5 ya maandishi yake yasiyosimbwa, urefu wa maandishi hayo, IV na ciphertext ya AES-256-CFB.<sup>[[27]](#references)</sup> `gore` hujaribu madirisha ya baiti 32 kutoka kwenye executable ya game au faili zilizo karibu kama funguo zinazowezekana. Huchuja wagombea kwa kuangalia urefu na kiambishi awali kinachowezekana cha path iliyofumbuliwa, kisha huthibitisha matokeo ya binary-scan kwa kufumbua jedwali zima na kukagua MD5 yake.<sup>[[26]](#references)[[28]](#references)</sup> Hutafuta kwanza sehemu za data za PE/ELF zilizoanzishwa, kisha hutafuta faili nzima; `--scan` huongeza faili nyingine zinazoweza kuwa na wagombea.<sup>[[28]](#references)</sup>

Ikiwa ufunguo uliopachikwa haupatikani, orodha ndogo ya manenosiri iliyojengewa ndani hujaribiwa; `--wordlist` hutoa wagombea wengine. Kila nenosiri hujaribiwa kama uwakilishi wa ufunguo unaotokana na nenosiri wa engine, thamani halisi iliyojazwa sufuri, au ufunguo wenye herufi 64 za hex. Tofauti na matokeo ya binary-scan, matokeo ya wordlist katika utekelezaji huu hupitishwa tu kwenye kichujio cha muundo wa path. Yathibitishe kwa kufungua pack na kuthibitisha assets zilizotolewa.<sup>[[26]](#references)[[28]](#references)</sup>

Baada ya kupata kifaa cha game kwenye mfumo wa karibu, chagua hatua inayohitajika kwa uchanganuzi. `recover` hutumia GDRE kujenga upya project inayoweza kufunguliwa, huku `extract` ikifungua tu faili ghafi. `key` huchapisha ufunguo unaowezekana ili utumike na zana nyingine.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Uchunguzi wa native unaoungwa mkono na ushahidi kwa kutumia REA

**REA** hutoa uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Kwanza sanidi provider ya native iliyopo; angalia `rea providers --json` na uchague provider waziwazi ikiwa zaidi ya mmoja anaunga mkono lengo. Tumia jina la function au anwani iliyoonekana kwenye orodha badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza na mfuatano wa feature au alama, fuata marejeleo na callers, kisha kagua dossier ya function iliyochaguliwa na pseudocode kwa `rea decompile`. REA hufungamanisha session na provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena tu bytes za artifact, provider, settings, operation na parameters zinazolingana; snapshot ni cache ya ndani, si database ya provider iliyohifadhiwa. Hifadhi Evidence iliyorejeshwa na mambo yasiyojulikana yaliyo wazi badala ya kuchukulia paths zilizokisiwa au maandishi ya decompiler kuwa source asilia.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekeza kwenye native add-ons, tazama [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Uchambuzi wa IDA na Ghidra kwa scripts kupitia daraja la TCP la ndani

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) huendeshwa ndani ya database ya IDA au programu ya Ghidra CodeBrowser ambayo **tayari imefunguliwa**, na huwezesha script tofauti kuuliza na kurekebisha database hiyo ya uchambuzi. Endesha `ID_Server.py` kutoka IDA Python CLI (`import ID_Server`) au `Ghidra_Server.py` kutoka Ghidra Script Manager. IDA hufungamanisha na `127.0.0.1` kuanzia port `5073` na hukagua ports za juu zaidi. Script ya sasa ya Ghidra huanza port `5093` na kujaribu ports kumi hadi `5102`; Java socket yake hufungamanisha na wildcard address, si loopback pekee. Angalia port iliyochapishwa na instance kabla ya kuunganisha. Tofauti na headless analyzer, bridge hii hufanya kazi kwenye programu iliyo wazi kwa sasa katika instance hiyo ya GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Tuma **amri moja inayoishia kwa newline kwa kila connection** na usome jibu linaloishia kwa newline. Kwa kawaida matokeo huwa JSON. Kwa mfano, baada ya kupata API iliyoingizwa ambayo inahusiana na input path, `IMPORTXREF` hupata call sites zake; kisha `DECOMP_XREF` hufanya decompile kwa kundi la callers wa address iliyochaguliwa. `FUNC` hukagua function, huku `PCODE` ikirejesha intermediate representation ya decompiler. Tumia address kutoka kwenye database inayotumika sasa, si address iliyonakiliwa kutoka kwenye binary iliyorebasewa tofauti. Mfano ulio hapa chini hutumia port chaguomsingi ya IDA; kwa Ghidra, tumia port iliyochapishwa na script yake.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Kituo hicho hicho kinaweza **kubadilisha hifadhidata ya uchanganuzi**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC`, na `PATCH` hubadilisha majina, aina, ufafanuzi wa miundo, mipaka ya functions, au bytes zilizohifadhiwa. `PATCH` ni uhariri wa hifadhidata, **si** ushahidi wa patch kwenye mchakato unaoendelea. Hakuna listener kati ya hizo inayoeleza kuhusu uthibitishaji. IDA inaruhusu miunganisho ya loopback pekee, lakini Ghidra inaweza kufikiwa kupitia network interfaces; zuia ufikiaji wa listener ya Ghidra unapoitumia. `QUIT` husimamisha listener yoyote kati ya hizo, na IDA pia hutoa `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kutatua shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **anwani yake ya kumbukumbu**, kisha husitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye anwani iliyochapishwa, kisha endeleza utekelezaji ili kutatua shellcode.

Ukurasa wa matoleo kwenye GitHub una zips zilizo na matoleo yaliyokompiliwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililorekebishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kulikompili, **unda mradi wa C/C++ katika Visual Studio Code, nakili na ubandike code, kisha ujenge mradi huo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kutatua shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye infinite loop. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha ndani ya loop hiyo, kisha endelea hatua kwa hatua hadi call inayofuata inayohamisha utekelezaji kwenda kwenye shellcode iliyotengwa.

![Debugger imesitishwa ndani ya infinite loop ya jmp2it mara moja kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokompiliwa la [jmp2it kwenye ukurasa wa matoleo](https://github.com/adamkramer/jmp2it/releases/).

### Kutatua shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuiga shellcode na kuichunguza wakati inaendelea kutekelezwa.

Kumbuka kuwa Cutter inaruhusu "Open File" na "Open Shellcode". Katika hali yangu, nilipofungua shellcode kama faili, iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi wakati bytes zilezile zinafunguliwa kama faili au shellcode](<../../images/image (562).png>)

Ili kuanza emulation kwenye sehemu unayotaka, weka bp hapo; inaonekana Cutter itaanza emulation hapo moja kwa moja:

![Kuweka breakpoint kwenye sehemu inayotakiwa ya kuanzia ya shellcode kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Emulator ya Cutter imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode inayoigwa kwenye hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuonyesha mambo kama **ni functions zipi** zinazotumiwa na shellcode na kama shellcode **inajidecode** yenyewe kwenye kumbukumbu.

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

Chaguo la **Create Dump** litatoa dump ya shellcode ya mwisho ikiwa mabadiliko yoyote yatafanywa kwa shellcode kwa nguvu kwenye memory (ni muhimu kwa kupakua shellcode iliyodecodewa). **start offset** inaweza kusaidia kuanzisha shellcode kwenye offset mahususi. Chaguo la **Debug Shell** ni muhimu kwa kutatua hitilafu kwenye shellcode kupitia terminal ya scDbg (hata hivyo, naona chaguo lolote kati ya yale yaliyoelezwa awali ni bora zaidi kwa jambo hili kwa sababu utaweza kutumia Ida au x64dbg).

### Kutenganisha instructions kwa kutumia CyberChef

Pakia faili yako ya shellcode kama input na utumie recipe ifuatayo kuitenganisha: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Kuondoa obfuscation ya MBA

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama `x + y` nyuma ya fomula zinazochanganya arithmetic (`+`, `-`, `*`) na waendeshaji wa bitwise (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identity hizi kwa kawaida huwa sahihi tu chini ya **hesabu za modular zenye upana usiobadilika**, kwa hiyo carry na overflow ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya usemi kwa kutumia zana za aljebra za jumla, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za upana wa biti zilipuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi upana wa awali wa biti** kutoka kwenye matokeo ya lifted code/IR/decompiler (`8/16/32/64` bits).
2. **ainisha usemi** kabla ya kujaribu kuurahisisha:
   - **Linear**: jumla zenye uzani za biti atomiki
   - **Semilinear**: linear pamoja na masks zisizobadilika kama `x & 0xFF`
   - **Polynomial**: kuna bidhaa
   - **Mixed**: bidhaa na mantiki ya bitwise zimechanganywa, mara nyingi zikiwa na subexpressions zinazojirudia
3. **Thibitisha kila rewrite inayopendekezwa** kwa kutumia majaribio ya nasibu au uthibitisho wa SMT. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi usemi wa awali badala ya kubahatisha.

### Epuka control flow iliyoflatteniwa kwa kutumia execution slice finyu

Mara nyingi si lazima kurejesha control-flow graph nzima. Ikiwa kuna control-flow flattening, opaque predicates, dispatchers kubwa, au code yenye MBA nyingi, fuata marejeo kutoka kwenye encrypted blobs na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha rudia tu data-flow slice hiyo, au iendeshe kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa state husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha executable na data sections, relocations, na cross-references. Dump candidate tables kutoka `.rodata` huku ukihifadhi mpangilio wake wa byte na upana wa element.
2. Tambua routine ya mwisho inayoweka plaintext au output buffer. Rekodi inputs zake, tables inazorejelea, imported calls, na global state inayohitajika.
3. Lift operations hizo pekee kwenye fixed-width Python model. Ikiwa slice bado inategemea state nyingi mno, iite routine hiyo chini ya Unicorn, QEMU, au debugger, na hook imports zisizo muhimu badala ya kuiga program nzima.
4. Thibitisha kuwa extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa silent fallbacks, itafute majibu yaliyopachikwa ndani yake, na iendeshe dhidi ya builds ambazo hazijaonekana zikiwa na strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za ukaguzi wa awali ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Gundua expressions za MBA zilizofichwa kama thamani zisizobadilika

Expression ya byte inayoonekana kutegemea input inaweza kufuta kabisa utegemezi wake kwa input. Baada ya kutoa tables zake, tathmini expression katika domain nzima ya 8-bit; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo ni thamani isiyobadilika, bila kuhitaji kurejesha mashine ya hali inayoizunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu addition ya awali ina wraparound ya upana wa byte. Kwa domain pana zaidi, iulize SMT solver kama `f(x1) != f(x2)` inaweza kuridhishwa kwa inputs mbili za symbolic zenye upana sawa: `unsat` huthibitisha invariance, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kutupiliwa mbali.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis si lazima ufanye branch au kusababisha crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye bit ya key, constant ya opaque-predicate, au hali ya flattened-dispatcher, kisha iendelee kawaida na kutoa plaintext inayoonekana kuwa sahihi lakini si ya kweli ndani ya emulator. Kwa hiyo, kurekebisha branches za failure zinazoonekana pekee hakutoshi; fuatilia utegemezi wa data kutoka kwa ukaguzi wa mazingira hadi kwenye hali ya decoder, linganisha sehemu hiyo hiyo kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa ajili ya uchanganuzi wa malware na reversing ya protected binary. Huainisha expression na kuielekeza kupitia pipelines maalum badala ya kutumia rewrite pass moja ya jumla kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini expression kwa ingizo za Boolean, hupata signature, kisha hujaribu kwa wakati mmoja mbinu kadhaa za recovery, kama pattern matching, ubadilishaji wa ANF, na coefficient interpolation.
- **Semilinear MBA**: atomu zilizofichwa kwa constant hujengwa upya kwa reconstruction iliyogawanywa kwa bit ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa katika cores, na subexpressions zinazojirudia zinaweza kuinuliwa kuwa temporaries kabla ya kurahisisha outer relation.

Mfano wa mixed identity ambayo kwa kawaida inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hii inaweza kurahisishwa kuwa:

```c
x * y
```

### Vidokezo vya reversing

- Pendelea kuendesha CoBRA kwenye **miundo ya IR iliyoinuliwa** au matokeo ya decompiler baada ya kutenga hesabu husika.
- Tumia `--bitwidth` moja kwa moja ikiwa usemi umetokana na masked arithmetic au rejista nyembamba.
- Ikiwa unahitaji hatua thabiti zaidi ya uthibitisho, angalia maelezo ya Z3 hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia huja kama **plugin ya LLVM pass** (`libCobraPass.so`), ambayo ni muhimu unapotaka kurekebisha IR ya LLVM yenye MBA nyingi kabla ya passes za uchanganuzi zinazofuata.
- Mabaki mchanganyiko wa domain yasiyotumika na yanayoathiriwa na carry yanapaswa kuchukuliwa kama ishara ya kuhifadhi usemi asilia na kuchanganua njia ya carry kwa mkono.

## Kurejesha mtiririko wa udhibiti uliolazwa kwa XOR-state

Flattener ya mtindo wa OLLVM inaweza kuhifadhi hali ya basic block ya sasa katika rejista mbili za biti 64 na kuijenga upya kwa kutumia XOR kwenye dispatcher. Kila block asilia huandika jozi ya hali inayofuata na kuruka kurudi kwenye dispatcher. Block yenye masharti inaweza kutumia `CMOVcc` kubadilisha nusu moja ya jozi kulingana na CPU flags, kwa hiyo kufuata maagizo ya tawi yanayoonekana pekee hukosa successors wote wawili. Tofauti na dispatcher ya indirect-jump, muundo huu unaweza kutumia direct back-edges kila mahali.<sup>[[19]](#references)[[20]](#references)</sup>

Ili kurejesha graph, tambua mti wa ulinganishaji wa dispatcher na rejista mbili za hali, linganisha kila hali ya XOR iliyolinganishwa na target block yake, kisha fuatilia writes zinazofikia jozi ya rejista katika kila block asilia. Kwa writes zenye masharti, jumuisha agizo linaloweka flags na matokeo yote mawili ya `CMOVcc`. Badilisha dispatcher exit ya kila block iwe successor yake ya moja kwa moja iliyobainishwa au tawi lenye masharti; dispatcher basi haitafikiwa tena bila kurekebisha binary. Hii ni mbinu ya full-CFG; ikiwa decoder moja tu ndiyo muhimu, [mchakato wa narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hapo juu unaweza kuwa wa haraka zaidi.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) huweka kiotomatiki muundo huu katika Binary Ninja. Nakili `plugins/DispatchThis` kwenye saraka ya plugin za mtumiaji ya Binary Ninja kisha uanze upya. Katika function iliyoathiriwa, fungua **Function Settings** na uchague `OLLVM_XOR_64`; ikiwa uchanganuzi hautaanza, tumia **Analysis → Reanalyze All Functions**. Hali hii hubadilisha edges za mtiririko wa udhibiti wa MLIL, si baiti za faili, na haihitaji Z3 wala indirect-jump resolver. Imejaribiwa kwenye Binary Ninja 5.3.9757+; haiondoi state writes zilizokufa za kila block, kwa hiyo usizichukulie kimakosa kuwa ni transitions hai zilizobaki.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa mfuatano wa maagizo unaotegemea `mov` na hutumia signal/exception handling kubadilisha mtiririko wa udhibiti. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binary zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation ya matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, workaround hii ya kupata flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa kutumia `::main` kama ilivyo hapa:

![Kutafuta entry point ya Rust katika Ghidra kwa kutafuta majina ya functions yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii binary iliitwa authenticator, kwa hivyo ni dhahiri kabisa kwamba hii ndiyo main function inayovutia.\
Kwa kuwa na **jina** la **functions** zinazotumiwa, zitafute kwenye **Internet** ili kujifunza kuhusu **inputs** na **outputs** zake.

### Kurejesha strings za Rust kutoka firmware ya ELF

Katika binaries za **Rust ELF**, strings nyingi tuli hazirejelewi kama pointers za C-style zinazokoma kwa NUL. Muundo wa kawaida wa `rustc` ni **pointer/length tuple** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa katika **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Hii inamaanisha kwamba `strings` au uchanganuzi chaguomsingi wa Ghidra unaweza kuunganisha mifuatano iliyo karibu au kukosa kabisa marejeleo mtambuka.<sup>[[3]](#references)</sup>

Mtiririko wa kazi wa haraka:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pata anwani pepe na ukubwa wa **`.rodata`**.
2. Orodhesha **`.data.rel.ro`** neno moja kwa wakati.
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer inayoweza kuelekeza kwenye string.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya ukaguzi wa uhalali (kwa mfano, hifadhi urefu kati ya **4** na **100** bytes).
6. Soma bytes `length` haswa kutoka `.rodata` badala ya kuchanganua hadi `0x00`.

Mantiki ya msingi ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hili ni muhimu hasa katika firmware reversing kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **njia za HTTP, majina ya RPC, ujumbe wa log, assertions, majina ya faili, funguo za config, handlers za command, na logic inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda data ya string kwenye offsets za `.rodata` zinazorejelewa. Zana za `rust-strings` na `RustStrings.py` zilizochapishwa na Pen Test Partners ni marejeleo mazuri ya kurekebisha wazo hilo ili litumike kwa **ukubwa mwingine wa word, endianness, na mipangilio ya section**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizokusanywa kwa Delphi, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kufanya reverse engineering ya binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** kwenye IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itaendesha binary na kutatua majina ya function kwa nguvu wakati debugging inaanza. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itasimama mwanzoni mwa code halisi.

Ukibonyeza kitufe kwenye programu ya picha, debugger inaweza kusimama kwenye function inayoitwa na kitufe hicho.

## Golang

Kwa binaries za kawaida za Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha miundo ya runtime na kuboresha majina ya function katika IDA. Pakia Python plugin yake kwa kubonyeza **Alt+F7**.

Ikiwa unahitaji kufanya reverse engineering ya binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** kwenye IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya function.

### Rejesha metadata bila jedwali la symbol

Executable ya Go ambayo symbols zake zimeondolewa bado inahitaji metadata ya runtime ili kuunganisha program counter na function. [GoReSym](https://github.com/mandiant/GoReSym) hutafuta na kuchanganua miundo kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya function, majina, njia za source, aina na maelezo ya build bila kutegemea jedwali la kawaida la symbol.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikiwa inatumika huku ikibadilisha majina yaliyorejeshwa. Garble, kwa mfano, huhash vitambulishi na njia za package na huondoa maelezo ya build, module na debug.<sup>[[12]](#references)</sup> Tokeni ya package iliyofichwa lazima ibaki ileile katika functions kutoka package hiyo. Panga functions kulingana na tokeni inayojirudia, bainisha package moja kutokana na callees, strings na APIs zake, kisha tumia lebo hiyo ya package kwa kundi lote.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huchanganya utoaji wa runtime-symbols na utengenezaji wa marejeleo safi pamoja na ulinganishaji wa control-flow-graph (CFG). Tumia mfuatano huu:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Bainisha toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator iliziondoa, linganisha sehemu za Go runtime iliyojumuishwa na reference runtimes zenye matoleo tofauti. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Chukulia hili kama uboreshaji uliothibitishwa kwa majaribio, si kiwango cha jumla.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeleo yanayolingana.** Tengeneza binaries safi kwa toleo la Go lililotambuliwa, target architecture na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazozalishwa na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama zilizosanifishwa kutoka `0.0` hadi `1.0`. Ulinganishaji wake wa basic-blocks unategemea ulinganishaji wenye uzani wa instructions zinazofanana. Matches zenye uhakika mkubwa huunganisha functions zilizobadilishwa majina kwa utekelezaji safi. Matches dhaifu zaidi bado zinaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia mahusiano ya calls, constants, strings na side effects, kisha ingiza ripoti ya JSON kwa kutumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Sakinisha toolchain na uendeshe extractor pamoja na graph matcher:<sup>[[10]](#references)</sup>

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

Kizingiti chaguomsingi cha match muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenga mojawapo ya hatua hizo, huku mipangilio chaguomsingi ikiendesha zote mbili kwa sababu metadata ya runtime iliyorejeshwa na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kihesabu cha heuristic: inlining, build flags, usanifu na tofauti za matoleo ya library zinaweza kubadilisha umbo la graph, kwa hiyo hifadhi functions ambazo hazijatatuliwa badala ya kuzipa majina yenye uhakika mdogo.<sup>[[13]](#references)</sup>

### Kurejesha Go string table

Binaries za Go huweka bytes za string kutoka kila package iliyounganishwa katika jedwali moja linaloendelea. Entries hazina NUL mwishoni, na miundo ya runtime haionyeshi base wala ukubwa wa jedwali. Hata hivyo, compiler hupanga entries kwanza kulingana na urefu, kisha alfabeti, katika mifumo ya uendeshaji na usanifu mbalimbali. Kwa hiyo, baada ya kupata entry moja, mchambuzi anaweza kupitia entries zilizo karibu na kutumia marejeleo ya data yanayoelekeza kwenye hizo ili kuhusisha strings na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha workflow hii kiotomatiki katika IDA Pro na Ghidra. Acha auto-analysis imalizike kwanza kwa sababu plugin hutegemea marejeleo ya data katika data segment. Anchor yake chaguomsingi ni runtime string `entersyscall`; baada ya hapo, inaweza kuchanganua kuelekea upande wowote, kufafanua strings zilizorejeshwa katika database na kuhamisha JSON mapping ya strings na functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa package ya function inayorejelea string ili kutenganisha code ya application au malware na kelele ya library zilizounganishwa. Mbinu hii haiwezi kurejesha literals zilizoharibiwa na obfuscation kama vile mabadiliko ya `-literals` ya Garble. Hata hivyo, inaweza kupanga runtime strings ambazo hazijafichwa kwa obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za Go runtime

Go hujumuisha taarifa za aina za runtime zinazotumiwa na vipengele kama garbage collection. Build information inapofutwa au disassembler inaposhindwa kuchanganua metadata hii, maagizo yanaweza kuonekana kana kwamba yanapakia anwani za data zisizohusiana, na eneo lengwa hubaki bila aina iliyobainishwa. Kurejesha metadata hubadilisha anwani hizo kuwa marejeleo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua aina za runtime ili kutengeneza ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwasha uchanganuzi wa aina. Ingiza report kwa kutumia plugin ya IDA Pro au Ghidra ya GoResolver ili kufafanua aina zilizorejeshwa na kutumia marejeleo yake kwenye database ya uchanganuzi. Katika umbizo la report lililoanzishwa na kipengele hiki, kutotumia `-y` huacha washiriki wa anwani ya RTTI na aina zilizorejeshwa wakiwa null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia sampuli za PE, ELF na Mach-O za x86, AMD64, ARM na ARM64, kwa hivyo workflow ileile inatumika kwa Go binaries za Windows, Linux na macOS.<sup>[[10]](#references)</sup>

## Python Iliyokompailiwa

Katika ukurasa huu unaweza kujifunza jinsi ya kupata code ya python kutoka kwenye binary ya ELF/EXE iliyokompailiwa ya python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA unaweza kutumia zana tofauti kuufanya **emulate** na kuufanyia **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Kila **kitufe huwa na thamani** ya kukitambulisha kinapobonyezwa:

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

Katika function hiyo, baada ya shughuli za awali za uanzishaji (zisizo na umuhimu wowote):

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

`if` ya mwisho inakagua ikiwa **`uVar4`** iko kwenye **Keys za mwisho** na si key ya sasa; hii pia huitwa kuachia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).

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

Katika msimbo uliotangulia, tunaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **thamani ya kitufe kilichobonyezwa** huhifadhiwa) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto hii, kitufe hiki husafisha skrini
- Kisha inalinganisha thamani na **8** (kitufe cha **START**); katika changamoto hii, njia hiyo hukagua kama msimbo ulioingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3 na msimbo fulani hutekelezwa ikiwa thamani zinafanana.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Mradi tu kaunta iko chini ya 8, thamani za vitufe vilivyobonyezwa hujumlishwa kwenye `DAT_030000d8`.

Kwa hiyo, katika changamoto hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mfuatano wenye urefu wa chini ya 8, ambao jumla yake ni 0xf3.**

**Marejeleo ya mafunzo haya:** [maandishi ya changamoto ya Nostalgia yaliyohifadhiwa kwenye kumbukumbu](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Uondoaji wa ufichaji wa binary)

## References

- [1] [Kurahisisha ufichaji wa MBA kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hifadhi ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kufasiri strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - strings za Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa kwenye kumbukumbu)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering inayosaidiwa na AI, au angalau kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya kulinganisha Control Flow Graphs kwa kutumia ulinganishaji wa Basic Block](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Hifadhi ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mbinu ya ufichaji ya Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia mfanano wa Control-Flow Graph ili kuondoa ufichaji wa binary za Golang kiotomatiki](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Hifadhi ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Masasisho ya zana za Golang za Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa CLI na Evidence wa REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Mtiririko wa kazi wa kuondoa control-flow flattening kwa Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Uvamizi wa PaperCut MF Zero-Day, Java Loader, Web Shell, na AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README ya IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Utekelezaji wa seva ya IDA bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Utekelezaji wa seva ya Ghidra bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) hufunga kwenye anwani wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Zana ya Godot reverse engineering](https://github.com/figurophobia/gore)
- [26] [Utekelezaji wa urejeshaji wa key wa gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Muundo wa encrypted-blob wa gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Utekelezaji wa amri na urejeshaji wa gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
