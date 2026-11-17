# Zana za Reversing na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za reversing zinazotumia ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Uendeshaji otomatiki wa user-mode kwenye WinDbg

{{#ref}}
windbg-automation.md
{{#endref}}

## Uchambuzi wa macro za hati za Office

Kwa hati za Office zinazotia shaka, kagua [VBA macro junk code and hidden UserForm controls](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

## Mtiririko wa udhibiti wa Windows unaoendeshwa na exception

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Utatuzi wa kernel ya Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / compiler ya Wat

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) **kudecompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) **kukompile** kutoka wat hadi wasm
- Unaweza pia kujaribu [web-wasmdec](https://wwwg.github.io/web-wasmdec/) kwa ajili ya decompilation.

Software:

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

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler inayodecompile na kuchunguza miundo mbalimbali, ikijumuisha maktaba (.dll), faili za metadata za Windows (.winmd), na faili zinazotekelezeka (.exe). Baada ya ku-decompile assembly, inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo chanzo uliopotea unahitaji kurejeshwa kutoka kwa assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hurahisisha kuvinjari msimbo ulio-decompile, na kuifanya kuwa mojawapo ya zana bora za uchambuzi wa algorithm za **Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na modeli pana ya add-in na API inayoweza kupanua zana ili kukidhi mahitaji yako halisi, .NET Reflector huokoa muda na kurahisisha uendelezaji. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa mwonekano wa jinsi data inavyopita kwenye maktaba au kipengele
- Hutoa mwonekano wa utekelezaji na matumizi ya lugha na mifumo ya .NET
- Hupata utendaji ambao haujaandikwa nyaraka au kufichuliwa ili kutumia zaidi API na teknolojia husika.
- Hupata dependencies na assembly tofauti
- Hufuatilia mahali hasa pa makosa kwenye msimbo wako, vipengele vya watu wengine, na maktaba.
- Hufanya debug kwenye chanzo cha msimbo wote wa .NET unaoufanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ya ILSpy ya Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bofya **Extensions** kisha **utafute ILSpy**).\
Ikiwa unahitaji **kudecompile**, **kurekebisha** na **kukompile tena**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed bila utekelezaji kwa kutumia REA

**REA** inaweza kukagua metadata ya PE/CLI na CIL bila kupakia assembly. Anza kwa kutambua artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii ni muhimu unapochunguza calls zinazotia shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa kulinganisha matoleo, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na fingerprints za decoded instructions badala ya kuchukulia metadata tokens kuwa thabiti kati ya builds. Tamko la P/Invoke si uthibitisho kwamba native code iliendeshwa; `verify_managed_native_boundaries` inahitaji export ya native au Evidence ya function inayolingana ili kuthibitisha mpaka huo. Hifadhi digest ya artifact, MVID na mappings ambazo hazijatatuliwa pamoja na matokeo.<sup>[[17]](#references)</sup>

### DNSpy Logging

Ili **DNSpy iandike baadhi ya taarifa kwenye faili**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Ili kutatua hitilafu kwenye code kwa kutumia DNSpy, unahitaji:

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

Hili ni muhimu kwa sababu usipofanya hivyo, **runtime** itatumia **optimisations** kadhaa kwenye code, na huenda wakati wa debugging **break-point isiguswe kamwe** au baadhi ya **variables zisiwepo**.

Kisha, ikiwa programu yako ya .NET inaendeshwa na **IIS**, unaweza kuiwasha upya kwa kutumia:

```
iisreset /noforce
```

Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa, kisha kwenye **Debug Tab** uchague **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Kisha, ili kuanza debugging, unapaswa kufunga faili zote zilizofunguliwa, kisha kwenye Debug Tab uchague Attach to Process](<../../images/image (318).png>)

Kisha chagua **w3wp.exe** ili kuambatisha kwenye **IIS server**, halafu ubofye **attach**:

![DNSpy Logging - DNSpy Debugging: Kisha chagua w3wp.exe ili kuambatisha kwenye IIS server, halafu ubofye attach](<../../images/image (113).png>)

Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya _Debug >> Break All_, kisha ubofye _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Kwa kuwa sasa tunafanya debugging ya process, ni wakati wa kuisimamisha na kupakia modules zote. Kwanza bofya Debug Break All, kisha ubofye Debug Windows Modules](<../../images/image (834).png>)

Bofya module yoyote kwenye **Modules**, kisha uchague **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Bofya module yoyote kwenye Modules, kisha uchague Open All Modules](<../../images/image (922).png>)

Bofya kulia module yoyote kwenye **Assembly Explorer**, kisha ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya kulia module yoyote kwenye Assembly Explorer, kisha ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Kufanya debugging ya DLLs

### Kutumia IDA

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Kutumia IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Kutumia IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimama kila DLL inapopakiwa**. Kwa hiyo, rundll32 itakapopakia DLL yako, utekelezaji utasimama.

Mbinu hii husimamisha utekelezaji kwenye matukio ya kupakiwa kwa module, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye mtiririko wa x64dbg hapa chini.

### Kutumia x64dbg/x32dbg

- **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**. Debugger itasimama kwenye kila dll main; wakati fulani **itasimama kwenye DLL Entry ya dll yako**. Kuanzia hapo, tafuta tu sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba utekelezaji ukisimama kwa sababu yoyote katika win64dbg, unaweza kuona **ni code gani unayoitazama** juu ya dirisha la win64dbg:

![Kutumia IDA - Kutumia x64dbg/x32dbg: Kumbuka kwamba utekelezaji ukisimama kwa sababu yoyote katika win64dbg, unaweza kuona ni code gani unayoitazama juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha kwamba utekelezaji umesimama ndani ya DLL unayotaka kufanya debugging yake.

## Programu za GUI / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa kwenye memory ya mchezo unaoendeshwa na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/tool ya reverse engineering ya GNU Project Debugger (GDB), inayolenga michezo. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti inayotumia decompilers kadhaa. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

### Kusimbua Godot PCK na kurejesha project

Kwa mchezo wa Godot uliosambazwa, tafuta PCK yake ikiwa ni `.pck` ya kujitegemea, pack iliyoambatishwa au kupachikwa kwenye executable, au kwenye saraka ya `assets` ya APK. [gore](https://github.com/figurophobia/gore) inaweza kukagua na kutoa pack; kurejesha kikamilifu scripts na resources kunahitaji GDRE Tools (`gore setup` huisakinisha, au tumia `--gdre`). Kwa mtiririko huu, tool hii inasaidia miundo ya Godot 4.x PCK v2–v4; inaweza kutambua vichwa vya v1 lakini inahitaji ufunguo uliotolewa kwa v1.<sup>[[25]](#references)</sup>

Urejeshaji wa ufunguo kiotomatiki unahitaji jedwali la faili lililosimbwa; ikiwa yaliyomo kwenye faili pekee ndiyo yaliyosimbwa, toa ufunguo unaojulikana badala yake. Urejeshaji ukishindwa hauthibitishi kwamba pack haijasimbwa.<sup>[[28]](#references)</sup>

Utafutaji wa ufunguo **si** shambulio la keyspace ya AES-256. Jedwali la faili lililosimbwa hufichua MD5 ya maandishi yake ya awali, urefu wa maandishi hayo, IV na ciphertext ya AES-256-CFB.<sup>[[27]](#references)</sup> `gore` hukagua madirisha ya baiti 32 kutoka kwenye executable ya mchezo au faili zilizo karibu kama funguo zinazowezekana. Huchuja wagombea kwa kuangalia urefu na kiambishi awali cha path iliyosimbuliwa, kisha huthibitisha matokeo ya binary-scan kwa kusimbua jedwali lote na kuangalia MD5 yake.<sup>[[26]](#references)[[28]](#references)</sup> Huchunguza kwanza sehemu za data za PE/ELF zilizoanzishwa, na kisha hutafuta kwenye faili zima ikishindwa; `--scan` huongeza faili nyingine za kuchunguza.<sup>[[28]](#references)</sup>

Ikiwa hakuna ufunguo uliopachikwa unaopatikana, hujaribu orodha ndogo ya nywila iliyojengewa ndani; `--wordlist` hutoa wagombea wengine. Kila nywila hujaribiwa kama uwakilishi wa ufunguo unaotokana na nywila wa engine, maandishi halisi yaliyoongezewa sufuri, au ufunguo wa herufi 64 za hexadecimal. Tofauti na matokeo ya binary-scan, matokeo ya wordlist katika utekelezaji huu hupita tu kichujio cha muundo wa path. Yathibitishe kwa kufungua pack na kuthibitisha assets zilizotolewa.<sup>[[26]](#references)[[28]](#references)</sup>

Baada ya kupata artifact ya mchezo ndani ya kifaa, chagua hatua inayohitajika kwa uchanganuzi. `recover` hutumia GDRE kujenga upya project inayoweza kufunguliwa, ilhali `extract` hufungua tu faili ghafi. `key` huchapisha ufunguo unaowezekana kutumiwa na tool nyingine.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Uchunguzi wa native unaoungwa mkono na ushahidi kwa kutumia REA

**REA** hutoa uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Kwanza sanidi provider ya native iliyopo; angalia `rea providers --json` na uchague provider waziwazi ikiwa zaidi ya mmoja anaunga mkono lengo. Tumia jina la function au anwani uliyoona kwenye inventory badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza na feature string au symbol, fuata marejeleo na callers, kisha kagua dossier ya function iliyochaguliwa na pseudocode kwa kutumia `rea decompile`. REA hufunga session kwenye provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena bytes za artifact zinazolingana tu, provider, settings, operation na parameters; snapshot ni cache ya ndani, si hifadhidata ya provider iliyohifadhiwa. Hifadhi Evidence iliyorudishwa na mambo yasiyojulikana yaliyoainishwa wazi badala ya kuchukulia paths zilizokisiwa au maandishi ya decompiler kuwa source ya asili.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekea kwenye native add-ons, tazama [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Uchambuzi wa IDA na Ghidra kwa scripts kupitia local TCP bridge

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) huendeshwa ndani ya database ya IDA au programu ya Ghidra CodeBrowser **ambayo tayari imefunguliwa**, na huruhusu script tofauti kuuliza na kurekebisha database hiyo ya uchambuzi. Endesha `ID_Server.py` kutoka IDA Python CLI (`import ID_Server`) au `Ghidra_Server.py` kutoka Ghidra Script Manager. IDA hujifunga kwenye `127.0.0.1` kuanzia port `5073` na kuchunguza ports za juu zaidi. Script ya sasa ya Ghidra huanza kwenye port `5093` na kujaribu ports kumi hadi `5102`; Java socket yake hujifunga kwenye wildcard address, si loopback pekee. Angalia port iliyochapishwa na instance kabla ya kuunganisha. Tofauti na headless analyzer, bridge hii hufanya kazi kwenye programu iliyofunguliwa kwa sasa katika GUI instance hiyo.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Tuma **command moja inayoishia kwa newline kwa kila connection** na usome response inayoishia kwa newline. Kwa kawaida matokeo huwa JSON. Kwa mfano, baada ya kupata API iliyoingizwa ambayo inahusiana na input path, `IMPORTXREF` hupata call sites zake; kisha `DECOMP_XREF` hufanya batch-decompile ya callers wa address iliyochaguliwa. `FUNC` hukagua function, huku `PCODE` ikirejesha intermediate representation ya decompiler. Tumia address kutoka kwenye database inayotumika, si address iliyonakiliwa kutoka kwenye binary iliyorebasewa kwa namna tofauti. Mfano ulio hapa chini unatumia port ya chaguo-msingi ya IDA; kwa Ghidra, tumia port iliyochapishwa na script yake.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Njia hiyo hiyo inaweza **kubadilisha hifadhidata ya uchanganuzi**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC`, na `PATCH` hubadilisha majina, aina, ufafanuzi wa miundo, mipaka ya function, au baiti zilizohifadhiwa. `PATCH` ni uhariri wa hifadhidata, **si** ushahidi wa patch kwenye mchakato unaoendelea. Hakuna listener kati ya hizo inayoeleza kuhusu uthibitishaji. IDA inapatikana kupitia loopback pekee, lakini Ghidra inaweza kufikiwa kupitia interfaces za mtandao; zuia ufikiaji wa listener ya Ghidra unapoitumia. `QUIT` husimamisha listener yoyote kati ya hizo, na IDA pia hutoa `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kutatua shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **anwani yake ya memory**, na kusitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye anwani iliyochapishwa, kisha endeleza utekelezaji ili kutatua shellcode.

Ukurasa wa matoleo kwenye GitHub una faili za zip zenye matoleo yaliyokompiliwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililobadilishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kulikompili, **unda tu mradi wa C/C++ katika Visual Studio Code, nakili na ubandike code, kisha ujenge mradi huo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kutatua shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye kitanzi kisichoisha. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha ndani ya kitanzi hicho, kisha step hadi kwenye call inayofuata inayohamisha utekelezaji kwenda kwenye shellcode iliyotengwa.

![Debugger ikiwa imesitishwa ndani ya kitanzi kisichoisha cha jmp2it, mara moja kabla ya call kwenda kwenye shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokompiliwa la [jmp2it kwenye ukurasa wa matoleo](https://github.com/adamkramer/jmp2it/releases/).

### Kutatua shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Ukiwa na Cutter unaweza kuiga shellcode na kuichunguza wakati wa utekelezaji.

Kumbuka kuwa Cutter hukuruhusu kutumia “Open File” na “Open Shellcode”. Katika hali yangu, nilipofungua shellcode kama faili, iliidecompile kwa usahihi, lakini nilipoifungua kama shellcode haikufanya hivyo:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi wakati baiti zilezile zinafunguliwa kama faili au kama shellcode](<../../images/image (562).png>)

Ili kuanza emulation mahali unapotaka, weka bp hapo; inaonekana Cutter itaanza emulation moja kwa moja kutoka hapo:

![Kuweka breakpoint kwenye sehemu ya kuingia ya shellcode inayotakiwa kabla ya kuanza emulation ya Cutter](<../../images/image (589).png>)

![Emulator ya Cutter ikiwa imesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode inayoigwa kwenye hex dump ya Cutter](<../../images/image (186).png>)

### Kuondoa obfuscation ya shellcode na kupata functions zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Itakuambia mambo kama **ni functions zipi** zinazotumiwa na shellcode na ikiwa shellcode **inajidecode** kwenye memory.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg pia ina graphical launcher ambapo unaweza kuchagua chaguo unazotaka na kutekeleza shellcode

![Graphical launcher ya scDbg ya kuchagua chaguo za emulation na tracing za shellcode](<../../images/image (258).png>)

Chaguo la **Create Dump** litadump shellcode ya mwisho iwapo mabadiliko yoyote yatafanywa kwa shellcode hiyo dynamically kwenye memory (ni muhimu kupakua shellcode iliyodecodeiwa). **start offset** inaweza kuwa muhimu kuanzisha shellcode kwenye offset maalum. Chaguo la **Debug Shell** ni muhimu kwa ku-debug shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona chaguo zozote kati ya zilizoelezwa hapo awali zinafaa zaidi kwa jambo hili kwa kuwa utaweza kutumia Ida au x64dbg).

### Disassembling kwa kutumia CyberChef

Pakia faili yako ya shellcode kama ingizo na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Obfuscation ya **Mixed Boolean-Arithmetic (MBA)** huficha expressions rahisi kama `x + y` ndani ya fomula zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, kwa hiyo carries na overflows ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya expression kwa kutumia zana za jumla za algebra unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za bit-width zilipuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi bit-width ya awali** kutoka kwenye code/IR iliyoinuliwa au matokeo ya decompiler (`8/16/32/64` bits).
2. **Panga expression katika aina yake** kabla ya kujaribu kuirahisisha:
   - **Linear**: jumla zenye uzani za atomi za bitwise
   - **Semilinear**: linear pamoja na masks za constant kama `x & 0xFF`
   - **Polynomial**: kuna bidhaa
   - **Mixed**: bidhaa na mantiki ya bitwise zimechanganywa, mara nyingi zikiwa na subexpressions zinazorudiwa
3. **Thibitisha kila rewrite inayowezekana** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi expression ya awali badala ya kubahatisha.

### Epuka control flow iliyosawazishwa kwa kutumia execution slice finyu

Mara nyingi si lazima kurejesha control-flow graph nzima. Katika control-flow flattening, opaque predicates, dispatchers kubwa, au code nzito ya MBA, fuata marejeo kutoka kwa blobs zilizosimbwa na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha rudia data-flow slice hiyo pekee, au iendeshe kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa hali husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha sehemu za executable na data, relocations, na cross-references. Dump candidate tables kutoka `.rodata` huku ukihifadhi mpangilio wa byte na upana wa elementi.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, tables zinazorejelewa, imported calls, na global state inayohitajika.
3. Lift operations hizo pekee kwenye modeli ya Python yenye upana usiobadilika. Ikiwa slice bado inategemea state nyingi mno, iite routine hiyo ndani ya Unicorn, QEMU, au debugger na u-hook imports zisizo muhimu badala ya kuiga program nzima.
4. Thibitisha kuwa extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa fallbacks za kimya, itafute majibu yaliyopachikwa ndani yake, na iendeshe dhidi ya builds ambazo haijaziona zenye strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za hatua ya kwanza ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua expressions za MBA zilizofichwa kama constants

Expression ya byte inayoonekana kutegemea input inaweza kuondoa kabisa athari ya input hiyo. Baada ya kutoa majedwali yake, tathmini expression hiyo katika eneo lote la 8-bit; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo ni constant bila kurejesha state machine inayoizunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu jumla ya awali huzunguka inapovuka upana wa byte. Kwa domain pana zaidi, uliza SMT solver ikiwa `f(x1) != f(x2)` inaweza kutimizwa kwa inputs mbili za symbolic zenye upana sawa: `unsat` huthibitisha invariance, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kutupwa.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis si lazima uwe na branch au kusababisha crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye bit ya key, constant ya opaque-predicate, au hali ya flattened-dispatcher, kuendelea kawaida, na kutoa plaintext inayoonekana kuwa sahihi lakini isiyo ya kweli kwenye emulator. Kwa hiyo, kurekebisha branches zinazoonyesha kushindwa pekee hakutoshi; fuatilia utegemezi wa data kutoka kwenye environment probes hadi kwenye hali ya decoder, linganisha slice ileile kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa malware analysis na reversing ya protected binary. Huainisha expression na kuielekeza kwenye pipelines maalum badala ya kutumia pass moja ya jumla ya rewrite kwa kila kitu.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA hutathmini expression kwa Boolean inputs, hupata signature, na huendesha kwa wakati mmoja mbinu kadhaa za kurejesha, kama pattern matching, ubadilishaji wa ANF, na interpolation ya coefficients.
- **Semilinear MBA**: atoms zilizofichwa kwa constants hujengwa upya kwa reconstruction iliyogawanywa kwa bits, ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: products hugawanywa katika cores, na subexpressions zinazorudiwa zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha uhusiano wa nje.

Mfano wa identity mchanganyiko ambayo kwa kawaida inafaa kujaribu kuirejesha:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Hii inaweza kurahisishwa kuwa:

```c
x * y
```

### Vidokezo vya reversing

- Pendelea kutumia CoBRA kwenye **lifted IR expressions** au matokeo ya decompiler baada ya kubainisha computation husika.
- Tumia `--bitwidth` waziwazi ikiwa expression imetokana na masked arithmetic au narrow registers.
- Ikiwa unahitaji hatua ya uthibitisho iliyo imara zaidi, angalia vidokezo vya Z3 vya ndani hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inapatikana kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kunormalize LLVM IR yenye MBA nyingi kabla ya hatua nyingine za uchanganuzi.
- Residuals mchanganyiko wa domains zinazotegemea carry ambazo hazitumiki zinapaswa kuchukuliwa kama ishara ya kuhifadhi expression ya awali na kuchanganua njia ya carry mwenyewe.

## Kurejesha control-flow flattening yenye XOR-state

Flattener ya mtindo wa OLLVM inaweza kuhifadhi hali ya basic-block ya sasa kwenye registers mbili za biti 64 na kuijenga upya kwa XOR kwenye dispatcher. Kila block ya awali huandika jozi inayowakilisha hali yake inayofuata na kuruka kurudi kwenye dispatcher. Block yenye sharti inaweza kutumia `CMOVcc` kubadilisha nusu moja ya jozi kulingana na flags za CPU, kwa hiyo kufuata tu branch instructions zinazoonekana hukosa successors zote mbili. Tofauti na indirect-jump dispatcher, muundo huu unaweza kutumia direct back-edges kote.<sup>[[19]](#references)[[20]](#references)</sup>

Ili kurejesha graph, tambua mti wa ulinganishaji wa dispatcher na registers mbili za state, linganisha kila XOR state inayolinganishwa na target block yake, kisha fuatilia writes zinazofika kwenye jozi ya registers katika kila block ya awali. Kwa writes zenye masharti, jumuisha instruction inayoweka flags na matokeo yote mawili ya `CMOVcc`. Andika upya dispatcher exit ya kila block iwe direct successor au conditional branch iliyotatuliwa; dispatcher haitafikiwa tena bila ku-patch binary. Hii ni njia ya full-CFG; ikiwa decoder moja tu ndiyo muhimu, workflow ya [narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hapo juu inaweza kuwa ya haraka zaidi.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) huendesha kiotomatiki muundo huu katika Binary Ninja. Nakili `plugins/DispatchThis` kwenye saraka ya user plugin ya Binary Ninja kisha uanze upya. Kwenye function husika, fungua **Function Settings** na uchague `OLLVM_XOR_64`; ikiwa uchanganuzi hauanzi, tumia **Analysis → Reanalyze All Functions**. Hali hii huandika upya edges za MLIL control-flow, si bytes za faili, na haihitaji Z3 wala indirect-jump resolver. Imejaribiwa kwenye Binary Ninja 5.3.9757+; haiondoi state writes zilizokufa za kila block, kwa hiyo usizichukulie kimakosa kuwa transitions hai zilizobaki.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa instruction sequences zinazotumia `mov` na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazotumika, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation hiyo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, workaround hii ya kupata flag** inaweza kukufaa sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta functions kwa kutumia `::main`, kama ilivyo hapa:

![Kupata entry point ya Rust katika Ghidra kwa kutafuta majina ya function yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni wazi kabisa kwamba hii ndiyo main function inayovutia.\
Ukiwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **ingizo** na **matokeo** yake.

### Kurejesha strings za Rust kutoka firmware ya ELF

Katika binaries za **Rust ELF**, strings nyingi tuli hazirejelewi kama pointers zenye mwisho wa NUL za mtindo wa C. Mpangilio wa kawaida wa `rustc` ni **tuple ya pointer/urefu** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa katika **`.rodata`**:

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
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer ya mfuatano inayowezekana.
4. Chukulia neno linalofuata kuwa urefu unaowezekana.
5. Tumia vichujio vya sanity (kwa mfano, weka urefu kati ya **4** na **100** baiti).
6. Soma baiti `length` pekee kutoka `.rodata` badala ya kuchanganua hadi `0x00`.

Mantiki ya msingi ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hili ni muhimu hasa katika firmware reversing kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, na logic inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda string data kwenye offsets za `.rodata` zilizorejelewa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeleo mazuri ya kurekebisha wazo hili kwa **word sizes, endianness, na section layouts** nyingine.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binaries zilizokompailiwa za Delphi, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kureverse binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itaendesha binary na kutatua majina ya functions kwa nguvu mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), kisha breakpoint itagonga mwanzoni mwa code halisi.

Ukibonyeza kitufe katika programu ya picha, debugger inaweza kusimama kwenye function iliyoitishwa na kitufe hicho.

## Golang

Kwa Go binaries za kawaida, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya functions katika IDA. Pakia Python plugin yake kwa **Alt+F7**.

Ikiwa unahitaji kureverse binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya functions.

### Rejesha metadata bila symbol table

Go executable iliyovuliwa bado inahitaji runtime metadata ili kuoanisha program counters na functions. [GoReSym](https://github.com/mandiant/GoReSym) hutafuta na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya functions, majina, source paths, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikiwa inaweza kutumika huku ikibadilisha majina yaliyorejeshwa. Kwa mfano, Garble huhash vitambulishi na njia za vifurushi na huondoa maelezo ya build, module na debug.<sup>[[12]](#references)</sup> Tokeni ya kifurushi iliyofichwa lazima ibaki thabiti katika functions kutoka kifurushi hicho. Panga functions kwa tokeni inayojirudia, tambua kifurushi kimoja kutokana na callees, strings na APIs zake, kisha sambaza lebo hiyo ya kifurushi kwa kundi zima.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huchanganya uchimbaji wa runtime symbols na utengenezaji wa marejeo safi pamoja na ulinganishaji wa control-flow-graph (CFG). Tumia mfuatano huu:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator imeziondoa, linganisha sehemu za Go runtime iliyojumuishwa na runtime za marejeo zenye matoleo maalum. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Ichukulie hii kama uboreshaji wa kimajaribio, si kizingiti kinachotumika kwa hali zote.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeo yanayolingana.** Tengeneza binaries safi kwa toleo la Go lililotambuliwa, usanifu lengwa na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazozalishwa na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama zilizosanifishwa kuanzia `0.0` hadi `1.0`. Ulinganishaji wake wa basic-block unategemea ulinganisho wenye uzani wa instructions zinazofanana. Ulinganishaji wenye uhakika mkubwa huunganisha functions zilizobadilishiwa majina bila mpangilio na utekelezaji safi. Ulinganishaji dhaifu bado unaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia uhusiano wa calls, constants, strings na side effects, kisha uingize ripoti ya JSON kwa kutumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Sakinisha toolchain na utekeleze extractor na graph matcher kwa pamoja:<sup>[[10]](#references)</sup>

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

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenga hatua yoyote kati ya hizo, huku chaguomsingi zikitekeleza zote mbili kwa sababu metadata ya runtime iliyorejeshwa na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kihisia: inlining, build flags, usanifu na tofauti za matoleo ya maktaba zinaweza kubadilisha umbo la grafu, kwa hivyo hifadhi functions ambazo hazijatatuliwa badala ya kulazimisha majina yasiyo na uhakika wa kutosha.<sup>[[13]](#references)</sup>

### Kurejesha jedwali la strings la Go

Binaries za Go huweka bytes za strings kutoka kila package iliyounganishwa katika jedwali moja endelevu. Entries hazina kimaliziaji cha NUL, na miundo ya runtime haionyeshi msingi au ukubwa wa jedwali. Hata hivyo, compiler hupanga entries kwanza kwa urefu, kisha kwa alfabeti katika mifumo ya uendeshaji na usanifu mbalimbali. Kwa hiyo, baada ya kupata entry moja, mchambuzi anaweza kupitia entries zilizo karibu na kutumia marejeleo ya data yanayovuka kuhusisha strings na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha mchakato huu kiotomatiki katika IDA Pro na Ghidra. Acha auto-analysis ikamilike kwanza kwa sababu plugin hutegemea marejeleo ya data yanayovuka katika sehemu ya data. Anchor yake chaguomsingi ni string ya runtime `entersyscall`; kisha inaweza kuchanganua upande wowote, kufafanua strings zilizorejeshwa kwenye database, na kuhamisha JSON inayohusisha strings na functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa package ya function inayorejelea ili kutenganisha code ya programu au malware na kelele za maktaba zilizounganishwa. Mbinu hii haiwezi kurejesha literals zilizoharibiwa na obfuscation kama vile mabadiliko ya `-literals` ya Garble. Bado inaweza kupanga strings za runtime ambazo hazikufichwa kwa obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za runtime za Go

Go hujumuisha taarifa za aina za runtime zinazotumiwa na vipengele kama garbage collection. Build information inapoondolewa au disassembler isipochanganua metadata hii, instructions zinaweza kuonekana kana kwamba zinapakia anwani za data zisizohusiana na eneo lengwa hubaki bila aina. Kurejesha metadata hubadilisha anwani hizo kuwa marejeo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua aina za runtime na kuweka matokeo katika ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwezesha uchanganuzi wa aina. Ingiza ripoti kwa kutumia plugin ya IDA Pro au Ghidra ya GoResolver ili kufafanua aina zilizopatikana na kutumia marejeleo yake kwenye hifadhidata ya uchanganuzi. Katika muundo wa ripoti ulioletwa na kipengele hiki, ukiacha `-y`, sehemu za anwani ya RTTI na aina zilizopatikana hubaki null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia sampuli za PE, ELF na Mach-O za x86, AMD64, ARM na ARM64, hivyo utaratibu huu huu hutumika kwa binaries za Go kutoka Windows, Linux na macOS.<sup>[[10]](#references)</sup>

## Python Iliyokusanywa

Katika ukurasa huu unaweza kupata maelekezo ya jinsi ya kupata msimbo wa python kutoka kwa binary ya python iliyokusanywa ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali kuiga na kutatua hitilafu zake:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye kiolesura
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![usanidi wa vidhibiti vya no$gba unaoonyesha mipangilio ya vitufe vya Game Boy Advance](<../../images/image (581).png>)

Unapobonyeza, kila **kitufe kina thamani** inayokitambulisha:

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

Kwa hiyo, katika aina hii ya programu, jambo la kuvutia litakuwa **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Katika anwani **0x4000130** utapata function inayopatikana mara nyingi: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA unaorejelea KEYINPUT kwenye anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya baadhi ya shughuli za uanzishaji (zisizo na umuhimu):

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

`if` ya mwisho inakagua ikiwa **`uVar4`** imo kwenye **Keys** za awali na si kitufe cha sasa, hali inayojulikana pia kama kuachia kitufe (kitufe cha sasa kimehifadhiwa kwenye **`uVar1`**).

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

Katika code iliyotangulia unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **thamani ya kitufe kilichobonyezwa** huhifadhiwa) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika challenge, kitufe hiki husafisha skrini
- Kisha inalinganisha thamani hiyo na **8** (kitufe cha **START**); katika challenge hii, njia hiyo hukagua ikiwa code iliyoingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3, na ikiwa thamani hizo zinafanana, code fulani hutekelezwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Kaunta ikiwa chini ya 8, thamani za vitufe vilivyobonyezwa hujumlishwa katika `DAT_030000d8`.

Kwa hiyo, katika challenge hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mfuatano wenye urefu chini ya 8 ambao jumla yake ni 0xf3.**

**Rejeleo la mafunzo haya:** [maelezo ya challenge ya Nostalgia yaliyohifadhiwa kwenye kumbukumbu](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Kurahisisha ufichaji wa MBA kwa kutumia CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hifadhi ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kudecode string za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa kwenye kumbukumbu)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering Inayosaidiwa na AI, au Angalau Kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya Kulinganisha Control Flow Graphs kwa Kutumia Ulinganishaji wa Basic Blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Hifadhi ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Utaratibu wa kuficha code wa Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia Ufanano wa Control-Flow Graph ili Kuondoa Ufichaji wa Golang Binaries Kiotomatiki](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Hifadhi ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Maboresho ya Volexity Golang Tooling](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Chochote](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed-code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa REA CLI na Evidence](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Mtiririko wa kazi wa Binary Ninja wa kuondoa control-flow flattening](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Uvamizi wa PaperCut MF Zero-Day, Java Loader, Web Shell na AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README ya IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Utekelezaji wa IDA bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Utekelezaji wa Ghidra bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) hufunga kwenye anwani wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: zana ya Godot ya reverse engineering](https://github.com/figurophobia/gore)
- [26] [Utekelezaji wa kurejesha key wa gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Muundo wa gore wa encrypted blob](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Utekelezaji wa amri na urejeshaji wa gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
