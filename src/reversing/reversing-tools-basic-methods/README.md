# Zana za Reverse Engineering na Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za Reverse Engineering zinazotumia ImGui

Programu:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Uendeshaji otomatiki wa WinDbg katika user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Mtiririko wa udhibiti wa Windows unaoendeshwa na exceptions

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Utatuzi wa hitilafu wa Windows kernel

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Decompiler ya Wasm / compiler ya Wat

Mtandaoni:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) **kudecompile** kutoka wasm (binary) hadi wat (maandishi yanayosomeka)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) **kukompile** kutoka wat hadi wasm
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

## Decompiler ya .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler ambayo **hudecompile na kuchunguza fomati nyingi**, zikiwemo **libraries** (.dll), **faili za metadata za Windows** (.winmd), na **executables** (.exe). Baada ya kudecompile, assembly inaweza kuhifadhiwa kama mradi wa Visual Studio (.csproj).

Faida yake ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwa assembly ya zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa urambazaji rahisi ndani ya msimbo uliodecompile, na kuifanya kuwa mojawapo ya zana bora za **uchambuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Ikiwa na mfumo mpana wa add-in na API inayopanua zana ili kukidhi mahitaji yako mahususi, .NET Reflector huokoa muda na kurahisisha uendelezaji. Hebu tuangalie huduma nyingi za reverse engineering zinazotolewa na zana hii:

- Hutoa mwanga kuhusu jinsi data inavyopita kwenye library au component
- Hutoa mwanga kuhusu utekelezaji na matumizi ya lugha na frameworks za .NET
- Hugundua utendaji ambao haujaandikwa kwenye nyaraka au kufichuliwa ili kunufaika zaidi na APIs na teknolojia zinazotumika.
- Hugundua dependencies na assemblies mbalimbali
- Hufuatilia eneo halisi la makosa kwenye msimbo wako, components za wahusika wengine, na libraries.
- Hufanya debug ndani ya chanzo cha msimbo wote wa .NET unaofanya nao kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ya ILSpy ya Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuitumia kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bofya **Extensions** kisha **tafuta ILSpy**).\
Ikiwa unahitaji **kudecompile**, **kurekebisha** na **kukompile tena**, unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Bofya kulia -> Modify Method** ili kubadilisha kitu ndani ya function).

### Ukaguzi wa managed code bila utekelezaji kwa kutumia REA

**REA** inaweza kukagua metadata ya PE/CLI na CIL bila kupakia assembly. Anza kwa kutambua artifact, kisha kagua members na mipaka ya native iliyotangazwa; hii ni muhimu unapochunguza calls zinazotiliwa shaka kabla ya kutumia decompiler au kuendesha programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Kwa kulinganisha matoleo, `compare_managed_members` hutumia utambulisho ghafi wa CIL/signature na alama za vidole za maagizo yaliyofasiriwa, badala ya kuchukulia metadata tokens kuwa thabiti kati ya builds. Tamko la P/Invoke halithibitishi kuwa native code ilitekelezwa; `verify_managed_native_boundaries` inahitaji native export au ushahidi wa function unaolingana ili kukagua mpaka huo. Hifadhi artifact digest, MVID na mappings ambazo hazijatatuliwa pamoja na matokeo.<sup>[[17]](#references)</sup>

### Uwekaji wa Kumbukumbu wa DNSpy

Ili **kuifanya DNSpy iandike taarifa fulani kwenye faili**, unaweza kutumia snippet hii:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Utatuzi wa hitilafu kwa DNSpy

Ili kutatua hitilafu za code kwa kutumia DNSpy, unahitaji:

Kwanza, badilisha **sifa za Assembly** zinazohusiana na **utatuzi wa hitilafu**:

![Uwekaji kumbukumbu wa DNSpy - Utatuzi wa hitilafu kwa DNSpy: Kwanza, badilisha sifa za Assembly zinazohusiana na utatuzi wa hitilafu](<../../images/image (973).png>)

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

Hili ni muhimu kwa sababu usipofanya hivyo, wakati wa **runtime** **optimisations** kadhaa yatatumika kwenye code, na huenda wakati wa debugging **break-point isiwahi kugongwa** au baadhi ya **variables zisiwepo**.

Kisha, ikiwa application yako ya .NET inaendeshwa na **IIS**, unaweza kuianzisha upya kwa:

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

Bofya-kulia module yoyote kwenye **Assembly Explorer** na ubofye **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Bofya-kulia module yoyote kwenye Assembly Explorer na ubofye Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Pakia rundll32** (64bits iko C:\Windows\System32\rundll32.exe na 32 bits iko C:\Windows\SysWOW64\rundll32.exe)
- Chagua debugger ya **Windbg**
- Chagua "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Chagua " Suspend on library load/unload "](<../../images/image (868).png>)

- Sanidi **parameters** za utekelezaji kwa kuweka **path ya DLL** na function unayotaka kuita:

![Debugging DLLs - Using IDA: Sanidi parameters za utekelezaji kwa kuweka path ya DLL na function unayotaka kuita](<../../images/image (704).png>)

Kisha, unapoanza debugging, **utekelezaji utasimamishwa kila DLL inapopakiwa**. Hivyo, rundll32 itakapopakia DLL yako, utekelezaji utasimamishwa.

Njia hii husimamisha utekelezaji kwenye matukio ya kupakiwa kwa module, lakini kufikia entry point ya DLL iliyopakiwa si rahisi kama ilivyo kwenye mtiririko wa kazi wa x64dbg hapa chini.

### Using x64dbg/x32dbg

- **Pakia rundll32** (64bits iko C:\Windows\System32\rundll32.exe na 32 bits iko C:\Windows\SysWOW64\rundll32.exe)
- **Badilisha Command Line** ( _File --> Change Command Line_ ) na uweke path ya dll na function unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Badilisha _Options --> Settings_ na uchague "**DLL Entry**".
- Kisha **anza utekelezaji**; debugger itasimama kwenye kila dll main. Wakati fulani **utasimama kwenye Entry ya dll yako**. Kuanzia hapo, tafuta sehemu unazotaka kuweka breakpoint.

Kumbuka kwamba utekelezaji ukisimama kwa sababu yoyote katika win64dbg, unaweza kuona **ni code gani unayoangalia** juu ya dirisha la win64dbg:

![Using IDA - Using x64dbg/x32dbg: Kumbuka kwamba utekelezaji ukisimama kwa sababu yoyote katika win64dbg, unaweza kuona ni code gani unayoangalia juu ya dirisha la win64dbg](<../../images/image (842).png>)

Kiashiria hiki kinathibitisha kwamba utekelezaji umesimama ndani ya DLL unayotaka kufanya debugging yake.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo values muhimu zimehifadhiwa kwenye memory ya game inayoendeshwa na kuzibadilisha. Maelezo zaidi katika:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni front-end/tool ya reverse engineering ya GNU Project Debugger (GDB), inayolenga games. Hata hivyo, inaweza kutumika kwa kazi yoyote inayohusiana na reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) ni front-end ya wavuti inayotumia decompilers kadhaa. Huduma hii ya wavuti hukuwezesha kulinganisha matokeo ya decompilers tofauti kwenye executables ndogo.

### Kusimbua Godot PCK na kurejesha project

Kwa game ya Godot iliyosambazwa, tafuta PCK yake ikiwa katika faili ya `.pck` inayojitegemea, pack iliyoongezwa au kupachikwa kwenye executable, au directory ya `assets` ya APK. [gore](https://github.com/figurophobia/gore) inaweza kukagua na kutoa pack, ilhali kurejesha scripts na resources kikamilifu kunahitaji GDRE Tools (`gore setup` huisakinisha, au tumia `--gdre`). Kwa mtiririko huu wa kazi, tool hii inatumia fomati za Godot 4.x PCK v2–v4; inaweza kutambua headers za v1 lakini inahitaji key iliyotolewa kwa v1.<sup>[[25]](#references)</sup>

Urejeshaji wa key kiotomatiki unahitaji jedwali la faili lililosimbwa; ikiwa maudhui ya faili pekee ndiyo yaliyosimbwa, toa key inayojulikana badala yake. Kushindwa kwa urejeshaji hakuthibitishi kwamba pack haijasimbwa.<sup>[[28]](#references)</sup>

Utafutaji wa key **si** shambulio la keyspace ya AES-256. Jedwali la faili lililosimbwa lina MD5 ya maandishi yake ya awali, urefu wa maandishi hayo, IV na ciphertext ya AES-256-CFB.<sup>[[27]](#references)</sup> `gore` hujaribu madirisha ya byte 32 kutoka kwenye executable ya game au faili za karibu kama keys zinazowezekana. Huchuja candidates kwa kuangalia urefu na kiambishi awali kinachowezekana cha path iliyosimbuliwa, kisha huthibitisha matokeo yaliyopatikana kwa binary-scan kwa kusimbua jedwali lote na kukagua MD5 yake.<sup>[[26]](#references)[[28]](#references)</sup> Hutafuta kwanza sehemu za data za PE/ELF zilizoinitialishwa na, zisipopatikana, huchanganua faili nzima; `--scan` huongeza faili nyingine zinazoweza kuwa candidates.<sup>[[28]](#references)</sup>

Ikiwa hakuna key iliyopachikwa inayopatikana, hujaribiwa orodha ndogo ya passwords iliyojengewa ndani; `--wordlist` hutoa candidates nyingine. Kila password hujaribiwa kama uwakilishi wa key unaotokana na password wa engine, literal iliyojazwa zero, au key ya herufi 64 za hex. Tofauti na matokeo yaliyopatikana kwa binary-scan, matokeo ya wordlist hupita tu kwenye kichujio cha muundo wa path katika implementation hii. Yathibitishe kwa kufungua pack na kuthibitisha assets zilizotolewa.<sup>[[26]](#references)[[28]](#references)</sup>

Ukiwa na artifact ya game kwenye kifaa cha ndani, chagua hatua inayohitajika kwa uchanganuzi. `recover` hutumia GDRE kujenga upya project inayoweza kufunguliwa, ilhali `extract` hufungua faili ghafi pekee. `key` huchapisha key inayowezekana kwa matumizi na tool nyingine.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Uchunguzi wa native unaoungwa mkono na ushahidi kwa kutumia REA

**REA** hutoa uchanganuzi wa Hopper, Ghidra na IDA kupitia CLI na MCP. Inahitaji Node.js 22.x (angalau 22.19), 24.x (angalau 24.11), au 26+, pamoja na npm. Sanidi kwanza provider ya native iliyopo; angalia `rea providers --json` na uchague provider wazi ikiwa zaidi ya mmoja anaweza kusaidia target. Tumia jina la function au anwani iliyozingatiwa kwenye inventory badala ya `0x1000` hapa chini.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Anza na feature string au symbol, fuata references na callers, kisha kagua dossier ya function iliyochaguliwa na pseudocode kwa `rea decompile`. REA hufunga session kwa provider iliyochaguliwa badala ya kuibadilisha kimyakimya baada ya hitilafu. Kwa queries zinazoweza kurudiwa, `--snapshot PATH` hutumia tena tu bytes za artifact, provider, settings, operation na parameters zinazolingana; snapshot ni local cache, si database iliyohifadhiwa ya provider. Hifadhi Evidence iliyorudishwa na unknowns zilizo wazi badala ya kuchukulia paths zilizokisiwa au maandishi ya decompiler kama source asilia.<sup>[[16]](#references)[[18]](#references)</sup>

Kwa entry points za JavaScript/Electron zinazoelekeza kwenye native add-ons, angalia [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Uchambuzi wa IDA na Ghidra kwa script kupitia bridge ya TCP ya ndani

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) huendeshwa ndani ya database ya IDA au program ya Ghidra CodeBrowser ambayo **tayari imefunguliwa**, na huruhusu script tofauti kuuliza na kurekebisha database hiyo ya uchambuzi. Endesha `ID_Server.py` kutoka IDA's Python CLI (`import ID_Server`) au `Ghidra_Server.py` kutoka Ghidra's Script Manager. IDA hufunga kwenye `127.0.0.1` kuanzia port `5073` na kukagua ports za juu zaidi. Script ya sasa ya Ghidra huanza kwenye port `5093` na kujaribu ports kumi hadi `5102`; Java socket yake hufunga kwenye wildcard address, si loopback pekee. Angalia port iliyochapishwa na instance kabla ya kuunganisha. Tofauti na headless analyzer, bridge hii hufanya kazi kwenye program iliyofunguliwa kwa sasa kwenye instance hiyo ya GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Tuma **command moja inayoishia kwa newline kwa kila connection** na usome response inayoishia kwa newline. Matokeo kwa kawaida huwa JSON. Kwa mfano, baada ya kupata API iliyoingizwa ambayo inahusiana na input path, `IMPORTXREF` hupata sehemu za code inakoitwa; kisha `DECOMP_XREF` hudecompile kwa batch callers wa address iliyochaguliwa. `FUNC` hukagua function, huku `PCODE` ikirudisha intermediate representation ya decompiler. Tumia address kutoka kwenye database inayotumika, si address iliyonakiliwa kutoka kwenye binary iliyorebase tofauti. Mfano hapa chini unatumia port chaguomsingi ya IDA; kwa Ghidra, tumia port iliyochapishwa na script yake.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Channel hiyo hiyo inaweza **kubadilisha hifadhidata ya uchanganuzi**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC`, na `PATCH` hubadilisha majina, aina, fasili za miundo, mipaka ya functions, au bytes zilizohifadhiwa. `PATCH` ni uhariri wa hifadhidata, **si** ushahidi wa patch kwenye mchakato unaoendelea. Hakuna listener inayotaja uthibitishaji. IDA inapatikana kupitia loopback pekee, lakini Ghidra inaweza kufikiwa kupitia interfaces za mtandao; zuia ufikiaji wa listener ya Ghidra unapoitumia. `QUIT` husimamisha listener yoyote kati ya hizo, na IDA pia hutoa `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Kutatua hitilafu za shellcode kwa kutumia blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hutenga **shellcode**, huchapisha **anwani yake ya memory**, kisha husitisha utekelezaji.\
Ambatisha debugger kama IDA au x64dbg, weka breakpoint kwenye anwani iliyochapishwa, kisha endeleza utekelezaji ili kutatua hitilafu za shellcode.

Ukurasa wa GitHub wa releases una zips zenye matoleo yaliyokompailiwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililorekebishwa kidogo la Blobrunner kwenye link ifuatayo. Ili kulikompaili, **tengeneza mradi wa C/C++ katika Visual Studio Code, nakili na ubandike code, kisha uijenge**.


{{#ref}}
blobrunner.md
{{#endref}}

### Kutatua hitilafu za shellcode kwa kutumia jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) inafanana na BlobRunner. Hutenga shellcode na kuingia kwenye kitanzi kisichoisha. Ambatisha debugger, endeleza utekelezaji kwa **sekunde 2–5**, sitisha utekelezaji ukiwa ndani ya kitanzi hicho, kisha songa hadi kwenye call inayofuata ambayo huhamishia utekelezaji kwenye shellcode iliyotengwa.

![Debugger imesitishwa ndani ya kitanzi kisichoisha cha jmp2it, mara moja kabla ya call ya shellcode iliyotengwa](<../../images/image (509).png>)

Unaweza kupakua toleo lililokompailiwa la [jmp2it kwenye ukurasa wa releases](https://github.com/adamkramer/jmp2it/releases/).

### Kutatua hitilafu za shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia Cutter unaweza kuiga utekelezaji wa shellcode na kuichunguza wakati inaendeshwa.

Kumbuka kuwa Cutter hukuruhusu kuchagua "Open File" na "Open Shellcode". Katika jaribio langu, nilipofungua shellcode kama faili, iliidecompile kwa usahihi; lakini nilipoifungua kama shellcode, haikuweza:

![Cutter ikionyesha matokeo tofauti ya uchanganuzi ilipofungua bytes zilezile kama faili au shellcode](<../../images/image (562).png>)

Ili kuanza uigaji mahali unapotaka, weka bp hapo, na inaonekana Cutter itaanza uigaji moja kwa moja kutoka hapo:

![Kuweka breakpoint kwenye mwanzo unaotakiwa wa shellcode kabla ya kuanza uigaji wa Cutter](<../../images/image (589).png>)

![Kiigaji cha Cutter kimesitishwa kwenye breakpoint iliyochaguliwa ya shellcode](<../../images/image (387).png>)

Kwa mfano, unaweza kuona stack ndani ya hex dump:

![Kuangalia stack ya shellcode inayoigwa kwenye hex dump ya Cutter](<../../images/image (186).png>)

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

scDbg pia ina graphical launcher ambapo unaweza kuchagua chaguo unazotaka na kutekeleza shellcode

![Kizindua cha picha cha scDbg cha kuchagua chaguo za uigaji na ufuatiliaji wa shellcode](<../../images/image (258).png>)

Chaguo la **Create Dump** litadump shellcode ya mwisho ikiwa mabadiliko yoyote yatafanywa kwa shellcode dynamically kwenye memory (ni muhimu kwa kupakua shellcode iliyodecodeiwa). **start offset** inaweza kusaidia kuanzisha shellcode kwenye offset maalum. Chaguo la **Debug Shell** linafaa kwa ku-debug shellcode ukitumia terminal ya scDbg (hata hivyo, ninaona chaguo zozote kati ya zilizoelezwa awali kuwa bora zaidi kwa hili, kwani utaweza kutumia Ida au x64dbg).

### Ku-disassemble kwa kutumia CyberChef

Pakia faili yako ya shellcode kama input na utumie recipe ifuatayo kuidecompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Kuondoa obfuscation ya MBA

**Mixed Boolean-Arithmetic (MBA)** obfuscation huficha expressions rahisi kama `x + y` kwa kutumia fomula zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Jambo muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, kwa hiyo carries na overflows ni muhimu:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Ukirahisisha aina hii ya usemi kwa kutumia zana za jumla za aljebra, unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za upana wa biti zilipuuzwa.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa vitendo

1. **Hifadhi upana asilia wa biti** kutoka kwenye msimbo/IR/decompiler iliyoinuliwa (`8/16/32/64` bits).
2. **ainisha usemi** kabla ya kujaribu kuurahisisha:
   - **Linear**: jumla zenye uzani za atomu za bitwise
   - **Semilinear**: linear pamoja na masks za kudumu kama vile `x & 0xFF`
   - **Polynomial**: bidhaa zinajitokeza
   - **Mixed**: bidhaa na mantiki ya bitwise zimechanganywa, mara nyingi zikiwa na subexpressions zinazojirudia
3. **Thibitisha kila rewrite inayowezekana** kwa majaribio ya nasibu au uthibitisho wa SMT. Ikiwa ulinganifu hauwezi kuthibitishwa, hifadhi usemi asilia badala ya kubahatisha.

### Bypass control flow iliyoflatteniwa kwa kutumia execution slice finyu

Mara nyingi si lazima kurejesha control-flow graph nzima. Katika control-flow flattening, opaque predicates, dispatchers kubwa, au msimbo mzito wa MBA, fuata marejeleo kutoka kwenye blobs zilizosimbwa kwa njia fiche na output buffers hadi kwenye routine ndogo zaidi inayozibadilisha. Kisha tengeneza upya data-flow slice hiyo pekee, au iendeshe kivyake; dispatcher si sehemu ya suluhisho linalohitajika ikiwa hali husika inaweza kuanzishwa moja kwa moja.<sup>[[7]](#references)</sup>

Mtiririko wa kazi wa vitendo ni:<sup>[[7]](#references)</sup>

1. Orodhesha executable na data sections, relocations, na cross-references. Dump candidate tables kutoka `.rodata` huku ukihifadhi mpangilio wa byte na upana wa kila element.
2. Tambua routine ya mwisho inayoandika plaintext au output buffer. Rekodi inputs zake, tables zinazorejelewa, imported calls, na global state inayohitajika.
3. Inua operations hizo pekee kuwa fixed-width Python model. Ikiwa slice bado inategemea state nyingi mno, iite routine hiyo chini ya Unicorn, QEMU, au debugger na hook imports zisizohusika badala ya kuemulate programu nzima.
4. Thibitisha kuwa extractor inapata output yake kutoka kwenye binary iliyotolewa: ondoa silent fallbacks, itafute majibu yaliyopachikwa ndani yake, na iendeshe dhidi ya builds ambazo hazijaonekana zenye strings, keys, identifiers, layouts, na obfuscation seeds zilizobadilishwa.

Amri muhimu za hatua ya kwanza ni:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Tambua misemo ya MBA inayoficha thamani zisizobadilika

Usemi wa byte unaoonekana kutegemea ingizo unaweza kufuta kabisa athari ya ingizo lake. Baada ya kutoa majedwali yake, tathmini usemi huo katika kikoa kizima cha biti 8; seti ya matokeo yenye thamani moja inathibitisha kuwa byte hiyo haibadiliki, bila kuhitaji kurejesha mashine ya hali inayouzunguka.<sup>[[7]](#references)</sup>

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

Hifadhi mask ya mwisho kwa sababu addition ya awali ina wraparound ya upana wa byte. Kwa domain pana zaidi, iulize SMT solver ikiwa `f(x1) != f(x2)` inaweza kutimizwa kwa symbolic inputs mbili zenye upana sawa: `unsat` huthibitisha invariance, huku `sat` ikitoa counterexample na kumaanisha kuwa input haiwezi kutupwa.<sup>[[7]](#references)</sup>

#### Tambua decoding inayotegemea mazingira

Ukaguzi wa anti-analysis si lazima ufanye branch au kusababisha crash. Decoder inaweza kuchanganya matokeo ya sensor kwenye biti ya key, constant ya opaque-predicate, au state ya flattened-dispatcher, kuendelea kama kawaida, na kutoa plaintext inayofanana na sahihi lakini si ya kweli ndani ya emulator. Kwa hiyo, kupachika patch kwenye failure branches zinazoonekana pekee hakutoshi; fuatilia data dependencies kutoka kwa environment probes hadi kwenye state ya decoder, linganisha slice hiyo hiyo kwenye kifaa halisi na emulator, na ujaribu jinsi kulazimisha kila matokeo ya sensor kunavyobadilisha buffer ya mwisho.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni MBA simplifier ya vitendo kwa ajili ya malware analysis na reversing ya protected binaries. Huainisha expression na kuipitisha kwenye pipelines maalum badala ya kutumia rewrite pass moja ya jumla kwa kila kitu.<sup>[[2]](#references)</sup>

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

Hali zinazofaa:

- **Linear MBA**: CoBRA hutathmini usemi kwa ingizo za Boolean, hupata signature, na huendesha kwa wakati mmoja mbinu kadhaa za urejeshaji, kama vile pattern matching, ubadilishaji wa ANF, na coefficient interpolation.
- **Semilinear MBA**: atomu zilizofichwa kwa constant hujengwa upya kwa kutumia bit-partitioned reconstruction ili maeneo yaliyofichwa yabaki sahihi.
- **Polynomial/Mixed MBA**: bidhaa hugawanywa katika cores, na subexpression zinazorudiwa zinaweza kuhamishiwa kwenye temporaries kabla ya kurahisisha uhusiano wa nje.

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
- Tumia `--bitwidth` waziwazi ikiwa expression imetokana na masked arithmetic au narrow registers.
- Ikiwa unahitaji hatua ya uthibitisho yenye nguvu zaidi, angalia vidokezo vya Z3 hapa:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inapatikana kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka kufanya normalization ya LLVM IR iliyojaa MBA kabla ya passes za baadaye za uchanganuzi.
- Residuals mchanganyiko wa domains zisizotumika na zinazoathiriwa na carry zichukulie kama ishara ya kuhifadhi expression asilia na kuchanganua carry path kwa mikono.

## Kurejesha control-flow flattening ya XOR-state

Flattener ya mtindo wa OLLVM inaweza kuhifadhi state ya basic block ya sasa kwenye registers mbili za 64-bit na kuijenga upya kwa kutumia XOR kwenye dispatcher. Kila block asilia huandika jozi ya state ya block inayofuata kisha huruka kurudi kwenye dispatcher. Block yenye masharti inaweza kutumia `CMOVcc` kubadilisha nusu moja ya jozi kulingana na CPU flags, kwa hiyo kufuata maagizo ya branch yanayoonekana pekee hukosa successors hao wawili. Tofauti na indirect-jump dispatcher, muundo huu unaweza kutumia direct back-edges kila mahali.<sup>[[19]](#references)[[20]](#references)</sup>

Ili kurejesha graph, tambua comparison tree ya dispatcher na registers mbili za state, ramani kila XOR state iliyolinganishwa kwa target block yake, kisha fuatilia writes zinazofika kwenye jozi ya registers katika kila block asilia. Kwa writes zenye masharti, jumuisha instruction inayoweka flags na matokeo yote mawili ya `CMOVcc`. Andika upya exit ya dispatcher ya kila block iwe direct successor au conditional branch iliyotatuliwa; baada ya hapo dispatcher haitafikiwa tena bila ku-patch binary. Hii ni mbinu ya full-CFG; ikiwa decoder moja tu ndiyo muhimu, workflow ya [narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) hapo juu inaweza kuwa ya haraka zaidi.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) huendesha automation ya muundo huu katika Binary Ninja. Nakili `plugins/DispatchThis` kwenye saraka ya user plugin ya Binary Ninja kisha uwashe upya. Kwenye function iliyoathiriwa, fungua **Function Settings** na uchague `OLLVM_XOR_64`; ikiwa uchanganuzi hautaanza, tumia **Analysis → Reanalyze All Functions**. Mode hii huandika upya control-flow edges za MLIL, si bytes za faili, na haihitaji Z3 wala indirect-jump resolver. Imejaribiwa kwenye Binary Ninja 5.3.9757+; haiondoi state writes zilizokufa za kila block, kwa hiyo usizichanganye na transitions zinazotumika bado.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator hii hubadilisha operations za programu kuwa instruction sequences zinazotumia `mov` na hutumia signal/exception handling kubadilisha control flow. Kwa maelezo zaidi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kwa binaries zinazoungwa mkono, [demovfuscator](https://github.com/kirschju/demovfuscator) inaweza kuondoa obfuscation kwenye matokeo. Ina dependencies kadhaa.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Na [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unashiriki kwenye **CTF, njia hii ya kutafuta flag** inaweza kuwa na manufaa sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point**, tafuta kwenye functions kwa kutumia `::main` kama ilivyo hapa:

![Kupata entry point ya Rust katika Ghidra kwa kutafuta majina ya function yenye double-colon main](<../../images/image (1080).png>)

Katika hali hii, binary iliitwa authenticator, kwa hiyo ni wazi kabisa kwamba hii ndiyo main function inayovutia.\
Ukiwa na **majina** ya **functions** zinazoitwa, zitafute kwenye **Internet** ili ujifunze kuhusu **inputs** na **outputs** zake.

### Kurejesha strings za Rust kutoka firmware ya ELF

Katika binary za **Rust ELF**, strings nyingi tuli hazirejelewi kama pointers za mtindo wa C zilizokomeshwa kwa NUL. Mpangilio wa kawaida wa `rustc` ni **pointer/length tuple** ndani ya **`.data.rel.ro`** inayoelekeza kwenye blob halisi ya string iliyohifadhiwa katika **`.rodata`**:

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
3. Chukulia thamani yoyote iliyo ndani ya masafa ya anwani ya `.rodata` kuwa pointer ya string inayoweza kufaa.
4. Chukulia neno linalofuata kuwa urefu unaoweza kufaa.
5. Tumia vichujio vya uhalali (kwa mfano, hifadhi urefu kati ya **4** na **100** bytes).
6. Soma bytes `length` hasa kutoka `.rodata` badala ya kusoma hadi `0x00`.

Mantiki ndogo ya extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Hili ni muhimu hasa katika firmware reversing kwa sababu strings za Rust zilizorejeshwa mara nyingi hufichua **HTTP routes, majina ya RPC, ujumbe wa log, assertions, majina ya faili, config keys, command handlers, na logic inayohusiana na auth**.

Ghidra ikikosa strings hizo, endesha script/plugin maalum inayotumia heuristic hiyo hiyo na kuunda data ya string kwenye offsets za `.rodata` zilizorejelewa. Zana zilizochapishwa za `rust-strings` na `RustStrings.py` kutoka Pen Test Partners ni marejeo mazuri ya kurekebisha wazo hilo kwa **ukubwa mwingine wa word, endianness, na miundo tofauti ya section**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Kwa binary zilizokompailiwa za Delphi unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa itabidi ureverse binary ya Delphi, ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Plugin hii itaendesha binary na kutatua majina ya functions kwa nguvu mwanzoni mwa debugging. Baada ya kuanza debugging, bonyeza tena kitufe cha Start (kile cha kijani au f9), na breakpoint itafikiwa mwanzoni mwa code halisi.

Ukibonyeza kitufe katika programu ya picha, debugger inaweza kusimama kwenye function iliyoitwa na kitufe hicho.

## Golang

Kwa binary za kawaida za Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) inaweza kurejesha runtime structures na kuboresha majina ya functions katika IDA. Pakia Python plugin yake kwa **Alt+F7**.

Ikiwa itabidi ureverse binary ya Golang, ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **Alt+F7** katika IDA ili kupakia Python plugin, kisha uchague faili ya plugin.

Hii itatatua majina ya functions.

### Rejesha metadata bila symbol table

Go executable iliyostripiwa bado inahitaji runtime metadata ili kuoanisha program counters na functions. [GoReSym](https://github.com/mandiant/GoReSym) hupata na kuchanganua structures kama `pclntab` na `moduledata` kwa kutumia code iliyotokana na Go runtime. Hii inaweza kurejesha mipaka ya functions, majina, source paths, types na maelezo ya build bila kutegemea symbol table ya kawaida.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator inaweza kuacha miundo hiyo ikiendelea kutumika huku ikibadilisha majina yaliyorejeshwa. Kwa mfano, Garble huhash vitambulishi na njia za package, na huondoa taarifa za build, module na debug.<sup>[[12]](#references)</sup> Tokeni ya package iliyofichwa lazima ibaki ileile katika functions kutoka package hiyo. Panga functions kwa tokeni inayojirudia, bainisha package moja kutokana na callees, strings na APIs zake, kisha sambaza lebo hiyo ya package kwa kundi lote.<sup>[[13]](#references)</sup>

### Rejesha majina ya Garble kwa GoResolver

[GoResolver](https://github.com/volexity/GoResolver) huunganisha uchimbaji wa runtime symbols na utengenezaji wa marejeo safi pamoja na ulinganishaji wa control-flow-graph (CFG). Tumia mfuatano huu:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Tambua toleo la compiler.** Jaribu `BuildInfo` na strings za toleo zilizopachikwa kwanza. Ikiwa obfuscator iliziondoa, linganisha sehemu za Go runtime iliyojumuishwa na runtime za marejeo zenye matoleo maalum. Katika majaribio ya Volexity, takriban `2%` ya runtime ilitosha kutofautisha matoleo makuu ya Go. Ichukulie hii kama uboreshaji uliothibitishwa kwa majaribio, si kizingiti cha jumla.<sup>[[13]](#references)</sup>
2. **Tengeneza marejeo yanayolingana.** Tengeneza binaries safi za toleo la Go lililotambuliwa, usanifu lengwa na libraries zinazowezekana. Kulinganisha toolchain hupunguza tofauti za CFG zinazotengenezwa na compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Linganisha functions.** GoGrapher hulinganisha CFG za functions na kutoa alama zilizosanifishwa kuanzia `0.0` hadi `1.0`. Ulinganishaji wake wa basic blocks unategemea ulinganishaji wenye uzito wa instructions zinazofanana. Ulinganishaji wenye uhakika mkubwa huunganisha functions zilizobadilishiwa majina nasibu na implementation safi. Ulinganishaji wenye uhakika mdogo bado unaweza kutambua package au module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Thibitisha na uingize.** Thibitisha majina yaliyopendekezwa kwa kutumia uhusiano wa calls, constants, strings na athari za pembeni, kisha ingiza ripoti ya JSON kwa kutumia plugin ya GoResolver ya IDA au Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Kizingiti chaguomsingi cha ulinganifu muhimu ni `0.9`. Swichi za `--extract` na `--graph` zinaweza kutenga hatua yoyote kati ya hizo, huku utekelezaji chaguomsingi ukiendesha zote mbili kwa sababu metadata ya runtime iliyorejeshwa na ushahidi wa CFG hukamilishana.<sup>[[10]](#references)</sup> Alama za CFG ni za kihisabati: inlining, build flags, usanifu na tofauti za matoleo ya library zinaweza kubadilisha umbo la grafu, kwa hiyo hifadhi functions ambazo hazijatatuliwa badala ya kulazimisha majina yenye kiwango cha chini cha uhakika.<sup>[[13]](#references)</sup>

### Kurejesha jedwali la strings la Go

Binaries za Go huweka bytes za strings kutoka kila package iliyounganishwa kwenye jedwali moja linaloendelea. Entries hazimalizwi kwa NUL na miundo ya runtime haionyeshi msingi au ukubwa wa jedwali. Hata hivyo, compiler hupanga entries kwanza kwa urefu, kisha kwa alfabeti, katika mifumo ya uendeshaji na usanifu mbalimbali. Kwa hiyo, baada ya kupata entry moja, mchambuzi anaweza kupitia entries zilizo karibu na kutumia marejeleo mtambuka ya data kuhusisha strings na code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) huendesha workflow hii kiotomatiki katika IDA Pro na Ghidra. Subiri auto-analysis ikamilike kwanza kwa sababu plugin hutegemea marejeleo mtambuka ya data-segment. Nanga yake chaguomsingi ni string ya runtime `entersyscall`; kisha inaweza kuchanganua kuelekea upande wowote, kufafanua strings zilizorejeshwa kwenye database, na kuhamisha JSON inayohusisha strings na functions zinazozirejelea.<sup>[[14]](#references)</sup>

Chuja ripoti kwa package ya function inayorejelea ili kutenganisha code ya application au malware na kelele za library zilizounganishwa. Mbinu hii haiwezi kurejesha literals zilizoharibiwa na obfuscation kama vile mabadiliko ya Garble ya `-literals`. Bado inaweza kupanga strings za runtime ambazo hazijafichwa kwa obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Kurejesha aina za runtime za Go

Go hujumuisha taarifa za aina za runtime zinazotumiwa na vipengele kama garbage collection. Build information inapofutwa au disassembler isipoweza kuchanganua metadata hii, instructions zinaweza kuonekana kana kwamba zinapakia anwani za data zisizohusiana na eneo lengwa hubaki bila aina. Kurejesha metadata hubadilisha anwani hizo kuwa marejeleo ya aina yanayosomeka na kurahisisha kuelewa uwezo wa package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) inaweza kutoa symbols na kuchanganua aina za runtime ili kuunda ripoti ya JSON. CLI ya sasa hutumia subcommand ya `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Chaguo la `-y`/`--types` huwasha uchanganuzi wa aina. Ingiza ripoti kwa kutumia plugin ya IDA Pro au Ghidra ya GoResolver ili kufafanua aina zilizorejeshwa na kutumia marejeleo yake katika hifadhidata ya uchanganuzi. Katika muundo wa ripoti ulioanzishwa na kipengele hiki, ukiacha `-y`, sehemu za anwani ya RTTI na aina zilizorejeshwa hubaki null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hutumia sampuli za PE, ELF na Mach-O za x86, AMD64, ARM na ARM64, kwa hivyo mtiririko huohuo wa kazi unatumika kwa binary za Go kutoka Windows, Linux na macOS.<sup>[[10]](#references)</sup>

## Python Iliyokompiliwa

Katika ukurasa huu unaweza kupata maelezo ya jinsi ya kupata msimbo wa python kutoka kwenye binary ya python iliyokompiliwa ya ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Ukipata **binary** ya mchezo wa GBA, unaweza kutumia zana mbalimbali ku **emulate** na **debug** mchezo huo:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la debug_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina debugger ya CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin ya Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), kwenye _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![Mipangilio ya vidhibiti vya no$gba inayoonyesha ulinganifu wa vitufe vya Game Boy Advance](<../../images/image (581).png>)

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

Kwa hiyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia ingizo la mtumiaji**. Katika anwani **0x4000130** utapata function inayopatikana mara nyingi: **KEYINPUT**.

![Mwonekano wa Ghidra wa binary ya GBA unaorejelea KEYINPUT kwenye anwani 0x4000130](<../../images/image (447).png>)

Katika picha iliyotangulia, unaweza kuona kwamba function inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

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

`if` ya mwisho inakagua kama **`uVar4`** imo kwenye **Keys** za awali na si ufunguo wa sasa. Hii pia huitwa kuachia kitufe (ufunguo wa sasa umehifadhiwa kwenye **`uVar1`**).

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

Katika code iliyotangulia unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **thamani ya kitufe kilichobonyezwa** ipo) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto hii, kitufe hiki hufuta skrini
- Kisha thamani inalinganishwa na **8** (kitufe cha **START**); katika changamoto hii, njia hiyo hukagua kama code iliyoingizwa ni halali.
  - Katika hali hii, var **`DAT_030000d8`** inalinganishwa na 0xf3 na ikiwa thamani ni sawa, code fulani hutekelezwa.
- Katika hali nyingine zote, kaunta (`DAT_030000d4`) hukaguliwa na kuongezwa.\
  Kaunta ikiwa chini ya 8, thamani za vitufe vilivyobonyezwa hukusanywa katika `DAT_030000d8`.

Kwa hiyo, katika changamoto hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu wa chini ya 8 ambao jumla yake ni 0xf3.**

**Marejeleo ya mafunzo haya:** [maelezo ya changamoto ya Nostalgia yaliyohifadhiwa](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (kuondoa obfuscation ya binary)

## References

- [1] [Kurahisisha obfuscation ya MBA kwa CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Hifadhi ya Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Kudecode strings za Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - strings za Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - mafunzo ya GBA reversing (yaliyohifadhiwa)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Kushinda Reverse Engineering inayosaidiwa na AI, au Angalau Kujaribu](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Mbinu ya Kulinganisha Control Flow Graphs kwa Kutumia Ulinganishaji wa Basic Block](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Hifadhi ya Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Utaratibu wa obfuscation wa Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Kutumia Ufanano wa Control-Flow Graph ili Kuondoa Obfuscation ya Golang Binaries Kiotomatiki](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Hifadhi ya Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Maboresho ya Zana za Golang za Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Chochote](https://github.com/morluto/rea)
- [17] [Uchambuzi wa managed-code wa REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Mwongozo wa REA CLI na Evidence](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Mchakato wa Binary Ninja wa kuondoa control-flow flattening](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Uvamizi wa PaperCut MF Zero-Day, Java Loader, Web Shell na AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README ya IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Utekelezaji wa IDA bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Utekelezaji wa Ghidra bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) hufunga kwenye anwani ya wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: zana za Godot reverse engineering](https://github.com/figurophobia/gore)
- [26] [Utekelezaji wa kurejesha key wa gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Muundo wa encrypted-blob wa gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Utekelezaji wa command na recovery wa gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
