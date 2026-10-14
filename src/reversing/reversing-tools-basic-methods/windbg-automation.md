# Uendeshaji wa WinDbg kiotomatiki kwa instrumentation inayolengwa

{{#include ../../banners/hacktricks-training.md}}

WinDbg na WinDbgX zinaweza kutekeleza amri za debugger zinapoanza, kunapotokea exceptions, na breakpoints zinapowashwa. Hii huruhusu kipindi cha fuzzing au reversing kukusanya hali ya mfumo kwenye njia inayoendeshwa na ingizo pekee, badala ya kusimama mwenyewe kila tukio linapotokea.<sup>[[1]](#references)</sup>

## Anza kwenye exception inayofaa

`-c` huendesha amri kwenye break ya awali ya debugger. Ongeza `;g` ili kuendelea baada ya usanidi. Kwa uendeshaji wa WinDbg Classic usiohitaji uangalizi, `-logo` huandika dirisha la amri kwenye logi, `-Q` huzima uhifadhi wa kiotomatiki wa workspace, na `-G` hupuuza breakpoint ya mwisho ili kipindi kiishe target inapotoka. WinDbgX pia hukubali `-c`; amri zake za Startup zilizosanidiwa huendeshwa baadaye.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Kwa access violations, **`sxe av` husimama kwenye first chance**, **`sxd av` huruka first chance lakini husimama kwenye second chance isiyoshughulikiwa**, na **`sxi av` hupuuza nafasi zote mbili**. Maelezo ya makala kuhusu `sxi`/`sxd` yamebadilishana hapa: Microsoft inaeleza `sxd` kama kichujio cha second-chance na `sxi` kama kupuuza. Tumia `-c` kwa amri ya first-chance na `-c2` kwa amri ya second-chance; handler ya first-chance `-c` haibadiliki kuwa handler ya second-chance kwa sababu tu kichujio ni `sxd`. Thibitisha vichujio vinavyotumika kwa `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Amri ya kwanza hukusanya registers, stack trace, na uchanganuzi wa exception kwa access violation isiyoshughulikiwa pekee. Ya pili huendesha `lm` moduli inapopakiwa. Matukio ya breakpoint (`bp`), upakiaji wa moduli (`ld`), na access violation (`av`) yana mizunguko tofauti ya maisha, kwa hivyo usipuuze `bp` duniani kote unapotegemea breakpoints za debugger.<sup>[[1]](#references)[[2]](#references)</sup>

## Weka breakpoints ghali chini ya udhibiti wa kichochezi

Chagua function inayoonekana kwenye script au inayodhibitiwa na input kwa njia nyingine, ambayo inaweza kuitwa mara moja kabla ya njia unayotaka kuchunguza. Sakinisha **action breakpoints** kwenye miito ya allocator, parser, au API unayotaka kukagua. Zizime kwa ID ukitumia `bd`. Sakinisha **trigger breakpoint** yenye amri iliyoambatishwa inayowasha ID hizo kwa `be`, kisha kuendelea na `g`; trigger ya pili inayodhibitiwa inaweza kuzizima tena. Angalia ID kwa `bl` kabla ya kuweka trigger, kwa sababu hutegemea mpangilio wa uundaji wa breakpoint. Hii hutenganisha sehemu za udhibiti za gharama ndogo na ufuatiliaji ghali, na kupunguza mabadiliko kwa muda wa utekelezaji wa target na mpangilio wa heap.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Baada ya kutatua alama hizo mbili, muundo wa amri uko hapa chini. Badilisha alama zilizo kwenye mabano ya mraba na ID ya action breakpoint iliyorudishwa na `bl`; usidhani kuwa ni sifuri.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Amri za action breakpoint zinaweza kuchapisha `@$ip` na `%y` (anwani iliyotambuliwa kwa symbol), kutoa dump ya arguments au memory zilizochaguliwa, kisha kuendelea. Ikiwa conditional breakpoint inaandika log ya pointers zilizo katika range iliyochaguliwa pekee, hakikisha kwanza kwamba range hiyo inajumuisha test input; condition isiyo sahihi hupoteza ushahidi bila taarifa.<sup>[[1]](#references)</sup>

### Tafuta trigger kwa kutumia symbols

Tafuta katika modules zote zilizopakiwa ikiwa module inayotekeleza haijulikani. `bm` huweka breakpoints kwenye kila symbol inayolingana; ita function inayoonekana kwa script na ukague ni breakpoint ipi inayosababishwa. Kwa mfano, source huendesha `Math.cos(0)` kwenye renderer inayochunguzwa, si tu kwenye process yoyote ya browser.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Hit inapobainisha function halisi, tumia `lm a <symbol>` kutambua image inayoijumuisha na `? <symbol> - <module>` kukokotoa offset inayohusiana na module. WinDbg inaweza kuonyesha jina fupi lilelile la module kwa executable na DLL, kwa hivyo thibitisha path ya image kabla ya kutumia offset hiyo katika process nyingine. Punguza breakpoint za wildcard ziwe kwenye symbol iliyothibitishwa ili kuepuka overhead.<sup>[[1]](#references)</sup>

### Tafuta candidate bila symbols

Corelan's Frida-based `corelan_trigscan.py` huchanganua module iliyochaguliwa ya process kutafuta mifumo ya floating-point, SSE, AVX na trigonometric instructions. Hutoa amri za WinDbg za breakpoint katika `corelan_trigscan.bps` na faili ndogo za `.bps` zenye nambari. Iendeshe kwa Python na `frida-tools` dhidi ya target **bila debugger nyingine kuunganishwa**; kisha unganisha WinDbg kwenye process/module hiyo hiyo na upakie kundi la breakpoint linaloweza kudhibitiwa.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Kwa offset inayohusiana na module inayojulikana, thibitisha kwamba inapita vizingiti kabla ya kuingiza breakpoints zote zilizotolewa:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` ni msongamano wa instructions husika, `--min-relevant` na `--min-total` huweka viwango vya chini vya idadi ya instructions, na `--min-trig` huhitaji ishara thabiti zinazofanana na trig. Ikiwa function inayojulikana haipatikani, pitisha offset yake **inayohusiana na module** kwa `--check-offset` ili kukagua prologue, msongamano, idadi na indirect calls. Wrapper nyembamba inaweza kuwa na msongamano mdogo na isiwe na instruction ya trig. Punguza thresholds na, ikiwa unatafuta wrappers, tumia option halisi ya `--min-icall 1` ya script (si `--min-ical`); direct callees huchanganuliwa, lakini indirect targets haziwezi kufuatiliwa kwa uhakika. Batches ndogo za `--splitsize` husaidia wakati breakpoints nyingi zinazozalishwa zinapunguza kasi ya WinDbg. Candidate haijathibitishwa hadi input iliyokusudiwa ifanye breakpoint yake iwake.<sup>[[1]](#references)[[6]](#references)</sup>

## Small debugger programs and PyKD

Tumia `.if` ikiwa condition ni ya kuaminika, `.foreach` kurudia output iliyotenganishwa kwa whitespace, na `.for` pamoja na pseudo-registers kupitia memory au structures. `.foreach` **haihifadhi columns**: kwa mfano, output ya `lm` yenye upana wa sehemu tofauti si input nzuri, ilhali `lm 1m` hutoa jina moja la module kwa kila token. Rekodi data isiyochujwa kwanza ikiwa condition uliyokisia inaweza kuficha njia inayoshindwa.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Aliases zinazoundwa kwa `as name value` ni vibadala vya maandishi, si vigeu vilivyo na aina. `al` huorodhesha aliases, `ad name` hufuta moja, na `${name}` hulazimisha upanuzi usio na utata. Epuka majina kama `bp`, `x`, au `r` kwa sababu alias inaweza kufunika amri iliyojengewa ndani. Expressions za MASM zinafaa kwa hesabu za pointer kama `poi(@$t0)`; `@@c++(...)` inaweza kufikia fields zenye aina pale symbols zinapopatikana, na hivyo kuepuka offsets za muundo zilizowekwa moja kwa moja.<sup>[[1]](#references)</sup>

Weka mfuatano mrefu wa amri kwenye faili ya amri. `$$><filename` huunganisha mistari kuwa block moja ya amri na kuruhusu amri ya debugger inayofuata iliyotenganishwa kwa semicolon. Miundo ya udhibiti yenye mistari mingi bado inaweza kuwa dhaifu; weka kila kauli ya `.if` au `.for` kwenye mstari mmoja. Faili hiyo hiyo inaweza kuitwa kutoka `-c` wakati wa kuwasha.<sup>[[1]](#references)[[8]](#references)</sup>

Kwa mantiki ambayo si rahisi kuandika katika lugha ya amri, PyKD huweka structures zenye aina, registers, memory na matokeo ya debugger wazi kwa Python. Kwa mfano, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` hufikia fields za PEB, `pykd.loadBytes(address, size)` husoma memory, na `pykd.dbgCommand("lm")` hurejesha matokeo ya debugger kwa ajili ya kuyachanganua. Pendelea `loadChars`/`loadWChars` zenye kikomo badala ya kusoma strings bila kikomo kwa data ambayo huenda haina terminator. `disasm(address).asm(instruction)` ya PyKD **huandika bytes zilizokusanywa kwenye anwani hiyo**, kwa hivyo hifadhi na urejeshe memory ya awali ukiitumia kupata opcodes katika process inayoendelea.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Utatuzi - Uendeshaji wa WinDBG(X) na Uandishi wa Skripti - Sehemu ya 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Kuweka Vighairi)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Kuwasha Breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Kuzima Breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Kuweka Breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Chanzo cha Corelan trigscan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: Chaguo za Mstari wa Amri za WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Kuendesha Faili ya Skripti](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
