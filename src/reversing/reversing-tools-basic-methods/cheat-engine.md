# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo values muhimu zimehifadhiwa ndani ya memory ya game inayoendesha na kuzibadilisha.\
Unapoipakua na kuiendesha, **utaonyeshwa** **tutorial** ya jinsi ya kutumia tool hii. Ikiwa unataka kujifunza jinsi ya kutumia tool hii, inapendekezwa sana kuikamilisha.

## Unatafuta nini?

![Cheat Engine - Unatafuta nini?: Unatafuta nini?](<../../images/image (762).png>)

Tool hii ni muhimu sana kutafuta **mahali ambapo value fulani** (kwa kawaida namba) **imehifadhiwa kwenye memory** ya program.\
**Kwa kawaida namba** huhifadhiwa katika mfumo wa **4bytes**, lakini unaweza pia kuzipata katika format za **double** au **float**, au unaweza kutaka kutafuta kitu **ambacho si namba**. Kwa sababu hiyo, unahitaji kuhakikisha kuwa **umechagua** unachotaka **kutafuta**:

![Cheat Engine - Unatafuta nini?: Kwa kawaida namba huhifadhiwa katika mfumo wa 4bytes, lakini unaweza pia kuzipata katika format za double au float, au unaweza kutaka kutafuta kitu...](<../../images/image (324).png>)

Pia unaweza kuonyesha aina **tofauti** za **searches**:

![Cheat Engine - Unatafuta nini?: Pia unaweza kuonyesha aina tofauti za searches](<../../images/image (311).png>)

Unaweza pia kuchagua kisanduku ili **kusimamisha game wakati wa kuscan memory**:

![Cheat Engine - Unatafuta nini?: Unaweza pia kuchagua kisanduku ili kusimamisha game wakati wa kuscan memory](<../../images/image (1052).png>)

### Hotkeys

Katika _**Edit --> Settings --> Hotkeys**_ unaweza kuweka **hotkeys** tofauti kwa madhumuni tofauti, kama vile **kusimamisha** **game** (ambayo ni muhimu sana ikiwa wakati fulani unataka kuscan memory). Options nyingine zinapatikana:

![Unatafuta nini? - Hotkeys: Katika Edit -- Settings -- Hotkeys unaweza kuweka hotkeys tofauti kwa madhumuni tofauti, kama vile kusimamisha game (ambayo ni muhimu sana ikiwa wakati fulani...](<../../images/image (864).png>)

## Kubadilisha value

Baada ya **kupata** mahali ambapo kuna **value** unayo **tafuta** (zaidi kuhusu hili katika hatua zifuatazo), unaweza **kuibadilisha** kwa kuibofya mara mbili, kisha kubofya value yake mara mbili:

![Hotkeys - Kubadilisha value: Baada ya kupata mahali ambapo kuna value unayotafuta (zaidi kuhusu hili katika hatua zifuatazo), unaweza kuibadilisha kwa kuibofya mara mbili, kisha kubofya...](<../../images/image (563).png>)

Na mwishowe **kuchagua kisanduku** ili kufanya mabadiliko kwenye memory:

![Hotkeys - Kubadilisha value: Na mwishowe kuchagua kisanduku ili kufanya mabadiliko kwenye memory](<../../images/image (385).png>)

**Mabadiliko** kwenye **memory** yata**tumiwa** mara moja (kumbuka kwamba hadi game itumie value hii tena, value **haitasasishwa kwenye game**).

## Kutafuta value

Kwa hiyo, tutachukulia kwamba kuna value muhimu (kama vile life ya user wako) ambayo unataka kuiboresha, na unatafuta value hii kwenye memory)

### Kupitia mabadiliko yanayojulikana

Tukichukulia kwamba unatafuta value 100, **unafanya scan** ukitafuta value hiyo na unapata matches nyingi:

![Kutafuta value - Kupitia mabadiliko yanayojulikana: Tukichukulia kwamba unatafuta value 100, unafanya scan ukitafuta value hiyo na unapata matches nyingi](<../../images/image (108).png>)

Kisha, unafanya kitu kinachofanya **value ibadilike**, na **unasimamisha** game na **kufanya** **next scan**:

![Kutafuta value - Kupitia mabadiliko yanayojulikana: Kisha, unafanya kitu kinachofanya value ibadilike, na unasimamisha game na kufanya next scan](<../../images/image (684).png>)

Cheat Engine itatafuta **values** ambazo **zilitoka 100 hadi value mpya**. Hongera, **umepata** **address** ya value uliyokuwa unatafuta, na sasa unaweza kuibadilisha.\
_Ikiwa bado una values kadhaa, fanya kitu cha kubadilisha value hiyo tena, kisha fanya "next scan" nyingine ili kuchuja addresses._

### Unknown Value, known change

Katika hali ambayo **hujui value**, lakini unajua **jinsi ya kuifanya ibadilike** (na hata value ya mabadiliko), unaweza kutafuta namba yako.

Anza kwa kufanya scan ya aina ya "**Unknown initial value**":

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Anza kwa kufanya scan ya aina ya " Unknown initial value "](<../../images/image (890).png>)

Kisha, fanya value ibadilike, onyesha **jinsi** **value** ilivyobadilika (katika hali yangu ilipungua kwa 1), na ufanye **next scan**:

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Kisha, fanya value ibadilike, onyesha jinsi value ilivyobadilika (katika hali yangu ilipungua kwa 1), na ufanye next scan](<../../images/image (371).png>)

Utaonyeshwa **values zote zilizobadilishwa kwa njia iliyochaguliwa**:

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Utaonyeshwa values zote zilizobadilishwa kwa njia iliyochaguliwa](<../../images/image (569).png>)

Baada ya kupata value yako, unaweza kuibadilisha.

Kumbuka kwamba kuna **mabadiliko mengi yanayowezekana**, na unaweza kufanya **hatua hizi mara nyingi unavyotaka** ili kuchuja results:

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Kumbuka kwamba kuna mabadiliko mengi yanayowezekana, na unaweza kufanya hatua hizi mara nyingi unavyotaka ili kuchuja results](<../../images/image (574).png>)

### Random Memory Address - Finding the code

Hadi sasa tumejifunza jinsi ya kupata address inayohifadhi value, lakini kuna uwezekano mkubwa kwamba katika **executions tofauti za game, address hiyo itakuwa katika maeneo tofauti ya memory**. Kwa hiyo, hebu tujue jinsi ya kuipata address hiyo kila mara.

Kwa kutumia baadhi ya tricks zilizotajwa, pata address ambayo game yako ya sasa inatumia kuhifadhi value muhimu. Kisha (ukisimamisha game ikiwa unataka), bofya **right click** kwenye **address** iliyopatikana na uchague "**Find out what accesses this address**" au "**Find out what writes to this address**":

![Unknown Value, known change - Random Memory Address - Finding the code: Kwa kutumia baadhi ya tricks zilizotajwa, pata address ambayo game yako ya sasa inatumia kuhifadhi value muhimu. Kisha...](<../../images/image (1067).png>)

**Option ya kwanza** ni muhimu kujua ni **sehemu zipi** za **code** **zinazotumia** **address** hii (ambayo ni muhimu kwa mambo mengine kama **kujua mahali unapoweza kubadilisha code** ya game).\
**Option ya pili** ni **maalum** zaidi, na itasaidia zaidi katika hali hii kwa sababu tunataka kujua **value hii inaandikwa kutoka wapi**.

Baada ya kuchagua mojawapo ya options hizo, **debugger** ita**ambatanishwa** na program na **window mpya tupu** itaonekana. Sasa, **cheza** **game** na **ubadilishe** **value** hiyo (bila kuanzisha game upya). **Window** inapaswa **kujazwa** na **addresses** ambazo **zinabadilisha** **value**:

![Unknown Value, known change - Random Memory Address - Finding the code: Baada ya kuchagua mojawapo ya options hizo, debugger itaambatanishwa na program na window mpya tupu itaonekana. Sasa...](<../../images/image (91).png>)

Sasa kwa kuwa umepata address inayobadilisha value, unaweza **kubadilisha code unavyotaka** (Cheat Engine inakuruhusu kuibadilisha kwa NOPs haraka sana):

![Unknown Value, known change - Random Memory Address - Finding the code: Sasa kwa kuwa umepata address inayobadilisha value, unaweza kubadilisha code unavyotaka (Cheat Engine...](<../../images/image (1057).png>)

Kwa hiyo, sasa unaweza kuibadilisha ili code isiathiri namba yako, au iathiri kila mara kwa njia chanya.

### Random Memory Address - Finding the pointer

Ukifuata hatua zilizotangulia, tafuta mahali ambapo value unayoihitaji ipo. Kisha, ukitumia "**Find out what writes to this address**", tafuta ni address ipi inayoandika value hii na uibofye mara mbili ili kupata disassembly view:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Ukifuata hatua zilizotangulia, tafuta mahali ambapo value unayoihitaji ipo. Kisha, ukitumia " Find out...](<../../images/image (1039).png>)

Kisha, fanya scan mpya **ukitafuta hex value iliyo kati ya "\[]"** (value ya $edx katika hali hii):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Kisha, fanya scan mpya ukitafuta hex value iliyo kati ya " ()" (value ya $edx katika hali hii)](<../../images/image (994).png>)

(_Ikiwa kadhaa zitaonekana, kwa kawaida unahitaji ile yenye address ndogo zaidi_)\
Sasa, **tumepata pointer itakayobadilisha value tunayovutiwa nayo**.

Bofya "**Add Address Manually**":

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Bofya " Add Address Manually "](<../../images/image (990).png>)

Sasa, bofya kisanduku cha "Pointer" na uongeze address iliyopatikana kwenye text box (katika hali hii, address iliyopatikana kwenye picha iliyotangulia ilikuwa "Tutorial-i386.exe"+2426B0):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Sasa, bofya kisanduku cha "Pointer" na uongeze address iliyopatikana kwenye text box (katika hali hii,...](<../../images/image (392).png>)

(Kumbuka jinsi "Address" ya kwanza inavyojazwa moja kwa moja kutoka kwenye pointer address uliyoingiza)

Bofya OK na pointer mpya itaundwa:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Bofya OK na pointer mpya itaundwa](<../../images/image (308).png>)

Sasa, kila mara unapobadilisha value hiyo, **unabadilisha value muhimu hata kama memory address ilipo value hiyo ni tofauti.**

### Code Injection

Code injection ni technique ambapo unaingiza kipande cha code kwenye target process, kisha unaelekeza upya execution ya code ipitie kwenye code uliyoandika mwenyewe (kama kukupa points badala ya kuzipunguza).

Kwa hiyo, fikiria kwamba umepata address inayopunguza life ya player wako kwa 1:

![Random Memory Address - Finding the pointer - Code Injection: Kwa hiyo, fikiria kwamba umepata address inayopunguza life ya player wako kwa 1](<../../images/image (203).png>)

Bofya Show disassembler ili kupata **disassemble code**.\
Kisha, bofya **CTRL+a** ili kufungua Auto assemble window na uchague _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Kisha, bofya CTRL+a ili kufungua Auto assemble window na uchague Template -- Code Injection](<../../images/image (902).png>)

Jaza **address ya instruction unayotaka kubadilisha** (kwa kawaida hujazwa moja kwa moja):

![Random Memory Address - Finding the pointer - Code Injection: Jaza address ya instruction unayotaka kubadilisha (kwa kawaida hujazwa moja kwa moja)](<../../images/image (744).png>)

Template itatengenezwa:

![Random Memory Address - Finding the pointer - Code Injection: Template itatengenezwa](<../../images/image (944).png>)

Kwa hiyo, weka assembly code yako mpya katika sehemu ya "**newmem**" na uondoe code ya awali kutoka kwenye "**originalcode**" ikiwa hutaki itekelezwe**.** Katika mfano huu, code iliyoingizwa itaongeza points 2 badala ya kupunguza 1:

![Random Memory Address - Finding the pointer - Code Injection: Kwa hiyo, weka assembly code yako mpya katika sehemu ya " newmem " na uondoe code ya awali kutoka kwenye " originalcode " ikiwa...](<../../images/image (521).png>)

**Bofya execute na kadhalika, na code yako inapaswa kuingizwa kwenye program na kubadilisha tabia ya functionality!**

## Relocation-safe code injection with AOB signatures

Script inayohook `game.exe+123456` inaweza kuacha kufanya kazi baada ya ASLR au software update. **Array of Bytes (AOB) signature** hupata instruction kwa kutumia machine code inayozunguka instruction hiyo badala yake. Tumia `aobscanmodule` kuzuia search kwenye module moja. Fanya signature iwe ndefu vya kutosha ili irudishe match moja. Tumia wildcards kwenye relocation bytes, addresses na bytes nyingine zinazoweza kubadilika. Usiweke wildcard kwenye instruction nzima unayohitaji kurejesha.<sup>[[4]](#references)</sup>

Katika Memory View, chagua instruction na utumie **Tools → Auto Assemble → Template → AOB Injection**. `[DISABLE]` block inayotengenezwa ni muhimu. Lazima irejeshe kila byte iliyooverwrite na ifungue allocation.<sup>[[4]](#references)</sup>

<details>
<summary>Minimal x64 AOB injection skeleton</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Kabla ya kuwezesha script, thibitisha mambo haya:

1. AOB inarejesha anwani **moja**. Ikiwa inarejesha zaidi, ongeza instructions thabiti pande zote mbili.
2. Jump inabadilisha instructions kamili. Usigawanye instruction kamwe.
3. Cave iliyotengwa inaweza kufikiwa na jump iliyotengenezwa. Kwenye x64, allocation ya mbali inaweza kuhitaji jump ya byte 14.
4. Code iliyoingizwa inalinda registers, flags na mpangilio wa stack unaotarajiwa na function ya awali.
5. Block ya kuzima inarejesha bytes halisi za awali. Jaribu kuwezesha na kuzima mara kadhaa kabla ya kuhifadhi table.

## Reliable pointer workflow

Pointer iliyopatikana katika run moja ni candidate pekee. Tengeneza pointer maps katika executions kadhaa mpya na ufanye rescan dhidi ya zote. Anzisha upya target kati ya captures ili ASLR na heap allocations zibadilike. Pendelea paths ambazo base yake ni module au symbol nyingine thabiti. Kataa paths zinazofanya kazi tu kwa save, level au object instance moja.

Filter ya **pointer lazima iishie kwa offsets maalum** na option yake ya deviation inaweza kuhifadhi paths muhimu wakati field iliyo karibu inaposogea kati ya builds. Release ya 7.5 pia iliongeza udhibiti huu wa deviation. Ni filter, si uthibitisho kwamba pointer chain ni thabiti.<sup>[[1]](#references)</sup>

Structure inapohama mara nyingi sana kiasi cha kufanya pointer scanning isiwe na manufaa, hook instruction inayoifikia. Capture live object pointer kutoka kwenye register hadi kwenye symbol iliyotengwa. Hii mara nyingi huwa ya kuaminika zaidi kwa entity lists na managed objects.

## Tracing code instead of scanning values

Tumia **Find out what writes to this address** wakati value inabadilishwa moja kwa moja. Tumia **Find out what accesses this address** unapohitaji owning object au wakati write inafanyika kupitia copied data. Trigger action moja tu kwenye target. Kisha linganisha hit count na register state.

**Ultimap 2** hutumia Intel Processor Trace kwenye Intel CPUs zinazoungwa mkono. Hurekodi control flow iliyotekelezwa kwa interruption ndogo kuliko ku-step kila instruction. Filter code iliyotekelezwa wakati action inayovutia ilipotokea, kisha ondoa code iliyotekelezwa pia wakati wa idle capture. Intel PT si stealth feature. Target bado inaweza kugundua tracing, mabadiliko ya timing au Cheat Engine yenyewe.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 pia iliongeza interface ya Intel PT iliyotolewa na Windows. Mode ya zamani ya Ultimap inayotegemea DBVM na mode ya Intel PT zina mahitaji tofauti ya hardware na OS. Usidhani kwamba CPU inayoweza kutumia DBVM inasaidia Intel PT.<sup>[[1]](#references)</sup>

## Debugger and breakpoint selection

Chagua debugger yenye usumbufu mdogo zaidi inayofanya kazi:

- **Windows debugger** ni rahisi lakini hutengeneza debug events za kawaida. Anti-debugging checks zinaweza kuigundua.
- **VEH debugger** hushughulikia breakpoints kupitia vectored exception handler. Huepuka baadhi ya debugger checks za msingi, lakini haionekani bila kugundulika.
- **Hardware breakpoints** hazibadilishi instruction bytes, lakini x86/x64 hutoa idadi ndogo tu ya debug-register slots.
- **Software breakpoints** hubadilisha byte moja kuwa `INT3`. Ni rahisi kugunduliwa na zinaweza kugongana na integrity checks.
- **DBVM debugger** huhamisha baadhi ya operations chini ya guest OS. Ina privilege kubwa zaidi na inaweza ku-crash host ikiwa imesanidiwa vibaya.

Cheat Engine 7.5 inaweza kutumia jump ya byte moja inayotegemea exception handler na `INT3` wakati hakuna nafasi ya kutosha kwa normal relative jump. Ichukulie kama software breakpoint. Thibitisha exception flow na usidhani kwamba inapita anti-tamper checks.<sup>[[1]](#references)</sup>

DBVM ni hypervisor, si switch ya jumla ya invisibility. Itumie tu katika lab inayoweza kutupwa. Usifichue control interface yake kwa code isiyoaminika. Kernel anti-cheat na endpoint products bado zinaweza kugundua driver, hypervisor state au memory iliyobadilishwa.

## Managed runtimes and recent 7.6/7.7 features

Kwa Mono, IL2CPP, .NET na Java targets, pendelea runtime metadata badala ya blind scans inapopatikana. Fungua **Mono → Activate mono features** au runtime information window inayolingana. Tafuta class, field au method kwanza. Kisha tumia native disassembly wakati managed method imekuwa JIT-compiled.

Line ya 7.6 iliongeza `AOBSCANEX` kwa signatures za executable-memory-only, interface ya `gdbserver` debugger, Java metadata inspection, IL2CPP enumeration yenye kasi zaidi na pointer-scan option inayopuuza upper pointer byte inayotumiwa na ARM memory tagging. Line ya 7.7 iliongeza native Linux builds, `HOOK`/`UNHOOK`, `aobscanfunction`, generic Mono method lookup iliyoboreshwa, PDB structure support iliyoboreshwa na basic Unreal Engine structure dissection.<sup>[[3]](#references)</sup>

Nyongeza hizi zinawezesha workflow muhimu:

1. Resolve managed method au static field kutoka kwenye metadata.
2. Trace au disassemble native code iliyotengenezwa kwa method hiyo.
3. Tumia `AOBSCANEX` au `aobscanfunction` kutafuta executable signature thabiti.
4. Generate reversible hook. Hifadhi original instructions na validate disable path.
5. Kagua upya signature baada ya kila target update. Match iliyofanikiwa haihakikishi kwamba surrounding logic bado ina maana ileile.

## Remote targets with `ceserver`

`ceserver` hufichua process enumeration, memory access na debugging kwa Cheat Engine GUI. Official builds zinahudumia Linux na Android. Endesha architecture inayolingana kwenye target na uunganishe kupitia **Network** tab. Kwenye Android, forwarding default port huepuka kuifichua kwenye network:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Daraja la third-party `frida-ceserver` linaweza kutoa interface inayooana na Cheat Engine kwa targets za iOS. Si `ceserver` rasmi, na operations zinazoungwa mkono zinaweza kutofautiana.<sup>[[2]](#references)</sup>

Chukulia kuwa protocol inatoa access ya kiwango cha debugger. Ifunge kwenye loopback au iweke nyuma ya SSH/ADB tunnel. Usiiweke kamwe TCP 52736 wazi kwenye mtandao usioaminika. Simamisha server session inapoisha.

## Usalama wa uendeshaji

Ambatisha tu kwenye software unayomiliki au umeidhinishwa kuifanyia majaribio. Usiendeshe Cheat Engine pamoja na online game au production endpoint. Memory writes, injected code, drivers na DBVM zinaweza ku-crash au kuharibu target.<sup>[[3]](#references)</sup>

Pakua builds kutoka kwenye site rasmi au compile source iliyochapishwa. Security products mara nyingi huainisha memory editors, debuggers na drivers zao kama hack tools. Usizime host protection kwa ujumla. Tumia VM maalum au lab host na uthibitishe artifact kabla ya kuiendesha.<sup>[[3]](#references)</sup>



## References

- [1] [Maelezo ya toleo la Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Bridge ya frida-ceserver kwa targets za mbali](https://github.com/gmh5225/frida-ceserver)
- [3] [Habari rasmi za matoleo ya Cheat Engine](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
