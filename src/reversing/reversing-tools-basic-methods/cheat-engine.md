# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo values muhimu zimehifadhiwa ndani ya memory ya game inayoendeshwa na kuzibadilisha.\
Unapoipakua na kuiendesha, utaonyeshwa **tutorial** ya jinsi ya kutumia tool hii. Ikiwa unataka kujifunza jinsi ya kutumia tool hii, inapendekezwa sana kuikamilisha.

## Unatafuta nini?

![Cheat Engine - Unatafuta nini?: Unatafuta nini?](<../../images/image (762).png>)

Tool hii ni muhimu sana kwa kutafuta **mahali ambapo value fulani** (kwa kawaida namba) **imehifadhiwa kwenye memory** ya program.\
**Kwa kawaida namba** huhifadhiwa katika mfumo wa **4bytes**, lakini unaweza pia kuzipata katika formats za **double** au **float**, au unaweza kutaka kutafuta kitu **ambacho si namba**. Kwa sababu hiyo, unahitaji kuhakikisha kuwa **umechagua** unachotaka **kutafuta**:

![Cheat Engine - Unatafuta nini?: Kwa kawaida namba huhifadhiwa katika mfumo wa 4bytes, lakini unaweza pia kuzipata katika formats za double au float, au unaweza kutaka kutafuta kitu...](<../../images/image (324).png>)

Pia unaweza kuonyesha aina **tofauti** za **searches**:

![Cheat Engine - Unatafuta nini?: Pia unaweza kuonyesha aina tofauti za searches](<../../images/image (311).png>)

Unaweza pia kuweka alama kwenye kisanduku ili **kusimamisha game wakati wa kuscan memory**:

![Cheat Engine - Unatafuta nini?: Unaweza pia kuweka alama kwenye kisanduku ili kusimamisha game wakati wa kuscan memory](<../../images/image (1052).png>)

### Hotkeys

Katika _**Edit --> Settings --> Hotkeys**_ unaweza kuweka **hotkeys** tofauti kwa madhumuni tofauti, kama vile **kusimamisha** **game** (ambayo ni muhimu sana ikiwa wakati fulani unataka kuscan memory). Options nyingine zinapatikana:

![Unatafuta nini? - Hotkeys: Katika Edit -- Settings -- Hotkeys unaweza kuweka hotkeys tofauti kwa madhumuni tofauti, kama vile kusimamisha game (ambayo ni muhimu sana ikiwa wakati fulani...](<../../images/image (864).png>)

## Kubadilisha value

Baada ya **kupata** mahali ambapo **value** unayoitafuta **ipo** (maelezo zaidi kuhusu hili yako katika hatua zinazofuata), unaweza **kuibadilisha** kwa kuibofya mara mbili, kisha ubofye value yake mara mbili:

![Hotkeys - Kubadilisha value: Baada ya kupata mahali ambapo value unayoitafuta ipo (maelezo zaidi kuhusu hili yako katika hatua zinazofuata), unaweza kuibadilisha kwa kuibofya mara mbili, kisha ubofye...](<../../images/image (563).png>)

Na mwishowe **kuweka alama kwenye kisanduku** ili mabadiliko yafanywe kwenye memory:

![Hotkeys - Kubadilisha value: Na mwishowe kuweka alama kwenye kisanduku ili mabadiliko yafanywe kwenye memory](<../../images/image (385).png>)

**Mabadiliko** kwenye **memory** yatatumika mara moja (kumbuka kuwa hadi game itumie value hii tena, value **haitasasishwa kwenye game**).

## Kutafuta value

Kwa hiyo, tuchukulie kuwa kuna value muhimu (kama vile life ya user wako) ambayo unataka kuiboresha, na unatafuta value hii kwenye memory)

### Kupitia mabadiliko yanayojulikana

Tukichukulia kuwa unatafuta value 100, **unatekeleza scan** ukitafuta value hiyo na unapata matches nyingi:

![Kutafuta value - Kupitia mabadiliko yanayojulikana: Tukichukulia kuwa unatafuta value 100, unatekeleza scan ukitafuta value hiyo na unapata matches nyingi](<../../images/image (108).png>)

Kisha, unafanya jambo linalofanya **value ibadilike**, na **unasimamisha** game kisha **unatekeleza** **next scan**:

![Kutafuta value - Kupitia mabadiliko yanayojulikana: Kisha, unafanya jambo linalofanya value ibadilike, na unasimamisha game kisha unatekeleza next scan](<../../images/image (684).png>)

Cheat Engine itatafuta **values** ambazo **zilitoka 100 hadi value mpya**. Hongera, **umepata** **address** ya value uliyokuwa ukiitafuta; sasa unaweza kuibadilisha.\
_Ikiwa bado una values kadhaa, fanya jambo la kubadilisha value hiyo tena, kisha utekeleze "next scan" nyingine ili kuchuja addresses._

### Value isiyojulikana, mabadiliko yanayojulikana

Katika hali ambayo **huijui value**, lakini unajua **jinsi ya kuifanya ibadilike** (na hata kiasi cha mabadiliko hayo), unaweza kuitafuta namba yako.

Anza kwa kutekeleza scan ya aina ya "**Unknown initial value**":

![Kupitia mabadiliko yanayojulikana - Value isiyojulikana, mabadiliko yanayojulikana: Anza kwa kutekeleza scan ya aina ya " Unknown initial value "](<../../images/image (890).png>)

Kisha, fanya value ibadilike, onyesha **jinsi** **value** hiyo **ilibadilika** (katika hali yangu ilipungua kwa 1), na utekeleze **next scan**:

![Kupitia mabadiliko yanayojulikana - Value isiyojulikana, mabadiliko yanayojulikana: Kisha, fanya value ibadilike, onyesha jinsi value hiyo ilivyobadilika (katika hali yangu ilipungua kwa 1), na utekeleze next scan](<../../images/image (371).png>)

Utaonyeshwa **values** zote zilizobadilishwa kwa njia uliyochagua:

![Kupitia mabadiliko yanayojulikana - Value isiyojulikana, mabadiliko yanayojulikana: Utaonyeshwa values zote zilizobadilishwa kwa njia uliyochagua](<../../images/image (569).png>)

Baada ya kupata value yako, unaweza kuibadilisha.

Kumbuka kuwa kuna **mabadiliko mengi yanayowezekana**, na unaweza kufanya **hatua hizi mara nyingi unavyotaka** ili kuchuja matokeo:

![Kupitia mabadiliko yanayojulikana - Value isiyojulikana, mabadiliko yanayojulikana: Kumbuka kuwa kuna mabadiliko mengi yanayowezekana, na unaweza kufanya hatua hizi mara nyingi unavyotaka ili kuchuja matokeo](<../../images/image (574).png>)

### Random Memory Address - Kutafuta code

Hadi sasa tumejifunza jinsi ya kupata address inayohifadhi value, lakini kuna uwezekano mkubwa kwamba katika **executions tofauti za game, address hiyo itakuwa katika sehemu tofauti za memory**. Kwa hiyo, hebu tujifunze jinsi ya kupata address hiyo kila wakati.

Kwa kutumia baadhi ya tricks zilizotajwa, tafuta address ambayo game yako ya sasa inatumia kuhifadhi value muhimu. Kisha (ukisimamisha game ikiwa unataka) bofya **right click** kwenye **address** uliyopata na uchague "**Find out what accesses this address**" au "**Find out what writes to this address**":

![Value isiyojulikana, mabadiliko yanayojulikana - Random Memory Address - Kutafuta code: Kwa kutumia baadhi ya tricks zilizotajwa, tafuta address ambayo game yako ya sasa inatumia kuhifadhi value muhimu. Kisha...](<../../images/image (1067).png>)

**Option ya kwanza** ni muhimu kwa kujua ni **sehemu zipi** za **code** **zinazotumia** **address** hii (jambo ambalo ni muhimu kwa mambo mengine, kama vile **kujua mahali unapoweza kubadilisha code** ya game).\
**Option ya pili** ni **maalum** zaidi, na itasaidia zaidi katika hali hii kwa kuwa tunataka kujua **value hii inaandikwa kutoka wapi**.

Baada ya kuchagua mojawapo ya options hizo, **debugger** ita-**attach** kwenye program na **window mpya tupu** itaonekana. Sasa, **cheza** **game** na **badilisha** **value** hiyo (bila kuanzisha game upya). **Window** hiyo inapaswa kujazwa na **addresses** ambazo **zinabadilisha** **value**:

![Value isiyojulikana, mabadiliko yanayojulikana - Random Memory Address - Kutafuta code: Baada ya kuchagua mojawapo ya options hizo, debugger ita-attach kwenye program na window mpya tupu itaonekana. Sasa...](<../../images/image (91).png>)

Kwa kuwa sasa umepata address inayobadilisha value, unaweza **kubadilisha code unavyotaka** (Cheat Engine inakuruhusu kuibadilisha kuwa NOPs haraka sana):

![Value isiyojulikana, mabadiliko yanayojulikana - Random Memory Address - Kutafuta code: Kwa kuwa sasa umepata address inayobadilisha value, unaweza kubadilisha code unavyotaka (Cheat Engine...](<../../images/image (1057).png>)

Kwa hiyo, sasa unaweza kuibadilisha ili code isiathiri namba yako, au iwe na athari chanya kila wakati.

### Random Memory Address - Kutafuta pointer

Ukitumia hatua zilizotangulia, tafuta mahali value unayovutiwa nayo ilipo. Kisha, ukitumia "**Find out what writes to this address**", tafuta address inayoandika value hii na uibofye mara mbili ili kupata disassembly view:

![Random Memory Address - Kutafuta code - Random Memory Address - Kutafuta pointer: Ukitumia hatua zilizotangulia, tafuta mahali value unayovutiwa nayo ilipo. Kisha, ukitumia " Find out...](<../../images/image (1039).png>)

Kisha, tekeleza scan mpya **ukitafuta hex value iliyo kati ya "\[]"** (value ya $edx katika hali hii):

![Random Memory Address - Kutafuta code - Random Memory Address - Kutafuta pointer: Kisha, tekeleza scan mpya ukitafuta hex value iliyo kati ya " ()" (value ya $edx katika hali hii)](<../../images/image (994).png>)

(_Ikiwa kadhaa zitaonekana, kwa kawaida unahitaji ile yenye address ndogo zaidi_)\
Sasa, **tumepata pointer itakayobadilisha value tunayovutiwa nayo**.

Bofya "**Add Address Manually**":

![Random Memory Address - Kutafuta code - Random Memory Address - Kutafuta pointer: Bofya " Add Address Manually "](<../../images/image (990).png>)

Sasa, bofya checkbox ya "Pointer" na uongeze address uliyopata kwenye text box (katika hali hii, address iliyopatikana kwenye picha iliyotangulia ilikuwa "Tutorial-i386.exe"+2426B0):

![Random Memory Address - Kutafuta code - Random Memory Address - Kutafuta pointer: Sasa, bofya checkbox ya "Pointer" na uongeze address uliyopata kwenye text box (katika hali hii,...](<../../images/image (392).png>)

(Angalia jinsi "Address" ya kwanza inavyojazwa kiotomatiki kutokana na pointer address uliyoingiza)

Bofya OK na pointer mpya itaundwa:

![Random Memory Address - Kutafuta code - Random Memory Address - Kutafuta pointer: Bofya OK na pointer mpya itaundwa](<../../images/image (308).png>)

Sasa, kila wakati unapobadilisha value hiyo, **unabadilisha value muhimu hata kama memory address ambayo value hiyo iko inabadilika.**

### Code Injection

Code injection ni technique ambayo unaingiza kipande cha code kwenye target process, kisha unaelekeza upya execution ya code ili ipitie kwenye code uliyoandika mwenyewe (kama vile kukupa points badala ya kuziondoa).

Kwa hiyo, fikiria kwamba umepata address inayopunguza life ya player wako kwa 1:

![Random Memory Address - Kutafuta pointer - Code Injection: Kwa hiyo, fikiria kwamba umepata address inayopunguza life ya player wako kwa 1](<../../images/image (203).png>)

Bofya Show disassembler ili kupata **disassembled code**.\
Kisha, bofya **CTRL+a** ili kufungua Auto assemble window na uchague _**Template --> Code Injection**_

![Random Memory Address - Kutafuta pointer - Code Injection: Kisha, bofya CTRL+a ili kufungua Auto assemble window na uchague Template -- Code Injection](<../../images/image (902).png>)

Jaza **address ya instruction unayotaka kubadilisha** (kwa kawaida hujazwa kiotomatiki):

![Random Memory Address - Kutafuta pointer - Code Injection: Jaza address ya instruction unayotaka kubadilisha (kwa kawaida hujazwa kiotomatiki)](<../../images/image (744).png>)

Template itatengenezwa:

![Random Memory Address - Kutafuta pointer - Code Injection: Template itatengenezwa](<../../images/image (944).png>)

Kwa hiyo, ingiza assembly code yako mpya katika sehemu ya "**newmem**", na uondoe code ya awali kutoka sehemu ya "**originalcode**" ikiwa hutaki itekelezwe**.** Katika mfano huu, code iliyoingizwa itaongeza points 2 badala ya kupunguza 1:

![Random Memory Address - Kutafuta pointer - Code Injection: Kwa hiyo, ingiza assembly code yako mpya katika sehemu ya " newmem ", na uondoe code ya awali kutoka sehemu ya " originalcode " ikiwa...](<../../images/image (521).png>)

**Bofya execute na kadhalika, na code yako inapaswa kuingizwa kwenye program, ikibadilisha tabia ya functionality hiyo!**

## Advanced features katika Cheat Engine 7.x (2023-2025)

Cheat Engine imeendelea kubadilika tangu version 7.0, na features kadhaa za kuboresha matumizi pamoja na features za *offensive-reversing* zimeongezwa; hizi ni muhimu sana wakati wa kuchambua software za kisasa (na si games pekee!). Ifuatayo ni **field guide iliyofupishwa sana** kuhusu additions utakazotumia mara nyingi wakati wa red-team/CTF work.<sup>[[1]](#references)</sup>

### Maboresho ya Pointer Scanner 2
* `Pointers must end with specific offsets` na slider mpya ya **Deviation** (≥7.4) hupunguza kwa kiasi kikubwa false positives unapofanya rescan baada ya update. Itumie pamoja na multi-map comparison (`.PTR` → *Compare results with other saved pointer map*) ili kupata **base-pointer moja inayodumu** ndani ya dakika chache.
* Shortcut ya bulk-filter: baada ya scan ya kwanza bonyeza `Ctrl+A → Space` ili kuweka alama kwenye kila kitu, kisha `Ctrl+I` (invert) ili kuondoa addresses zilizoshindwa kwenye rescan.

### Ultimap 3 – Intel PT tracing
*Kuanzia 7.5, Ultimap ya zamani iliundwa upya juu ya **Intel Processor-Trace (IPT)***. Hii inamaanisha kuwa sasa unaweza kurekodi *kila branch ambayo target inachukua* **bila single-stepping** (user-mode pekee; haitawasha anti-debug gadgets nyingi).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Baada ya sekunde chache, simamisha capture na **bofya kulia → Save execution list to file**. Unganisha branch addresses na session ya `Find out what addresses this instruction accesses` ili kupata kwa kasi kubwa sana maeneo ya game logic hotspots yenye marudio ya juu.

### Templates za `jmp` ya baiti 1 / auto-patch
Toleo la 7.5 lilianzisha stub ya *one-byte* JMP (0xEB) inayosakinisha SEH handler na kuweka INT3 katika eneo la awali. Hutengenezwa kiotomatiki unapotumia **Auto Assembler → Template → Code Injection** kwenye instructions ambazo haziwezi kupachikwa kwa 5-byte relative jump. Hii huwezesha “tight” hooks ndani ya routines zilizopakiwa kwa packer au zenye nafasi ndogo.<sup>[[1]](#references)</sup>

### Stealth ya kiwango cha kernel kwa DBVM (AMD & Intel)
*DBVM* ni Type-2 hypervisor iliyojengwa ndani ya CE. Builds za hivi karibuni hatimaye ziliongeza **AMD-V/SVM support**, hivyo unaweza kuendesha `Driver → Load DBVM` kwenye hosts za Ryzen/EPYC. DBVM hukuwezesha:
1. Kuunda hardware breakpoints zisizoonekana kwa Ring-3/anti-debug checks.
2. Kusoma/kuandika maeneo ya kernel memory yaliyo pageable au protected hata user-mode driver ikiwa imezimwa.
3. Kufanya VM-EXIT-less timing-attack bypasses (kwa mfano, kuuliza `rdtsc` kutoka kwa hypervisor).

**Tip:** DBVM itakataa kupakiwa wakati HVCI/Memory-Integrity imewezeshwa kwenye Windows 11 → izime au uboot dedicated VM-host.

### Remote / cross-platform debugging kwa **ceserver**
CE sasa inasafirisha rewrite kamili ya *ceserver* na inaweza kujiunga kupitia TCP kwenye targets za **Linux, Android, macOS & iOS**. Fork maarufu inaunganisha *Frida* ili kuchanganya dynamic instrumentation na GUI ya CE – bora unapohitaji kupatch games za Unity au Unreal zinazoendeshwa kwenye simu:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Kwa bridge ya Frida tazama `bb33bb/frida-ceserver` kwenye GitHub.<sup>[[1]](#references)[[2]](#references)</sup>

### Vifaa vingine muhimu
* **Patch Scanner** (MemView → Tools) – hugundua mabadiliko yasiyotarajiwa ya code katika sehemu zinazoweza kutekelezwa; ni muhimu kwa malware analysis.
* **Structure Dissector 2** – buruta anwani → `Ctrl+D`, kisha *Guess fields* ili kutathmini kiotomatiki C-structures.
* **.NET & Mono Dissector** – usaidizi ulioboreshwa wa Unity games; ita methods moja kwa moja kutoka kwenye CE Lua console.
* **Big-Endian custom types** – scan/edit ya byte order iliyogeuzwa (inafaa kwa console emulators na network packet buffers).
* **Autosave & tabs** kwa madirisha ya AutoAssembler/Lua, pamoja na `reassemble()` kwa instruction rewrite ya mistari mingi.<sup>[[1]](#references)</sup>

### Maelezo ya Installation & OPSEC (2024-2025)
* Installer rasmi imefungwa pamoja na **ad-offers** za InnoSetup (`RAV` n.k.). **Daima bofya *Decline*** *au compile kutoka kwenye source* ili kuepuka PUPs. AVs bado zitaonyesha `cheatengine.exe` kama *HackTool*, jambo linalotarajiwa.
* Modern anti-cheat drivers (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) hutambua window class ya CE hata ikiwa imepewa jina jipya. Endesha copy yako ya reversing **ndani ya disposable VM** au baada ya kuzima network play.
* Ikiwa unahitaji tu user-mode access, chagua **`Settings → Extra → Kernel mode debug = off`** ili kuepuka kupakia unsigned driver ya CE ambayo inaweza kusababisha BSOD kwenye Windows 11 24H2 Secure-Boot.

---

## Marejeleo

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
