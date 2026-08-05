# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa ndani ya memory ya game inayoendeshwa na kuzibadilisha.\
Unapoipakua na kuiendesha, **utaonyeshwa** **tutorial** ya jinsi ya kutumia tool hii. Ikiwa unataka kujifunza jinsi ya kuitumia, inashauriwa sana kuikamilisha.<sup>[[3]](#references)</sup>

## Unatafuta nini?

![Cheat Engine - Unatafuta nini?: Unatafuta nini?](<../../images/image (762).png>)

Tool hii ni muhimu sana kwa kutafuta **mahali ambapo thamani fulani** (kwa kawaida namba) **imehifadhiwa kwenye memory** ya program.\
**Kwa kawaida namba** huhifadhiwa katika mfumo wa **4bytes**, lakini unaweza pia kuzipata katika formats za **double** au **float**, au unaweza kutaka kutafuta kitu **ambacho si namba**. Kwa sababu hiyo, unahitaji kuhakikisha kuwa **umechagua** unachotaka **kutafuta**:

![Cheat Engine - Unatafuta nini?: Kwa kawaida namba huhifadhiwa katika mfumo wa 4bytes, lakini unaweza pia kuzipata katika formats za double au float, au unaweza kutaka kutafuta kitu...](<../../images/image (324).png>)

Pia unaweza kuonyesha aina **tofauti** za **searches**:

![Cheat Engine - Unatafuta nini?: Pia unaweza kuonyesha aina tofauti za searches](<../../images/image (311).png>)

Unaweza pia kuchagua kisanduku ili **kusimamisha game wakati wa kuscan memory**:

![Cheat Engine - Unatafuta nini?: Unaweza pia kuchagua kisanduku ili kusimamisha game wakati wa kuscan memory](<../../images/image (1052).png>)

### Hotkeys

Katika _**Edit --> Settings --> Hotkeys**_ unaweza kuweka **hotkeys** tofauti kwa madhumuni mbalimbali, kama vile **kusimamisha** **game** (jambo ambalo ni muhimu sana ikiwa wakati fulani unataka kuscan memory). Options nyingine zinapatikana:

![Unatafuta nini? - Hotkeys: Katika Edit -- Settings -- Hotkeys unaweza kuweka hotkeys tofauti kwa madhumuni mbalimbali, kama vile kusimamisha game (jambo ambalo ni muhimu sana ikiwa wakati fulani...](<../../images/image (864).png>)

## Kubadilisha thamani

Baada ya **kupata** mahali ambapo kuna **thamani** unayo **tafuta** (maelezo zaidi yako katika hatua zifuatazo), unaweza **kuibadilisha** kwa kuibofya mara mbili, kisha kubofya thamani yake mara mbili:

![Hotkeys - Kubadilisha thamani: Baada ya kupata mahali ambapo kuna thamani unayotafuta (maelezo zaidi yako katika hatua zifuatazo), unaweza kuibadilisha kwa kuibofya mara mbili, kisha kubofya...](<../../images/image (563).png>)

Kisha **uchague kisanduku** ili mabadiliko yafanyike kwenye memory:

![Hotkeys - Kubadilisha thamani: Kisha uchague kisanduku ili mabadiliko yafanyike kwenye memory](<../../images/image (385).png>)

**Mabadiliko** kwenye **memory** yatafanyika mara moja (kumbuka kwamba hadi game itumie tena thamani hii, thamani **haitasasishwa kwenye game**).

## Kutafuta thamani

Kwa hiyo, tutachukulia kwamba kuna thamani muhimu (kama vile life ya user wako) unayotaka kuboresha, na unatafuta thamani hii kwenye memory)

### Kupitia mabadiliko yanayojulikana

Tukichukulia kuwa unatafuta thamani 100, **unafanya scan** ukitafuta thamani hiyo na kupata matokeo mengi yanayolingana:

![Kutafuta thamani - Kupitia mabadiliko yanayojulikana: Tukichukulia kuwa unatafuta thamani 100, unafanya scan ukitafuta thamani hiyo na kupata matokeo mengi yanayolingana](<../../images/image (108).png>)

Kisha, unafanya kitu kinachosababisha **thamani ibadilike**, na **unasimamisha** game kisha **unafanya** **next scan**:

![Kutafuta thamani - Kupitia mabadiliko yanayojulikana: Kisha, unafanya kitu kinachosababisha thamani ibadilike, unasimamisha game na kufanya next scan](<../../images/image (684).png>)

Cheat Engine itatafuta **thamani** ambazo **zilibadilika kutoka 100 hadi thamani mpya**. Hongera, **umepata** **address** ya thamani uliyokuwa unatafuta; sasa unaweza kuibadilisha.\
_Ikiwa bado una thamani kadhaa, fanya kitu cha kubadilisha thamani hiyo tena, kisha ufanye "next scan" nyingine ili kuchuja addresses._

### Unknown Value, known change

Katika hali ambapo **huijui thamani**, lakini unajua **jinsi ya kuifanya ibadilike** (na hata thamani ya mabadiliko hayo), unaweza kuitafuta namba yako.

Anza kwa kufanya scan ya aina ya "**Unknown initial value**":

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Anza kwa kufanya scan ya aina ya " Unknown initial value "](<../../images/image (890).png>)

Kisha, badilisha thamani, onyesha **jinsi** **thamani** hiyo **ilibadilika** (katika mfano wangu ilipungua kwa 1), na ufanye **next scan**:

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Kisha, badilisha thamani, onyesha jinsi thamani ilivyobadilika (katika mfano wangu ilipungua kwa 1), na ufanye next scan](<../../images/image (371).png>)

Utaonyeshwa **thamani zote zilizobadilishwa kwa njia uliyochagua**:

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Utaonyeshwa thamani zote zilizobadilishwa kwa njia uliyochagua](<../../images/image (569).png>)

Baada ya kupata thamani yako, unaweza kuibadilisha.

Kumbuka kwamba kuna **mabadiliko mengi yanayowezekana**, na unaweza kurudia **hatua hizi mara nyingi unavyotaka** ili kuchuja matokeo:

![Kupitia mabadiliko yanayojulikana - Unknown Value, known change: Kumbuka kwamba kuna mabadiliko mengi yanayowezekana, na unaweza kurudia hatua hizi mara nyingi unavyotaka ili kuchuja matokeo](<../../images/image (574).png>)

### Random Memory Address - Finding the code

Hadi sasa tumejifunza jinsi ya kupata address inayohifadhi thamani, lakini kuna uwezekano mkubwa kwamba katika **executions tofauti za game, address hiyo itakuwa katika maeneo tofauti ya memory**. Kwa hiyo, hebu tujifunze jinsi ya kuipata address hiyo kila mara.

Kwa kutumia baadhi ya mbinu zilizotajwa, tafuta address ambayo game yako ya sasa inatumia kuhifadhi thamani muhimu. Kisha (ukitaka, simamisha game) bofya **right click** kwenye **address** iliyopatikana na uchague "**Find out what accesses this address**" au "**Find out what writes to this address**":

![Unknown Value, known change - Random Memory Address - Finding the code: Kwa kutumia baadhi ya mbinu zilizotajwa, tafuta address ambayo game yako ya sasa inatumia kuhifadhi thamani muhimu. Kisha...](<../../images/image (1067).png>)

**Option ya kwanza** ni muhimu kwa kujua ni **sehemu zipi** za **code** **zinazotumia** **address** hii (jambo linalofaa pia kwa mambo mengine, kama **kujua mahali unapoweza kubadilisha code** ya game).\
**Option ya pili** ni **maalum zaidi**, na itasaidia zaidi katika hali hii kwa kuwa tunataka kujua **mahali ambapo thamani hii inaandikwa**.

Baada ya kuchagua mojawapo ya options hizo, **debugger** itaunganishwa kwenye program na **window mpya tupu** itaonekana. Sasa, **cheza** **game** na **ubadilishe** **thamani** hiyo (bila kuanzisha game upya). **Window** hiyo inapaswa kujazwa na **addresses** ambazo **zinabadilisha** **thamani**:

![Unknown Value, known change - Random Memory Address - Finding the code: Baada ya kuchagua mojawapo ya options hizo, debugger itaunganishwa kwenye program na window mpya tupu...](<../../images/image (91).png>)

Sasa kwa kuwa umepata address inayobadilisha thamani, unaweza **kubadilisha code unavyotaka** (Cheat Engine inakuruhusu kuibadilisha kuwa NOPs haraka sana):

![Unknown Value, known change - Random Memory Address - Finding the code: Sasa kwa kuwa umepata address inayobadilisha thamani, unaweza kubadilisha code unavyotaka (Cheat Engine...](<../../images/image (1057).png>)

Kwa hiyo, sasa unaweza kuibadilisha ili code isiathiri namba yako, au iathiri kwa njia chanya kila mara.

### Random Memory Address - Finding the pointer

Kwa kufuata hatua zilizotangulia, tafuta mahali ilipo thamani unayovutiwa nayo. Kisha, kwa kutumia "**Find out what writes to this address**", tafuta ni address ipi inayoandika thamani hii na uibofye mara mbili ili kupata disassembly view:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Kwa kufuata hatua zilizotangulia, tafuta mahali ilipo thamani unayovutiwa nayo. Kisha, kwa kutumia " Find out...](<../../images/image (1039).png>)

Kisha, fanya scan mpya **ukitafuta hex value iliyo kati ya "\[]"** (thamani ya $edx katika hali hii):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Kisha, fanya scan mpya ukitafuta hex value iliyo kati ya " ()" (thamani ya $edx katika hali hii)](<../../images/image (994).png>)

(_Ikiwa kadhaa zitaonekana, kwa kawaida unahitaji ile yenye address ndogo zaidi_)\
Sasa, **tumepata pointer itakayobadilisha thamani tunayovutiwa nayo**.

Bofya "**Add Address Manually**":

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Bofya " Add Address Manually "](<../../images/image (990).png>)

Sasa, bofya kisanduku cha "Pointer" na uongeze address iliyopatikana kwenye text box (katika hali hii, address iliyopatikana kwenye picha iliyotangulia ilikuwa "Tutorial-i386.exe"+2426B0):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Sasa, bofya kisanduku cha "Pointer" na uongeze address iliyopatikana kwenye text box (katika hali hii,...](<../../images/image (392).png>)

(Angalia jinsi "Address" ya kwanza inavyojazwa kiotomatiki kutoka kwenye pointer address uliyoingiza)

Bofya OK na pointer mpya itaundwa:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Bofya OK na pointer mpya itaundwa](<../../images/image (308).png>)

Sasa, kila mara unapobadilisha thamani hiyo, **unabadilisha thamani muhimu hata kama memory address ilipo thamani hiyo imebadilika.**

### Code Injection

Code injection ni technique ambapo unaingiza kipande cha code kwenye target process, kisha unaelekeza upya execution ya code ipitie kwenye code uliyoandika mwenyewe (kama kukupa points badala ya kuziondoa).

Kwa hiyo, fikiria kwamba umepata address inayopunguza life ya player wako kwa 1:

![Random Memory Address - Finding the pointer - Code Injection: Fikiria kwamba umepata address inayopunguza life ya player wako kwa 1](<../../images/image (203).png>)

Bofya Show disassembler ili kupata **disassemble code**.\
Kisha, bofya **CTRL+a** ili kufungua Auto assemble window na uchague _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Kisha, bofya CTRL+a ili kufungua Auto assemble window na uchague Template -- Code Injection](<../../images/image (902).png>)

Jaza **address ya instruction unayotaka kubadilisha** (kwa kawaida hujazwa kiotomatiki):

![Random Memory Address - Finding the pointer - Code Injection: Jaza address ya instruction unayotaka kubadilisha (kwa kawaida hujazwa kiotomatiki)](<../../images/image (744).png>)

Template itaundwa:

![Random Memory Address - Finding the pointer - Code Injection: Template itaundwa](<../../images/image (944).png>)

Kwa hiyo, weka assembly code yako mpya katika sehemu ya "**newmem**" na uondoe code ya awali kutoka sehemu ya "**originalcode**" ikiwa hutaki itekelezwe**.** Katika mfano huu, code iliyoingizwa itaongeza points 2 badala ya kupunguza 1:

![Random Memory Address - Finding the pointer - Code Injection: Kwa hiyo, weka assembly code yako mpya katika sehemu ya " newmem " na uondoe code ya awali kutoka sehemu ya " originalcode " ikiwa...](<../../images/image (521).png>)

**Bofya execute na kadhalika, na code yako inapaswa kuingizwa kwenye program na kubadilisha tabia ya functionality hiyo!**

## Advanced features in Cheat Engine 7.x (2023-2025)

Cheat Engine imeendelea kubadilika tangu version 7.0, na quality-of-life pamoja na *offensive-reversing* features kadhaa zimeongezwa. Features hizi ni muhimu sana unapochambua software ya kisasa (na si games pekee!). Hapa chini kuna **field guide fupi sana** ya additions utakazotumia mara nyingi wakati wa red-team/CTF work.<sup>[[1]](#references)</sup>

### Pointer Scanner 2 improvements
* `Pointers must end with specific offsets` pamoja na **Deviation** slider mpya (≥7.4) hupunguza kwa kiasi kikubwa false positives unapofanya rescan baada ya update. Itumie pamoja na multi-map comparison (`.PTR` → *Compare results with other saved pointer map*) ili kupata **base-pointer moja thabiti** ndani ya dakika chache.
* Bulk-filter shortcut: baada ya scan ya kwanza bonyeza `Ctrl+A → Space` ili ku-mark kila kitu, kisha `Ctrl+I` (invert) ili ku-deselect addresses ambazo hazikufaulu rescan.

### Ultimap 3 – Intel PT tracing
*Kuanzia 7.5, Ultimap ya zamani iliundwa upya juu ya **Intel Processor-Trace (IPT)***. Hii inamaanisha kwamba sasa unaweza kurekodi *kila branch ambayo target inafuata* **bila single-stepping** (user-mode pekee; haitachochea anti-debug gadgets nyingi).*
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Baada ya sekunde chache, simamisha capture na **bofya kulia → Save execution list to file**. Changanya anwani za matawi na session ya `Find out what addresses this instruction accesses` ili kupata kwa haraka sana maeneo yenye matumizi ya juu ya game-logic.

### 1-byte `jmp` / auto-patch templates
Version 7.5 ilianzisha stub ya *one-byte* JMP (0xEB) ambayo husakinisha SEH handler na kuweka INT3 katika eneo la awali. Hutengenezwa kiotomatiki unapotumia **Auto Assembler → Template → Code Injection** kwenye instructions ambazo haziwezi kupatchiwa kwa relative jump ya 5-byte. Hii huwezesha hooks “tight” ndani ya routines zilizopakiwa au zenye nafasi ndogo.

### Kernel-level stealth with DBVM (AMD & Intel)
*DBVM* ni Type-2 hypervisor iliyojengwa ndani ya CE. Builds za hivi karibuni hatimaye ziliongeza **AMD-V/SVM support**, hivyo unaweza kuendesha `Driver → Load DBVM` kwenye hosts za Ryzen/EPYC. DBVM inakuwezesha:
1. Kuunda hardware breakpoints zisizoonekana kwa Ring-3/anti-debug checks.
2. Kusoma/kuandika maeneo ya kernel memory yanayoweza kupaginishwa au yaliyolindwa hata wakati user-mode driver imezimwa.
3. Kufanya VM-EXIT-less timing-attack bypasses (kwa mfano, kuuliza `rdtsc` kutoka kwa hypervisor).

**Tip:** DBVM itakataa kupakia wakati HVCI/Memory-Integrity imewezeshwa kwenye Windows 11 → izime au boot dedicated VM-host.

### Remote / cross-platform debugging with **ceserver**
CE sasa inasafirisha rewrite kamili ya *ceserver* na inaweza ku-attach kupitia TCP kwenye targets za **Linux, Android, macOS & iOS**. Fork maarufu inaunganisha *Frida* ili kuchanganya dynamic instrumentation na GUI ya CE – inafaa sana unapohitaji kupatch games za Unity au Unreal zinazoendesha kwenye simu:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Kwa Frida bridge, tazama `bb33bb/frida-ceserver` kwenye GitHub.<sup>[[2]](#references)</sup>

### Zana nyingine muhimu
* **Patch Scanner** (MemView → Tools) – hutambua mabadiliko yasiyotarajiwa ya code katika sehemu zinazoweza kutekelezwa; ni muhimu kwa malware analysis.
* **Structure Dissector 2** – buruta-an-address → `Ctrl+D`, kisha *Guess fields* ili kufanya tathmini otomatiki ya C-structures.
* **.NET & Mono Dissector** – huongeza support ya Unity game; ita methods moja kwa moja kutoka CE Lua console.
* **Big-Endian custom types** – huchanganua/kuhariri byte order iliyogeuzwa (ni muhimu kwa console emulators na network packet buffers).
* **Autosave & tabs** kwa madirisha ya AutoAssembler/Lua, pamoja na `reassemble()` kwa multi-line instruction rewrite.

### Maelezo ya usakinishaji na OPSEC (2024-2025)
* Official installer imefungwa na **ad-offers** za InnoSetup (`RAV` n.k.). **Bofya *Decline* kila mara** *au compile kutoka source* ili kuepuka PUPs. AVs bado zita-flag `cheatengine.exe` kama *HackTool*, jambo linalotarajiwa.
* Modern anti-cheat drivers (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) hutambua CE’s window class hata inapopewa jina jipya. Endesha copy yako ya reversing **ndani ya disposable VM** au baada ya kuzima network play.
* Ikiwa unahitaji tu user-mode access, chagua **`Settings → Extra → Kernel mode debug = off`** ili kuepuka kupakia CE’s unsigned driver ambayo inaweza kusababisha BSOD kwenye Windows 11 24H2 Secure-Boot.

---

## Marejeleo

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial, ikamilishe ili ujifunze jinsi ya kuanza kutumia Cheat Engine

{{#include ../../banners/hacktricks-training.md}}
