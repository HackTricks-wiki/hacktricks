# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa ndani ya kumbukumbu ya mchezo unaoendelea na kuzibadilisha.\
Unaposhusha na kuendesha, unapata **mafunzo** ya jinsi ya kutumia chombo hiki. Ikiwa unataka kujifunza jinsi ya kutumia chombo hiki, inashauriwa kukamilisha mafunzo hayo.

## Unatafuta nini?

![](<../../images/image (762).png>)

Chombo hiki ni muhimu sana kutafuta **mahali ambapo thamani fulani** (kawaida ni nambari) **imehifadhiwa katika kumbukumbu** ya programu.\
**Kawaida nambari** huhifadhiwa katika **4bytes** lakini unaweza pia kuzikuta katika **double** au **float** formats, au unaweza kutaka kutafuta kitu **tofauti na nambari**. Kwa sababu hiyo, unahitaji kuwa na uhakika kuwa **unachagua** unachotaka **kutafuta**:

![](<../../images/image (324).png>)

Pia unaweza kuashiria **aina tofauti** za **tafutizi**:

![](<../../images/image (311).png>)

Unaweza pia kuangalia kisanduku ili **kusitisha mchezo wakati wa kuskania kumbukumbu**:

![](<../../images/image (1052).png>)

### Hotkeys

Katika _**Edit --> Settings --> Hotkeys**_ unaweza kuweka **hotkeys** tofauti kwa madhumuni tofauti kama **kusitisha** **mchezo** (ambayo ni muhimu sana ikiwa kwa wakati fulani unataka kuskania kumbukumbu). Chaguzi nyingine zinapatikana:

![](<../../images/image (864).png>)

## Kubadilisha thamani

Mara tu unapokuwa **umeipata** wapi **thamani** unayo **tafuta** (zaidi kuhusu hii katika hatua zinazofuata) unaweza **kuibadilisha** kwa kubofya mara mbili, kisha kubofya mara mbili kwenye thamani yake:

![](<../../images/image (563).png>)

Na hatimaye **kuweka alama** ili kupata mabadiliko yafanyike katika kumbukumbu:

![](<../../images/image (385).png>)

**Mabadiliko** kwa **kumbukumbu** yatakuwa **yamewekwa** mara moja (kumbuka kuwa hadi mchezo usitumie thamani hii tena, thamani **haitawekwa upya katika mchezo**).

## Kutafuta thamani

Hivyo, tunaenda kudhani kuwa kuna thamani muhimu (kama maisha ya mtumiaji wako) unayotaka kuboresha, na unatafuta thamani hii katika kumbukumbu)

### Kupitia mabadiliko yanayojulikana

Tukidhani unatafuta thamani 100, unafanya **scan** ukitafuta thamani hiyo na unapata coincidences nyingi:

![](<../../images/image (108).png>)

Kisha, unafanya kitu ili **thamani ibadilike**, na un **asitisha** mchezo na **kufanya** **scan** ya **next**:

![](<../../images/image (684).png>)

Cheat Engine itatafuta **thamani** ambazo **zilipita kutoka 100 hadi thamani mpya**. Hongera, umepata **anwani** ya thamani uliyokuwa unatafuta, sasa unaweza kuibadilisha.\
_Ikiwa bado una thamani kadhaa, fanya kitu ili kubadilisha tena thamani hiyo, na fanya "next scan" nyingine ili kuchuja anwani._

### Thamani isiyojulikana, mabadiliko yanayojulikana

Katika hali ambapo **hujui thamani** lakini unajua **jinsi ya kuifanya ibadilike** (na hata thamani ya mabadiliko) unaweza kutafuta nambari yako.

Hivyo, anza kwa kufanya scan ya aina "**Unknown initial value**":

![](<../../images/image (890).png>)

Kisha, fanya thamani ibadilike, onyesha **jinsi** **thamani** **ilibadilika** (katika kesi yangu ilipungua kwa 1) na fanya **next scan**:

![](<../../images/image (371).png>)

Utawasilishwa **na thamani zote ambazo zilibadilishwa kwa njia iliyochaguliwa**:

![](<../../images/image (569).png>)

Mara tu unapokuwa umepata thamani yako, unaweza kuibadilisha.

Kumbuka kuwa kuna **mabadiliko mengi yanayowezekana** na unaweza kufanya hatua hizi **mara nyingi kadri unavyotaka** ili kuchuja matokeo:

![](<../../images/image (574).png>)

### Anwani ya Kumbukumbu ya Nasibu - Kutafuta msimbo

Hadi sasa tumefundishwa jinsi ya kupata anwani inayohifadhi thamani, lakini ni uwezekano mkubwa kwamba katika **utekelezaji tofauti wa mchezo anwani hiyo iko katika maeneo tofauti ya kumbukumbu**. Hivyo, hebu tujifunze jinsi ya kila wakati kupata anwani hiyo.

Kwa kutumia baadhi ya hila zilizotajwa, pata anwani ambapo mchezo wako wa sasa unahifadhi thamani muhimu. Kisha (ukisitisha mchezo ikiwa unataka) fanya **right click** kwenye **anwani** iliyopatikana na uchague "**Find out what accesses this address**" au "**Find out what writes to this address**":

![](<../../images/image (1067).png>)

**Chaguo la kwanza** ni muhimu kujua **sehemu** za **msimbo** zinazotumia **anwani hii** (ambayo ni muhimu kwa mambo zaidi kama **kujua wapi unaweza kubadilisha msimbo** wa mchezo).\
**Chaguo la pili** ni **maalum zaidi**, na litakuwa na msaada zaidi katika kesi hii kwani tunavutiwa kujua **kutoka wapi thamani hii inaandikwa**.

Mara tu unapochagua moja ya chaguzi hizo, **debugger** itakuwa **imeunganishwa** na programu na dirisha jipya **bila maudhui** litajitokeza. Sasa, **cheza** **mchezo** na **badilisha** **thamani** hiyo (bila kuanzisha upya mchezo). **Dirisha** linapaswa kuwa **limejaa** na **anwani** zinazobadilisha **thamani**:

![](<../../images/image (91).png>)

Sasa kwamba umepata anwani inayobadilisha thamani unaweza **kubadilisha msimbo kwa mapenzi yako** (Cheat Engine inakuwezesha kuibadilisha kwa NOPs haraka):

![](<../../images/image (1057).png>)

Hivyo, sasa unaweza kuibadilisha ili msimbo usiathiri nambari yako, au uathiri kila wakati kwa njia chanya.

### Anwani ya Kumbukumbu ya Nasibu - Kutafuta kiashiria

Kufuata hatua zilizopita, pata wapi thamani unayovutiwa nayo iko. Kisha, kwa kutumia "**Find out what writes to this address**" pata anwani ipi inaandika thamani hii na ubofye mara mbili ili kupata mtazamo wa disassembly:

![](<../../images/image (1039).png>)

Kisha, fanya scan mpya **ukitafuta thamani ya hex kati ya "\[]"** (thamani ya $edx katika kesi hii):

![](<../../images/image (994).png>)

(_Ikiwa kadhaa zinaonekana unahitaji mara nyingi anwani ndogo zaidi_)\
Sasa, tumepata **kiashiria ambacho kitakuwa kinabadilisha thamani tunayotaka**.

Bofya kwenye "**Add Address Manually**":

![](<../../images/image (990).png>)

Sasa, bofya kwenye kisanduku cha "Pointer" na ongeza anwani iliyopatikana katika kisanduku cha maandiko (katika hali hii, anwani iliyopatikana katika picha ya awali ilikuwa "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Kumbuka jinsi "Anwani" ya kwanza inajazwa kiotomatiki kutoka kwa anwani ya kiashiria unayoingiza)

Bofya OK na kiashiria kipya kitaundwa:

![](<../../images/image (308).png>)

Sasa, kila wakati unabadilisha thamani hiyo unakuwa **unabadilisha thamani muhimu hata kama anwani ya kumbukumbu ambapo thamani hiyo iko ni tofauti.**

### Uingizaji wa Msimbo

Uingizaji wa msimbo ni mbinu ambapo unatia kipande cha msimbo katika mchakato wa lengo, na kisha kuhamasisha utekelezaji wa msimbo ili upite kupitia msimbo wako ulioandikwa (kama kukupa alama badala ya kuziondoa).

Hivyo, fikiria umepata anwani inayopunguza 1 kwa maisha ya mchezaji wako:

![](<../../images/image (203).png>)

Bofya kwenye Onyesha disassembler ili kupata **msimbo wa disassemble**.\
Kisha, bofya **CTRL+a** ili kuanzisha dirisha la Auto assemble na uchague _**Template --> Code Injection**_

![](<../../images/image (902).png>)

Jaza **anwani ya maagizo unayotaka kubadilisha** (hii kawaida hujaza kiotomatiki):

![](<../../images/image (744).png>)

Kigezo kitaundwa:

![](<../../images/image (944).png>)

Hivyo, ingiza msimbo wako mpya wa assembly katika sehemu ya "**newmem**" na ondoa msimbo wa asili kutoka kwa "**originalcode**" ikiwa hutaki utekelezwe. Katika mfano huu, msimbo uliotiwa utaongeza alama 2 badala ya kupunguza 1:

![](<../../images/image (521).png>)

**Bofya kwenye execute na kadhalika na msimbo wako unapaswa kuingizwa katika programu ukibadilisha tabia ya kazi hiyo!**

## Vipengele vya Juu katika Cheat Engine 7.x (2023-2025)

Cheat Engine imeendelea kubadilika tangu toleo la 7.0 na vipengele kadhaa vya kuboresha maisha na *offensive-reversing* vimeongezwa ambavyo ni muhimu sana wakati wa kuchambua programu za kisasa (na sio michezo pekee!). Hapa kuna **mwongozo wa uwanja wa muhtasari** wa nyongeza ambazo huenda ukatumia wakati wa kazi za red-team/CTF.

### Maboresho ya Pointer Scanner 2
* `Pointers lazima iishe na offsets maalum` na slider mpya ya **Deviation** (≥7.4) inapunguza sana matokeo ya uwongo unapofanya skani tena baada ya sasisho. Tumia pamoja na kulinganisha ramani nyingi (`.PTR` → *Compare results with other saved pointer map*) ili kupata **pointer ya msingi inayodumu** kwa dakika chache tu.
* Kifunguo cha kuchuja kwa wingi: baada ya skani ya kwanza bonyeza `Ctrl+A → Space` ili kuweka alama kila kitu, kisha `Ctrl+I` (geuza) ili kuondoa alama kwenye anwani ambazo zimeshindwa skani tena.

### Ultimap 3 – Intel PT tracing
*Tangu 7.5 Ultimap ya zamani ilirejelewa juu ya **Intel Processor-Trace (IPT)***. Hii inamaanisha sasa unaweza kurekodi *kila* tawi ambalo lengo linachukua **bila hatua moja moja** (mode ya mtumiaji pekee, haitasababisha vifaa vingi vya kupambana na debug).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Baada ya sekunde chache, simamisha kukamata na **bonyeza-kulia → Hifadhi orodha ya utekelezaji kwenye faili**. Changanya anwani za tawi na kikao cha `Find out what addresses this instruction accesses` ili kupata maeneo ya juu ya mantiki ya mchezo kwa haraka sana.

### Mifano ya `jmp` / auto-patch ya byte 1
Toleo la 7.5 lilianzisha *stub ya JMP byte moja* (0xEB) ambayo inasakinisha mhandisi wa SEH na kuweka INT3 kwenye eneo la awali. Inazalishwa kiotomatiki unapofanya **Auto Assembler → Template → Code Injection** kwenye maagizo ambayo hayawezi kupachikwa na kuruka kwa uhusiano wa byte 5. Hii inafanya "hooks" za "tight" kuwa na uwezekano ndani ya taratibu zilizopakizwa au zilizopangwa kwa ukubwa.

### Stealth ya kiwango cha Kernel na DBVM (AMD & Intel)
*DBVM* ni hypervisor ya Aina-2 iliyojengwa ndani ya CE. Mifumo ya hivi karibuni hatimaye iliongeza **support ya AMD-V/SVM** ili uweze kuendesha `Driver → Load DBVM` kwenye mwenyeji wa Ryzen/EPYC. DBVM inakuwezesha:
1. Kuunda alama za kuvunja zisizoonekana kwa ukaguzi wa Ring-3/anti-debug.
2. Kusoma/kandika maeneo ya kumbukumbu ya kernel yanayoweza kubadilishwa au kulindwa hata wakati dereva wa hali ya mtumiaji umekataliwa.
3. Kufanya upitishaji wa shambulio la wakati bila VM-EXIT (mfano: uliza `rdtsc` kutoka kwa hypervisor).

**Kidokezo:** DBVM itakataa kupakia wakati HVCI/Memory-Integrity imewezeshwa kwenye Windows 11 → izime au uanzishe mwenyeji wa VM maalum.

### Urekebishaji wa mbali / wa jukwaa tofauti na **ceserver**
CE sasa inatoa upya kamili wa *ceserver* na inaweza kuunganishwa kupitia TCP kwa malengo ya **Linux, Android, macOS & iOS**. Tawi maarufu linajumuisha *Frida* ili kuunganisha uhandisi wa dynamic na GUI ya CE – bora unapohitaji kupachika michezo ya Unity au Unreal inayotembea kwenye simu:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Kwa ajili ya daraja la Frida angalia `bb33bb/frida-ceserver` kwenye GitHub.

### Vitu vingine vya kuzingatia
* **Patch Scanner** (MemView → Tools) – inagundua mabadiliko yasiyotarajiwa ya msimbo katika sehemu zinazoweza kutekelezwa; muhimu kwa uchambuzi wa malware.
* **Structure Dissector 2** – drag-an-address → `Ctrl+D`, kisha *Guess fields* ili kujitathmini kiotomatiki C-structures.
* **.NET & Mono Dissector** – msaada bora wa mchezo wa Unity; piga simu kwa njia moja kwa moja kutoka kwenye CE Lua console.
* **Big-Endian custom types** – skana/edit ya mpangilio wa byte iliyogeuzwa (inayofaa kwa emulators za console na buffers za pakiti za mtandao).
* **Autosave & tabs** kwa AutoAssembler/Lua windows, pamoja na `reassemble()` kwa uandishi wa maagizo ya mistari mingi.

### Maelezo ya Usanidi & OPSEC (2024-2025)
* Msimamizi rasmi umefungwa na InnoSetup **ad-offers** (`RAV` n.k.). **Daima bonyeza *Decline*** *au tengeneza kutoka chanzo* ili kuepuka PUPs. AVs bado zitabaini `cheatengine.exe` kama *HackTool*, ambayo inatarajiwa.
* Madereva ya kisasa ya kupambana na udanganyifu (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) yanagundua daraja la CE hata wakati limepewa jina jipya. Endesha nakala yako ya kurudi nyuma **ndani ya VM inayoweza kutumika** au baada ya kuzima mchezo wa mtandao.
* Ikiwa unahitaji tu ufikiaji wa hali ya mtumiaji chagua **`Settings → Extra → Kernel mode debug = off`** ili kuepuka kupakia dereva usio na saini wa CE ambao unaweza BSOD kwenye Windows 11 24H2 Secure-Boot.

---

## **Marejeleo**

- [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Cheat Engine tutorial, complete it to learn how to start with Cheat Engine**

{{#include ../../banners/hacktricks-training.md}}
