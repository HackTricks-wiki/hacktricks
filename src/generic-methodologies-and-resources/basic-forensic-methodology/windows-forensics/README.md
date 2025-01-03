# Windows Artifacts

## Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

Katika njia `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` unaweza kupata database `appdb.dat` (kabla ya Windows anniversary) au `wpndatabase.db` (baada ya Windows Anniversary).

Ndani ya database hii ya SQLite, unaweza kupata jedwali la `Notification` lenye taarifa zote za arifa (katika muundo wa XML) ambazo zinaweza kuwa na data ya kuvutia.

### Timeline

Timeline ni sifa ya Windows inayotoa **historia ya muda** ya kurasa za wavuti zilizotembelewa, hati zilizohaririwa, na programu zilizotekelezwa.

Database inapatikana katika njia `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Database hii inaweza kufunguliwa kwa zana ya SQLite au kwa zana [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **ambayo inazalisha faili 2 ambazo zinaweza kufunguliwa kwa zana** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Faili zilizopakuliwa zinaweza kuwa na **ADS Zone.Identifier** ikionyesha **jinsi** ilivyokuwa **imepakuliwa** kutoka intranet, internet, n.k. Programu zingine (kama vivinjari) kawaida huweka hata **zaidi** ya **taarifa** kama **URL** kutoka ambapo faili ilipakuliwa.

## **File Backups**

### Recycle Bin

Katika Vista/Win7/Win8/Win10 **Recycle Bin** inaweza kupatikana katika folda **`$Recycle.bin`** katika mzizi wa diski (`C:\$Recycle.bin`).\
Wakati faili inafuta katika folda hii, faili 2 maalum zinaundwa:

- `$I{id}`: Taarifa za faili (tarehe ya kufutwa)
- `$R{id}`: Maudhui ya faili

![](<../../../images/image (1029).png>)

Kuwa na faili hizi unaweza kutumia zana [**Rifiuti**](https://github.com/abelcheung/rifiuti2) kupata anwani ya asili ya faili zilizofutwa na tarehe ilifutwa (tumia `rifiuti-vista.exe` kwa Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### Nakala za Kivuli

Shadow Copy ni teknolojia iliyojumuishwa katika Microsoft Windows ambayo inaweza kuunda **nakala za akiba** au picha za faili au volumu za kompyuta, hata wakati zinatumika.

Nakala hizi za akiba kwa kawaida zinapatikana katika `\System Volume Information` kutoka kwenye mzizi wa mfumo wa faili na jina lake linaundwa na **UIDs** zilizoonyeshwa katika picha ifuatayo:

![](<../../../images/image (94).png>)

Kuweka picha ya uchunguzi kwa kutumia **ArsenalImageMounter**, chombo [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) kinaweza kutumika kuchunguza nakala ya kivuli na hata **kutoa faili** kutoka kwenye nakala za akiba za kivuli.

![](<../../../images/image (576).png>)

Kichupo cha rejista `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` kina faili na funguo **za kutokuweka akiba**:

![](<../../../images/image (254).png>)

Rejista `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` pia ina taarifa za usanidi kuhusu `Volume Shadow Copies`.

### Faili za Ofisi Zilizohifadhiwa Kiotomatiki

Unaweza kupata faili za ofisi zilizohifadhiwa kiotomatiki katika: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Vitu vya Shell

Kitu cha shell ni kitu kinachobeba taarifa kuhusu jinsi ya kufikia faili nyingine.

### Hati za Karibuni (LNK)

Windows **hujenga** hizi **kiungo** kiotomatiki wakati mtumiaji **anapofungua, kutumia au kuunda faili** katika:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Ofisi: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wakati folda inaundwa, kiungo kwa folda, kwa folda ya mzazi, na folda ya babu pia kinaundwa.

Hizi faili za kiungo zilizoundwa kiotomatiki **zina taarifa kuhusu asili** kama ikiwa ni **faili** **au** **folda**, **MAC** **nyakati** za faili hiyo, **taarifa za volumu** ya mahali faili imehifadhiwa na **folda ya faili lengwa**. Taarifa hii inaweza kuwa muhimu kurejesha faili hizo ikiwa zingeondolewa.

Pia, **tarehe iliyoundwa ya kiungo** faili ni **wakati** wa kwanza faili asili ilitumika na **tarehe** **iliyorekebishwa** ya faili ya kiungo ni **wakati** wa **mwisho** faili asili ilitumika.

Ili kuchunguza faili hizi unaweza kutumia [**LinkParser**](http://4discovery.com/our-tools/).

Katika chombo hiki utapata **seti 2** za nyakati:

- **Seti ya Kwanza:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Seti ya Pili:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Seti ya kwanza ya nyakati inarejelea **nyakati za faili yenyewe**. Seti ya pili inarejelea **nyakati za faili iliyounganishwa**.

Unaweza kupata taarifa sawa ukitumia chombo cha CLI cha Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Katika kesi hii, habari itahifadhiwa ndani ya faili ya CSV.

### Jumplists

Hizi ni faili za hivi karibuni ambazo zinaonyeshwa kwa kila programu. Ni orodha ya **faili za hivi karibuni zinazotumiwa na programu** ambazo unaweza kufikia kwenye kila programu. Zinaundwa **kiotomatiki au kuwa za kawaida**.

**Jumplists** zilizoundwa kiotomatiki zinahifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplists zinaitwa kwa kufuata muundo wa `{id}.autmaticDestinations-ms` ambapo ID ya awali ni ID ya programu.

Jumplists za kawaida zinahifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` na huundwa na programu kwa kawaida kwa sababu jambo **muhimu** limetokea na faili (labda imewekwa kama kipenzi).

**Wakati ulioanzishwa** wa jumplist yoyote unaonyesha **wakati wa kwanza faili ilipofikiwa** na **wakati uliobadilishwa mara ya mwisho**.

Unaweza kuchunguza jumplists kwa kutumia [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../images/image (168).png>)

(_Kumbuka kwamba alama za wakati zinazotolewa na JumplistExplorer zinahusiana na faili ya jumplist yenyewe_)

### Shellbags

[**Fuata kiungo hiki kujifunza ni nini shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Matumizi ya Windows USBs

Inawezekana kubaini kwamba kifaa cha USB kilitumika kutokana na uundaji wa:

- Folda ya Hivi Karibuni ya Windows
- Folda ya Hivi Karibuni ya Microsoft Office
- Jumplists

Kumbuka kwamba baadhi ya faili za LNK badala ya kuelekeza kwenye njia ya asili, zinaelekeza kwenye folda ya WPDNSE:

![](<../../../images/image (218).png>)

Faili katika folda ya WPDNSE ni nakala ya zile za asili, hivyo hazitakuwa na uwezo wa kuishi baada ya kuanzisha tena PC na GUID inachukuliwa kutoka shellbag.

### Taarifa za Registry

[Angalia ukurasa huu kujifunza](interesting-windows-registry-keys.md#usb-information) ni funguo zipi za registry zina habari za kuvutia kuhusu vifaa vilivyounganishwa vya USB.

### setupapi

Angalia faili `C:\Windows\inf\setupapi.dev.log` ili kupata alama za wakati kuhusu wakati muunganisho wa USB ulifanyika (tafuta `Section start`).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) inaweza kutumika kupata habari kuhusu vifaa vya USB ambavyo vimeunganishwa kwenye picha.

![](<../../../images/image (452).png>)

### Plug and Play Cleanup

Kazi iliyopangwa inayojulikana kama 'Plug and Play Cleanup' imeundwa hasa kwa ajili ya kuondoa toleo la zamani la madereva. Kinyume na kusudi lake lililotajwa la kuhifadhi toleo la hivi karibuni la kifurushi cha dereva, vyanzo vya mtandaoni vinapendekeza pia inawalenga madereva ambayo hayajatumika kwa siku 30. Kwa hivyo, madereva ya vifaa vinavyoweza kuondolewa ambavyo havijaundwa katika siku 30 zilizopita yanaweza kufutwa.

Kazi hiyo iko katika njia ifuatayo: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Picha ya skrini inayoonyesha maudhui ya kazi hiyo inapatikana: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Vipengele Muhimu na Mipangilio ya Kazi:**

- **pnpclean.dll**: DLL hii inawajibika kwa mchakato halisi wa kusafisha.
- **UseUnifiedSchedulingEngine**: Imewekwa kuwa `TRUE`, ikionyesha matumizi ya injini ya kupanga kazi ya kawaida.
- **MaintenanceSettings**:
- **Period ('P1M')**: Inamwelekeza Mpangaji wa Kazi kuanzisha kazi ya kusafisha kila mwezi wakati wa matengenezo ya Kiotomatiki.
- **Deadline ('P2M')**: Inamwelekeza Mpangaji wa Kazi, ikiwa kazi hiyo inashindwa kwa miezi miwili mfululizo, kutekeleza kazi hiyo wakati wa matengenezo ya dharura ya Kiotomatiki.

Usanidi huu unahakikisha matengenezo ya kawaida na kusafisha madereva, huku ukiweka masharti ya kujaribu tena kazi hiyo endapo kutakuwa na kushindwa mfululizo.

**Kwa maelezo zaidi angalia:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Barua pepe

Barua pepe zina **sehemu 2 za kuvutia: Vichwa na maudhui** ya barua pepe. Katika **vichwa** unaweza kupata habari kama:

- **Nani** alituma barua pepe (anwani ya barua pepe, IP, seva za barua ambazo zimeelekeza barua pepe)
- **Lini** barua pepe ilitumwa

Pia, ndani ya vichwa vya `References` na `In-Reply-To` unaweza kupata ID ya ujumbe:

![](<../../../images/image (593).png>)

### Windows Mail App

Programu hii huhifadhi barua pepe katika HTML au maandiko. Unaweza kupata barua pepe ndani ya folda ndogo ndani ya `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Barua pepe huhifadhiwa kwa kiendelezi cha `.dat`.

**Metadata** ya barua pepe na **mawasiliano** yanaweza kupatikana ndani ya **EDB database**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Badilisha kiendelezi** cha faili kutoka `.vol` kuwa `.edb` na unaweza kutumia zana [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) kuifungua. Ndani ya jedwali la `Message` unaweza kuona barua pepe.

### Microsoft Outlook

Wakati seva za Exchange au wateja wa Outlook zinapotumika kutakuwa na vichwa vya MAPI:

- `Mapi-Client-Submit-Time`: Wakati wa mfumo wakati barua pepe ilitumwa
- `Mapi-Conversation-Index`: Idadi ya ujumbe wa watoto wa thread na alama za wakati za kila ujumbe wa thread
- `Mapi-Entry-ID`: Kitambulisho cha ujumbe.
- `Mappi-Message-Flags` na `Pr_last_Verb-Executed`: Habari kuhusu mteja wa MAPI (ujumbe umesomwa? haujasomwa? umejibu? umeelekezwa? nje ya ofisi?)

Katika mteja wa Microsoft Outlook, ujumbe wote waliotumwa/waliopokelewa, data za mawasiliano, na data za kalenda huhifadhiwa katika faili ya PST katika:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Njia ya registry `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` inaonyesha faili inayotumika.

Unaweza kufungua faili ya PST kwa kutumia zana [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Faili ya **OST** inaundwa na Microsoft Outlook wakati imewekwa
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ina lengo sawa na prefetch, **kupakia programu haraka zaidi** kwa kutabiri kile kitakachopakuliwa next. Hata hivyo, haitoi huduma ya prefetch.\
Huduma hii itaunda faili za database katika `C:\Windows\Prefetch\Ag*.db`.

Katika hizi databases unaweza kupata **jina** la **programu**, **idadi** ya **utekelezaji**, **faili** **zilizofunguliwa**, **kiasi** **kilichofikiwa**, **njia** **kamili**, **muda** na **alama za muda**.

Unaweza kufikia taarifa hii kwa kutumia chombo [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **inasimamia** **rasilimali** **zinazotumika** **na mchakato**. Ilionekana katika W8 na inahifadhi data katika database ya ESE iliyoko katika `C:\Windows\System32\sru\SRUDB.dat`.

Inatoa taarifa zifuatazo:

- AppID na Njia
- Mtumiaji aliyeendesha mchakato
- Bytes zilizotumwa
- Bytes zilizopokelewa
- Kiunganishi cha Mtandao
- Muda wa Muunganisho
- Muda wa Mchakato

Taarifa hii inasasishwa kila dakika 60.

Unaweza kupata tarehe kutoka faili hii kwa kutumia chombo [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, pia inajulikana kama **ShimCache**, ni sehemu ya **Database ya Ufanisi wa Maombi** iliyotengenezwa na **Microsoft** ili kushughulikia masuala ya ufanisi wa maombi. Kipengele hiki cha mfumo kinarekodi vipande mbalimbali vya metadata ya faili, ambavyo vinajumuisha:

- Njia kamili ya faili
- Ukubwa wa faili
- Wakati wa Marekebisho ya Mwisho chini ya **$Standard_Information** (SI)
- Wakati wa Sasisho la Mwisho la ShimCache
- Bendera ya Utekelezaji wa Mchakato

Taarifa kama hizi zinahifadhiwa ndani ya rejista katika maeneo maalum kulingana na toleo la mfumo wa uendeshaji:

- Kwa XP, data inahifadhiwa chini ya `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` ikiwa na uwezo wa kuingia 96.
- Kwa Server 2003, pamoja na toleo la Windows 2008, 2012, 2016, 7, 8, na 10, njia ya hifadhi ni `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, ikikubali kuingia 512 na 1024, mtawalia.

Ili kuchambua taarifa zilizohifadhiwa, zana ya [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) inapendekezwa kutumika.

![](<../../../images/image (75).png>)

### Amcache

Faili ya **Amcache.hve** kimsingi ni hive ya rejista inayorekodi maelezo kuhusu maombi ambayo yamefanywa kwenye mfumo. Kawaida hupatikana katika `C:\Windows\AppCompat\Programas\Amcache.hve`.

Faili hii ni ya kipekee kwa kuhifadhi rekodi za michakato iliyotekelezwa hivi karibuni, ikiwa ni pamoja na njia za faili zinazoweza kutekelezwa na hash zao za SHA1. Taarifa hii ni muhimu kwa kufuatilia shughuli za maombi kwenye mfumo.

Ili kutoa na kuchambua data kutoka **Amcache.hve**, zana ya [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) inaweza kutumika. Amri ifuatayo ni mfano wa jinsi ya kutumia AmcacheParser kuchambua maudhui ya faili ya **Amcache.hve** na kutoa matokeo katika muundo wa CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Kati ya faili za CSV zilizozalishwa, `Amcache_Unassociated file entries` ni muhimu sana kutokana na taarifa nyingi inazotoa kuhusu faili zisizohusishwa.

Faili ya CVS inayovutia zaidi iliyozalishwa ni `Amcache_Unassociated file entries`.

### RecentFileCache

Kichaka hiki kinaweza kupatikana tu katika W7 katika `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` na kina taarifa kuhusu utekelezaji wa hivi karibuni wa baadhi ya binaries.

Unaweza kutumia chombo [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) kuchambua faili hiyo.

### Scheduled tasks

Unaweza kuzitoa kutoka `C:\Windows\Tasks` au `C:\Windows\System32\Tasks` na kuzisoma kama XML.

### Services

Unaweza kuziona katika rejista chini ya `SYSTEM\ControlSet001\Services`. Unaweza kuona kinachotarajiwa kutekelezwa na lini.

### **Windows Store**

Programu zilizowekwa zinaweza kupatikana katika `\ProgramData\Microsoft\Windows\AppRepository\`\
Hifadhi hii ina **log** yenye **kila programu iliyowekwa** katika mfumo ndani ya database **`StateRepository-Machine.srd`**.

Ndani ya jedwali la Programu la database hii, inawezekana kupata safu: "Application ID", "PackageNumber", na "Display Name". Safu hizi zina taarifa kuhusu programu zilizowekwa awali na zilizowekwa na zinaweza kupatikana ikiwa baadhi ya programu ziliondolewa kwa sababu IDs za programu zilizowekwa zinapaswa kuwa za mfululizo.

Pia inawezekana **kupata programu zilizowekwa** ndani ya njia ya rejista: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Na **programu zilizondolewa** katika: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Taarifa zinazojitokeza ndani ya matukio ya Windows ni:

- Nini kilitokea
- Wakati (UTC + 0)
- Watumiaji waliohusika
- Kompyuta zilizohusika (jina la kompyuta, IP)
- Mali zilizofikiwa (faili, folda, printer, huduma)

Marekodi yako katika `C:\Windows\System32\config` kabla ya Windows Vista na katika `C:\Windows\System32\winevt\Logs` baada ya Windows Vista. Kabla ya Windows Vista, marekodi ya matukio yalikuwa katika muundo wa binary na baada yake, yako katika **muundo wa XML** na yanatumia kiendelezi **.evtx**.

Mahali pa faili za matukio yanaweza kupatikana katika rejista ya SYSTEM katika **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Zinaweza kuonyeshwa kutoka kwa Windows Event Viewer (**`eventvwr.msc`**) au kwa zana nyingine kama [**Event Log Explorer**](https://eventlogxp.com) **au** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Kuelewa Usajili wa Matukio ya Usalama wa Windows

Matukio ya ufikiaji yanarekodiwa katika faili ya usanidi wa usalama iliyoko katika `C:\Windows\System32\winevt\Security.evtx`. Ukubwa wa faili hii unaweza kubadilishwa, na wakati uwezo wake unafikiwa, matukio ya zamani yanabadilishwa. Matukio yaliyorekodiwa ni pamoja na kuingia na kutoka kwa watumiaji, vitendo vya watumiaji, na mabadiliko ya mipangilio ya usalama, pamoja na ufikiaji wa faili, folda, na mali zilizoshirikiwa.

### Nambari za Matukio Muhimu za Uthibitishaji wa Mtumiaji:

- **EventID 4624**: Inaonyesha mtumiaji ameweza kuthibitishwa kwa mafanikio.
- **EventID 4625**: Inaashiria kushindwa kwa uthibitishaji.
- **EventIDs 4634/4647**: Zinawakilisha matukio ya kutoka kwa mtumiaji.
- **EventID 4672**: Inaashiria kuingia kwa mamlaka ya usimamizi.

#### Aina za chini ndani ya EventID 4634/4647:

- **Interactive (2)**: Kuingia moja kwa moja kwa mtumiaji.
- **Network (3)**: Ufikiaji wa folda zilizoshirikiwa.
- **Batch (4)**: Utekelezaji wa michakato ya batch.
- **Service (5)**: Uzinduzi wa huduma.
- **Proxy (6)**: Uthibitishaji wa proxy.
- **Unlock (7)**: Skrini imefunguliwa kwa neno la siri.
- **Network Cleartext (8)**: Uhamasishaji wa nenosiri wazi, mara nyingi kutoka IIS.
- **New Credentials (9)**: Matumizi ya uthibitisho tofauti kwa ufikiaji.
- **Remote Interactive (10)**: Kuingia kwa desktop ya mbali au huduma za terminal.
- **Cache Interactive (11)**: Kuingia kwa uthibitisho wa cache bila kuwasiliana na udhibiti wa kikoa.
- **Cache Remote Interactive (12)**: Kuingia kwa mbali kwa uthibitisho wa cache.
- **Cached Unlock (13)**: Kufungua kwa uthibitisho wa cache.

#### Nambari za Hali na Nambari za Hali za chini kwa EventID 4625:

- **0xC0000064**: Jina la mtumiaji halipo - Inaweza kuashiria shambulio la kuhesabu majina ya watumiaji.
- **0xC000006A**: Jina la mtumiaji sahihi lakini nenosiri si sahihi - Jaribio la kukisia nenosiri au jaribio la nguvu.
- **0xC0000234**: Akaunti ya mtumiaji imefungwa - Inaweza kufuatia shambulio la nguvu linalosababisha kuingia kwa mara nyingi bila mafanikio.
- **0xC0000072**: Akaunti imezuiliwa - Jaribio zisizoidhinishwa za kufikia akaunti zilizozuiliwa.
- **0xC000006F**: Kuingia nje ya wakati ulioidhinishwa - Inaonyesha jaribio la kufikia nje ya masaa yaliyowekwa ya kuingia, ishara inayoweza kuashiria ufikiaji usioidhinishwa.
- **0xC0000070**: Kukiuka vikwazo vya workstation - Inaweza kuwa jaribio la kuingia kutoka eneo lisiloidhinishwa.
- **0xC0000193**: Kuisha kwa akaunti - Jaribio la kufikia akaunti za mtumiaji zilizokwisha.
- **0xC0000071**: Nenosiri lililoisha - Jaribio la kuingia kwa nenosiri lililokwisha.
- **0xC0000133**: Masuala ya usawazishaji wa wakati - Tofauti kubwa za wakati kati ya mteja na seva zinaweza kuashiria mashambulizi ya hali ya juu kama pass-the-ticket.
- **0xC0000224**: Mabadiliko ya nenosiri ya lazima yanahitajika - Mabadiliko ya lazima mara kwa mara yanaweza kuashiria jaribio la kuharibu usalama wa akaunti.
- **0xC0000225**: Inaonyesha hitilafu ya mfumo badala ya suala la usalama.
- **0xC000015b**: Aina ya kuingia iliyopewa ruhusa - Jaribio la ufikiaji kwa aina ya kuingia isiyoidhinishwa, kama mtumiaji anajaribu kutekeleza kuingia kwa huduma.

#### EventID 4616:

- **Mabadiliko ya Wakati**: Mabadiliko ya wakati wa mfumo, yanaweza kuficha mfululizo wa matukio.

#### EventID 6005 na 6006:

- **Kuanza na Kufunga Mfumo**: EventID 6005 inaonyesha mfumo unaanzishwa, wakati EventID 6006 inaashiria unafungwa.

#### EventID 1102:

- **Futa Marekodi**: Marekodi ya usalama yanapofutwa, ambayo mara nyingi ni ishara mbaya ya kuficha shughuli haramu.

#### EventIDs za Ufuatiliaji wa Kifaa cha USB:

- **20001 / 20003 / 10000**: Muunganisho wa kwanza wa kifaa cha USB.
- **10100**: Sasisho la dereva wa USB.
- **EventID 112**: Wakati wa kuingizwa kwa kifaa cha USB.

Kwa mifano halisi ya kuiga aina hizi za kuingia na fursa za kutupa uthibitisho, rejelea [mwongozo wa kina wa Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Maelezo ya matukio, ikiwa ni pamoja na nambari za hali na za hali za chini, yanatoa ufahamu zaidi kuhusu sababu za matukio, hasa yanayoonekana katika Event ID 4625.

### Kuokoa Matukio ya Windows

Ili kuongeza nafasi za kuokoa matukio ya Windows yaliyofutwa, ni vyema kuzima kompyuta inayoshukiwa kwa kuiondoa moja kwa moja. **Bulk_extractor**, chombo cha kuokoa kinachobainisha kiendelezi cha `.evtx`, kinapendekezwa kwa kujaribu kuokoa matukio kama haya.

### Kutambua Mashambulizi ya Kawaida kupitia Matukio ya Windows

Kwa mwongozo wa kina juu ya kutumia Nambari za Matukio ya Windows katika kutambua mashambulizi ya kawaida ya mtandao, tembelea [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Mashambulizi ya Nguvu

Inatambulika kwa rekodi nyingi za EventID 4625, ikifuatwa na EventID 4624 ikiwa shambulio linafanikiwa.

#### Mabadiliko ya Wakati

Yanakumbukwa na EventID 4616, mabadiliko ya wakati wa mfumo yanaweza kuleta changamoto katika uchambuzi wa forensics.

#### Ufuatiliaji wa Kifaa cha USB

Nambari za Matukio za Mfumo zinazofaa kwa ufuatiliaji wa kifaa cha USB ni pamoja na 20001/20003/10000 kwa matumizi ya awali, 10100 kwa sasisho za dereva, na EventID 112 kutoka kwa DeviceSetupManager kwa wakati wa kuingizwa.

#### Matukio ya Nguvu ya Mfumo

EventID 6005 inaonyesha kuanzishwa kwa mfumo, wakati EventID 6006 inaashiria kufungwa.

#### Futa Marekodi

EventID ya Usalama 1102 inaashiria kufutwa kwa marekodi, tukio muhimu kwa uchambuzi wa forensics.

{{#include ../../../banners/hacktricks-training.md}}
