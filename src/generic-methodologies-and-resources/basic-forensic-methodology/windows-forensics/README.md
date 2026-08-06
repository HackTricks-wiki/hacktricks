# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

Katika path `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` unaweza kupata database `appdb.dat` (kabla ya Windows anniversary) au `wpndatabase.db` (baada ya Windows Anniversary).

Ndani ya database hii ya SQLite, unaweza kupata table ya `Notification` yenye notifications zote (katika muundo wa XML) ambazo zinaweza kuwa na data muhimu.

### Timeline

Timeline ni kipengele cha Windows kinachotoa **historia ya mpangilio wa matukio** ya kurasa za wavuti zilizotembelewa, nyaraka zilizohaririwa, na applications zilizotekelezwa.

Database iko katika path `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Database hii inaweza kufunguliwa kwa kutumia SQLite tool au tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **ambayo hutengeneza files 2 zinazoweza kufunguliwa kwa kutumia tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Files zilizopakuliwa zinaweza kuwa na **ADS Zone.Identifier** inayoonyesha **jinsi** zilivyopakuliwa kutoka intranet, internet, n.k. Baadhi ya software (kama browsers) kwa kawaida huweka **taarifa** **zaidi**, kama **URL** ambayo file lilipakuliwa kutoka.

## **File Backups**

### Recycle Bin

Katika Vista/Win7/Win8/Win10 **Recycle Bin** inaweza kupatikana katika folder **`$Recycle.bin`** kwenye root ya drive (`C:\$Recycle.bin`).\
File inapofutwa katika folder hili, files 2 maalum hutengenezwa:

- `$I{id}`: Taarifa za file (tarehe lilipofutwa}
- `$R{id}`: Maudhui ya file

![File Backups - Recycle Bin: $R{id}: Maudhui ya file](<../../../images/image (1029).png>)

Ukiwa na files hizi unaweza kutumia tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) kupata address ya awali ya files zilizofutwa na tarehe zilipofutwa (tumia `rifiuti-vista.exe` kwa Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy ni teknolojia iliyojumuishwa kwenye Microsoft Windows inayoweza kuunda **nakala za chelezo** au snapshots za faili au volumes za kompyuta, hata zinapotumika.

Nakala hizi za chelezo kwa kawaida hupatikana kwenye `\System Volume Information` kutoka kwenye mzizi wa file system, na jina huundwa kwa **UIDs** zinazoonyeshwa kwenye picha ifuatayo:

![Recycle Bin - Volume Shadow Copies: Nakala hizi za chelezo kwa kawaida hupatikana kwenye System Volume Information kutoka kwenye mzizi wa file system, na jina huundwa kwa UIDs zinazoonyeshwa kwenye...](<../../../images/image (94).png>)

Kwa ku-mount forensic image kwa kutumia **ArsenalImageMounter**, tool [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) inaweza kutumika kukagua shadow copy na hata **kutoa faili** kutoka kwenye nakala za chelezo za shadow copy.

![Recycle Bin - Volume Shadow Copies: Kwa ku-mount forensic image kwa kutumia ArsenalImageMounter, tool ShadowCopyView inaweza kutumika kukagua shadow copy na hata kutoa faili...](<../../../images/image (576).png>)

Registry entry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` ina faili na keys **ambazo hazipaswi kuwekewa chelezo**:

![Recycle Bin - Volume Shadow Copies: Registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore ina faili na keys ambazo hazipaswi kuwekewa chelezo](<../../../images/image (254).png>)

Registry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` pia ina taarifa za usanidi kuhusu `Volume Shadow Copies`.

### Office AutoSaved Files

Unaweza kupata faili za office autosave kwenye: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item ni item iliyo na taarifa kuhusu jinsi ya kufikia faili nyingine.

### Recent Documents (LNK)

Windows **huunda** **shortcuts** hizi **kiotomatiki** mtumiaji **anapofungua, kutumia au kuunda faili** kwenye:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Folder inapoundwa, link ya folder hiyo, parent folder, na grandparent folder pia huundwa.

Faili hizi za link zinazoundwa kiotomatiki **zina taarifa kuhusu chanzo** kama ikiwa ni **faili** **au** **folder**, **nyakati** za **MAC** za faili hiyo, **taarifa za volume** ya mahali faili ilipohifadhiwa, na **folder ya target file**. Taarifa hii inaweza kusaidia kurejesha faili hizo ikiwa ziliondolewa.

Pia, **tarehe ya kuundwa kwa link** file ndiyo **muda** wa kwanza ambao faili ya awali **ilitumika** kwa mara **ya kwanza**, na **tarehe** ya **kurekebishwa** kwa link file ndiyo **muda** wa mwisho ambao faili ya chanzo ilitumika.

Ili kukagua faili hizi unaweza kutumia [**LinkParser**](http://4discovery.com/our-tools/).

Katika tool hii utapata **seti 2** za timestamps:

- **Seti ya Kwanza:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Seti ya Pili:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Seti ya kwanza ya timestamp inarejelea **timestamps za faili yenyewe**. Seti ya pili inarejelea **timestamps za faili iliyounganishwa**.

Unaweza kupata taarifa hiyo hiyo kwa kuendesha Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Katika hali hii, taarifa zitahifadhiwa ndani ya faili ya CSV.

### Jumplists

Hizi ni faili za hivi karibuni zinazoonyeshwa kwa kila application. Ni orodha ya **faili za hivi karibuni zilizotumiwa na application** ambayo unaweza kuifikia kwenye kila application. Zinaweza kuundwa **kiotomatiki au kwa custom**.

Jumplists **zinazoundwa kiotomatiki** huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplists hupewa majina kwa kufuata muundo `{id}.autmaticDestinations-ms`, ambapo ID ya mwanzo ni ID ya application.

Jumplists za custom huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` na kwa kawaida huundwa na application kwa sababu kuna kitu **muhimu** kilichotokea kwa faili (labda faili iliwekwa kama favorite).

**Muda wa kuundwa** wa jumplist yoyote unaonyesha **mara ya kwanza faili ilipofikiwa**, na **muda wa kurekebishwa unaonyesha mara ya mwisho**.

Unaweza kukagua jumplists kwa kutumia [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Recent Documents (LNK) - Jumplists: Unaweza kukagua jumplists kwa kutumia JumplistExplorer](<../../../images/image (168).png>)

(_Kumbuka kwamba timestamps zinazotolewa na JumplistExplorer zinahusiana na faili ya jumplist yenyewe_)

### Shellbags

[**Fuata link hii ili ujifunze shellbags ni nini.**](interesting-windows-registry-keys.md#shellbags)

## Matumizi ya Windows USBs

Inawezekana kubaini kwamba kifaa cha USB kilitumika kutokana na kuundwa kwa:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Kumbuka kwamba baadhi ya faili za LNK, badala ya kuelekeza kwenye path ya asili, huelekeza kwenye folder ya WPDNSE:

![Shellbags - Matumizi ya Windows USBs: Kumbuka kwamba baadhi ya faili za LNK, badala ya kuelekeza kwenye path ya asili, huelekeza kwenye folder ya WPDNSE](<../../../images/image (218).png>)

Faili zilizo kwenye folder ya WPDNSE ni nakala za faili za asili, kwa hiyo hazitadumu baada ya PC kuanzishwa upya, na GUID inatokana na shellbag.

### Taarifa za Registry

[Angalia ukurasa huu ili ujifunze](interesting-windows-registry-keys.md#usb-information) ni registry keys zipi zina taarifa muhimu kuhusu vifaa vya USB vilivyounganishwa.

### setupapi

Angalia faili `C:\Windows\inf\setupapi.dev.log` ili kupata timestamps za wakati muunganisho wa USB ulipofanyika (tafuta `Section start`).

![Taarifa za Registry - setupapi: Angalia faili C: Windows inf setupapi.dev.log ili kupata timestamps za wakati muunganisho wa USB ulipofanyika (tafuta Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) inaweza kutumika kupata taarifa kuhusu vifaa vya USB vilivyowahi kuunganishwa kwenye image.

![setupapi - USB Detective: USBDetective inaweza kutumika kupata taarifa kuhusu vifaa vya USB vilivyowahi kuunganishwa kwenye image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Scheduled task inayojulikana kama 'Plug and Play Cleanup' imeundwa hasa kwa ajili ya kuondoa matoleo ya zamani ya drivers. Kinyume na madhumuni yake yaliyoainishwa ya kubakiza toleo la hivi karibuni la driver package, vyanzo vya mtandaoni vinaonyesha kwamba pia inalenga drivers ambazo hazijatumika kwa siku 30. Kwa hiyo, drivers za vifaa vinavyoweza kuondolewa ambavyo havijaunganishwa katika siku 30 zilizopita zinaweza kufutwa.<sup>[[1]](#references)</sup>

Task hii iko kwenye path ifuatayo: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Screenshot inayoonyesha maudhui ya task hii imetolewa: ![USB Detective - Plug and Play Cleanup: Task iko kwenye path ifuatayo: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Vipengele na Settings Muhimu za Task:**

- **pnpclean.dll**: DLL hii inawajibika kwa mchakato halisi wa cleanup.
- **UseUnifiedSchedulingEngine**: Imewekwa kuwa `TRUE`, ikionyesha matumizi ya generic task scheduling engine.
- **MaintenanceSettings**:
- **Period ('P1M')**: Inaelekeza Task Scheduler kuanzisha cleanup task kila mwezi wakati wa Automatic maintenance ya kawaida.
- **Deadline ('P2M')**: Inaagiza Task Scheduler, ikiwa task itashindwa kwa miezi miwili mfululizo, kutekeleza task wakati wa emergency Automatic maintenance.

Configuration hii inahakikisha maintenance na cleanup ya drivers vinafanyika mara kwa mara, pamoja na masharti ya kujaribu tena task endapo kutatokea kushindwa mfululizo.

**Kwa taarifa zaidi angalia:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Emails zina **sehemu 2 muhimu: Headers na content** ya email. Kwenye **headers** unaweza kupata taarifa kama:

- **Nani** alituma emails (email address, IP, mail servers zilizoelekeza upya email)
- **Lini** email ilitumwa

Pia, ndani ya headers za `References` na `In-Reply-To` unaweza kupata ID ya messages:

![Plug and Play Cleanup - Emails: Email ilitumwa lini](<../../../images/image (593).png>)

### Windows Mail App

Application hii huhifadhi emails katika HTML au text. Unaweza kupata emails ndani ya subfolders zilizo kwenye `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Emails huhifadhiwa zikiwa na extension ya `.dat`.

**Metadata** ya emails na **contacts** inaweza kupatikana ndani ya **EDB database**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Badilisha extension** ya faili kutoka `.vol` kuwa `.edb`, kisha unaweza kutumia tool ya [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) kuifungua. Ndani ya table ya `Message` unaweza kuona emails.

### Microsoft Outlook

Exchange servers au Outlook clients zinapotumika, kutakuwa na baadhi ya MAPI headers:

- `Mapi-Client-Submit-Time`: Muda wa mfumo ambao email ilitumwa
- `Mapi-Conversation-Index`: Idadi ya child messages za thread na timestamp ya kila message ya thread
- `Mapi-Entry-ID`: Kitambulisho cha message.
- `Mappi-Message-Flags` na `Pr_last_Verb-Executed`: Taarifa kuhusu MAPI client (message ilisomwa? haikusomwa? ilijibiwa? ilielekezwa upya? out of the office?)

Katika Microsoft Outlook client, messages zote zilizotumwa/kupokelewa, data ya contacts, na data ya calendar huhifadhiwa kwenye faili ya PST katika:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` huonyesha faili linalotumika.

Unaweza kufungua faili ya PST kwa kutumia tool ya [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: Unaweza kufungua faili ya PST kwa kutumia tool ya Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** huundwa na Microsoft Outlook inapowekwa pamoja na server ya **IMAP** au **Exchange**, na huhifadhi taarifa zinazofanana na za faili ya PST. Faili hii husawazishwa na server, ikihifadhi data ya **miezi 12 iliyopita** hadi kufikia **ukubwa wa juu wa 50GB**, na hupatikana kwenye directory sawa na faili ya PST. Ili kuona faili ya OST, [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) inaweza kutumika.

### Kupata Attachments

Attachments zilizopotea zinaweza kupatikana kutoka:

- Kwa **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Kwa **IE11 na matoleo ya baadaye**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** hutumia **MBOX files** kuhifadhi data, zinazopatikana katika `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Image Thumbnails

- **Windows XP na 8-8.1**: Kufikia folder yenye thumbnails huunda faili ya `thumbs.db` inayohifadhi previews za images, hata baada ya kufutwa.
- **Windows 7/10**: `thumbs.db` huundwa inapofikiwa kupitia network kwa kutumia UNC path.
- **Windows Vista na mpya zaidi**: Thumbnail previews huwekwa pamoja katika `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` zikiwa na majina ya faili **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) na [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) ni tools za kuangalia faili hizi.

### Taarifa za Windows Registry

Windows Registry, inayohifadhi data nyingi za mfumo na shughuli za mtumiaji, imo ndani ya mafaili katika:

- `%windir%\System32\Config` kwa subkeys mbalimbali za `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` kwa `HKEY_CURRENT_USER`.
- Windows Vista na matoleo ya baadaye huhifadhi nakala rudufu za mafaili ya `HKEY_LOCAL_MACHINE` registry katika `%Windir%\System32\Config\RegBack\`.
- Zaidi ya hayo, taarifa za utekelezaji wa program huhifadhiwa katika `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` kuanzia Windows Vista na Windows 2008 Server.

### Tools

Baadhi ya tools ni muhimu kwa kuchanganua mafaili ya registry:

- **Registry Editor**: Imesakinishwa ndani ya Windows. Ni GUI ya kuvinjari Windows registry ya session ya sasa.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Inakuruhusu kupakia faili ya registry na kuvinjari humo kwa kutumia GUI. Pia ina Bookmarks zinazoangazia keys zenye taarifa muhimu.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Tena, ina GUI inayokuruhusu kuvinjari registry iliyopakiwa, na pia ina plugins zinazoangazia taarifa muhimu ndani ya registry iliyopakiwa.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Ni GUI application nyingine inayoweza kutoa taarifa muhimu kutoka kwenye registry iliyopakiwa.

### Kurecover Element Iliyofutwa

Key inapofutwa, huwekwa alama ya kufutwa, lakini hadi nafasi inayotumiwa ihitajike, haitaondolewa. Kwa hiyo, kwa kutumia tools kama **Registry Explorer**, inawezekana kurecover keys hizi zilizofutwa.

### Last Write Time

Kila Key-Value ina **timestamp** inayoonyesha mara ya mwisho iliporekebishwa.

### SAM

Faili/hive ya **SAM** ina hashes za **users, groups na users passwords** za mfumo.

Katika `SAM\Domains\Account\Users` unaweza kupata username, RID, login ya mwisho, logon iliyoshindikana ya mwisho, login counter, password policy na wakati account iliundwa. Ili kupata **hashes**, pia **unahitaji** faili/hive ya **SYSTEM**.

### Entries Muhimu katika Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Zilizotekelezwa

### Basic Windows Processes

Katika [post hii](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) unaweza kujifunza kuhusu Windows processes za kawaida ili kugundua tabia zinazotiliwa shaka.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Ndani ya registry `NTUSER.DAT`, katika path `Software\Microsoft\Current Version\Search\RecentApps`, unaweza kupata subkeys zenye taarifa kuhusu **application iliyotekelezwa**, **mara ya mwisho** ilipotekelezwa, na **idadi ya mara** ilipoanzishwa.

### BAM (Background Activity Moderator)

Unaweza kufungua faili ya `SYSTEM` kwa kutumia registry editor, kisha ndani ya path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` unaweza kupata taarifa kuhusu **applications zilizotekelezwa na kila user** (zingatia `{SID}` iliyo kwenye path) na **muda** zilipotekelezwa (muda huo uko ndani ya Data value ya registry).

### Windows Prefetch

Prefetching ni technique inayowezesha computer **kupata resources muhimu zinazohitajika kuonyesha content** ambayo user **anaweza kuifikia hivi karibuni**, ili resources ziweze kufikiwa kwa haraka zaidi.

Windows prefetch inahusisha kuunda **caches za programs zilizotekelezwa** ili ziweze kupakiwa kwa haraka zaidi. Caches hizi huundwa kama mafaili ya `.pf` ndani ya path: `C:\Windows\Prefetch`. Kuna kikomo cha mafaili 128 katika XP/VISTA/WIN7 na mafaili 1024 katika Win8/Win10.

Jina la faili huundwa kama `{program_name}-{hash}.pf` (hash inategemea path na arguments za executable). Katika W10 mafaili haya hubanwa. Kumbuka kwamba uwepo wa faili hili pekee unaonyesha kuwa **program iliwahi kutekelezwa**.

Faili `C:\Windows\Prefetch\Layout.ini` lina **majina ya mafolder ya mafaili yaliyoprefetchiwa**. Faili hili lina **taarifa kuhusu idadi ya executions**, **dates** za execution na **files** **zilizofunguliwa** na program.

Ili kukagua mafaili haya unaweza kutumia tool ya [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ina lengo sawa na prefetch, **kupakia programu kwa kasi zaidi** kwa kutabiri kitakachopakiwa baadaye. Hata hivyo, haibadilishi huduma ya prefetch.\
Huduma hii itatengeneza faili za database katika `C:\Windows\Prefetch\Ag*.db`.

Katika database hizi unaweza kupata **jina** la **programu**, **idadi ya** **utekelezaji**, **faili** **zilizofunguliwa**, **volume** **iliyofikiwa**, **path** **kamili**, **vipindi vya muda** na **timestamps**.

Unaweza kufikia taarifa hii ukitumia tool [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **hufuatilia** **resources** **zinazotumiwa** **na process**. Ilionekana katika W8 na huhifadhi data katika database ya ESE iliyoko `C:\Windows\System32\sru\SRUDB.dat`.

Inatoa taarifa zifuatazo:

- AppID na Path
- User aliye-execute process
- Bytes Zilizotumwa
- Bytes Zilizopokelewa
- Network Interface
- Muda wa connection
- Muda wa process

Taarifa hii husasishwa kila dakika 60.

Unaweza kupata tarehe kutoka kwenye faili hii ukitumia tool [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, pia inajulikana kama **ShimCache**, ni sehemu ya **Application Compatibility Database** iliyoundwa na **Microsoft** kushughulikia masuala ya utangamano wa application. Kipengele hiki cha mfumo huhifadhi taarifa mbalimbali za metadata ya faili, zikiwemo:

- Njia kamili ya faili
- Ukubwa wa faili
- Muda wa mwisho wa kurekebishwa chini ya **$Standard_Information** (SI)
- Muda wa mwisho wa kusasishwa kwa ShimCache
- Bendera ya utekelezaji wa process

Data hii huhifadhiwa kwenye registry katika maeneo maalum kulingana na toleo la operating system:

- Kwa XP, data huhifadhiwa katika `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` ikiwa na nafasi ya entries 96.
- Kwa Server 2003, pamoja na Windows versions 2008, 2012, 2016, 7, 8, na 10, njia ya uhifadhi ni `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, ikiwa na nafasi ya entries 512 na 1024, mtawalia.

Ili kuchanganua taarifa zilizohifadhiwa, inashauriwa kutumia [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Ili kuchanganua taarifa zilizohifadhiwa, inashauriwa kutumia AppCompatCacheParser tool](<../../../images/image (75).png>)

### Amcache

Faili ya **Amcache.hve** kimsingi ni registry hive inayorekodi maelezo kuhusu applications ambazo zimetekelezwa kwenye mfumo. Kwa kawaida hupatikana katika `C:\Windows\AppCompat\Programas\Amcache.hve`.

Faili hii ni muhimu kwa sababu huhifadhi rekodi za processes zilizotekelezwa hivi karibuni, zikiwemo njia za executable files na SHA1 hashes zake. Taarifa hii ni muhimu sana kwa kufuatilia shughuli za applications kwenye mfumo.

Ili kutoa na kuchanganua data kutoka **Amcache.hve**, [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool inaweza kutumika. Command ifuatayo ni mfano wa jinsi ya kutumia AmcacheParser kuchanganua yaliyomo kwenye faili ya **Amcache.hve** na kutoa matokeo katika muundo wa CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Kati ya faili za CSV zilizozalishwa, `Amcache_Unassociated file entries` ni ya kuzingatiwa hasa kutokana na taarifa nyingi inazotoa kuhusu maingizo ya faili yasiyohusishwa.

Faili ya CVS inayovutia zaidi iliyozalishwa ni `Amcache_Unassociated file entries`.

### RecentFileCache

Artifact hii inaweza kupatikana tu katika W7 kwenye `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` na ina taarifa kuhusu utekelezaji wa hivi karibuni wa baadhi ya binaries.

Unaweza kutumia tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) kuchanganua faili hiyo.

### Scheduled tasks

Unaweza kuzitoa kutoka `C:\Windows\Tasks` au `C:\Windows\System32\Tasks` na kuzisoma kama XML.

### Services

Unaweza kuzipata kwenye registry chini ya `SYSTEM\ControlSet001\Services`. Unaweza kuona kitakachotekelezwa na wakati kitakapotekelezwa.

### **Windows Store**

Applications zilizosakinishwa zinaweza kupatikana kwenye `\ProgramData\Microsoft\Windows\AppRepository`\  
Repository hii ina **log** yenye **kila application iliyosakinishwa** kwenye mfumo ndani ya database **`StateRepository-Machine.srd`**.

Ndani ya jedwali la Application la database hii, inawezekana kupata columns: "Application ID", "PackageNumber", na "Display Name". Columns hizi zina taarifa kuhusu applications zilizosakinishwa awali na zilizosakinishwa, na inaweza kubainika kama baadhi ya applications ziliondolewa kwa sababu IDs za applications zilizosakinishwa zinapaswa kuwa za mfululizo.

Pia inawezekana **kupata application iliyosakinishwa** ndani ya registry path: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`\  
Na **applications** **zilizoondolewa** kwenye: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Taarifa zinazoonekana ndani ya Windows events ni:

- Kilichotokea
- Timestamp (UTC + 0)
- Users waliohusika
- Hosts waliohusika (hostname, IP)
- Assets zilizofikiwa (files, folder, printer, services)

Logs ziko kwenye `C:\Windows\System32\config` kabla ya Windows Vista na kwenye `C:\Windows\System32\winevt\Logs` baada ya Windows Vista. Kabla ya Windows Vista, event logs zilikuwa katika binary format, na baada yake ziko katika **XML format** na hutumia extension ya **.evtx**.

Mahali zilipo event files panaweza kupatikana kwenye SYSTEM registry katika **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Zinaweza kuonyeshwa kupitia Windows Event Viewer (**`eventvwr.msc`**) au kwa tools nyingine kama [**Event Log Explorer**](https://eventlogxp.com) **au** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Kuelewa Windows Security Event Logging

Access events hurekodiwa katika security configuration file iliyoko `C:\Windows\System32\winevt\Security.evtx`. Ukubwa wa faili hii unaweza kurekebishwa, na uwezo wake ukifikia kikomo, events za zamani huandikwa upya. Events zilizorekodiwa zinajumuisha user logins na logoffs, vitendo vya users, na mabadiliko kwenye security settings, pamoja na access ya files, folders, na shared assets.

### Event IDs Muhimu za User Authentication:

- **EventID 4624**: Huonyesha kuwa user amefanya authentication kwa mafanikio.
- **EventID 4625**: Huonyesha authentication failure.
- **EventIDs 4634/4647**: Huonyesha events za user logoff.
- **EventID 4672**: Huonyesha login yenye administrative privileges.

#### Sub-types ndani ya EventID 4634/4647:

- **Interactive (2)**: Direct user login.
- **Network (3)**: Access kwenye shared folders.
- **Batch (4)**: Utekelezaji wa batch processes.
- **Service (5)**: Service launches.
- **Proxy (6)**: Proxy authentication.
- **Unlock (7)**: Screen imefunguliwa kwa password.
- **Network Cleartext (8)**: Usafirishaji wa clear text password, mara nyingi kutoka IIS.
- **New Credentials (9)**: Matumizi ya credentials tofauti kwa access.
- **Remote Interactive (10)**: Remote desktop au terminal services login.
- **Cache Interactive (11)**: Login kwa cached credentials bila mawasiliano na domain controller.
- **Cache Remote Interactive (12)**: Remote login kwa cached credentials.
- **Cached Unlock (13)**: Kufungua kwa kutumia cached credentials.

#### Status na Sub Status Codes za EventID 4625:

- **0xC0000064**: User name haipo - Inaweza kuonyesha username enumeration attack.
- **0xC000006A**: User name ni sahihi lakini password si sahihi - Inaweza kuonyesha password guessing au brute-force attempt.
- **0xC0000234**: User account imefungwa - Inaweza kutokea baada ya brute-force attack iliyosababisha logins nyingi zilizoshindikana.
- **0xC0000072**: Account imezimwa - Attempts zisizoidhinishwa za kufikia accounts zilizozimwa.
- **0xC000006F**: Logon nje ya muda unaoruhusiwa - Huonyesha attempts za access nje ya login hours zilizowekwa, ishara inayowezekana ya access isiyoidhinishwa.
- **0xC0000070**: Ukiukaji wa workstation restrictions - Inaweza kuwa attempt ya ku-login kutoka location isiyoidhinishwa.
- **0xC0000193**: Account imeisha muda - Attempts za access kwa kutumia user accounts zilizokwisha muda.
- **0xC0000071**: Password imeisha muda - Login attempts kwa kutumia passwords zilizopitwa na wakati.
- **0xC0000133**: Time sync issues - Tofauti kubwa za muda kati ya client na server zinaweza kuonyesha attacks za hali ya juu zaidi kama pass-the-ticket.
- **0xC0000224**: Mabadiliko ya lazima ya password yanahitajika - Mabadiliko ya mara kwa mara ya lazima yanaweza kupendekeza attempt ya kuvuruga account security.
- **0xC0000225**: Huonyesha system bug badala ya security issue.
- **0xC000015b**: Logon type imekataliwa - Attempt ya access kwa kutumia logon type isiyoidhinishwa, kama user anayejaribu kutekeleza service logon.

#### EventID 4616:

- **Time Change**: Mabadiliko ya system time, ambayo yanaweza kuficha timeline ya events.

#### EventID 6005 na 6006:

- **System Startup and Shutdown**: EventID 6005 huonyesha system inaanza, huku EventID 6006 ikionyesha system inazimika.

#### EventID 1102:

- **Log Deletion**: Security logs zimefutwa, jambo ambalo mara nyingi ni red flag ya kuficha shughuli haramu.

#### EventIDs za USB Device Tracking:

- **20001 / 20003 / 10000**: USB device imeunganishwa kwa mara ya kwanza.
- **10100**: USB driver update.
- **EventID 112**: Muda ambao USB device iliingizwa.

Kwa mifano ya vitendo ya ku-simulate login types hizi na credential dumping opportunities, rejelea [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Event details, zikiwemo status na sub-status codes, hutoa maarifa zaidi kuhusu sababu za events, hasa katika Event ID 4625.

### Recovering Windows Events

Ili kuongeza uwezekano wa kurecover Windows Events zilizofutwa, inashauriwa kuzima suspect computer kwa kuiondoa moja kwa moja kwenye umeme. **Bulk_extractor**, recovery tool inayobainisha extension ya `.evtx`, inapendekezwa kwa kujaribu kurecover events hizo.

### Kutambua Attacks za Kawaida kupitia Windows Events

Kwa mwongozo kamili wa kutumia Windows Event IDs kutambua cyber attacks za kawaida, tembelea [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Zinatambuliwa kupitia records nyingi za EventID 4625, zikifuatiwa na EventID 4624 ikiwa attack imefanikiwa.

#### Time Change

Hurekodiwa na EventID 4616; mabadiliko kwenye system time yanaweza kufanya forensic analysis iwe ngumu.

#### USB Device Tracking

System EventIDs muhimu kwa USB device tracking zinajumuisha 20001/20003/10000 kwa matumizi ya awali, 10100 kwa driver updates, na EventID 112 kutoka DeviceSetupManager kwa insertion timestamps.

#### System Power Events

EventID 6005 huonyesha system startup, huku EventID 6006 ikionyesha shutdown.

#### Log Deletion

Security EventID 1102 huashiria kufutwa kwa logs, event muhimu kwa forensic analysis.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
