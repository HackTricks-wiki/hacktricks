# Mabaki ya Windows

{{#include ../../../banners/hacktricks-training.md}}

## Mabaki ya Kawaida ya Windows

### Arifa za Windows 10

Hifadhidata ya arifa kwa kila mtumiaji iko katika `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (kwa mfano, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Matoleo ya awali ya Windows 10 yalitumia `appdb.dat`; Anniversary Update (1607) ilianzisha `wpndatabase.db`. Hifadhidata ya SQLite ina jedwali la `Notification` lenye data za arifa na sehemu za muda, ingawa muda wa kuhifadhi na data inayopatikana hutofautiana kulingana na toleo na sera ya usafishaji.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline ni kipengele cha historia ya shughuli kinachoweza kuwa na rekodi za programu zinazotumika, hati na shughuli nyingine za mtumiaji; kiwango cha shughuli zinazorekodiwa hutegemea programu na toleo la Windows.<sup>[[4]](#references)</sup>

Hifadhidata iko katika `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Inaweza kufunguliwa kwa SQLite au kuchanganuliwa kwa [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), kisha matokeo yake yakakaguliwa kwa [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### Picha za Windows Recall (Kompyuta za Copilot+)

Recall ni hiari kwenye kompyuta zinazotumika za Windows 11 Copilot+. Matoleo ya sasa husimba picha na faharasa yake kwa njia fiche, kwa kutumia funguo zinazohusishwa na Windows Hello na enclave ya VBS. Usichukulie nakala ya hifadhi iliyopatikana nje ya mtandao kuwa hifadhidata ya SQLite isiyosimbwa kwa njia fiche; toleo la majaribio la 2024 na muundo uliotolewa zina sifa tofauti za ufikiaji.<sup>[[77]](#references)</sup>

Kwa **kipindi cha Recall kilicho hai na kilichowezeshwa**, mchakato wa uwasilishaji wa `AIXHost.exe` wa mtumiaji huyo huyo ni njia tofauti ya ufikiaji. Uthibitisho wa dhana wa TotalRecall Reloaded huingiza DLL kwenye mchakato huo na kuita violesura vyake vya Recall COM. Utoaji wa historia yote bado unahitaji mtumiaji kuthibitisha utambulisho wake kwa Windows Hello; hii si usimbuaji fiche wa nje ya mtandao wala njia ya kukwepa Hello. Mtafiti aliandika kuhusu zana hiyo kwenye Windows 11 ARM64, kwa hivyo thibitisha uoanifu na toleo lengwa kabla ya kuitumia.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` hutumia `GetRecentCaptureThumbnail` kuomba toleo kubwa la capture ya hivi karibuni bila Hello. Baada ya kuidhinishwa, `--wait` inaweza kutoa picha za skrini, maandishi ya OCR na metadata ya kila capture, ikijumuisha muktadha wa programu na dirisha. Matokeo huhifadhiwa kwenye saraka ya `extraction_*` yenye muhuri wa muda. Haya ni matokeo yanayotegemea build kutoka kwenye proof of concept, si hakikisho kwamba Recall imewashwa au kwamba kila skrini ilinakiliwa.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

Faili zilizopakuliwa kutoka nje ya mpaka wa uaminifu wa ndani zinaweza kuwa na **alternate data stream ya `Zone.Identifier`**, inayorekodi taarifa za zone na inaweza kujumuisha metadata ya chanzo kama URL. Uwepo wake na sehemu zake hutegemea mtayarishaji na sera ya mfumo.<sup>[[6]](#references)</sup>

## **Hifadhi Nakala za Faili**

### Recycle Bin

Kuanzia Vista na matoleo ya baadaye, **Recycle Bin** hupatikana kwenye folda ya **`$Recycle.bin`** kwenye mzizi wa hifadhi (kwa mfano, `C:\$Recycle.bin`).\
Faili inapofutwa kwenye folda hii, faili 2 maalum huundwa:

- `$I{id}`: Taarifa za faili, ikijumuisha muda wa kufutwa na njia ya awali
- `$R{id}`: Maudhui ya faili

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Ukiwa na faili hizi, unaweza kutumia [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) kutoa njia ya awali na muda wa kufutwa (tumia toleo linalofaa kwa toleo la Windows lengwa).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) inaweza kuunda nakala za shadow za volumes kwa wakati maalum, hata faili zinapotumika; nakala ya shadow si mbadala wa forensic image.<sup>[[8]](#references)</sup>

Metadata ya nakala kwa kawaida huhusishwa na `\System Volume Information` kwenye mzizi wa volume, na vitambulisho hutofautiana kulingana na mfumo:

![Recycle Bin - Volume Shadow Copies: Nakala hizi za chelezo kwa kawaida hupatikana katika System Volume Information kwenye mzizi wa mfumo wa faili, na jina lake linajumuisha UID zinazoonyeshwa katika...](<../../../images/image (94).png>)

Baada ya ku-mount image kwa kutumia forensic mounter inayofaa, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) inaweza kuorodhesha snapshots za VSS zinazopatikana na kuvinjari au kunakili faili kutoka humo.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Baada ya ku-mount forensic image kwa kutumia ArsenalImageMounter, zana ya ShadowCopyView inaweza kutumika kukagua shadow copy na hata kutoa faili...](<../../../images/image (576).png>)

Usanidi wa VSS registry writer unajumuisha `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, ambao unaweza kubainisha faili na keys ambazo hazitajumuishwa kwenye backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Ingizo la registry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore lina faili na keys ambazo hazipaswi kuhifadhiwa kwenye backup](<../../../images/image (254).png>)

Key ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` pia ina usanidi wa huduma ya VSS.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

Mahali pa AutoRecover hutofautiana kulingana na programu ya Office, toleo, na usanidi. Kwa Word, Microsoft inaeleza `%APPDATA%\Microsoft\Word` kuwa mahali chaguomsingi; angalia mipangilio ya programu ili kupata njia inayotumika.<sup>[[12]](#references)</sup>

## Shell Items

Shell item ni kipengee kilicho na maelezo kuhusu jinsi ya kufikia faili nyingine.

### Recent Documents (LNK)

Windows kwa kawaida huunda njia za mkato za vipengee vya hivi karibuni mtumiaji anapofungua au kufikia kipengee kwa njia nyingine:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Kufikia folda kunaweza pia kuunda viungo vya folda hiyo na folda zinazohusiana nayo za ngazi za juu.

Faili hizi za viungo zinaweza kuwa na aina ya lengwa, nyakati za MAC za lengwa, maelezo ya volume, na njia ya lengwa. Metadata hiyo inaweza kusaidia kubaini lengwa lililoondolewa, lakini artifact yenyewe si uthibitisho kwamba lengwa lilifunguliwa na mtumiaji fulani.<sup>[[13]](#references)[[14]](#references)</sup>

Timestamp za mfumo wa faili za LNK yenyewe ni tofauti na timestamp za lengwa zilizopachikwa ndani yake. Usichukulie uundaji wa kiungo kuwa matumizi ya kwanza au urekebishaji wa kiungo kuwa matumizi ya mwisho bila artifacts za ziada zinazothibitisha hilo; fomati hii huhifadhi timestamp za lengwa kando na timestamp za faili ya kiungo.<sup>[[13]](#references)[[14]](#references)</sup>

Kiungo cha [**LinkParser**](http://4discovery.com/our-tools/) kilichopo kimehifadhiwa kama chaguo la kihistoria, lakini nyaraka zake hazikupatikana wakati wa ukaguzi. Kwa parser ya command-line yenye nyaraka, tumia [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Zana hizi kwa kawaida huonyesha seti mbili za timestamp:

- **Timestamp za lengwa:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Timestamp za faili ya kiungo:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Seti ya kwanza inahusu lengwa; seti ya pili inahusu faili ya LNK yenyewe. Tafsiri zote mbili kwa kuzingatia nyaraka za parser na muktadha wa mfumo wa faili.<sup>[[14]](#references)[[15]](#references)</sup>

Unaweza kupata taarifa hizo hizo kwa kutumia zana ya Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

Katika hali hii, taarifa zitahifadhiwa ndani ya faili ya CSV.

### Jumplists

Jump Lists ni orodha za kila programu za vipengee vilivyotumika hivi karibuni au vinavyohusiana na kazi maalum, na zinaweza kuundwa kiotomatiki au maalum.<sup>[[13]](#references)</sup>

Automatic Jump Lists huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` na hutumia majina kama `{id}.automaticDestinations-ms`, ambapo ID hutambulisha programu.

Custom Jump Lists huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; programu huamua maingizo ya kazi au vipengee itakavyounda.

Muda wa kuundwa na kurekebishwa wa mfumo wa faili unaeleza kuhusu faili ya Jump List, si lazima ufikio wa kwanza na wa mwisho wa kila lengwa lililoorodheshwa. Linganisha maingizo yaliyoparsiwa na mihuri ya muda ya faili pamoja na vizalia vingine.<sup>[[13]](#references)</sup>

Unaweza kukagua Jump Lists kwa kutumia [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Unaweza kukagua jumplists kwa kutumia JumplistExplorer](<../../../images/image (168).png>)

(_Kumbuka kuwa mihuri ya muda inayotolewa na JumplistExplorer inahusiana na faili ya jumplist yenyewe_)

### Shellbags

[**Fuata kiungo hiki ili ujifunze kuhusu shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Matumizi ya USB kwenye Windows

Wakati mwingine matumizi ya USB yanaweza kuthibitishwa kwa kulinganisha na vizalia vinavyoundwa faili zinapofikiwa kutoka kwenye media inayoweza kutolewa, vikiwemo:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Zana kama [**USBDetective**](https://usbdetective.com) hulinganisha vizalia hivi na rekodi za vifaa vya USB, lakini upatikanaji wa vizalia hutegemea toleo la Windows na programu husika.<sup>[[18]](#references)</sup>

Katika majaribio yaliyoandikwa kuhusu mtiririko wa kazi wa MTP kwenye Windows XP na Windows 7, baadhi ya LNK zilielekeza kwenye folda ya `WPDNSE` badala ya njia asili.<sup>[[16]](#references)</sup>

![Shellbags - Matumizi ya USB kwenye Windows: Kumbuka kuwa baadhi ya faili za LNK badala ya kuelekeza kwenye njia asili, huelekeza kwenye folda ya WPDNSE](<../../../images/image (218).png>)

Utafiti huo ulibaini nakala katika `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; maudhui ya muda hayakudumu baada ya kuwasha upya katika majaribio yake, na GUID inaweza kulinganishwa na data ya shellbag. Ichukulie hii kama tabia inayotegemea OS, kifaa na programu, badala ya kanuni ya jumla.<sup>[[16]](#references)</sup>

### Taarifa za Registry

[Angalia ukurasa huu ili ujifunze](interesting-windows-registry-keys.md#usb-information) ni registry keys zipi zina taarifa muhimu kuhusu vifaa vya USB vilivyounganishwa.

### setupapi

Kwenye Vista na matoleo mapya zaidi, kagua `C:\Windows\inf\setupapi.dev.log` ili kuona shughuli za usakinishaji wa vifaa. Vichwa vya sehemu vina mihuri ya muda ya `Section start`; vinaandika mchakato wa usanidi, na vinapaswa kulinganishwa na ushahidi mwingine wa muunganisho badala ya kuchukuliwa kuwa muda halisi wa kifaa kuunganishwa kimwili.<sup>[[17]](#references)</sup>

![Taarifa za Registry - setupapi: Kagua faili C: Windows inf setupapi.dev.log ili kupata mihuri ya muda ya muunganisho wa USB (tafuta Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) inaweza kutumika kupata taarifa kuhusu vifaa vya USB ambavyo vimeunganishwa kwenye image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective inaweza kutumika kupata taarifa kuhusu vifaa vya USB ambavyo vimeunganishwa kwenye image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Kazi iliyoratibiwa inayojulikana kama `Plug and Play Cleanup` huondoa matoleo ya zamani ya driver. Ufafanuzi wa kazi ya Windows 10 ulioandikwa na Adam Harrison pia unalenga driver ambazo hazijatumika kwa siku 30, hivyo ushahidi wa driver za vifaa vinavyoweza kutolewa unaweza kusafishwa; thibitisha ufafanuzi wa kazi ya mfumo husika na build ya Windows kabla ya kujumlisha tabia hii.<sup>[[1]](#references)</sup>

Kazi hii iko katika njia ifuatayo: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Ufafanuzi wa XML wa kazi iliyoratibiwa ya Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Vipengele na Mipangilio Muhimu ya Kazi:**

- **pnpclean.dll**: DLL hii inawajibika kwa mchakato halisi wa usafishaji.
- **UseUnifiedSchedulingEngine**: Imewekwa kuwa `TRUE`, ikionyesha matumizi ya injini ya jumla ya kuratibu kazi.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Huelekeza Task Scheduler kuanzisha kazi ya usafishaji kila mwezi wakati wa matengenezo ya kawaida ya Automatic.
  - **Deadline ('P2M')**: Huelekeza Task Scheduler, ikiwa kazi itashindwa kwa miezi miwili mfululizo, kuitekeleza wakati wa matengenezo ya dharura ya Automatic.

Mipangilio hii huratibu matengenezo ya kawaida na majaribio mapya baada ya kushindwa mfululizo; XML halisi na tabia hutegemea toleo.<sup>[[1]](#references)</sup>

**Kwa maelezo zaidi angalia:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Barua pepe

Barua pepe zina **sehemu 2 muhimu: vichwa na maudhui** ya barua pepe. Katika **vichwa** unaweza kupata taarifa kama:

- **Nani** alituma barua pepe (anwani ya barua pepe, IP, seva za barua zilizopitisha barua pepe)
- **Barua pepe ilitumwa lini**

Pia, vichwa vya `References` na `In-Reply-To` vinaweza kuwa na message IDs zinazotumika kuhusisha majibu na mazungumzo.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Barua pepe: Barua pepe ilitumwa lini](<../../../images/image (593).png>)

### Windows Mail App

Programu hii huhifadhi maudhui ya barua pepe katika faili saidizi za maandishi au HTML chini ya njia kama `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; mpangilio halisi wa folda na faili zenye nambari unaweza kutofautiana kulingana na artifact.<sup>[[75]](#references)</sup>

**Metadata** ya barua pepe na **contacts** zinaweza kupatikana ndani ya **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` hutumia umbizo la Extensible Storage Engine (ESE). Fanyia kazi nakala na utumie ESE parser kama [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); ikiwa zana inahitaji kiambishi tamati cha `.edb`, badili jina la nakala pekee, na uthibitishe schema ya jedwali kabla ya kutegemea jedwali la `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Unapokagua sifa za Outlook MAPI, sifa za kawaida ni pamoja na:

- `PidTagClientSubmitTime`: muda wa UTC ambao client ilituma ujumbe.
- `PidTagConversationIndex`: nafasi ya ujumbe katika mfululizo wa mazungumzo.
- `PidTagEntryId`: kitambulisho cha object ya ujumbe.
- `PidTagMessageFlags`: alama za hali kama vile umetumwa, umesomwa, haujasomwa, au una attachments.
- `PidTagLastVerbExecuted`: operesheni ya mwisho iliyoandikwa kwa ujumbe, kama vile kufungua, kujibu, au kupeleka mbele.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Mahali pa faili za data za Outlook hutofautiana kulingana na toleo na aina ya akaunti. Microsoft inaandika maeneo haya ya kawaida ya faili za PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Njia ya registry `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` inaweza kutambulisha profile ya Outlook na usanidi unaohusiana wa faili za data.

Faili za PST zinaweza kuwa na ujumbe, contacts, data ya kalenda na vipengee vingine vya Outlook. Unaweza kukagua nakala kwa kutumia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Unaweza kufungua faili ya PST kwa kutumia zana Kernel PST Viewer](<../../../images/image (498).png>)

### Faili za Microsoft Outlook OST

**Faili ya OST** ni cache ya ndani kwa akaunti za Exchange au Microsoft 365; Cached Exchange Mode haitumiki kwa akaunti za POP au IMAP. Kipindi cha offline kinaweza kusanidiwa na mara nyingi huwa miezi 12 kwa chaguomsingi, ilhali vikomo vya ukubwa wa PST/OST ni mipangilio tofauti inayoweza kusanidiwa. Ili kuona faili ya OST, unaweza kutumia [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Kurejesha Attachments

Attachments zilizopotea zinaweza kurejeshwa kutoka:

- Kwa usanidi wa zamani wa Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Kwa usanidi mpya zaidi wa Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Faili za Thunderbird MBOX

**Thunderbird** huhifadhi data ya profile chini ya `%APPDATA%\Thunderbird\Profiles`; folda za barua kwa kawaida hutumia faili za mbox zisizo na kiambishi tamati katika saraka za `Mail` au `ImapMail` zinazohusiana na akaunti.<sup>[[29]](#references)[[30]](#references)</sup>

### Vijipicha vya Picha

- **Windows XP**: Muhtasari wa vijipicha kwa kawaida ulihifadhiwa katika faili za `thumbs.db` za kila folda.
- **Folda za mtandao**: Faili ya `thumbs.db` bado inaweza kuundwa kwa folda ya UNC ikiwa tabia husika ya vijipicha imewezeshwa; usidhani kuwa kila toleo au sera ya Windows huunda faili hiyo.
- **Windows Vista na matoleo mapya zaidi**: Cache ya vijipicha ya mfumo huwekwa pamoja chini ya `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` kwenye faili kama **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) inaweza kuparse `Thumbs.db` za zamani, huku [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) ikiweza kuparse database za kisasa za cache ya vijipicha.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Taarifa za Windows Registry

Windows Registry, inayohifadhi data ya usanidi wa mfumo na mtumiaji, imo ndani ya faili za hive katika:

- `%WINDIR%\System32\Config` kwa hive za mashine zinazohifadhi subkey mbalimbali za `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` kwa hive ya `HKEY_CURRENT_USER` ya mtumiaji.
- Baadhi ya usakinishaji wa zamani wa Windows zina nakala katika `%WINDIR%\System32\Config\RegBack\`; Windows 10 version 1803 na matoleo mapya zaidi hazijazi saraka hii kiotomatiki isipokuwa backup ya mara kwa mara iwe imewezeshwa.<sup>[[34]](#references)[[35]](#references)</sup>
- Data ya shell na usajili wa class kwa kila mtumiaji pia kwa kawaida huhifadhiwa katika `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` kwenye Windows za kisasa.<sup>[[34]](#references)[[66]](#references)</sup>

### Zana

Baadhi ya zana zinafaa kwa kuchanganua registry hives; thibitisha miundo ya hive na matoleo yanayoungwa mkono na kila zana kabla ya kutegemea matokeo:

- **Registry Editor**: Imesakinishwa kwenye Windows. Ni GUI ya kuvinjari Windows registry ya session ya sasa.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Hukuwezesha kupakia faili ya registry na kuvinjari kwa GUI. Pia ina Bookmarks zinazoangazia keys zenye taarifa muhimu.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Tena, ina GUI inayowezesha kuvinjari registry iliyopakiwa na pia ina plugins zinazoangazia taarifa muhimu ndani ya registry iliyopakiwa.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Programu nyingine ya GUI inayoweza kutoa taarifa kutoka kwenye registry hive iliyopakiwa.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Kurejesha Kipengee Kilichofutwa

Seli za hive zilizofutwa zinaweza kubaki hadi nafasi yake itumike tena, lakini urejeshaji hutegemea hali ya hive na parser; ichukulie keys zilizofutwa zilizorejeshwa kuwa ushahidi unaohitaji uthibitishaji, si rekodi zilizohakikishwa.

### Muda wa Mwisho wa Kuandikwa

Registry keys zina muhuri wa muda wa mwisho wa kuandikwa; Windows huutoa kwa key au maingizo yake yoyote ya value, kwa hivyo value si lazima iwe na muhuri wake huru wa muda wa kurekebishwa.<sup>[[69]](#references)</sup>

### SAM

Hive ya **SAM** ina data ya akaunti za watumiaji na vikundi vya ndani, ikiwemo password hashes zilizolindwa kwa nyenzo za system boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

Katika `SAM\Domains\Account\Users` unaweza kupata vitambulisho vya akaunti na baadhi ya sehemu za kuingia na sera. Uchimbaji wa hash ukiwa offline pia unahitaji hive ya `SYSTEM` ili kurejesha nyenzo husika za boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

### Maingizo muhimu katika Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programu Zilizotekelezwa

### Michakato ya Msingi ya Windows

[Chapisho kuhusu michakato ya kawaida ya Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) limehifadhiwa kama usomaji wa ziada; linganisha madai yoyote kuhusu tabia ya michakato na nyaraka za sasa za Windows pamoja na ushahidi wa ndani.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Kwenye matoleo ya Windows 10 yanayoonyesha kipengele hiki, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` ina subkeys za kila programu zenye sehemu kama muda wa mwisho kutumika na idadi ya uzinduzi; artifact hii iliondolewa katika matoleo ya baadaye, kwa hivyo thibitisha build lengwa.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Kwenye mifumo inayoonyesha Background Activity Moderator, kagua njia ya `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` au njia mpya zaidi ya `...\bam\State\UserSettings\{SID}`. Values zimepangwa kwa user SID na zinaweza kuwa na njia za executable zinazofuatiliwa na data ya utekelezaji inayofanana na FILETIME; artifact hii hutegemea toleo na inapaswa kuthibitishwa kwa ushahidi mwingine.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching huweka cache ya rasilimali na metadata ya uzinduzi ili programu zianze kwa haraka zaidi.

Faili za Prefetch huhifadhiwa kama faili za `.pf` katika `C:\Windows\Prefetch`; umbizo, muda wa kuhifadhi na vikomo vya idadi ya faili hutofautiana kulingana na toleo la Windows. Microsoft inaandika kuwa Windows 8 na matoleo mapya zaidi huhifadhi muda wa utekelezaji mara nane za mwisho na hadi faili 1024, kwa hivyo muhtasari wa zamani wa vikomo visivyobadilika haupaswi kujumlishwa.<sup>[[13]](#references)</sup>

Jina la faili kwa kawaida hutumia muundo wa `{program_name}-{hash}.pf`, ambapo hash hutokana na muktadha wa utekelezaji kama njia na arguments; Windows 10 na matoleo mapya zaidi yanaweza kubana faili. Kuwepo kwake ni ushahidi muhimu wa utekelezaji, lakini peke yake hakuthibitishi kuwa mtumiaji ndiye aliyeitekeleza, na kunapaswa kulinganishwa na vizalia vingine.<sup>[[13]](#references)</sup>

Ili kukagua faili hizi unaweza kutumia [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), ambayo inaandika kuhusu kuparse saraka, kutoa CSV/HTML na kuondoa compression kwa faili za Windows 10 Prefetch zinazohusika.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** hukamilisha Prefetch kwa kutumia mifumo ya matumizi ya awali ili kuboresha upakiaji. Kwenye mifumo inayozalisha faili hizo, faili zake za hifadhidata kwa kawaida hupatikana katika `C:\Windows\Prefetch\Ag*.db`; umbizo na uwepo wake hutegemea toleo.<sup>[[41]](#references)</sup>

Hifadhidata hizi zinaweza kuwa na majina ya programu, idadi ya matumizi, faili au volumes zilizofikiwa, njia na vipindi vya muda, lakini hazipaswi kuchukuliwa kama rekodi kamili ya utekelezaji.<sup>[[41]](#references)</sup>

Kiungo kilichopo cha [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) kimehifadhiwa kama kichanganuzi kinachoweza kutumika; kabla ya kukitumia, thibitisha upatikanaji wake wa sasa na matokeo kinachoauni kwa kurejelea nyaraka za zana hiyo.

### SRUM

**System Resource Usage Monitor** (SRUM) hurekodi matumizi ya rasilimali kwa programu na watumiaji. Ilianzishwa katika Windows 8 na huhifadhi data kwenye hifadhidata ya ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Hutoa taarifa zifuatazo:

- AppID and Path
- User/SID associated with the record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Muda wa kukusanya data na muda wa kuzihifadhi hutegemea utekelezaji; usidhani kwamba kila rekodi inawakilisha muda halisi wa utekelezaji wa dakika 60.<sup>[[13]](#references)</sup>

Unaweza kutoa na kukagua data kwa kutumia [**srum_dump**](https://github.com/MarkBaggett/srum-dump), kwa kutumia chaguo zilizoandikwa kwenye toleo la sasa la zana hiyo.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, inayojulikana pia kama **ShimCache**, ni sehemu ya miundombinu ya Windows ya uoanifu wa programu na huhifadhi metadata ya faili kwa ajili ya maamuzi ya uoanifu. Njia ya hive, muundo wa rekodi, uwezo wa kuhifadhi, na sehemu hutofautiana kulingana na toleo la Windows; kwenye Windows za kisasa, ShimCache pekee haiwezi kuthibitisha kuwa mtumiaji aliendesha faili. Changanua hive husika ya `SYSTEM` kwa kutumia zana ya [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) na linganisha matokeo yake na vielelezo vya utekelezaji.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Ili kuchanganua taarifa zilizohifadhiwa, inashauriwa kutumia zana ya AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Faili ya **Amcache.hve** ni hive ya registry inayoorodhesha programu na faili zilizotambuliwa na Windows. Kwa kawaida hupatikana katika `C:\Windows\AppCompat\Programs\Amcache.hve`.

Inaweza kuwa na maingizo ya faili yanayohusishwa na yasiyohusishwa, njia, na thamani za SHA1, lakini kuwepo kwake ni ushahidi wa orodha tu na hakuthibitishi peke yake kuwa mchakato uliendeshwa.<sup>[[13]](#references)[[44]](#references)</sup>

Ili kutoa na kuchanganua **Amcache.hve**, tumia zana ya [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Amri hii huchanganua hive na kuandika matokeo katika umbizo la CSV.<sup>[[44]](#references)</sup>

Kwa mfano:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Miongoni mwa faili za CSV zilizozalishwa, `Amcache_Unassociated file entries` inaweza kuwa muhimu unapochunguza faili ambazo hazihusishwi na programu inayotambulika.<sup>[[44]](#references)</sup>

### RecentFileCache

Kwenye mifumo ya Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` inaweza kuwa na taarifa kuhusu binaries zilizoonekana hivi karibuni; upatikanaji na maana yake hutegemea toleo.

Unaweza kutumia [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) kuchanganua faili hiyo.<sup>[[45]](#references)</sup>

### Scheduled tasks

Ushahidi wa scheduled tasks unaweza kupatikana katika `C:\Windows\System32\Tasks` kwa tasks za kisasa na `C:\Windows\Tasks` zenye faili za `.job` kwa tasks za zamani; kagua muundo wa ufafanuzi wa task unaofaa kwa OS.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Hifadhidata ya Service Control Manager iko chini ya `SYSTEM\CurrentControlSet\Services` (kwa hive ya SYSTEM ya offline, kagua key inayolingana ya control set); ina usanidi wa services na drivers kama vile njia za executable na aina za uanzishaji.<sup>[[72]](#references)</sup>

### **Windows Store**

Programu za Windows Store zilizosakinishwa zinaweza kuwakilishwa chini ya `\ProgramData\Microsoft\Windows\AppRepository\`, ikiwemo hifadhidata **`StateRepository-Machine.srd`**. Schema na njia hutofautiana kulingana na toleo la Windows.<sup>[[71]](#references)</sup>

Hifadhidata inaweza kuwa na vitambulisho vya programu, nambari za package na majina ya kuonyesha. Mapengo katika vitambulisho si uthibitisho, peke yake, kwamba programu iliondolewa; linganisha na hali ya package na registry.

Usajili wa package pia unaweza kuonekana chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft inaandika kuhusu subkey ya `Deprovisioned` inayotegemea toleo kwa programu zilizoondolewa kwenye provisioning; usidhani kwamba subkey ya `Deleted` ipo kwenye kila build.<sup>[[70]](#references)</sup>

## Windows Events

Kulingana na provider, Windows events zinaweza kuwa na:

- Kilichotokea
- Timestamp ya `TimeCreated` inayopaswa kufasiriwa kulingana na schema ya event na muktadha wa muda wa host
- Watumiaji waliohusika
- Hosts zilizohusika (hostname, IP)
- Assets zilizofikiwa (faili, folda, printers au services).<sup>[[49]](#references)</sup>

Kabla ya Windows Vista, kumbukumbu za events kwa ujumla zilitumia muundo wa zamani wa binary chini ya `C:\Windows\System32\config`; Vista na matoleo ya baadaye hutumia muundo wa Windows Event Log, kwa kawaida chini ya `C:\Windows\System32\winevt\Logs`, huku faili za `.evtx` zikiwa na data ya event iliyowasilishwa kama XML.<sup>[[46]](#references)[[47]](#references)</sup>

Registry ya SYSTEM huhifadhi usanidi wa channel chini ya **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, ikijumuisha njia ya faili iliyosanidiwa na mipangilio ya uhifadhi.<sup>[[47]](#references)</sup>

Zinaweza kutazamwa kwa Windows Event Viewer (**`eventvwr.msc`**) au zana kama [**Event Log Explorer**](https://eventlogxp.com) na [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Kuelewa Uwekaji Kumbukumbu wa Windows Security Events

Kwenye Vista na matoleo ya baadaye, channel ya Security kwa kawaida huhifadhiwa kwenye `C:\Windows\System32\winevt\Logs\Security.evtx`. Ukubwa wake wa juu na sera ya uhifadhi vinaweza kusanidiwa; kwa circular logging, rekodi za zamani zinaweza kufutwa faili inapofikia kikomo chake. Channel inaweza kurekodi events za uthibitishaji, kuondoka kwenye akaunti, privilege, sera ya ukaguzi na ufikiaji wa object wakati ukaguzi husika umewashwa.<sup>[[46]](#references)[[47]](#references)</sup>

### Event IDs Muhimu za Uthibitishaji wa Mtumiaji:

- **Event ID 4624**: Kuingia kwa akaunti kumefaulu.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Kuingia kwa akaunti kumeshindwa.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Session ya kuingia ilisitishwa.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Mtumiaji alianzisha kuondoka kwenye akaunti.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Privileges maalum zilipewa kuingia kupya; hili ni la kawaida kwa akaunti za system na administrator, kwa hivyo si uthibitisho wa shughuli hasidi peke yake.<sup>[[54]](#references)</sup>

#### Aina za logon zinazorekodiwa mara nyingi katika 4624, 4625, 4634, na 4647:

- **Interactive (2)**: Kuingia kwa akaunti kwa njia ya moja kwa moja kwenye mashine ya ndani.
- **Network (3)**: Kufikia rasilimali iliyoshirikiwa.
- **Batch (4)**: Kuingia kwa akaunti kwa mchakato wa batch.
- **Service (5)**: Kuingia kwa akaunti kwa service.
- **Unlock (7)**: Kufungua workstation.
- **NetworkCleartext (8)**: Kuingia kupitia mtandao kunakowasilisha credentials kwa maandishi wazi kwa authentication package.
- **NewCredentials (9)**: Kuingia kwa kutumia credentials mbadala zilizotolewa kwa miunganisho ya nje.
- **RemoteInteractive (10)**: Kuingia kwa Remote Desktop au Terminal Services.
- **CachedInteractive (11)**: Kuingia kwa njia ya moja kwa moja kwa kutumia credentials za domain zilizowekwa kwenye cache.
- **CachedRemoteInteractive (12)**: Kuingia kwa mbali kwa njia ya moja kwa moja kwa kutumia credentials zilizowekwa kwenye cache.
- **CachedUnlock (13)**: Kufungua kwa kutumia credentials zilizowekwa kwenye cache.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status na Sub Status Codes za EventID 4625:

- **0xC0000064**: Mtumiaji huyo hayupo.
- **0xC000006A**: Jina la mtumiaji ni sahihi lakini password si sahihi.
- **0xC0000234**: Akaunti imefungwa.
- **0xC0000072**: Akaunti imezimwa.
- **0xC000006F**: Kuingia nje ya saa zinazoruhusiwa.
- **0xC0000070**: Ukiukaji wa kizuizi cha workstation.
- **0xC0000193**: Muda wa akaunti umeisha.
- **0xC0000071**: Muda wa password umeisha.
- **0xC0000133**: Tofauti ya muda kati ya client na server ni kubwa mno.
- **0xC0000224**: Akaunti lazima ibadilishe password yake.
- **0xC0000225**: `STATUS_NOT_FOUND`; code hii peke yake haitambui hitilafu ya system au shambulio.
- **0xC000015B**: Aina ya logon iliyoombwa haijaruhusiwa kwa akaunti hiyo.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Mabadiliko ya Muda**: Muda wa system ulibadilishwa. Events nyingi huonyesha marekebisho ya kawaida ya huduma ya muda, kwa hivyo linganisha mtendaji na chanzo cha muda kabla ya kuyachukulia kama kuchezea mfumo.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, na 6009:

- **Muktadha wa nishati na service**: Event 12 hurekodi OS kuanza, 13 hurekodi OS kuzimwa, 1074 hurekodi uzimaji au kuwashwa upya uliopangwa, 6008 huashiria uzimaji usiotarajiwa, na 6009 hurekodi toleo la Windows wakati wa kuwasha. Events 6005 na 6006 huashiria service ya Event Log kuanza na kusimama, mtawalia; zenyewe si uthibitisho wa OS kuwashwa na kuzimwa.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Kufutwa kwa Kumbukumbu**: Event 1102 hurekodi kwamba kumbukumbu ya ukaguzi ya Security ilifutwa; chunguza mtendaji na events zinazoizunguka badala ya kudhani nia kutokana na event hii pekee.<sup>[[62]](#references)</sup>

#### EventIDs za Kufuatilia Vifaa vya USB:

- **20001 / 20003**: Events za usakinishaji wa kifaa za `UserPnp` zinazoweza kusaidia kubaini matumizi au usakinishaji wa kwanza.
- **10000 / 10100**: Events za `DriverFrameworks-UserMode` zinazoweza kuambatana na shughuli za kifaa.
- **Event ID 112**: Shughuli za `DeviceSetupManager/Admin` zinazoweza kutoa timestamps zinazohusiana na kuingiza kifaa.
- Provider, channel na maana ya event hutofautiana kulingana na toleo la Windows; kagua jina la provider na payload ya event kabla ya kuipa maana.<sup>[[59]](#references)</sup>

Kwa mifano ya vitendo kuhusu aina za logon na nyenzo zake za credentials, tazama [mwongozo wa kina wa Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Maelezo ya event, yakiwemo aina ya logon, status, substatus, anwani ya chanzo na sehemu za mchakato, hutoa muktadha wa Event ID 4625; status code au muundo wa kushindwa unaojirudia ni kidokezo cha uchunguzi, si hitimisho.<sup>[[51]](#references)[[55]](#references)</sup>

### Kurejesha Windows Events

Kwa kuwa kumbukumbu za events mara nyingi hutumia circular logging, rekodi zilizofutwa na logger huenda zisiweze kurejeshwa. Hifadhi forensic image au nakala ya kazi kabla ya kuingiliana na mfumo unaotumika; tumia parser au carver iliyothibitishwa kama **Bulk_extractor** baada tu ya kuthibitisha kwamba toleo la zana linaunga mkono data lengwa ya `.evtx`, na usitoe tu plagi ya mfumo unaoendelea kufanya kazi kwa lengo la kujaribu kurejesha events.<sup>[[46]](#references)</sup>

### Kutambua Mashambulizi ya Kawaida kupitia Windows Events

Kwa rejeleo la vitendo la event-ID, tazama kiungo kilichopo cha [Red Team Recipe](https://redteamrecipe.com/event-codes/) na uthibitishe mifano yake dhidi ya nyaraka za provider zilizo hapo juu.

#### Mashambulizi ya Brute Force

Linganisha kushindwa kwa Event ID 4625 kunakojirudia na mafanikio ya baadaye ya 4624, aina ya logon, status, chanzo na muktadha wa akaunti; mfuatano huo ni kiashiria cha kuchunguza, si uthibitisho wa shambulio.<sup>[[50]](#references)[[51]](#references)</sup>

#### Mabadiliko ya Muda

Event ID 4616 hurekodi mabadiliko ya muda wa system, ambayo yanaweza kutatiza uchanganuzi wa timeline; ilinganishe na ushahidi wa huduma ya muda na host.<sup>[[56]](#references)</sup>

#### Kufuatilia Vifaa vya USB

USB event IDs hutegemea provider; linganisha `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100, na `DeviceSetupManager/Admin` 112 na mabaki ya SetupAPI na registry.<sup>[[17]](#references)[[59]](#references)</sup>

#### Events za Nishati ya System

Tumia 12/13/1074/6008/6009 kwa muktadha wa OS kuanza, kuzimwa, kuwashwa upya na kukatika kwa nishati kusikotazamiwa; 6005/6006 huashiria service ya Event Log kuanza/kusimama.<sup>[[57]](#references)[[58]](#references)</sup>

#### Kufutwa kwa Kumbukumbu

Security Event ID 1102 hurekodi kwamba kumbukumbu ya ukaguzi ya Security ilifutwa na inapaswa kulinganishwa na akaunti na mchakato uliohusika.<sup>[[62]](#references)</sup>



## References

- [1] [Usafishaji wa Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Kuchunguza Michakato ya Kawaida ya Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Mtazamo wa Uchunguzi wa Kidijitali kuhusu Arifa za Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Zana za uchunguzi wa kidijitali za Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier na Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Huduma ya Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operesheni za kuhifadhi nakala na kurejesha Registry kupitia VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry keys za kuhifadhi nakala na kurejesha](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Tatizo la utendaji wa Word kwenye eneo la AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Mwongozo wa Kukabiliana na Matukio](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Muundo wa Faili ya Binary ya Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Uchunguzi wa USB MTP: Kutambua Mabaki ya Utoaji wa Data](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Maingizo ya kumbukumbu ya usakinishaji wa kifaa ya SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID na Aina Zinazohusiana](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Tafuta na uhamishe faili za data za Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Washa Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Ni sehemu ndogo tu ya vipengee inayosawazishwa](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Sanidi vikomo vya ukubwa wa faili za data za Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Mahali Thunderbird huhifadhi data ya mtumiaji](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Mipangilio ya akaunti ya Thunderbird na saraka za mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Kiolesura cha IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Registry ya mfumo haijahifadhiwa nakala kwenye RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Urejeshaji wa Windows Registry](https://www.mitec.cz/wrr.html)
- [38] [Hariri registry ukiwa mbali](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Muhtasari wa kiufundi wa passwords](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Ushahidi wa Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Muundo wa Faili ya Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Registry key ya Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Sifa ya event ya TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: Thamani za NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Tatua kuwashwa upya kusikotazamiwa kwa kutumia kumbukumbu za system events](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Tatua kuzimwa kunakoendelea](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Uchunguzi wa Vifaa vya Hifadhi vya USB katika Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Aina za Logon za Windows za Kuvutia](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Kidhibiti cha shughuli za usuli](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print inaacha kuchapisha viambatisho vya PDF katika Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Faili za Windows Registry](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Zuia programu zilizoondolewa zisirudi wakati wa sasisho](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Matokeo ya Majaribio ya FTK na Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Hifadhidata ya Services Zilizosakinishwa](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks hushindwa kwa hitilafu kwamba Huduma ya Task Scheduler haipatikani](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Kuchunguza hifadhidata ya Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Muundo wa Ujumbe wa Mtandao](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Dhibiti Recall kwa wateja wa Windows](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
