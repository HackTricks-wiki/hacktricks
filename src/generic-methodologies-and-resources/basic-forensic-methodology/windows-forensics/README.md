# Artifacts za Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artifacts za Windows za Jumla

### Windows 10 Notifications

Database ya notifications ya kila mtumiaji iko kwenye `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (kwa mfano, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Matoleo ya awali ya Windows 10 yalitumia `appdb.dat`; Anniversary Update (1607) ilianzisha `wpndatabase.db`. Database ya SQLite inajumuisha jedwali la `Notification` lenye payloads za notifications na sehemu za muda, ingawa muda wa kuhifadhi na data inayopatikana hutofautiana kulingana na toleo na sera ya cleanup.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline ni kipengele cha historia ya shughuli ambacho kinaweza kuwa na rekodi za applications, nyaraka na shughuli nyingine za mtumiaji zinazotumika; data inayokusanywa hutegemea application na toleo la Windows.<sup>[[4]](#references)</sup>

Database iko kwenye `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Inaweza kufunguliwa kwa SQLite au ku-parse kwa kutumia [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), ambao output yake inaweza kukaguliwa kwa kutumia [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Files zilizopakuliwa kutoka nje ya trust boundary ya ndani zinaweza kuwa na **`Zone.Identifier` alternate data stream**, ambayo huhifadhi taarifa za zone na inaweza kujumuisha metadata ya origin kama vile URL. Uwepo wake na fields zake hutegemea producer na sera ya mfumo.<sup>[[6]](#references)</sup>

## **Hifadhi Nakala za Files**

### Recycle Bin

Kwenye Vista na matoleo ya baadaye, **Recycle Bin** inaweza kupatikana kwenye folder **`$Recycle.bin`** iliyo kwenye root ya drive (kwa mfano, `C:\$Recycle.bin`).\
File inapofutwa kwenye folder hii, files 2 maalum huundwa:

- `$I{id}`: Taarifa za file, ikiwemo muda wa kufutwa na path ya awali
- `$R{id}`: Content ya file

![Hifadhi Nakala za Files - Recycle Bin: $R{id}: Content ya file](<../../../images/image (1029).png>)

Ukiwa na files hizi, unaweza kutumia [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) kutoa path ya awali na muda wa kufutwa (tumia version inayofaa kwa Windows release inayolengwa).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Hifadhi Nakala za Faili - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) inaweza kuunda nakala kivuli za volumes kwa wakati maalum huku faili zikitumika; nakala kivuli si mbadala wa forensic image.<sup>[[8]](#references)</sup>

Metadata ya nakala kwa kawaida huhusishwa na `\System Volume Information` kwenye mzizi wa volume, ikiwa na vitambulisho vinavyotofautiana kulingana na mfumo:

![Recycle Bin - Volume Shadow Copies: Nakala hizi kwa kawaida hupatikana katika System Volume Information kutoka kwenye mzizi wa mfumo wa faili, na jina huundwa kwa kutumia UIDs zinazoonyeshwa kwenye...](<../../../images/image (94).png>)

Baada ya ku-mount image kwa kutumia forensic mounter inayofaa, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) inaweza kuorodhesha VSS snapshots zinazopatikana na kuvinjari au kunakili faili kutoka kwazo.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Baada ya ku-mount forensic image kwa kutumia ArsenalImageMounter, tool ya ShadowCopyView inaweza kutumika kukagua shadow copy na hata kutoa faili...](<../../../images/image (576).png>)

Configuration ya VSS registry writer inajumuisha `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, ambayo inaweza kubainisha faili na keys zitakazoondolewa kwenye backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore ina faili na keys ambazo hazitafanyiwa backup](<../../../images/image (254).png>)

Key ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` pia ina configuration ya huduma ya VSS.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

Maeneo ya AutoRecover hutofautiana kulingana na Office application, version, na configuration. Kwa Word, Microsoft inaandika `%APPDATA%\Microsoft\Word` kama eneo chaguo-msingi; kagua settings za application ili kupata path inayotumika.<sup>[[12]](#references)</sup>

## Shell Items

Shell item ni item yenye taarifa kuhusu jinsi ya kufikia faili nyingine.

### Recent Documents (LNK)

Windows kwa kawaida huunda shortcuts za items za hivi karibuni mtumiaji anapofungua au kufikia item kwa njia nyingine:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Kufikia folder kunaweza pia kuunda links za folder hiyo na folders zake za parent zinazohusiana.

Faili hizi za link zinaweza kuwa na aina ya target, nyakati za MAC za target, taarifa za volume, na path ya target. Metadata hiyo inaweza kusaidia kutambua target iliyoondolewa, lakini artifact yenyewe si uthibitisho kwamba target ilifunguliwa na mtumiaji fulani.<sup>[[13]](#references)[[14]](#references)</sup>

Timestamps za filesystem za LNK yenyewe na timestamps za target zilizohifadhiwa ndani yake ni tofauti. Usitafsiri uundaji wa link kama matumizi ya kwanza au urekebishaji wa link kama matumizi ya mwisho bila artifacts za ziada za kuthibitisha; format huhifadhi timestamps za target tofauti na timestamps za faili ya link.<sup>[[13]](#references)[[14]](#references)</sup>

Link iliyopo ya [**LinkParser**](http://4discovery.com/our-tools/) imehifadhiwa kama chaguo la kihistoria, lakini documentation yake haikupatikana wakati wa ukaguzi. Kwa parser ya command-line yenye documentation, tumia [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Tools hizi kwa kawaida huonyesha seti mbili za timestamps:

- **Timestamps za target:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamps za faili ya link:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Seti ya kwanza inahusu target; seti ya pili inahusu faili ya LNK yenyewe. Tafsiri zote mbili kwa kuzingatia documentation ya parser na muktadha wa filesystem.<sup>[[14]](#references)[[15]](#references)</sup>

Unaweza kupata taarifa hiyo hiyo kwa kuendesha Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Katika hali hii, taarifa itahifadhiwa ndani ya faili la CSV.

### Jumplists

Jump Lists ni orodha za kila application za vipengee vya hivi karibuni au maalum kwa kazi, na zinaweza kuwa za kiotomatiki au maalum.<sup>[[13]](#references)</sup>

Automatic Jump Lists huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` na hutumia majina kama `{id}.automaticDestinations-ms`, ambapo ID hutambulisha application.

Custom Jump Lists huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; application hudhibiti ni entries zipi za kazi au vipengee inavyounda.

Nyakati za kuundwa na kurekebishwa za filesystem zinaeleza faili la Jump List, si lazima ziwe mara ya kwanza na ya mwisho kila target iliyoorodheshwa kufikiwa. Linganisha entries zilizoparsiwa na timestamps za faili pamoja na artifacts nyingine.<sup>[[13]](#references)</sup>

Unaweza kukagua Jump Lists ukitumia [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Unaweza kukagua jumplists ukitumia JumplistExplorer](<../../../images/image (168).png>)

(_Kumbuka kwamba timestamps zinazotolewa na JumplistExplorer zinahusiana na faili lenyewe la jumplist_)

### Shellbags

[**Fuata link hii ili ujifunze shellbags ni nini.**](interesting-windows-registry-keys.md#shellbags)

## Matumizi ya Windows USBs

Matumizi ya USB yanaweza wakati mwingine kuthibitishwa kwa kulinganisha na artifacts zinazoundwa wakati faili zinapofikiwa kutoka removable media, ikiwa ni pamoja na:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Tools kama [**USBDetective**](https://usbdetective.com) hulandanisha artifacts hizi na rekodi za vifaa vya USB, lakini upatikanaji wa artifacts hutegemea toleo la Windows na application.<sup>[[18]](#references)</sup>

Katika majaribio yaliyoandikwa kwa workflows za MTP za Windows XP na Windows 7, baadhi ya LNK zilielekeza kwenye folder la `WPDNSE` badala ya path ya awali.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: Kumbuka kwamba baadhi ya faili za LNK, badala ya kuelekeza kwenye path ya awali, huelekeza kwenye folder la WPDNSE](<../../../images/image (218).png>)

Utafiti huo ulibaini nakala chini ya `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; maudhui ya muda hayakubaki baada ya restart katika majaribio yake, na GUID iliweza kulinganishwa na data ya shellbag. Chukulia hili kama tabia inayotegemea OS, kifaa, na application, badala ya kanuni ya jumla.<sup>[[16]](#references)</sup>

### Taarifa za Registry

[Angalia ukurasa huu ili ujifunze](interesting-windows-registry-keys.md#usb-information) ni registry keys zipi zilizo na taarifa muhimu kuhusu vifaa vya USB vilivyounganishwa.

### setupapi

Kwenye Vista na matoleo ya baadaye, kagua `C:\Windows\inf\setupapi.dev.log` kwa shughuli za usakinishaji wa vifaa. Vichwa vya sehemu vina timestamps za `Section start`; vinaandika mchakato wa setup na vinapaswa kulinganishwa na ushahidi mwingine wa muunganisho, badala ya kuchukuliwa kama muda sahihi wa kuingizwa kimwili kwa kifaa.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Kagua faili C: Windows inf setupapi.dev.log ili kupata timestamps kuhusu wakati muunganisho wa USB ulifanyika (tafuta Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) inaweza kutumika kupata taarifa kuhusu vifaa vya USB ambavyo vimeunganishwa kwenye image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective inaweza kutumika kupata taarifa kuhusu vifaa vya USB ambavyo vimeunganishwa kwenye image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Scheduled task inayojulikana kama `Plug and Play Cleanup` huondoa matoleo ya zamani ya drivers. Task definition ya Windows 10 iliyoandikwa na Adam Harrison pia inalenga drivers ambazo hazijatumika kwa siku 30, hivyo ushahidi wa drivers za vifaa vinavyoweza kutolewa unaweza kusafishwa; thibitisha task definition ya eneo husika na Windows build kabla ya kujumlisha tabia hii.<sup>[[1]](#references)</sup>

Task iko kwenye path ifuatayo: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Vipengee na Settings Muhimu za Task:**

- **pnpclean.dll**: DLL hii inawajibika kwa mchakato halisi wa cleanup.
- **UseUnifiedSchedulingEngine**: Imewekwa kuwa `TRUE`, ikionyesha matumizi ya generic task scheduling engine.
- **MaintenanceSettings**:
- **Period ('P1M')**: Huagiza Task Scheduler kuanzisha task ya cleanup kila mwezi wakati wa Automatic maintenance ya kawaida.
- **Deadline ('P2M')**: Huagiza Task Scheduler, ikiwa task itashindwa kwa miezi miwili mfululizo, kutekeleza task hiyo wakati wa emergency Automatic maintenance.

Configuration hii hupanga maintenance ya kawaida na majaribio tena baada ya kushindwa mfululizo; XML halisi na tabia hutegemea toleo.<sup>[[1]](#references)</sup>

**Kwa maelezo zaidi angalia:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Barua pepe

Barua pepe zina **sehemu 2 muhimu: headers na maudhui** ya barua pepe. Kwenye **headers** unaweza kupata taarifa kama:

- **Nani** alituma barua pepe (anwani ya barua pepe, IP, mail servers zilizoelekeza upya barua pepe)
- **Lini** barua pepe ilitumwa

Pia, headers za `References` na `In-Reply-To` zinaweza kubeba message IDs zinazotumika kuhusisha majibu na mazungumzo.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Barua pepe ilitumwa lini](<../../../images/image (593).png>)

### Windows Mail App

Application hii huhifadhi maudhui ya barua pepe katika faili saidizi za text au HTML chini ya paths kama `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; mpangilio halisi wa folder lenye nambari na faili unaweza kutofautiana kulingana na artifact.<sup>[[75]](#references)</sup>

**Metadata** ya barua pepe na **contacts** inaweza kupatikana ndani ya **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` hutumia format ya Extensible Storage Engine (ESE). Fanyia kazi nakala na utumie ESE parser kama [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); ikiwa tool inahitaji suffix ya `.edb`, badilisha jina la nakala pekee, na thibitisha schema ya table kabla ya kutegemea table ya `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Wakati wa kukagua MAPI properties za Outlook, properties za canonical zinajumuisha:

- `PidTagClientSubmitTime`: muda wa UTC ambao client iliwasilisha message.
- `PidTagConversationIndex`: nafasi ya message kwa kulinganisha na messages nyingine kwenye conversation thread.
- `PidTagEntryId`: kitambulisho cha message object.
- `PidTagMessageFlags`: status flags kama submitted, read, unread, au kuwa na attachments.
- `PidTagLastVerbExecuted`: operation ya mwisho iliyorekodiwa kwa message, kama open, reply, au forward.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Maeneo ya data-files za Outlook hutofautiana kulingana na toleo na aina ya account. Microsoft inaandika maeneo haya ya kawaida kwa faili za PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` inaweza kutambulisha profile ya Outlook na configuration inayohusiana na data-file.

Faili za PST zinaweza kuwa na messages, contacts, data ya calendar, na vipengee vingine vya Outlook. Unaweza kukagua nakala ukitumia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Unaweza kufungua faili la PST ukitumia tool ya Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** ni cache ya ndani kwa accounts za Exchange au Microsoft 365; Cached Exchange Mode haitumiki kwa accounts za POP au IMAP. Kipindi cha offline kinaweza kusanidiwa na mara nyingi huwa miezi 12 kwa default, huku limits za ukubwa wa PST/OST zikiwa settings tofauti zinazoweza kusanidiwa. Ili kuona OST file, [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) inaweza kutumika.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Kupata Attachments

Attachments zilizopotea zinaweza kurecoveriwa kutoka:

- Kwa configurations za zamani za Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Kwa configurations mpya za Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** huhifadhi profile data chini ya `%APPDATA%\Thunderbird\Profiles`; mail folders kwa kawaida hutumia mbox files zisizo na extension ndani ya directories za `Mail` au `ImapMail` zinazohusiana na account.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews kwa kawaida zilihifadhiwa katika faili za `thumbs.db` za kila folder.
- **Network folders**: Faili la `thumbs.db` bado linaweza kuundwa kwa UNC folder wakati thumbnail behavior inayohusika imewezeshwa; usidhani kwamba kila Windows version au policy huunda faili hilo.
- **Windows Vista and newer**: System thumbnail cache huwekwa pamoja chini ya `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` ikiwa na faili kama **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) inaweza kuparse legacy `Thumbs.db`, huku [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) inaweza kuparse modern thumbnail-cache databases.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Windows Registry, inayohifadhi configuration data ya mfumo na mtumiaji, imo ndani ya hive files katika:

- `%WINDIR%\System32\Config` kwa machine hives zinazowezesha subkeys mbalimbali za `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` kwa user's `HKEY_CURRENT_USER` hive.
- Baadhi ya installations za zamani za Windows zina nakala katika `%WINDIR%\System32\Config\RegBack\`; Windows 10 version 1803 na za baadaye hazijazi directory hii automatically isipokuwa periodic backup iwe imewezeshwa.<sup>[[34]](#references)[[35]](#references)</sup>
- Shell na class-registration data ya kila user pia kwa kawaida huhifadhiwa katika `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` kwenye Windows za kisasa.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Baadhi ya tools zinafaa kwa kuchanganua registry hives; thibitisha formats za hive na version zinazoungwa mkono na kila tool kabla ya kutegemea output:

- **Registry Editor**: Imesakinishwa ndani ya Windows. Ni GUI ya kuvinjari Windows registry ya session ya sasa.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Hukuruhusu kupakia registry file na kuvinjari kupitia GUI. Pia ina Bookmarks zinazoangazia keys zenye taarifa muhimu.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Pia ina GUI inayokuruhusu kuvinjari registry iliyopakiwa na ina plugins zinazoangazia taarifa muhimu ndani ya registry iliyopakiwa.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): GUI application nyingine inayoweza kutoa taarifa kutoka kwenye registry hive iliyopakiwa.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Kurecoveri Element Iliyofutwa

Hive cells zilizofutwa zinaweza kubaki hadi nafasi yake itumike tena, lakini recovery hutegemea hali ya hive na parser; chukulia keys zilizofutwa na kurecoveriwa kama ushahidi unaohitaji validation, badala ya records zilizohakikishwa.

### Last Write Time

Registry keys hubeba timestamp ya last-write; Windows huionyesha kwa key au value entries zake, hivyo value si lazima iwe na timestamp yake huru ya modification.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive ina data ya accounts za ndani za users na groups, ikiwemo password hashes zinazolindwa na boot-key material ya mfumo.<sup>[[38]](#references)[[39]](#references)</sup>

Katika `SAM\Domains\Account\Users` unaweza kupata identifiers za accounts pamoja na baadhi ya fields za logon na policy. Offline hash extraction pia inahitaji `SYSTEM` hive ili kurecover boot-key material husika.<sup>[[38]](#references)[[39]](#references)</sup>

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[Post iliyopo kuhusu common Windows processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) imehifadhiwa kama usomaji wa ziada; thibitisha madai yoyote kuhusu tabia ya process kwa nyaraka za sasa za Windows na ushahidi wa eneo husika.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Kwenye Windows 10 versions zinazoiweka wazi, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` ina subkeys za kila application zenye fields kama muda wa mwisho kutumika na launch count; artifact hii iliondolewa kwenye releases za baadaye, hivyo thibitisha target build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Kwenye systems zinazoonyesha Background Activity Moderator, kagua path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` au path mpya zaidi ya `...\bam\State\UserSettings\{SID}`. Values zimepangwa kwa user SID na zinaweza kuwa na executable paths zilizofuatiliwa pamoja na execution data inayofanana na FILETIME; artifact hii hutegemea version na inapaswa kuthibitishwa kwa ushahidi mwingine.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch huhifadhi resources na launch metadata kwenye cache ili programs zianze kwa haraka zaidi.

Prefetch files huhifadhiwa kama `.pf` files katika `C:\Windows\Prefetch`; format, retention, na limits za idadi ya files hutofautiana kulingana na Windows version. Microsoft inaandika kwamba Windows 8 na za baadaye huhifadhi execution times nane za mwisho na hadi files 1024, hivyo muhtasari wa zamani unaotumia fixed limits haupaswi kujumlishwa.<sup>[[13]](#references)</sup>

Jina la faili kwa kawaida hutumia `{program_name}-{hash}.pf`, ambapo hash hutokana na execution context kama path na arguments; Windows 10 na za baadaye zinaweza kubana faili. Uwepo wake ni ushahidi muhimu wa execution, lakini peke yake si uthibitisho kwamba mtumiaji aliitekeleza na unapaswa kulinganishwa na artifacts nyingine.<sup>[[13]](#references)</sup>

Ili kukagua faili hizi unaweza kutumia [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), ambayo inaandika kuhusu directory parsing, CSV/HTML output, na decompression support kwa Prefetch files zinazotumika kwenye Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** hukamilisha Prefetch kwa kutumia mifumo ya kihistoria ya matumizi ili kuboresha upakiaji. Kwenye mifumo inayozalisha faili hizi, database zake hupatikana kwa kawaida katika `C:\Windows\Prefetch\Ag*.db`; muundo na uwepo wake hutegemea toleo.<sup>[[41]](#references)</sup>

Database hizi zinaweza kuwa na majina ya applications, idadi ya matumizi, faili au volumes zilizofikiwa, paths, na vipindi vya muda, lakini hazipaswi kuchukuliwa kuwa execution log sahihi.<sup>[[41]](#references)</sup>

Kiungo kilichopo cha [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) kimehifadhiwa kama parser inayowezekana; thibitisha upatikanaji wake wa sasa na output inayotumika dhidi ya documentation ya tool kabla ya kuitumia.

### SRUM

**System Resource Usage Monitor** (SRUM) hurekodi matumizi ya rasilimali na applications na users. Ilianzishwa katika Windows 8 na huhifadhi data katika ESE database `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Inatoa taarifa zifuatazo:

- AppID na Path
- User/SID inayohusishwa na record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Mzunguko wa ukusanyaji na retention hutegemea implementation; usidhani kwamba kila record inawakilisha execution interval sahihi ya dakika 60.<sup>[[13]](#references)</sup>

Unaweza kutoa na kuchanganua data kwa kutumia [**srum_dump**](https://github.com/MarkBaggett/srum-dump), ukitumia options zilizoelezwa na toleo la sasa la tool.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, pia inajulikana kama **ShimCache**, ni sehemu ya miundombinu ya Windows ya ulinganifu wa applications na huhifadhi metadata ya mafaili kwa ajili ya maamuzi ya ulinganifu. Njia ya hive, muundo wa rekodi, uwezo wa kuhifadhi, na fields hutofautiana kulingana na toleo la Windows; kwenye Windows za kisasa, ShimCache pekee haiwezi kuthibitisha kwamba mtumiaji ali-execute faili. Parse `SYSTEM` hive husika kwa kutumia [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) na ulinganishe matokeo yake na execution artifacts.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Ili ku-parse taarifa zilizohifadhiwa, inashauriwa kutumia AppCompatCacheParser tool](<../../../images/image (75).png>)

### Amcache

Faili ya **Amcache.hve** ni registry hive inayoorodhesha applications na mafaili yaliyoonekana na Windows. Kwa kawaida hupatikana kwenye `C:\Windows\AppCompat\Programs\Amcache.hve`.

Inaweza kuwa na entries za mafaili zilizounganishwa na zisizounganishwa, paths, na values za SHA1, lakini uwepo wake ni ushahidi wa inventory na hauwezi peke yake kuthibitisha kwamba process ili-execute.<sup>[[13]](#references)[[44]](#references)</sup>

Ili kutoa na kuchanganua **Amcache.hve**, tumia tool ya [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Command hii hu-parse hive na kuandika output ya CSV.<sup>[[44]](#references)</sup>

Kwa mfano:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Kati ya faili za CSV zilizozalishwa, `Amcache_Unassociated file entries` inaweza kuwa muhimu wakati wa kuchunguza faili ambazo hazijahusishwa na programu inayotambulika.<sup>[[44]](#references)</sup>

### RecentFileCache

Kwenye mifumo ya Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` inaweza kuwa na taarifa kuhusu binaries zilizotambuliwa hivi karibuni; upatikanaji na maana yake hutegemea toleo.

Unaweza kutumia [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) kuchanganua faili hiyo.<sup>[[45]](#references)</sup>

### Scheduled tasks

Ushahidi wa scheduled tasks unaweza kupatikana katika `C:\Windows\System32\Tasks` kwa tasks za kisasa na `C:\Windows\Tasks` zenye faili za `.job` kwa tasks za zamani; chunguza muundo wa task definition unaofaa kwa OS hiyo.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Database ya Service Control Manager iko chini ya `SYSTEM\CurrentControlSet\Services` (kwa SYSTEM hive ya offline, chunguza control-set key inayolingana); ina usanidi wa services na drivers, kama vile executable paths na start types.<sup>[[72]](#references)</sup>

### **Windows Store**

Applications za Windows Store zilizosakinishwa zinaweza kuwakilishwa chini ya `\ProgramData\Microsoft\Windows\AppRepository\`, ikijumuisha database **`StateRepository-Machine.srd`**. Schema na paths hutofautiana kulingana na Windows release.<sup>[[71]](#references)</sup>

Database inaweza kuwa na application identifiers, package numbers, na display names. Mapengo katika identifiers si ushahidi wa moja kwa moja kwamba application iliondolewa; thibitisha kwa kulinganisha na package na registry state.

Package registrations zinaweza pia kuonekana chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft inaandika kuhusu `Deprovisioned` subkey inayotegemea toleo kwa apps za provisioned zilizoondolewa; usidhani kwamba `Deleted` subkey ipo kwenye kila build.<sup>[[70]](#references)</sup>

## Windows Events

Kulingana na provider, Windows events zinaweza kuwa na:

- Kilichotokea
- Timestamp ya `TimeCreated` ambayo lazima itafsiriwe kwa kutumia event schema na muktadha wa muda wa host
- Users waliohusika
- Hosts zilizohusika (hostname, IP)
- Assets zilizofikiwa (files, folders, printers, au services).<sup>[[49]](#references)</sup>

Kabla ya Windows Vista, event logs kwa kawaida zilitumia legacy binary format chini ya `C:\Windows\System32\config`; Vista na matoleo ya baadaye hutumia Windows Event Log format, kwa kawaida chini ya `C:\Windows\System32\winevt\Logs`, zikiwa na faili za `.evtx` zilizo na event data iliyowasilishwa katika XML.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry huhifadhi channel configuration chini ya **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, ikijumuisha file path iliyosanidiwa na retention settings.<sup>[[47]](#references)</sup>

Zinaweza kuangaliwa kwa Windows Event Viewer (**`eventvwr.msc`**) au tools kama [**Event Log Explorer**](https://eventlogxp.com) na [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Kwenye Vista na matoleo ya baadaye, Security channel kwa kawaida huhifadhiwa katika `C:\Windows\System32\winevt\Logs\Security.evtx`. Maximum size na retention policy yake vinaweza kusanidiwa; kwa circular logging, records za zamani zinaweza kuandikwa upya faili inapofikia kikomo chake. Channel inaweza kurekodi authentication, logoff, privilege, audit-policy, na object-access events wakati auditing husika imewezeshwa.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Account logon iliyofanikiwa.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Account logon iliyoshindikana.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Logon session ilisitishwa.<sup>[[52]](#references)</sup>
- **Event ID 4647**: User alianzisha logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Special privileges zilipewa logon mpya; hii ni kawaida kwa system na administrator accounts, kwa hiyo si ushahidi wa moja kwa moja wa malicious activity.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: Local logon ya interactive.
- **Network (3)**: Ufikiaji wa shared resource.
- **Batch (4)**: Batch-process logon.
- **Service (5)**: Service logon.
- **Unlock (7)**: Kufungua workstation.
- **NetworkCleartext (8)**: Network logon inayowasilisha credentials kwa cleartext kwa authentication package.
- **NewCredentials (9)**: Logon inayotumia alternate credentials zilizotolewa kwa outbound connections.
- **RemoteInteractive (10)**: Remote Desktop au Terminal Services logon.
- **CachedInteractive (11)**: Interactive logon inayotumia cached domain credentials.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Unlock inayotumia cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: User huyo hayupo.
- **0xC000006A**: User name ni sahihi lakini password si sahihi.
- **0xC0000234**: Account imefungwa.
- **0xC0000072**: Account imezimwa.
- **0xC000006F**: Logon nje ya saa zinazoruhusiwa.
- **0xC0000070**: Ukiukaji wa kizuizi cha workstation.
- **0xC0000193**: Account imekwisha muda.
- **0xC0000071**: Password imekwisha muda.
- **0xC0000133**: Tofauti ya muda kati ya client na server ni kubwa sana.
- **0xC0000224**: Account lazima ibadilishe password yake.
- **0xC0000225**: `STATUS_NOT_FOUND`; code pekee haitambulishi system bug au attack.
- **0xC000015B**: Aina ya logon iliyoombwa hairuhusiwi kwa account hiyo.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Muda wa system ulibadilishwa. Events nyingi huonyesha marekebisho ya kawaida ya time-service, kwa hiyo linganisha actor na time source kabla ya kuuchukulia kama tampering.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12 hurekodi OS start, 13 hurekodi OS shutdown, 1074 hurekodi shutdown au restart iliyopangwa, 6008 huonyesha shutdown isiyotarajiwa, na 6009 hurekodi Windows version wakati wa boot. Events 6005 na 6006 huonyesha kwamba Event Log service ilianza na kusimama, mtawalia; zenyewe si ushahidi wa OS startup na shutdown.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 hurekodi kwamba Security audit log ilifutwa; chunguza actor na events zinazozunguka badala ya kudhani intent kutokana na event hii pekee.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events zinazoweza kusaidia kuthibitisha first-use au installation activity.
- **10000 / 10100**: `DriverFrameworks-UserMode` events zinazoweza kuambatana na device activity.
- **Event ID 112**: `DeviceSetupManager/Admin` activity inayoweza kutoa timestamps zinazohusiana na insertion.
- Provider, channel, na event semantics hutofautiana kulingana na Windows version; chunguza provider name na event payload kabla ya kuipa maana.<sup>[[59]](#references)</sup>

Kwa mifano ya vitendo kuhusu logon types na credential material inayohusishwa nayo, angalia [mwongozo wa kina wa Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Event details, ikijumuisha logon type, status, substatus, source address, na process fields, hutoa muktadha wa Event ID 4625; status code au pattern ya failures zinazorudiwa ni lead ya uchunguzi, si hitimisho.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Kwa sababu event logs kwa kawaida huwa circular, records zilizoandikwa upya na logger zinaweza zisiweze kurejeshwa. Hifadhi forensic image au working copy kabla ya kuingiliana na live system; tumia parser au carver iliyothibitishwa kama **Bulk_extractor** baada tu ya kuthibitisha kwamba tool version inaunga mkono target `.evtx` data, na usichomoe system inayoendesha kwa lengo pekee la kujaribu kurejesha events.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Kwa reference ya vitendo ya event IDs, angalia link iliyopo ya [Red Team Recipe](https://redteamrecipe.com/event-codes/) na thibitisha mifano yake dhidi ya provider documentation iliyo hapo juu.

#### Brute Force Attacks

Linganisha failures zinazorudiwa za Event ID 4625 na success ya baadaye ya 4624, logon type, status, source, na account context; mfuatano huo ni indicator ya uchunguzi, si ushahidi wa attack.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 hurekodi mabadiliko ya system time, ambayo yanaweza kutatiza timeline analysis; ilinganishe na time-service na host evidence.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs hutegemea provider; linganisha `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100, na `DeviceSetupManager/Admin` 112 na SetupAPI na registry artifacts.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Tumia 12/13/1074/6008/6009 kwa muktadha wa OS start, shutdown, restart, na unexpected power; 6005/6006 huashiria Event Log service start/stop.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 hurekodi kwamba Security audit log ilifutwa na inapaswa kuhusishwa na account na process iliyohusika.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Kuchunguza Windows Processes za Kawaida](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Mtazamo wa Digital Forensics wa Windows 10 Notifications](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier na Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Registry backup and restore operations under VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry keys for backup and restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Tatizo la Word performance kwenye AutoRecover location](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Kutambua Data Exfiltration Artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID and Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Kutafuta na kuhamisha Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Kuwasha Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Ni subset tu ya items inayosynchronized](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Kusanidi size limits za Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Ambapo Thunderbird huhifadhi user data](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings na mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry haibackupiwi kwenye RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Kuhariri registry remotely](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Kutatua unexpected reboots kwa kutumia system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Kutatua shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics for Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print huacha kuchapisha PDF attachments katika Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Kuzuia apps zilizoondolewa zisirudi wakati wa update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK and Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Fail with Error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Kuelekeza kwenye Windows Mail database](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
