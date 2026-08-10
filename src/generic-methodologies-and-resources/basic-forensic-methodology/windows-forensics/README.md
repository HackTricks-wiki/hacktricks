# Artifacts za Windows

## Artifacts za Jumla za Windows

### Windows 10 Notifications

Database ya notifications kwa kila mtumiaji iko katika `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (kwa mfano, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Matoleo ya awali ya Windows 10 yalitumia `appdb.dat`; Anniversary Update (1607) ilianzisha `wpndatabase.db`. Database ya SQLite ina jedwali la `Notification` lenye payloads za notifications na sehemu za muda, ingawa muda wa kuhifadhi na data inayopatikana hutofautiana kulingana na toleo na sera ya usafishaji.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline ni kipengele cha historia ya shughuli ambacho kinaweza kuwa na rekodi za applications zinazotumika, documents na shughuli nyingine za mtumiaji; wigo wake hutegemea application na toleo la Windows.<sup>[[4]](#references)</sup>

Database iko katika `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Inaweza kufunguliwa kwa SQLite au kuchanganuliwa kwa [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), ambaye output yake inaweza kukaguliwa kwa [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Files zilizopakuliwa kutoka nje ya mpaka wa uaminifu wa ndani zinaweza kuwa na **`Zone.Identifier` alternate data stream**, ambayo huhifadhi taarifa za zone na inaweza kujumuisha metadata ya chanzo kama vile URL. Uwepo na sehemu zake hutegemea producer na sera ya mfumo.<sup>[[6]](#references)</sup>

## **Hifadhi Nakala za Files**

### Recycle Bin

Kwenye Vista na matoleo ya baadaye, **Recycle Bin** inaweza kupatikana katika folder **`$Recycle.bin`** kwenye root ya drive (kwa mfano, `C:\$Recycle.bin`).\
File inapofutwa katika folder hii, files 2 maalum huundwa:

- `$I{id}`: Taarifa za file, ikijumuisha muda wa kufutwa na path ya awali
- `$R{id}`: Maudhui ya file

![Hifadhi Nakala za Files - Recycle Bin: $R{id}: Maudhui ya file](<../../../images/image (1029).png>)

Ukiwa na files hizi, unaweza kutumia [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) kutoa path ya awali na muda wa kufutwa (tumia version inayofaa kwa release ya Windows inayolengwa).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) inaweza kuunda shadow copies za volumes za wakati maalum wakati faili zinatumika; shadow copy si mbadala wa forensic image.<sup>[[8]](#references)</sup>

Metadata ya copy kwa kawaida huhusishwa na `\System Volume Information` kwenye mzizi wa volume, ikiwa na vitambulisho vinavyotofautiana kulingana na mfumo:

![Recycle Bin - Volume Shadow Copies: Backups hizi kwa kawaida hupatikana kwenye System Volume Information kutoka kwenye mzizi wa file system, na jina linaundwa na UIDs zinazoonyeshwa kwenye...](<../../../images/image (94).png>)

Baada ya ku-mount image kwa kutumia forensic mounter inayofaa, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) inaweza kuorodhesha VSS snapshots zinazopatikana na kuvinjari au kunakili faili kutoka kwazo.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Baada ya ku-mount forensic image kwa ArsenalImageMounter, tool ya ShadowCopyView inaweza kutumika kukagua shadow copy na hata kutoa faili...](<../../../images/image (576).png>)

Configuration ya VSS registry writer inajumuisha `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, ambayo inaweza kubainisha faili na keys zitakazoondolewa kwenye backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore ina faili na keys ambazo hazipaswi ku-backup](<../../../images/image (254).png>)

Key ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` pia ina configuration ya VSS service.<sup>[[8]](#references)</sup>

### Faili za Office AutoSaved

Maeneo ya AutoRecover hutofautiana kulingana na Office application, version na configuration. Kwa Word, Microsoft inaandika `%APPDATA%\Microsoft\Word` kama eneo chaguo-msingi; angalia settings za application ili kupata path inayotumika.<sup>[[12]](#references)</sup>

## Shell Items

Shell item ni item iliyo na taarifa kuhusu jinsi ya kufikia faili nyingine.

### Recent Documents (LNK)

Windows kwa kawaida huunda shortcuts za recent items mtumiaji anapofungua au kufikia item kwa njia nyingine:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Kufikia folder kunaweza pia kuunda links za folder hiyo na parent folders zinazohusiana.

Faili hizi za link zinaweza kuwa na aina ya target, MAC times za target, taarifa za volume na path ya target. Metadata hiyo inaweza kusaidia kutambua target iliyoondolewa, lakini artifact hiyo yenyewe si ushahidi kwamba target ilifunguliwa na mtumiaji fulani.<sup>[[13]](#references)[[14]](#references)</sup>

Filesystem timestamps za LNK yenyewe na timestamps za target zilizopachikwa ndani yake ni tofauti. Usitafsiri uundaji wa link kama matumizi ya kwanza au urekebishaji wa link kama matumizi ya mwisho bila artifacts za ziada za kuthibitisha; format huhifadhi timestamps za target kando na timestamps za faili la link.<sup>[[13]](#references)[[14]](#references)</sup>

Link iliyopo ya [**LinkParser**](http://4discovery.com/our-tools/) imehifadhiwa kama chaguo la kihistoria, lakini documentation yake haikupatikana wakati wa review. Kwa parser ya command-line iliyo na documentation, tumia [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Tools hizi kwa kawaida huonyesha seti mbili za timestamps:

- **Timestamps za target:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamps za faili la link:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Seti ya kwanza inarejelea target; seti ya pili inarejelea faili la LNK lenyewe. Tafsiri zote mbili kwa kuzingatia documentation ya parser na muktadha wa filesystem.<sup>[[14]](#references)[[15]](#references)</sup>

Unaweza kupata taarifa hiyo hiyo kwa kuendesha Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Katika hali hii, taarifa itahifadhiwa ndani ya faili la CSV.

### Jumplists

Jump Lists ni orodha za kila application za vipengee vya hivi karibuni au vya kazi maalum, na zinaweza kuwa za kiotomatiki au maalum.<sup>[[13]](#references)</sup>

Automatic Jump Lists huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` na hutumia majina kama `{id}.automaticDestinations-ms`, ambapo ID hutambulisha application.

Custom Jump Lists huhifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; application hudhibiti ni maingizo yapi ya kazi au vipengee inavyounda.

Muda wa kuundwa na kurekebishwa wa filesystem hueleza faili la Jump List, wala si moja kwa moja ufikiaji wa kwanza na wa mwisho wa kila target iliyoorodheshwa. Linganisha maingizo yaliyoparsiwa na timestamp za faili pamoja na artifacts nyingine.<sup>[[13]](#references)</sup>

Unaweza kukagua Jump Lists ukitumia [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Unaweza kukagua jumplists ukitumia JumplistExplorer](<../../../images/image (168).png>)

(_Kumbuka kuwa timestamps zinazotolewa na JumplistExplorer zinahusiana na faili la jumplist lenyewe_)

### Shellbags

[**Fuata kiungo hiki ili ujifunze shellbags ni nini.**](interesting-windows-registry-keys.md#shellbags)

## Matumizi ya Windows USBs

Matumizi ya USB yanaweza wakati mwingine kuthibitishwa kwa artifacts zinazoundwa wakati faili zinapofikiwa kutoka kwenye media inayoweza kutolewa, zikiwemo:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Tools kama [**USBDetective**](https://usbdetective.com) huunganisha artifacts hizi na rekodi za vifaa vya USB, lakini upatikanaji wa artifacts hutegemea toleo la Windows na application.<sup>[[18]](#references)</sup>

Katika majaribio yaliyoandikwa kwa workflows za MTP za Windows XP na Windows 7, baadhi ya LNK zilielekeza kwenye folder la `WPDNSE` badala ya path ya awali.<sup>[[16]](#references)</sup>

![Shellbags - Matumizi ya Windows USBs: Kumbuka kuwa baadhi ya faili za LNK, badala ya kuelekeza kwenye path ya awali, huelekeza kwenye folder la WPDNSE](<../../../images/image (218).png>)

Utafiti huo ulibaini nakala chini ya `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; katika majaribio yake, maudhui ya muda hayakuendelea baada ya restart, na GUID iliweza kuhusishwa na data ya shellbag. Chukulia hili kama tabia inayotegemea OS, kifaa na application, wala si kanuni ya jumla.<sup>[[16]](#references)</sup>

### Taarifa za Registry

[Angalia ukurasa huu ili ujifunze](interesting-windows-registry-keys.md#usb-information) ni registry keys zipi zina taarifa muhimu kuhusu vifaa vya USB vilivyounganishwa.

### setupapi

Kwenye Vista na matoleo ya baadaye, kagua `C:\Windows\inf\setupapi.dev.log` kwa shughuli za usakinishaji wa vifaa. Vichwa vya sehemu vina timestamps za `Section start`; vinaandika mchakato wa setup na vinapaswa kulinganishwa na ushahidi mwingine wa muunganisho badala ya kuchukuliwa kama muda sahihi wa kuingizwa kimwili kwa kifaa.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Kagua faili C: Windows inf setupapi.dev.log ili kupata timestamps zinazoonyesha muunganisho wa USB ulifanyika lini (tafuta Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) inaweza kutumika kupata taarifa kuhusu vifaa vya USB ambavyo vimeunganishwa kwenye image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective inaweza kutumika kupata taarifa kuhusu vifaa vya USB ambavyo vimeunganishwa kwenye image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Scheduled task inayojulikana kama `Plug and Play Cleanup` huondoa matoleo ya zamani ya drivers. Task definition ya Windows 10 iliyoandikwa na Adam Harrison pia inalenga drivers ambazo hazijatumika kwa siku 30, hivyo ushahidi wa drivers za vifaa vinavyoweza kutolewa unaweza kusafishwa; thibitisha task definition ya eneo hilo na Windows build kabla ya kujumlisha tabia hii.<sup>[[1]](#references)</sup>

Task hiyo iko kwenye path ifuatayo: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Vipengele na Settings Muhimu za Task:**

- **pnpclean.dll**: DLL hii inawajibika kwa mchakato halisi wa usafishaji.
- **UseUnifiedSchedulingEngine**: Imewekwa kuwa `TRUE`, ikionyesha matumizi ya generic task scheduling engine.
- **MaintenanceSettings**:
- **Period ('P1M')**: Huagiza Task Scheduler kuanzisha task ya usafishaji kila mwezi wakati wa Automatic maintenance ya kawaida.
- **Deadline ('P2M')**: Humwagiza Task Scheduler, ikiwa task itashindwa kwa miezi miwili mfululizo, kutekeleza task hiyo wakati wa emergency Automatic maintenance.

Configuration hii huratibu maintenance ya kawaida na majaribio tena baada ya kushindwa mfululizo; XML halisi na tabia hutegemea toleo.<sup>[[1]](#references)</sup>

**Kwa maelezo zaidi angalia:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Barua pepe

Barua pepe zina **sehemu 2 muhimu: headers na content** ya barua pepe. Katika **headers** unaweza kupata taarifa kama:

- **Nani** alituma barua pepe (email address, IP, mail servers zilizoelekeza upya barua pepe)
- **Lini** barua pepe ilitumwa

Pia, headers za `References` na `In-Reply-To` zinaweza kubeba message IDs zinazotumika kuhusisha majibu na mazungumzo.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Barua pepe: Barua pepe ilitumwa lini](<../../../images/image (593).png>)

### Windows Mail App

Application hii huhifadhi content ya barua pepe katika auxiliary text au HTML files chini ya paths kama `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; mpangilio halisi wa folder na files zenye nambari unaweza kutofautiana kulingana na artifact.<sup>[[75]](#references)</sup>

**Metadata** ya barua pepe na **contacts** inaweza kupatikana ndani ya **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` hutumia format ya Extensible Storage Engine (ESE). Fanyia kazi nakala na utumie ESE parser kama [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); ikiwa tool inahitaji suffix ya `.edb`, badilisha jina la nakala pekee, na thibitisha schema ya table kabla ya kutegemea table ya `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Unapokagua MAPI properties za Outlook, canonical properties zinajumuisha:

- `PidTagClientSubmitTime`: muda wa UTC ambapo client iliwasilisha message.
- `PidTagConversationIndex`: nafasi ya relative ya message katika conversation thread.
- `PidTagEntryId`: identifier ya message object.
- `PidTagMessageFlags`: status flags kama vile submitted, read, unread, au kuwa na attachments.
- `PidTagLastVerbExecuted`: operation ya mwisho iliyorekodiwa kwa message, kama vile open, reply au forward.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Maeneo ya data-files za Outlook hutofautiana kulingana na version na account type. Microsoft inaandika maeneo haya ya kawaida kwa PST/OST files:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` inaweza kutambulisha Outlook profile na configuration ya data-file inayohusiana.

PST files zinaweza kuwa na messages, contacts, calendar data na Outlook items nyingine. Unaweza kukagua nakala ukitumia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Unaweza kufungua PST file ukitumia tool Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** ni cache ya ndani kwa Exchange au Microsoft 365 accounts; Cached Exchange Mode haitumiki kwa POP au IMAP accounts. Kipindi cha offline kinaweza kusanidiwa na mara nyingi huwa miezi 12 kwa default, huku limits za ukubwa wa PST/OST zikiwa settings tofauti zinazoweza kusanidiwa. Ili kuona OST file, [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) inaweza kutumika.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Kupata Attachments

Attachments zilizopotea zinaweza kupatikana kutoka:

- Kwa legacy Outlook/IE configurations: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Kwa newer Outlook/IE11 configurations: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** huhifadhi profile data chini ya `%APPDATA%\Thunderbird\Profiles`; mail folders kwa kawaida hutumia mbox files zisizo na extension ndani ya directories za `Mail` au `ImapMail` maalum kwa account.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews kwa kawaida zilihifadhiwa katika `thumbs.db` files za kila folder.
- **Network folders**: `thumbs.db` file bado inaweza kuundwa kwa UNC folder wakati thumbnail behavior husika imewezeshwa; usidhanie kuwa kila Windows version au policy huunda file hiyo.
- **Windows Vista na mpya zaidi**: System thumbnail cache huwekwa pamoja chini ya `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` ikiwa na files kama **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) inaweza kuparse legacy `Thumbs.db`, huku [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) inaweza kuparse modern thumbnail-cache databases.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Taarifa za Windows Registry

Windows Registry, inayohifadhi system na user configuration data, imo ndani ya hive files katika:

- `%WINDIR%\System32\Config` kwa machine hives zinazowezesha subkeys mbalimbali za `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` kwa user's `HKEY_CURRENT_USER` hive.
- Baadhi ya Windows installations za zamani zina nakala katika `%WINDIR%\System32\Config\RegBack\`; Windows 10 version 1803 na mpya zaidi hazijazi directory hii automatically isipokuwa periodic backup imewezeshwa.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-user shell na class-registration data pia kwa kawaida huhifadhiwa katika `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` kwenye modern Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Baadhi ya tools ni muhimu kwa kuchanganua registry hives; thibitisha formats za hive na version zinazoungwa mkono na kila tool kabla ya kutegemea output:

- **Registry Editor**: Imewekwa ndani ya Windows. Ni GUI ya kuvinjari Windows registry ya session ya sasa.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Inakuruhusu kupakia registry file na kuvinjari kwa kutumia GUI. Pia ina Bookmarks zinazoangazia keys zenye taarifa muhimu.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Tena, ina GUI inayokuruhusu kuvinjari registry iliyopakiwa na pia ina plugins zinazoangazia taarifa muhimu ndani ya registry iliyopakiwa.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): GUI application nyingine yenye uwezo wa kutoa taarifa kutoka kwenye registry hive iliyopakiwa.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Kurejesha Kipengee Kilichofutwa

Hive cells zilizofutwa zinaweza kubaki hadi nafasi yake itumike tena, lakini recovery hutegemea hali ya hive na parser; chukulia keys zilizofutwa zilizorejeshwa kama ushahidi unaohitaji validation, wala si records zilizohakikishwa.

### Last Write Time

Registry keys hubeba timestamp ya last-write; Windows huionyesha kwa key au value entries zake, hivyo value si lazima iwe na modification timestamp yake huru.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive ina data za local user na group accounts, ikiwemo password hashes zilizolindwa na system boot-key material.<sup>[[38]](#references)[[39]](#references)</sup>

Katika `SAM\Domains\Account\Users` unaweza kupata account identifiers na baadhi ya logon na policy fields. Offline hash extraction pia inahitaji `SYSTEM` hive ili kurejesha boot-key material husika.<sup>[[38]](#references)[[39]](#references)</sup>

### Maingizo Muhimu katika Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[Post iliyopo kuhusu common Windows processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) imehifadhiwa kama usomaji wa ziada; thibitisha madai yoyote kuhusu tabia ya process kwa current Windows documentation na ushahidi wa eneo hilo.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Kwenye Windows 10 versions zinazoionyesha, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` ina subkeys za kila application zenye fields kama muda wa mwisho wa matumizi na launch count; artifact hii iliondolewa katika releases za baadaye, hivyo thibitisha target build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Kwenye systems zinazoonyesha Background Activity Moderator, kagua `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` au path mpya ya `...\bam\State\UserSettings\{SID}`. Values hupangwa kwa user SID na zinaweza kuwa na executable paths zilizofuatiliwa pamoja na execution data inayofanana na FILETIME; artifact hii hutegemea version na inapaswa kuthibitishwa kwa ushahidi mwingine.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching hu-cache resources na launch metadata ili programs zianze kwa haraka zaidi.

Prefetch files huhifadhiwa kama `.pf` files katika `C:\Windows\Prefetch`; format, retention na limits za idadi ya files hutofautiana kulingana na Windows version. Microsoft inaandika retention ya execution times nane za mwisho na hadi files 1024 kwenye Windows 8 na mpya zaidi, hivyo summaries za zamani zenye fixed limits hazipaswi kutumika kwa ujumla.<sup>[[13]](#references)</sup>

Filename kwa kawaida hutumia `{program_name}-{hash}.pf`, ambapo hash hutokana na execution context kama path na arguments; Windows 10 na mpya zaidi inaweza ku-compress file. Kuwepo kwa file ni ushahidi muhimu wa execution, lakini peke yake si uthibitisho kwamba mtumiaji aliitekeleza na kunapaswa kulinganishwa na artifacts nyingine.<sup>[[13]](#references)</sup>

Ili kukagua files hizi unaweza kutumia [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), ambayo inaandika kuhusu directory parsing, CSV/HTML output na decompression support kwa Windows 10 Prefetch files zinazohusika.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** hukamilisha Prefetch kwa kutumia mifumo ya matumizi ya kihistoria ili kuboresha upakiaji. Kwenye mifumo inayozalisha faili hizo, faili zake za database kwa kawaida hupatikana katika `C:\Windows\Prefetch\Ag*.db`; muundo na uwepo wake hutegemea toleo la mfumo.<sup>[[41]](#references)</sup>

Database hizi zinaweza kuwa na majina ya applications, idadi ya matumizi, faili au volumes zilizofikiwa, paths, na vipindi vya muda, lakini hazipaswi kuchukuliwa kama logi sahihi ya utekelezaji.<sup>[[41]](#references)</sup>

Kiungo kilichopo cha [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) kimehifadhiwa kama parser inayowezekana; thibitisha upatikanaji wake wa sasa na output inayoungwa mkono dhidi ya documentation ya tool kabla ya kuitumia.

### SRUM

**System Resource Usage Monitor** (SRUM) hurekodi matumizi ya rasilimali na applications pamoja na users. Ilianzishwa katika Windows 8 na huhifadhi data katika ESE database `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Hutoa taarifa zifuatazo:

- AppID and Path
- User/SID inayohusishwa na record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Muda wa ukusanyaji na uhifadhi hutegemea utekelezaji; usidhani kwamba kila record inawakilisha interval sahihi ya utekelezaji ya dakika 60.<sup>[[13]](#references)</sup>

Unaweza ku-extract na kukagua data kwa kutumia [**srum_dump**](https://github.com/MarkBaggett/srum-dump), ukitumia options zilizoandikwa na toleo la sasa la tool.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, pia inajulikana kama **ShimCache**, ni sehemu ya miundombinu ya Windows ya application-compatibility na huhifadhi metadata ya faili kwa ajili ya maamuzi ya compatibility. Njia ya hive, muundo wa rekodi, uwezo wa kuhifadhi rekodi, na fields hutofautiana kulingana na toleo la Windows; kwenye Windows za kisasa, ShimCache pekee haiwezi kuthibitisha kwamba mtumiaji aliendesha faili. Parse hive husika ya `SYSTEM` kwa kutumia [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) na linganisha matokeo yake na execution artifacts.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Ili ku-parse taarifa iliyohifadhiwa, inashauriwa kutumia AppCompatCacheParser tool](<../../../images/image (75).png>)

### Amcache

Faili ya **Amcache.hve** ni registry hive inayoorodhesha applications na files zilizotambuliwa na Windows. Kwa kawaida hupatikana katika `C:\Windows\AppCompat\Programs\Amcache.hve`.

Inaweza kuwa na entries za files zilizounganishwa na zisizounganishwa, paths, na values za SHA1, lakini uwepo wake ni ushahidi wa inventory na hauwezi kuthibitisha peke yake kwamba process ilitekelezwa.<sup>[[13]](#references)[[44]](#references)</sup>

Ili kutoa na kuchanganua **Amcache.hve**, tumia tool ya [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Command hii hu-parse hive na kuandika output ya CSV.<sup>[[44]](#references)</sup>

Kwa mfano:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Miongoni mwa faili za CSV zilizotengenezwa, `Amcache_Unassociated file entries` inaweza kuwa muhimu wakati wa kuchunguza faili ambazo hazijahusishwa na program inayotambulika.<sup>[[44]](#references)</sup>

### RecentFileCache

Kwenye mifumo ya Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` inaweza kuwa na taarifa kuhusu binaries zilizoonekana hivi karibuni; upatikanaji na maana yake hutegemea toleo.

Unaweza kutumia [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) kuchanganua faili hiyo.<sup>[[45]](#references)</sup>

### Scheduled tasks

Ushahidi wa scheduled tasks unaweza kupatikana kwenye `C:\Windows\System32\Tasks` kwa tasks za kisasa na `C:\Windows\Tasks` zenye faili za `.job` kwa tasks za zamani; kagua format ya task definition inayofaa kwa OS.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Database ya Service Control Manager iko chini ya `SYSTEM\CurrentControlSet\Services` (kwa SYSTEM hive iliyo offline, kagua control-set key inayolingana); ina configuration ya services na drivers kama vile executable paths na start types.<sup>[[72]](#references)</sup>

### **Windows Store**

Windows Store applications zilizosakinishwa zinaweza kuwakilishwa chini ya `\ProgramData\Microsoft\Windows\AppRepository\`, ikiwemo database **`StateRepository-Machine.srd`**. Schema na paths hutofautiana kulingana na Windows release.<sup>[[71]](#references)</sup>

Database inaweza kuwa na application identifiers, package numbers, na display names. Mapengo katika identifiers si ushahidi wa kutosha peke yake kwamba application iliondolewa; thibitisha kwa package na registry state.

Package registrations pia zinaweza kuonekana chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft inaandika kuhusu subkey ya `Deprovisioned` inayotegemea toleo kwa apps zilizotolewa kwenye provision; usidhani kwamba subkey ya `Deleted` ipo kwenye kila build.<sup>[[70]](#references)</sup>

## Windows Events

Kulingana na provider, Windows events zinaweza kuwa na:

- Kilichotokea
- Timestamp ya `TimeCreated` ambayo lazima itafsiriwe kwa kuzingatia event schema na muktadha wa muda wa host
- Users waliohusika
- Hosts waliohusika (hostname, IP)
- Assets zilizofikiwa (files, folders, printers, au services).<sup>[[49]](#references)</sup>

Kabla ya Windows Vista, event logs kwa kawaida zilitumia legacy binary format chini ya `C:\Windows\System32\config`; Vista na matoleo ya baadaye hutumia Windows Event Log format, kwa kawaida chini ya `C:\Windows\System32\winevt\Logs`, huku faili za `.evtx` zikiwa na event data iliyotolewa kwa XML.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry huhifadhi channel configuration chini ya **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, ikiwemo file path iliyosanidiwa na retention settings.<sup>[[47]](#references)</sup>

Zinaweza kuangaliwa kwa Windows Event Viewer (**`eventvwr.msc`**) au tools kama vile [**Event Log Explorer**](https://eventlogxp.com) na [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Kwenye Vista na matoleo ya baadaye, Security channel kwa kawaida huhifadhiwa kwenye `C:\Windows\System32\winevt\Logs\Security.evtx`. Maximum size na retention policy yake zinaweza kusanidiwa; kwa circular logging, records za zamani zinaweza kuandikwa upya faili inapofikia kikomo chake. Channel inaweza kurekodi authentication, logoff, privilege, audit-policy, na object-access events pale auditing husika imewezeshwa.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Account logon iliyofanikiwa.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Account logon iliyoshindikana.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Logon session ilisitishwa.<sup>[[52]](#references)</sup>
- **Event ID 4647**: User alianzisha logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Special privileges zilipewa logon mpya; hii ni kawaida kwa system na administrator accounts, kwa hiyo si ushahidi wa malicious activity peke yake.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: Interactive local logon.
- **Network (3)**: Ufikiaji wa shared resource.
- **Batch (4)**: Batch-process logon.
- **Service (5)**: Service logon.
- **Unlock (7)**: Workstation unlock.
- **NetworkCleartext (8)**: Network logon inayowasilisha credentials kwa cleartext kwa authentication package.
- **NewCredentials (9)**: Logon inayotumia alternate credentials zilizotolewa kwa outbound connections.
- **RemoteInteractive (10)**: Remote Desktop au Terminal Services logon.
- **CachedInteractive (11)**: Interactive logon inayotumia cached domain credentials.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Unlock inayotumia cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: User kama huyo hayupo.
- **0xC000006A**: Username ni sahihi lakini password si sahihi.
- **0xC0000234**: Account imefungiwa.
- **0xC0000072**: Account imezimwa.
- **0xC000006F**: Logon imefanyika nje ya saa zinazoruhusiwa.
- **0xC0000070**: Uvunjaji wa restriction ya workstation.
- **0xC0000193**: Account ime-expire.
- **0xC0000071**: Password ime-expire.
- **0xC0000133**: Tofauti ya muda kati ya client na server ni kubwa mno.
- **0xC0000224**: Account lazima ibadilishe password yake.
- **0xC0000225**: `STATUS_NOT_FOUND`; code hii pekee haitambui system bug au attack.
- **0xC000015B**: Logon type iliyoombwa hairuhusiwi kwa account.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Muda wa system ulibadilishwa. Events nyingi huonyesha marekebisho ya kawaida ya time-service, kwa hiyo correlate actor na time source kabla ya kuichukulia kama tampering.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12 hurekodi OS start, 13 hurekodi OS shutdown, 1074 hurekodi shutdown au restart iliyopangwa, 6008 huonyesha shutdown isiyotarajiwa, na 6009 hurekodi Windows version wakati wa boot. Events 6005 na 6006 huonyesha kwamba Event Log service ilianza na kusimama, mtawalia; zenyewe si ushahidi wa OS startup na shutdown.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 hurekodi kwamba Security audit log ilifutwa; chunguza actor na events zinazozunguka badala ya kudhani intent kutokana na event hii pekee.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events zinazoweza kusaidia kuthibitisha first-use au installation activity.
- **10000 / 10100**: `DriverFrameworks-UserMode` events zinazoweza kuambatana na device activity.
- **Event ID 112**: `DeviceSetupManager/Admin` activity inayoweza kutoa timestamps zinazohusiana na insertion.
- Provider, channel, na event semantics hutofautiana kulingana na Windows version; kagua provider name na event payload kabla ya kuipa maana.<sup>[[59]](#references)</sup>

Kwa mifano ya kivitendo kuhusu logon types na credential material inayohusishwa nayo, tazama [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Event details, ikiwemo logon type, status, substatus, source address, na process fields, hutoa muktadha wa Event ID 4625; status code au pattern ya repeated failures ni lead ya uchunguzi, si hitimisho.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Kwa sababu event logs kwa kawaida huwa circular, records zilizoandikwa upya na logger huenda zisipatikane tena. Hifadhi forensic image au working copy kabla ya kuingiliana na live system; tumia parser au carver iliyothibitishwa kama vile **Bulk_extractor** tu baada ya kuthibitisha kwamba tool version inaunga mkono target `.evtx` data, na usitoe power kwenye system inayoendelea kufanya kazi kwa lengo pekee la kujaribu kurejesha events.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Kwa reference ya vitendo ya event-ID, tazama link iliyopo ya [Red Team Recipe](https://redteamrecipe.com/event-codes/) na thibitisha mifano yake dhidi ya provider documentation hapo juu.

#### Brute Force Attacks

Correlate repeated Event ID 4625 failures na 4624 success ya baadaye, logon type, status, source, na account context; mfululizo huo ni indicator ya uchunguzi, si ushahidi wa attack.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 hurekodi mabadiliko ya system time, ambayo yanaweza kufanya timeline analysis iwe ngumu; ilinganishe na time-service na host evidence.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs hutegemea provider; correlate `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100, na `DeviceSetupManager/Admin` 112 na SetupAPI na registry artifacts.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Tumia 12/13/1074/6008/6009 kwa muktadha wa OS start, shutdown, restart, na unexpected power; 6005/6006 huonyesha kuanza/kusimama kwa Event Log service.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 hurekodi kwamba Security audit log ilifutwa na inapaswa ku-correlate na account na process iliyohusika.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [A Digital Forensic View of Windows 10 Notifications](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier and Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Registry backup and restore operations under VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry keys for backup and restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word performance issue on AutoRecover location](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Identifying Data Exfiltration Artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID and Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Find and transfer Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Turn on Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Only a subset of items is synchronized](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configure size limits for Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Where Thunderbird stores user data](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings and mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry not backed up to RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Remotely edit the registry](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
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
- [57] [Troubleshoot unexpected reboots using system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Troubleshoot shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics for Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print stops printing PDF attachments in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Keep removed apps from returning during an update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK and Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Fail with Error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigating the Windows Mail database](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
