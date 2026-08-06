# Windows Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Algemene Windows Artefakte

### Windows 10 Notifications

In die pad `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` kan jy die databasis `appdb.dat` (voor Windows anniversary) of `wpndatabase.db` (ná Windows Anniversary) vind.

Binne hierdie SQLite-databasis kan jy die `Notification`-tabel vind met al die notifications (in XML-formaat), wat interessante data kan bevat.

### Timeline

Timeline is ’n Windows-eienskap wat **chronologiese geskiedenis** van besoekte webblaaie, geredigeerde dokumente en uitgevoerde toepassings verskaf.

Die databasis is geleë in die pad `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Hierdie databasis kan met ’n SQLite-tool of met die tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) oopgemaak word, **wat 2 lêers genereer wat met die tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **oopgemaak kan word**.

### ADS (Alternate Data Streams)

Lêers wat afgelaai is, kan die **ADS Zone.Identifier** bevat wat aandui **hoe** dit vanaf die intranet, internet, ensovoorts **afgelaai** is. Sommige sagteware (soos browsers) plaas gewoonlik selfs **meer** **inligting**, soos die **URL** waarvandaan die lêer afgelaai is.

## **Lêerrugsteune**

### Recycle Bin

In Vista/Win7/Win8/Win10 kan die **Recycle Bin** in die vouer **`$Recycle.bin`** in die wortel van die skyf gevind word (`C:\$Recycle.bin`).\
Wanneer ’n lêer in hierdie vouer uitgevee word, word 2 spesifieke lêers geskep:

- `$I{id}`: Lêerinligting (datum waarop dit uitgevee is}
- `$R{id}`: Inhoud van die lêer

![Lêerrugsteune - Recycle Bin: $R{id}: Inhoud van die lêer](<../../../images/image (1029).png>)

Met hierdie lêers kan jy die tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) gebruik om die oorspronklike ligging van die uitgevee lêers en die datum waarop dit uitgevee is, te verkry (gebruik `rifiuti-vista.exe` vir Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Lêerrugsteun - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy is 'n tegnologie wat by Microsoft Windows ingesluit is en **rugsteunkopieë** of momentopnames van rekenaarlêers of volumes kan skep, selfs wanneer hulle gebruik word.

Hierdie rugsteunlêers is gewoonlik in `\System Volume Information` vanaf die wortel van die lêerstelsel geleë, en die naam bestaan uit **UIDs** wat in die volgende prent getoon word:

![Recycle Bin - Volume Shadow Copies: Hierdie rugsteunlêers is gewoonlik in die System Volume Information vanaf die wortel van die lêerstelsel geleë, en die naam bestaan uit UIDs wat in die...](<../../../images/image (94).png>)

Nadat die forensics image met die **ArsenalImageMounter** gemonteer is, kan die hulpmiddel [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) gebruik word om 'n shadow copy te inspekteer en selfs die **lêers** uit die shadow copy-rugsteunlêers te **onttrek**.

![Recycle Bin - Volume Shadow Copies: Nadat die forensics image met die ArsenalImageMounter gemonteer is, kan die hulpmiddel ShadowCopyView gebruik word om 'n shadow copy te inspekteer en selfs die lêers...](<../../../images/image (576).png>)

Die registerinskrywing `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` bevat die lêers en sleutels **wat nie gerugsteun moet word nie**:

![Recycle Bin - Volume Shadow Copies: Die registerinskrywing HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore bevat die lêers en sleutels wat nie gerugsteun moet word nie](<../../../images/image (254).png>)

Die register `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` bevat ook konfigurasie-inligting oor die `Volume Shadow Copies`.

### Outomaties gestoorde Office-lêers

Jy kan die outomaties gestoorde Office-lêers vind in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

'n Shell item is 'n item wat inligting bevat oor hoe om toegang tot 'n ander lêer te verkry.

### Onlangse dokumente (LNK)

Windows **skep** **outomaties** hierdie **kortpaaie** wanneer die gebruiker 'n lêer **oopmaak, gebruik of skep** in:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wanneer 'n vouer geskep word, word 'n skakel na die vouer, die ouervouer en die grootouervouer ook geskep.

Hierdie outomaties geskepte skakellêers **bevat inligting oor die oorsprong**, soos of dit 'n **lêer** **of** 'n **vouer** is, die **MAC**-**tye** van daardie lêer, **volume-inligting** oor waar die lêer gestoor word en die **vouer van die teikenlêer**. Hierdie inligting kan nuttig wees om daardie lêers te herstel indien hulle verwyder is.

Die **skeppingsdatum van die skakel**-lêer is ook die eerste **tyd** waarop die oorspronklike lêer **die eerste keer** **gebruik** is, en die **wysigingsdatum** van die skakel-lêer is die laaste **tyd** waarop die oorspronklike lêer gebruik is.

Om hierdie lêers te inspekteer, kan jy [**LinkParser**](http://4discovery.com/our-tools/) gebruik.

In hierdie hulpmiddel sal jy **2 stelle** tydstempels vind:

- **Eerste stel:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Tweede stel:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die eerste stel tydstempels verwys na die **tydstempels van die lêer self**. Die tweede stel verwys na die **tydstempels van die gekoppelde lêer**.

Jy kan dieselfde inligting verkry deur die Windows CLI-hulpmiddel te gebruik: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In hierdie geval gaan die inligting binne 'n CSV-lêer gestoor word.

### Jumplists

Dit is die onlangse lêers wat per application aangedui word. Dit is die lys van **onlangse lêers wat deur 'n application gebruik is** waartoe jy in elke application toegang kan verkry. Hulle kan **outomaties of pasgemaak** geskep word.

Die **jumplists** wat outomaties geskep word, word in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gestoor. Die jumplists word volgens die formaat `{id}.autmaticDestinations-ms` benoem, waar die aanvanklike ID die ID van die application is.

Die pasgemaakte jumplists word in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` gestoor en word gewoonlik deur die application geskep omdat iets **belangrik** met die lêer gebeur het (miskien is dit as gunsteling gemerk).

Die **created time** van enige jumplist dui die **eerste keer aan wat die lêer accessed is**, en die **modified time** dui die laaste keer aan.

Jy kan die jumplists met [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) inspekteer.

![Recent Documents (LNK) - Jumplists: Jy kan die jumplists met JumplistExplorer inspekteer](<../../../images/image (168).png>)

(_Let daarop dat die timestamps wat deur JumplistExplorer verskaf word, met die jumplist-lêer self verband hou_)

### Shellbags

[**Volg hierdie skakel om te leer wat shellbags is.**](interesting-windows-registry-keys.md#shellbags)

## Gebruik van Windows USBs

Dit is moontlik om te identifiseer dat 'n USB-toestel gebruik is danksy die skepping van:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Let daarop dat sommige LNK-lêers, in plaas daarvan om na die oorspronklike path te wys, na die WPDNSE-folder wys:

![Shellbags - Gebruik van Windows USBs: Let daarop dat sommige LNK-lêers, in plaas daarvan om na die oorspronklike path te wys, na die WPDNSE-folder wys](<../../../images/image (218).png>)

Die lêers in die WPDNSE-folder is kopieë van die oorspronklikes en sal dus nie 'n restart van die PC oorleef nie. Die GUID word uit 'n shellbag geneem.

### Registry Information

[Lees hierdie bladsy om te leer](interesting-windows-registry-keys.md#usb-information) watter registry keys interessante inligting oor USB-toestelle wat connected is, bevat.

### setupapi

Gaan die lêer `C:\Windows\inf\setupapi.dev.log` na om die timestamps te verkry van wanneer die USB-connection plaasgevind het (soek vir `Section start`).

![Registry Information - setupapi: Gaan die lêer C: Windows inf setupapi.dev.log na om die timestamps te verkry van wanneer die USB-connection plaasgevind het](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kan gebruik word om inligting te verkry oor die USB-toestelle wat aan 'n image connected was.

![setupapi - USB Detective: USBDetective kan gebruik word om inligting te verkry oor die USB-toestelle wat aan 'n image connected was](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die scheduled task bekend as 'Plug and Play Cleanup' is hoofsaaklik ontwerp vir die verwydering van verouderde driver-weergawes. In teenstelling met die gespesifiseerde doel om die nuutste driver package-weergawes te behou, dui online bronne daarop dat dit ook drivers teiken wat vir 30 dae inactive was. Gevolglik kan drivers vir removable devices wat nie in die afgelope 30 dae connected was nie, onderhewig wees aan deletion.<sup>[[1]](#references)</sup>

Die task is by die volgende path geleë: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

'n Screenshot wat die task se inhoud uitbeeld, word verskaf: ![USB Detective - Plug and Play Cleanup: Die task is by die volgende path geleë: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Key Components and Settings of the Task:**

- **pnpclean.dll**: Hierdie DLL is verantwoordelik vir die werklike cleanup-proses.
- **UseUnifiedSchedulingEngine**: Gestel op `TRUE`, wat aandui dat die generiese task scheduling engine gebruik word.
- **MaintenanceSettings**:
- **Period ('P1M')**: Gee die Task Scheduler opdrag om die cleanup-task maandeliks tydens gereelde Automatic maintenance te begin.
- **Deadline ('P2M')**: Gee die Task Scheduler opdrag om, indien die task vir twee opeenvolgende maande misluk, die task tydens emergency Automatic maintenance uit te voer.

Hierdie configuration verseker gereelde maintenance en cleanup van drivers, met voorsiening om die task weer te probeer indien opeenvolgende mislukkings voorkom.

**Vir meer inligting, kyk na:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## E-posse

E-posse bevat **2 interessante dele: Die headers en die inhoud** van die e-pos. In die **headers** kan jy inligting vind soos:

- **Wie** die e-posse gestuur het (e-pos address, IP, mail servers wat die e-pos redirected het)
- **Wanneer** die e-pos gestuur is

Binne die `References`- en `In-Reply-To`-headers kan jy ook die ID van die boodskappe vind:

![Plug and Play Cleanup - E-posse: Wanneer die e-pos gestuur is](<../../../images/image (593).png>)

### Windows Mail App

Hierdie application stoor e-posse as HTML of text. Jy kan die e-posse binne subfolders in `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` vind. Die e-posse word met die `.dat`-extension gestoor.

Die **metadata** van die e-posse en die **contacts** kan binne die **EDB database** gevind word: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Change the extension** van die lêer van `.vol` na `.edb`, waarna jy die tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) kan gebruik om dit oop te maak. Binne die `Message`-table kan jy die e-posse sien.

### Microsoft Outlook

Wanneer Exchange servers of Outlook clients gebruik word, sal daar sommige MAPI-headers wees:

- `Mapi-Client-Submit-Time`: Tyd van die system toe die e-pos gestuur is
- `Mapi-Conversation-Index`: Aantal child messages van die thread en timestamp van elke boodskap van die thread
- `Mapi-Entry-ID`: Message identifier.
- `Mappi-Message-Flags` en `Pr_last_Verb-Executed`: Inligting oor die MAPI-client (boodskap gelees? nie gelees nie? beantwoord? redirected? out of the office?)

In die Microsoft Outlook-client word alle gestuurde/ontvange boodskappe, contacts-data en calendar-data in 'n PST-lêer gestoor by:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Die registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` dui die lêer aan wat gebruik word.

Jy kan die PST-lêer met die tool [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) oopmaak.

![Windows Mail App - Microsoft Outlook: Jy kan die PST-lêer met die tool Kernel PST Viewer oopmaak](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

'n **OST file** word deur Microsoft Outlook gegenereer wanneer dit met **IMAP** of 'n **Exchange**-server configured is, en stoor soortgelyke inligting as 'n PST-lêer. Hierdie lêer word met die server gesynchroniseer, behou data vir **die laaste 12 maande** tot 'n **maksimumgrootte van 50GB**, en is in dieselfde directory as die PST-lêer geleë. Om 'n OST-lêer te view, kan die [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) gebruik word.

### Retrieving Attachments

Verlore attachments kan moontlik herwin word vanaf:

- Vir **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Vir **IE11 en hoër**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** gebruik **MBOX files** om data te stoor, geleë by `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Image Thumbnails

- **Windows XP en 8-8.1**: Deur toegang tot 'n folder met thumbnails te verkry, word 'n `thumbs.db`-lêer gegenereer wat image previews stoor, selfs nadat dit deleted is.
- **Windows 7/10**: `thumbs.db` word geskep wanneer dit oor 'n network via UNC path accessed word.
- **Windows Vista en nuwer**: Thumbnail previews word gesentraliseer in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` met lêers genaamd **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) en [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) is tools om hierdie lêers te view.

### Windows Registry Information

Die Windows Registry, wat uitgebreide system- en user-activity data stoor, is vervat in lêers by:

- `%windir%\System32\Config` vir verskeie `HKEY_LOCAL_MACHINE`-subkeys.
- `%UserProfile%{User}\NTUSER.DAT` vir `HKEY_CURRENT_USER`.
- Windows Vista en latere weergawes back-up `HKEY_LOCAL_MACHINE`-registry-lêers in `%Windir%\System32\Config\RegBack\`.
- Daarbenewens word program execution-information vanaf Windows Vista en Windows 2008 Server en verder in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` gestoor.

### Tools

Sommige tools is nuttig om die registry-lêers te analiseer:

- **Registry Editor**: Dit is in Windows geïnstalleer. Dit is 'n GUI om deur die Windows Registry van die current session te navigeer.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Dit laat jou toe om die registry-lêer te load en met 'n GUI daardeur te navigeer. Dit bevat ook Bookmarks wat keys met interessante inligting uitlig.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Weereens het dit 'n GUI waarmee jy deur die loaded registry kan navigeer en bevat dit ook plugins wat interessante inligting binne die loaded registry uitlig.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Nog 'n GUI-application wat die belangrike inligting uit die loaded registry kan extract.

### Recovering Deleted Element

Wanneer 'n key deleted word, word dit as sodanig gemerk, maar totdat die space wat dit occupy benodig word, sal dit nie verwyder word nie. Daarom is dit moontlik om hierdie deleted keys met tools soos **Registry Explorer** te recover.

### Last Write Time

Elke Key-Value bevat 'n **timestamp** wat aandui wanneer dit laas modified is.

### SAM

Die file/hive **SAM** bevat die **users, groups en users passwords**-hashes van die system.

In `SAM\Domains\Account\Users` kan jy die username, die RID, laaste login, laaste failed logon, login counter, password policy en wanneer die account geskep is, verkry. Om die **hashes** te verkry, **benodig** jy ook die file/hive **SYSTEM**.

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

In [hierdie post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) kan jy meer leer oor die algemene Windows-processes om suspicious behaviours te detect.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Binne die registry `NTUSER.DAT`, by die path `Software\Microsoft\Current Version\Search\RecentApps`, kan jy subkeys vind met inligting oor die **application executed**, die **laaste keer** wat dit executed is, en die **aantal kere** wat dit launched is.

### BAM (Background Activity Moderator)

Jy kan die `SYSTEM`-file met 'n registry-editor oopmaak. Binne die path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` kan jy inligting vind oor die **applications wat deur elke user executed is** (let op die `{SID}` in die path) en **hoe laat** hulle executed is (die tyd is binne die Data-value van die registry).

### Windows Prefetch

Prefetching is 'n tegniek wat 'n computer toelaat om stilweg **die nodige resources te fetch wat benodig word om content te display** waartoe 'n user **moontlik in die nabye toekoms toegang kan verkry**, sodat resources vinniger accessed kan word.

Windows prefetch bestaan uit die skepping van **caches van die executed programs** om hulle vinniger te kan load. Hierdie caches word as `.pf`-lêers binne die path `C:\Windows\Prefetch` geskep. Daar is 'n limiet van 128 lêers in XP/VISTA/WIN7 en 1024 lêers in Win8/Win10.

Die lêernaam word geskep as `{program_name}-{hash}.pf` (die hash is gebaseer op die path en arguments van die executable). In W10 word hierdie lêers compressed. Let daarop dat die blote teenwoordigheid van die lêer aandui dat **die program op een of ander stadium executed is**.

Die lêer `C:\Windows\Prefetch\Layout.ini` bevat die **name van die folders van die lêers wat prefetched word**. Hierdie lêer bevat **inligting oor die aantal executions**, **datums** van die execution en **lêers** wat deur die program **opened** is.

Om hierdie lêers te inspekteer, kan jy die tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) gebruik:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** het dieselfde doel as prefetch, om **programme vinniger te laai** deur te voorspel wat volgende gelaai gaan word. Dit vervang egter nie die prefetch-diens nie.\
Hierdie diens genereer databasislêers in `C:\Windows\Prefetch\Ag*.db`.

In hierdie databasisse kan jy die **naam** van die **program**, die **aantal** **uitvoerings**, **lêers** wat **oopgemaak** is, die **volume** waartoe **toegang verkry** is, die **volledige** **pad**, **tydperke** en **tydstempels** vind.

Jy kan toegang tot hierdie inligting verkry met die hulpmiddel [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitor** die **hulpbronne** wat **deur ’n proses** **verbruik** word. Dit het in W8 verskyn en stoor die data in ’n ESE-databasis wat in `C:\Windows\System32\sru\SRUDB.dat` geleë is.

Dit verskaf die volgende inligting:

- AppID en Path
- Gebruiker wat die proses uitgevoer het
- Gestuurde grepe
- Ontvange grepe
- Netwerkkoppelvlak
- Verbindingstydsduur
- Prosesduur

Hierdie inligting word elke 60 minute opgedateer.

Jy kan die data uit hierdie lêer verkry met die hulpmiddel [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Die **AppCompatCache**, ook bekend as **ShimCache**, vorm deel van die **Application Compatibility Database** wat deur **Microsoft** ontwikkel is om toepassingsversoenbaarheidskwessies aan te spreek. Hierdie stelselkomponent teken verskeie stukke lêermetadata aan, insluitend:

- Volledige pad van die lêer
- Grootte van die lêer
- Laaste wysigingstyd onder **$Standard_Information** (SI)
- Laaste bywerkingstyd van die ShimCache
- Prosesuitvoeringsvlag

Sulke data word in die register gestoor op spesifieke plekke, gebaseer op die weergawe van die bedryfstelsel:

- Vir XP word die data gestoor onder `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, met kapasiteit vir 96 inskrywings.
- Vir Server 2003, sowel as Windows-weergawes 2008, 2012, 2016, 7, 8 en 10, is die stoorpad `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`, met onderskeidelik plek vir 512 en 1024 inskrywings.

Om die gestoorde inligting te ontleed, word die [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) aanbeveel.

![SRUM - AppCompatCache (ShimCache): Om die gestoorde inligting te ontleed, word die AppCompatCacheParser tool aanbeveel](<../../../images/image (75).png>)

### Amcache

Die **Amcache.hve**-lêer is in wese ’n register-hive wat besonderhede aanteken oor toepassings wat op ’n stelsel uitgevoer is. Dit word gewoonlik gevind by `C:\Windows\AppCompat\Programas\Amcache.hve`.

Hierdie lêer is noemenswaardig omdat dit rekords van onlangs uitgevoerde prosesse stoor, insluitend die paaie na die uitvoerbare lêers en hul SHA1-hashes. Hierdie inligting is van onskatbare waarde om die aktiwiteit van toepassings op ’n stelsel na te spoor.

Om die data uit **Amcache.hve** te onttrek en te ontleed, kan die [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)-tool gebruik word. Die volgende opdrag is ’n voorbeeld van hoe om AmcacheParser te gebruik om die inhoud van die **Amcache.hve**-lêer te ontleed en die resultate in CSV-formaat uit te voer:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Onder die gegenereerde CSV-lêers is die `Amcache_Unassociated file entries` besonder noemenswaardig weens die ryk inligting wat dit oor ongeassosieerde lêerinskrywings verskaf.

Die interessantste CSV-lêer wat gegenereer word, is die `Amcache_Unassociated file entries`.

### RecentFileCache

Hierdie artifact kan slegs in W7 gevind word by `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, en dit bevat inligting oor die onlangse uitvoering van sommige binaries.

Jy kan die tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) gebruik om die lêer te parse.

### Scheduled tasks

Jy kan dit uit `C:\Windows\Tasks` of `C:\Windows\System32\Tasks` onttrek en dit as XML lees.

### Services

Jy kan dit in die registry vind onder `SYSTEM\ControlSet001\Services`. Jy kan sien wat uitgevoer gaan word en wanneer.

### **Windows Store**

Die geïnstalleerde applications kan gevind word in `\ProgramData\Microsoft\Windows\AppRepository\`\
Hierdie repository het ’n **log** met **elke application wat geïnstalleer is** in die system binne die database **`StateRepository-Machine.srd`**.

Binne die Application-tabel van hierdie database is dit moontlik om die kolomme "Application ID", "PackageNumber" en "Display Name" te vind. Hierdie kolomme bevat inligting oor vooraf geïnstalleerde en geïnstalleerde applications, en daar kan vasgestel word of sommige applications uninstalled is, omdat die IDs van geïnstalleerde applications opeenvolgend behoort te wees.

Dit is ook moontlik om **geïnstalleerde applications** binne die registry-path te vind: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
En **uninstalled** **applications** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Inligting wat binne Windows events verskyn, is:

- Wat gebeur het
- Timestamp (UTC + 0)
- Users wat betrokke was
- Hosts wat betrokke was (hostname, IP)
- Assets waartoe toegang verkry is (lêers, folders, printer, services)

Die logs is geleë in `C:\Windows\System32\config` voor Windows Vista en in `C:\Windows\System32\winevt\Logs` ná Windows Vista. Voor Windows Vista was die event logs in binary format, en daarna is hulle in **XML format** en gebruik hulle die **.evtx**-extensie.

Die ligging van die event files kan in die SYSTEM registry gevind word by **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Hulle kan vanaf die Windows Event Viewer (**`eventvwr.msc`**) of met ander tools soos [**Event Log Explorer**](https://eventlogxp.com) **of** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** gevisualiseer word.**

## Understanding Windows Security Event Logging

Access events word aangeteken in die security configuration file wat geleë is by `C:\Windows\System32\winevt\Security.evtx`. Die grootte van hierdie lêer kan aangepas word, en wanneer die kapasiteit bereik word, word ouer events oorgeskryf. Aangetekende events sluit user logins en logoffs, user actions en veranderinge aan security settings in, sowel as access tot lêers, folders en shared assets.

### Key Event IDs for User Authentication:

- **EventID 4624**: Dui aan dat ’n user suksesvol geauthentiseer is.
- **EventID 4625**: Dui op ’n authentication failure.
- **EventIDs 4634/4647**: Verteenwoordig user-logoff-events.
- **EventID 4672**: Dui op ’n login met administrative privileges.

#### Sub-types within EventID 4634/4647:

- **Interactive (2)**: Direkte user-login.
- **Network (3)**: Toegang tot shared folders.
- **Batch (4)**: Uitvoering van batch processes.
- **Service (5)**: Service launches.
- **Proxy (6)**: Proxy authentication.
- **Unlock (7)**: Screen unlocked met ’n password.
- **Network Cleartext (8)**: Clear text password transmission, dikwels vanaf IIS.
- **New Credentials (9)**: Gebruik van verskillende credentials vir access.
- **Remote Interactive (10)**: Remote desktop- of terminal services-login.
- **Cache Interactive (11)**: Login met cached credentials sonder kontak met die domain controller.
- **Cache Remote Interactive (12)**: Remote login met cached credentials.
- **Cached Unlock (13)**: Unlocking met cached credentials.

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: User name bestaan nie - Kan dui op ’n username enumeration attack.
- **0xC000006A**: Korrekte user name maar verkeerde password - Moontlike password guessing- of brute-force attempt.
- **0xC0000234**: User account is locked out - Kan volg op ’n brute-force attack wat verskeie failed logins veroorsaak het.
- **0xC0000072**: Account disabled - Unauthorized attempts om toegang tot disabled accounts te verkry.
- **0xC000006F**: Logon buite toegelate tyd - Dui op attempts om buite die vasgestelde login hours toegang te verkry, wat ’n moontlike teken van unauthorized access is.
- **0xC0000070**: Violation of workstation restrictions - Kan ’n poging wees om vanaf ’n unauthorized location in te log.
- **0xC0000193**: Account expiration - Access attempts met expired user accounts.
- **0xC0000071**: Expired password - Login attempts met outdated passwords.
- **0xC0000133**: Time sync issues - Groot tydsverskille tussen client en server kan aanduidend wees van meer sophisticated attacks soos pass-the-ticket.
- **0xC0000224**: Mandatory password change required - Gereelde verpligte changes kan ’n poging aandui om account security te destabilize.
- **0xC0000225**: Dui op ’n system bug eerder as ’n security issue.
- **0xC000015b**: Denied logon type - Access attempt met ’n unauthorized logon type, soos ’n user wat probeer om ’n service logon uit te voer.

#### EventID 4616:

- **Time Change**: Modification van die system time, wat die timeline van events kan obscure.

#### EventID 6005 and 6006:

- **System Startup and Shutdown**: EventID 6005 dui aan dat die system start, terwyl EventID 6006 aandui dat dit shutdown.

#### EventID 1102:

- **Log Deletion**: Security logs wat cleared word, wat dikwels ’n red flag is vir die covering up van illicit activities.

#### EventIDs for USB Device Tracking:

- **20001 / 20003 / 10000**: USB device se eerste connection.
- **10100**: USB driver update.
- **EventID 112**: Tyd van USB device insertion.

Vir practical examples oor die simulation van hierdie login types en credential dumping opportunities, verwys na [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Event details, insluitend status- en sub-status-codes, verskaf verdere insights oor die oorsake van events, veral in Event ID 4625.

### Recovering Windows Events

Om die kanse te verbeter om deleted Windows Events te recover, word dit aanbeveel om die suspect computer af te skakel deur dit direk uit te plug. **Bulk_extractor**, ’n recovery tool wat die `.evtx`-extension spesifiseer, word aanbeveel om sulke events te probeer recover.

### Identifying Common Attacks via Windows Events

Vir ’n comprehensive guide oor die gebruik van Windows Event IDs om common cyber attacks te identifiseer, besoek [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Identifiseerbaar deur multiple EventID 4625 records, gevolg deur ’n EventID 4624 indien die attack suksesvol is.

#### Time Change

Word deur EventID 4616 aangeteken; changes aan die system time kan forensic analysis bemoeilik.

#### USB Device Tracking

Nuttige System EventIDs vir USB device tracking sluit 20001/20003/10000 vir initial use, 10100 vir driver updates en EventID 112 vanaf DeviceSetupManager vir insertion timestamps in.

#### System Power Events

EventID 6005 dui op system startup, terwyl EventID 6006 shutdown aandui.

#### Log Deletion

Security EventID 1102 dui op die deletion van logs, ’n critical event vir forensic analysis.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
