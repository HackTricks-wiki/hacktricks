# Windows Artefakte

## Windows Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Generiese Windows Artefakte

### Windows 10 Kennisgewings

In die pad `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` kan jy die databasis `appdb.dat` (voor Windows herdenking) of `wpndatabase.db` (na Windows Herdenking) vind.

Binne hierdie SQLite-databasis kan jy die `Notification` tabel vind met al die kennisgewings (in XML-formaat) wat dalk interessante data kan bevat.

### Tydlyn

Tydlyn is 'n Windows kenmerk wat **chronologiese geskiedenis** van webblaaie, gewysigde dokumente en uitgevoerde toepassings verskaf.

Die databasis is geleë in die pad `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Hierdie databasis kan geopen word met 'n SQLite-gereedskap of met die gereedskap [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **wat 2 lêers genereer wat met die gereedskap** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **geopen kan word**.

### ADS (Alternatiewe Data Strome)

Lêers wat afgelaai is, kan die **ADS Zone.Identifier** bevat wat aandui **hoe** dit **afgelaai** is vanaf die intranet, internet, ens. Sommige sagteware (soos blaaiers) plaas gewoonlik selfs **meer** **inligting** soos die **URL** waarvandaan die lêer afgelaai is.

## **Lêer Rugsteun**

### Herwinningsblik

In Vista/Win7/Win8/Win10 kan die **Herwinningsblik** gevind word in die gids **`$Recycle.bin`** in die wortel van die skyf (`C:\$Recycle.bin`).\
Wanneer 'n lêer in hierdie gids verwyder word, word 2 spesifieke lêers geskep:

- `$I{id}`: Lêer inligting (datum van wanneer dit verwyder is)
- `$R{id}`: Inhoud van die lêer

![](<../../../images/image (1029).png>)

Met hierdie lêers kan jy die gereedskap [**Rifiuti**](https://github.com/abelcheung/rifiuti2) gebruik om die oorspronklike adres van die verwyderde lêers en die datum waarop dit verwyder is, te kry (gebruik `rifiuti-vista.exe` vir Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy is 'n tegnologie ingesluit in Microsoft Windows wat **rugsteun kopieë** of snappshots van rekenaar lêers of volumes kan skep, selfs wanneer hulle in gebruik is.

Hierdie rugsteun is gewoonlik geleë in die `\System Volume Information` vanaf die wortel van die lêerstelsel en die naam is saamgestel uit **UIDs** wat in die volgende beeld getoon word:

![](<../../../images/image (94).png>)

Deur die forensiese beeld met die **ArsenalImageMounter** te monteer, kan die hulpmiddel [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) gebruik word om 'n skadu kopie te ondersoek en selfs **die lêers** uit die skadu kopie rugsteun te **onttrek**.

![](<../../../images/image (576).png>)

Die registerinskrywing `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` bevat die lêers en sleutels **om nie rugsteun te maak nie**:

![](<../../../images/image (254).png>)

Die register `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` bevat ook konfigurasie-inligting oor die `Volume Shadow Copies`.

### Office AutoSaved Files

Jy kan die kantoor outomaties gestoor lêers vind in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

'n Shell-item is 'n item wat inligting bevat oor hoe om toegang te verkry tot 'n ander lêer.

### Recent Documents (LNK)

Windows **skep** hierdie **skakels** **automaties** wanneer die gebruiker **'n lêer oopmaak, gebruik of skep** in:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wanneer 'n gids geskep word, word 'n skakel na die gids, na die ouergids, en die grootouergids ook geskep.

Hierdie outomaties geskepte skakel lêers **bevat inligting oor die oorsprong** soos of dit 'n **lêer** **of** 'n **gids** is, **MAC** **tye** van daardie lêer, **volume inligting** van waar die lêer gestoor is en **gids van die teikenlêer**. Hierdie inligting kan nuttig wees om daardie lêers te herstel in die geval dat hulle verwyder is.

Ook, die **datum geskep van die skakel** lêer is die eerste **tyd** wat die oorspronklike lêer **eerste** **gebruik** is en die **datum** **gewysig** van die skakel lêer is die **laaste** **tyd** wat die oorspronklike lêer gebruik is.

Om hierdie lêers te ondersoek kan jy [**LinkParser**](http://4discovery.com/our-tools/) gebruik.

In hierdie hulpmiddel sal jy **2 stelle** van tydstempels vind:

- **Eerste Stel:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Tweedestel:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die eerste stel tydstempels verwys na die **tydstempels van die lêer self**. Die tweede stel verwys na die **tydstempels van die gelinkte lêer**.

Jy kan dieselfde inligting verkry deur die Windows CLI hulpmiddel: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) te gebruik.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In hierdie geval gaan die inligting binne 'n CSV-lêer gestoor word.

### Jumplists

Dit is die onlangse lêers wat per toepassing aangedui word. Dit is die lys van **onlangse lêers wat deur 'n toepassing gebruik is** wat jy op elke toepassing kan toegang. Hulle kan **outomaties geskep of persoonlik wees**.

Die **jumplists** wat outomaties geskep word, word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Die jumplists word genoem volgens die formaat `{id}.autmaticDestinations-ms` waar die aanvanklike ID die ID van die toepassing is.

Die persoonlike jumplists word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` en hulle word gewoonlik deur die toepassing geskep omdat iets **belangrik** met die lêer gebeur het (miskien as gunsteling gemerk).

Die **geskepte tyd** van enige jumplist dui die **eerste keer aan dat die lêer toegang verkry is** en die **gewysigde tyd die laaste keer**.

Jy kan die jumplists inspekteer met behulp van [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../images/image (168).png>)

(_Let daarop dat die tydstempels wat deur JumplistExplorer verskaf word, verband hou met die jumplist-lêer self_)

### Shellbags

[**Volg hierdie skakel om te leer wat die shellbags is.**](interesting-windows-registry-keys.md#shellbags)

## Gebruik van Windows USBs

Dit is moontlik om te identifiseer dat 'n USB-toestel gebruik is danksy die skepping van:

- Windows Onlangse Gids
- Microsoft Office Onlangse Gids
- Jumplists

Let daarop dat sommige LNK-lêers in plaas daarvan om na die oorspronklike pad te wys, na die WPDNSE-gids wys:

![](<../../../images/image (218).png>)

Die lêers in die WPDNSE-gids is 'n kopie van die oorspronklike, en sal dus nie oorleef na 'n herstart van die PC nie en die GUID word van 'n shellbag geneem.

### Registrasie-inligting

[Kontroleer hierdie bladsy om te leer](interesting-windows-registry-keys.md#usb-information) watter registrasiesleutels interessante inligting oor USB-verbonden toestelle bevat.

### setupapi

Kontroleer die lêer `C:\Windows\inf\setupapi.dev.log` om die tydstempels te kry oor wanneer die USB-verbinding gemaak is (soek vir `Section start`).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kan gebruik word om inligting oor die USB-toestelle wat aan 'n beeld gekoppel is, te verkry.

![](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geskeduleerde taak bekend as 'Plug and Play Cleanup' is hoofsaaklik ontwerp vir die verwydering van verouderde stuurprogramweergawe. In teenstelling met sy gespesifiseerde doel om die nuutste stuurprogrampakketweergawe te behou, dui aanlynbronne aan dat dit ook stuurprogramme teiken wat vir 30 dae inaktief was. Gevolglik kan stuurprogramme vir verwyderbare toestelle wat nie in die afgelope 30 dae gekoppel is nie, onderhewig wees aan verwydering.

Die taak is geleë op die volgende pad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

'n Skermskoot wat die taak se inhoud toon, word verskaf: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Belangrike Komponente en Instellings van die Taak:**

- **pnpclean.dll**: Hierdie DLL is verantwoordelik vir die werklike skoonmaakproses.
- **UseUnifiedSchedulingEngine**: Gestel op `TRUE`, wat die gebruik van die generiese taakbeplanning enjin aandui.
- **MaintenanceSettings**:
- **Period ('P1M')**: Beveel aan dat die Taakbeplanner die skoonmaaktaak maandeliks tydens gereelde Outomatiese onderhoud begin.
- **Deadline ('P2M')**: Instruksies aan die Taakbeplanner, indien die taak vir twee agtereenvolgende maande misluk, om die taak tydens nood Outomatiese onderhoud uit te voer.

Hierdie konfigurasie verseker gereelde onderhoud en skoonmaak van stuurprogramme, met voorsienings vir herpoging van die taak in die geval van agtereenvolgende mislukkings.

**Vir meer inligting, kyk:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-pos

E-pos bevat **2 interessante dele: Die koptekste en die inhoud** van die e-pos. In die **koptekste** kan jy inligting vind soos:

- **Wie** die e-posse gestuur het (e-posadres, IP, posbedieners wat die e-pos herlei het)
- **Wanneer** die e-pos gestuur is

Ook, binne die `References` en `In-Reply-To` koptekste kan jy die ID van die boodskappe vind:

![](<../../../images/image (593).png>)

### Windows Mail App

Hierdie toepassing stoor e-posse in HTML of teks. Jy kan die e-posse binne subgidsen binne `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` vind. Die e-posse word gestoor met die `.dat` uitbreiding.

Die **metadata** van die e-posse en die **kontakte** kan binne die **EDB-databasis** gevind word: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Verander die uitbreiding** van die lêer van `.vol` na `.edb` en jy kan die hulpmiddel [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gebruik om dit te open. Binne die `Message` tabel kan jy die e-posse sien.

### Microsoft Outlook

Wanneer Exchange-bedieners of Outlook-kliënte gebruik word, sal daar 'n paar MAPI-koptekste wees:

- `Mapi-Client-Submit-Time`: Tyd van die stelsel wanneer die e-pos gestuur is
- `Mapi-Conversation-Index`: Aantal kinders boodskappe van die draad en tydstempel van elke boodskap van die draad
- `Mapi-Entry-ID`: Boodskapidentifiseerder.
- `Mappi-Message-Flags` en `Pr_last_Verb-Executed`: Inligting oor die MAPI-kliënt (boodskap gelees? nie gelees nie? geantwoord? herlei? buite kantoor?)

In die Microsoft Outlook-kliënt, word al die gestuurde/ontvange boodskappe, kontakdata, en kalenderdata in 'n PST-lêer gestoor in:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Die registrasiepunt `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` dui die lêer aan wat gebruik word.

Jy kan die PST-lêer open met die hulpmiddel [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../images/image (498).png>)

### Microsoft Outlook OST Lêers

'n **OST-lêer** word deur Microsoft Outlook gegenereer wanneer dit met **IMAP** of 'n **Exchange** bediener geconfigureer is, wat soortgelyke inligting stoor as 'n PST-lêer. Hierdie lêer word gesinkroniseer met die bediener, wat data vir **die laaste 12 maande** behou tot 'n **maksimumgrootte van 50GB**, en is geleë in dieselfde gids as die PST-lêer. Om 'n OST-lêer te sien, kan die [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) gebruik word.

### Herwinning van Aanhangsels

Verloore aanhangsels mag herstelbaar wees van:

- Vir **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Vir **IE11 en hoër**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Lêers

**Thunderbird** gebruik **MBOX-lêers** om data te stoor, geleë in `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Beeld Miniatuur

- **Windows XP en 8-8.1**: Toegang tot 'n gids met miniatuur genereer 'n `thumbs.db` lêer wat beeldvoorskou stoor, selfs na verwydering.
- **Windows 7/10**: `thumbs.db` word geskep wanneer dit oor 'n netwerk via UNC-pad toegang verkry.
- **Windows Vista en nuwer**: Miniatuurvoorskou is gesentraliseer in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` met lêers wat **thumbcache_xxx.db** genoem word. [**Thumbsviewer**](https://thumbsviewer.github.io) en [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) is hulpmiddels vir die sien van hierdie lêers.

### Windows Registrasie-inligting

Die Windows Registrasie, wat uitgebreide stelsel- en gebruikersaktiwiteitsdata stoor, is vervat in lêers in:

- `%windir%\System32\Config` vir verskeie `HKEY_LOCAL_MACHINE` subsleutels.
- `%UserProfile%{User}\NTUSER.DAT` vir `HKEY_CURRENT_USER`.
- Windows Vista en later weergawes maak 'n rugsteun van `HKEY_LOCAL_MACHINE` registrasielêers in `%Windir%\System32\Config\RegBack\`.
- Daarbenewens word programuitvoeringsinligting gestoor in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` vanaf Windows Vista en Windows 2008 Server.

### Hulpmiddels

Sommige hulpmiddels is nuttig om die registrasielêers te analiseer:

- **Registry Editor**: Dit is geïnstalleer in Windows. Dit is 'n GUI om deur die Windows registrasie van die huidige sessie te navigeer.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Dit laat jou toe om die registrasielêer te laai en deur hulle met 'n GUI te navigeer. Dit bevat ook Boekmerke wat sleutels met interessante inligting uitlig.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Weereens, dit het 'n GUI wat toelaat om deur die gelaaide registrasie te navigeer en bevat ook plugins wat interessante inligting binne die gelaaide registrasie uitlig.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Nog 'n GUI-toepassing wat in staat is om die belangrike inligting uit die gelaaide registrasie te onttrek.

### Herwinning van Verwyderde Element

Wanneer 'n sleutel verwyder word, word dit as sodanig gemerk, maar totdat die ruimte wat dit beset, benodig word, sal dit nie verwyder word nie. Daarom, deur hulpmiddels soos **Registry Explorer** is dit moontlik om hierdie verwyderde sleutels te herstel.

### Laaste Skryftyd

Elke Sleutel-Waarde bevat 'n **tydstempel** wat die laaste keer aandui dat dit gewysig is.

### SAM

Die lêer/hive **SAM** bevat die **gebruikers, groepe en gebruikerswagwoorde** hashes van die stelsel.

In `SAM\Domains\Account\Users` kan jy die gebruikersnaam, die RID, laaste aanmelding, laaste mislukte aanmelding, aanmeldtelling, wagwoordbeleid en wanneer die rekening geskep is, verkry. Om die **hashes** te kry, moet jy ook die lêer/hive **SYSTEM** hê.

### Interessante inskrywings in die Windows Registrasie

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Uitgevoerde Programme

### Basiese Windows Prosesse

In [hierdie pos](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) kan jy leer oor die algemene Windows prosesse om verdagte gedrag te detecteer.

### Windows Onlangse APPs

Binne die registrasielêer `NTUSER.DAT` in die pad `Software\Microsoft\Current Version\Search\RecentApps` kan jy subsleutels met inligting oor die **toepassing uitgevoer**, **laaste keer** dit uitgevoer is, en **aantal kere** dit gelanseer is.

### BAM (Achtergrondaktiwiteit Moderator)

Jy kan die `SYSTEM` lêer met 'n registrasiebewerker open en binne die pad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` kan jy die inligting oor die **toepassings uitgevoer deur elke gebruiker** vind (let op die `{SID}` in die pad) en **op watter tyd** hulle uitgevoer is (die tyd is binne die Data waarde van die registrasie).

### Windows Prefetch

Prefetching is 'n tegniek wat 'n rekenaar toelaat om stilweg **die nodige hulpbronne te verkry wat benodig word om inhoud te vertoon** wat 'n gebruiker **binne die nabye toekoms mag toegang** hê, sodat hulpbronne vinniger toegang verkry kan word.

Windows prefetch bestaan uit die skepping van **kaste van die uitgevoerde programme** om hulle vinniger te kan laai. Hierdie kaste word geskep as `.pf` lêers binne die pad: `C:\Windows\Prefetch`. Daar is 'n limiet van 128 lêers in XP/VISTA/WIN7 en 1024 lêers in Win8/Win10.

Die lêernaam word geskep as `{program_name}-{hash}.pf` (die hash is gebaseer op die pad en argumente van die eksekuteerbare). In W10 is hierdie lêers gecomprimeer. Let daarop dat die blote teenwoordigheid van die lêer aandui dat **die program op 'n stadium uitgevoer is**.

Die lêer `C:\Windows\Prefetch\Layout.ini` bevat die **name van die gidse van die lêers wat geprefetch is**. Hierdie lêer bevat **inligting oor die aantal uitvoerings**, **datums** van die uitvoering en **lêers** **geopen** deur die program.

Om hierdie lêers te inspekteer, kan jy die hulpmiddel [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) gebruik:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** het dieselfde doel as prefetch, **laai programme vinniger** deur te voorspel wat volgende gelaai gaan word. Dit vervang egter nie die prefetch diens nie.\
Hierdie diens sal databasislêers genereer in `C:\Windows\Prefetch\Ag*.db`.

In hierdie databasisse kan jy die **naam** van die **program**, **aantal** **uitvoerings**, **lêers** **geopen**, **volume** **toegang**, **volledige** **pad**, **tydraamwerke** en **tydstempels** vind.

Jy kan toegang tot hierdie inligting verkry met die hulpmiddel [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitor** die **hulpbronne** **verbruik** **deur 'n proses**. Dit het in W8 verskyn en dit stoor die data in 'n ESE-databasis geleë in `C:\Windows\System32\sru\SRUDB.dat`.

Dit gee die volgende inligting:

- AppID en Pad
- Gebruiker wat die proses uitgevoer het
- Gestuurde Bytes
- Ontvange Bytes
- Netwerkinterface
- Verbinding duur
- Proses duur

Hierdie inligting word elke 60 minute opgedateer.

Jy kan die data uit hierdie lêer verkry met die hulpmiddel [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Die **AppCompatCache**, ook bekend as **ShimCache**, is 'n deel van die **Application Compatibility Database** wat deur **Microsoft** ontwikkel is om toepassingskompatibiliteitsprobleme aan te spreek. Hierdie stelseldel vorm 'n rekord van verskeie stukke lêermetadat, wat insluit:

- Volledige pad van die lêer
- Grootte van die lêer
- Laaste Gewysig tyd onder **$Standard_Information** (SI)
- Laaste Opgedateerde tyd van die ShimCache
- Proses Uitvoeringsvlag

Sulke data word in die register gestoor op spesifieke plekke gebaseer op die weergawe van die bedryfstelsel:

- Vir XP, word die data gestoor onder `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` met 'n kapasiteit vir 96 inskrywings.
- Vir Server 2003, sowel as vir Windows weergawes 2008, 2012, 2016, 7, 8, en 10, is die stoorpad `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, wat 512 en 1024 inskrywings akkommodeer, onderskeidelik.

Om die gestoor inligting te ontleed, word die [**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser) aanbeveel vir gebruik.

![](<../../../images/image (75).png>)

### Amcache

Die **Amcache.hve** lêer is in wese 'n registerhive wat besonderhede log oor toepassings wat op 'n stelsel uitgevoer is. Dit word tipies gevind by `C:\Windows\AppCompat\Programas\Amcache.hve`.

Hierdie lêer is opvallend omdat dit rekords van onlangs uitgevoerde prosesse stoor, insluitend die pades na die uitvoerbare lêers en hul SHA1-hashes. Hierdie inligting is van onskatbare waarde vir die opsporing van die aktiwiteit van toepassings op 'n stelsel.

Om die data uit **Amcache.hve** te onttrek en te analiseer, kan die [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool gebruik word. Die volgende opdrag is 'n voorbeeld van hoe om AmcacheParser te gebruik om die inhoud van die **Amcache.hve** lêer te ontleed en die resultate in CSV-formaat uit te voer:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Onder die gegenereerde CSV-lêers is die `Amcache_Unassociated file entries` veral noemenswaardig weens die ryk inligting wat dit verskaf oor nie-geassosieerde lêer inskrywings.

Die mees interessante CVS-lêer wat gegenereer is, is die `Amcache_Unassociated file entries`.

### RecentFileCache

Hierdie artefak kan slegs in W7 gevind word in `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` en dit bevat inligting oor die onlangse uitvoering van sommige binaries.

Jy kan die hulpmiddel [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) gebruik om die lêer te ontleed.

### Geskeduleerde take

Jy kan dit uit `C:\Windows\Tasks` of `C:\Windows\System32\Tasks` onttrek en dit as XML lees.

### Dienste

Jy kan dit in die register onder `SYSTEM\ControlSet001\Services` vind. Jy kan sien wat gaan uitgevoer word en wanneer.

### **Windows Store**

Die geïnstalleerde toepassings kan gevind word in `\ProgramData\Microsoft\Windows\AppRepository\`\
Hierdie repository het 'n **log** met **elke toepassing geïnstalleer** in die stelsel binne die databasis **`StateRepository-Machine.srd`**.

Binne die Toepassing tabel van hierdie databasis, is dit moontlik om die kolomme: "Application ID", "PackageNumber", en "Display Name" te vind. Hierdie kolomme het inligting oor vooraf geïnstalleerde en geïnstalleerde toepassings en dit kan gevind word as sommige toepassings verwyder is omdat die ID's van geïnstalleerde toepassings opeenvolgend moet wees.

Dit is ook moontlik om **geïnstalleerde toepassing** binne die registerpad te vind: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
En **verwyderde** **toepassings** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Gebeure

Inligting wat binne Windows gebeure verskyn, is:

- Wat gebeur het
- Tydstempel (UTC + 0)
- Betrokke gebruikers
- Betrokke gasheer (hostname, IP)
- Toegang tot bates (lêers, gids, drukker, dienste)

Die logs is geleë in `C:\Windows\System32\config` voor Windows Vista en in `C:\Windows\System32\winevt\Logs` na Windows Vista. Voor Windows Vista was die gebeurtenislogs in binêre formaat en daarna is dit in **XML-formaat** en gebruik die **.evtx** uitbreiding.

Die ligging van die gebeurtenis lêers kan in die SYSTEM register gevind word in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Hulle kan van die Windows Event Viewer (**`eventvwr.msc`**) of met ander hulpmiddels soos [**Event Log Explorer**](https://eventlogxp.com) **of** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Verstaan Windows Sekuriteit Gebeurtenis Logging

Toegang gebeurtenisse word in die sekuriteitskonfigurasielêer aangeteken wat geleë is in `C:\Windows\System32\winevt\Security.evtx`. Die grootte van hierdie lêer is aanpasbaar, en wanneer sy kapasiteit bereik word, word ouer gebeurtenisse oorgeskryf. Aangetekende gebeurtenisse sluit gebruikers aanmeldings en afmeldings, gebruikers aksies, en veranderinge aan sekuriteitsinstellings in, sowel as lêer, gids, en gedeelde bate toegang.

### Sleutel Gebeurtenis ID's vir Gebruiker Verifikasie:

- **EventID 4624**: Dui aan dat 'n gebruiker suksesvol geverifieer is.
- **EventID 4625**: Gee 'n verifikasiefout aan.
- **EventIDs 4634/4647**: Verteenwoordig gebruiker afmeld gebeurtenisse.
- **EventID 4672**: Dui aan dat daar met administratiewe regte aangemeld is.

#### Sub-tipes binne EventID 4634/4647:

- **Interaktief (2)**: Direkte gebruikersaanmelding.
- **Netwerk (3)**: Toegang tot gedeelde gidse.
- **Batch (4)**: Uitvoering van batch prosesse.
- **Dienste (5)**: Diens bekendstellings.
- **Proxy (6)**: Proxy verifikasie.
- **Ontsluit (7)**: Skerm ontsluit met 'n wagwoord.
- **Netwerk Duidelike teks (8)**: Duidelike teks wagwoord oordrag, dikwels van IIS.
- **Nuwe Kredensiale (9)**: Gebruik van verskillende kredensiale vir toegang.
- **Afgeleë Interaktief (10)**: Afgeleë lessenaar of terminal dienste aanmelding.
- **Gekapte Interaktief (11)**: Aanmelding met gekapte kredensiale sonder kontak met die domeinbeheerder.
- **Gekapte Afgeleë Interaktief (12)**: Afgeleë aanmelding met gekapte kredensiale.
- **Gekapte Ontsluiting (13)**: Ontsluiting met gekapte kredensiale.

#### Status en Sub Status Kodes vir EventID 4625:

- **0xC0000064**: Gebruikersnaam bestaan nie - Kan 'n gebruikersnaam enumerasie aanval aandui.
- **0xC000006A**: Regte gebruikersnaam maar verkeerde wagwoord - Mogelijke wagwoord raai of brute-force poging.
- **0xC0000234**: Gebruikersrekening is geblokkeer - Mag volg op 'n brute-force aanval wat tot verskeie mislukte aanmeldings gelei het.
- **0xC0000072**: Rekening gedeaktiveer - Ongeoorloofde pogings om toegang tot gedeaktiveerde rekeninge te verkry.
- **0xC000006F**: Aanmelding buite toegelate tyd - Dui pogings aan om buite die gestelde aanmeldure toegang te verkry, 'n moontlike teken van ongeoorloofde toegang.
- **0xC0000070**: Oortreding van werkstasie beperkings - Kan 'n poging wees om van 'n ongeoorloofde plek aan te meld.
- **0xC0000193**: Rekening vervaldatum - Toegang pogings met vervalde gebruikersrekeninge.
- **0xC0000071**: Vervalde wagwoord - Aanmelding pogings met verouderde wagwoorde.
- **0xC0000133**: Tyd sinkronisasie probleme - Groot tyd verskille tussen kliënt en bediener kan aandui van meer gesofistikeerde aanvalle soos pass-the-ticket.
- **0xC0000224**: Verpligte wagwoord verandering vereis - Frekwente verpligte veranderinge mag 'n poging aandui om rekening sekuriteit te destabiliseer.
- **0xC0000225**: Dui 'n stelselfout aan eerder as 'n sekuriteitskwessie.
- **0xC000015b**: Ontkende aanmeld tipe - Toegang poging met ongeoorloofde aanmeld tipe, soos 'n gebruiker wat probeer om 'n diens aanmelding uit te voer.

#### EventID 4616:

- **Tyd Verandering**: Wysiging van die stelseltijd, kan die tydlyn van gebeurtenisse verdoesel.

#### EventID 6005 en 6006:

- **Stelsel Begin en Afsluiting**: EventID 6005 dui aan dat die stelsel begin, terwyl EventID 6006 dit afsluit.

#### EventID 1102:

- **Log Verwydering**: Sekuriteitslogs wat verwyder word, wat dikwels 'n rooi vlag is vir die bedek van onwettige aktiwiteite.

#### EventIDs vir USB Toestel Opvolging:

- **20001 / 20003 / 10000**: USB toestel eerste verbinding.
- **10100**: USB bestuurder opdatering.
- **EventID 112**: Tyd van USB toestel inset.

Vir praktiese voorbeelde oor die simulasie van hierdie aanmeld tipes en kredensiaal dumping geleenthede, verwys na [Altered Security se gedetailleerde gids](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Gebeure besonderhede, insluitend status en sub-status kodes, bied verdere insigte in gebeurtenis oorsake, veral noemenswaardig in Event ID 4625.

### Herstel van Windows Gebeure

Om die kanse van die herstel van verwyderde Windows Gebeure te verbeter, is dit raadsaam om die verdagte rekenaar af te skakel deur dit direk uit te trek. **Bulk_extractor**, 'n herstel hulpmiddel wat die `.evtx` uitbreiding spesifiseer, word aanbeveel om te probeer om sulke gebeurtenisse te herstel.

### Identifisering van Algemene Aanvalle via Windows Gebeure

Vir 'n omvattende gids oor die gebruik van Windows Gebeurtenis ID's in die identifisering van algemene kuber aanvalle, besoek [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Aanvalle

Identifiseerbaar deur verskeie EventID 4625 rekords, gevolg deur 'n EventID 4624 as die aanval slaag.

#### Tyd Verandering

Aangeteken deur EventID 4616, veranderinge aan stelseltijd kan forensiese analise bemoeilik.

#### USB Toestel Opvolging

Nuttige Stelsel Gebeurtenis ID's vir USB toestel opvolging sluit 20001/20003/10000 in vir aanvanklike gebruik, 10100 vir bestuurder opdaterings, en EventID 112 van DeviceSetupManager vir inset tydstempels.

#### Stelsel Krag Gebeurtenisse

EventID 6005 dui aan stelsel begin, terwyl EventID 6006 afsluiting merk.

#### Log Verwydering

Sekuriteit EventID 1102 dui die verwydering van logs aan, 'n kritieke gebeurtenis vir forensiese analise.

{{#include ../../../banners/hacktricks-training.md}}
