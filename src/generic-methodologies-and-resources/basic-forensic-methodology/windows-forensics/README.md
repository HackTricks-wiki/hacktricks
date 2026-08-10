# Windows-artefakte

## Algemene Windows-artefakte

### Windows 10-kennisgewings

Die per-gebruiker-kennisgewingdatabasis is onder `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (byvoorbeeld, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Vroeë Windows 10-vrystellings het `appdb.dat` gebruik; die Anniversary Update (1607) het `wpndatabase.db` bekendgestel. Die SQLite-databasis bevat ’n `Notification`-tabel met kennisgewingpayloads en tydsvelde, hoewel behoud en beskikbare data volgens vrystelling en opruimingsbeleid verskil.<sup>[[3]](#references)</sup>

### Tydlyn

Windows Timeline is ’n aktiwiteitgeskiedenisfunksie wat rekords vir ondersteunde toepassings, dokumente en ander gebruikersaktiwiteite kan bevat; die dekking daarvan hang van die toepassing en Windows-weergawe af.<sup>[[4]](#references)</sup>

Die databasis is geleë by `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Dit kan met SQLite oopgemaak of met [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) ontleed word, waarna die uitvoer met [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) nagegaan kan word.<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Lêers wat van buite die plaaslike vertrouensgrens afgelaai word, kan die **`Zone.Identifier` alternate data stream** bevat, wat sone-inligting aanteken en oorsprongmetadata, soos ’n URL, kan insluit. Die teenwoordigheid en velde daarvan hang van die bron en stelselbeleid af.<sup>[[6]](#references)</sup>

## **Lêerrugsteunkopieë**

### Recycle Bin

Op Vista en later kan die **Recycle Bin** gevind word in die vouer **`$Recycle.bin`** in die wortel van die skyf (byvoorbeeld, `C:\$Recycle.bin`).\
Wanneer ’n lêer in hierdie vouer uitgevee word, word 2 spesifieke lêers geskep:

- `$I{id}`: Lêerinligting, insluitend die uitvee-tyd en oorspronklike pad
- `$R{id}`: Inhoud van die lêer

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Met hierdie lêers kan jy [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) gebruik om die oorspronklike pad en uitvee-tyd te onttrek (gebruik die weergawe wat toepaslik is vir die teiken se Windows-vrystelling).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Lêerrugsteun - Herwinningsdrom: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) kan tydstip-gebaseerde shadow copies van volumes skep terwyl lêers gebruik word; ’n shadow copy is nie ’n plaasvervanger vir ’n forensiese image nie.<sup>[[8]](#references)</sup>

Die copy-metadata word normaalweg met `\System Volume Information` by die volume se wortel geassosieer, met identifiseerders wat per stelsel verskil:

![Herwinningsdrom - Volume Shadow Copies: Hierdie backups word gewoonlik in die System Volume Information vanaf die wortel van die lêerstelsel gestoor en die naam word saamgestel uit UIDs wat in die...](<../../../images/image (94).png>)

Nadat ’n image met ’n geskikte forensiese mounter gemount is, kan [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) beskikbare VSS-snapshots opsom en lêers daarin bekyk of daaruit kopieer.<sup>[[9]](#references)</sup>

![Herwinningsdrom - Volume Shadow Copies: Nadat die forensiese image met die ArsenalImageMounter gemount is, kan die tool ShadowCopyView gebruik word om ’n shadow copy te inspekteer en selfs die lêers te onttrek...](<../../../images/image (576).png>)

Die VSS registry writer-konfigurasie sluit `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` in, wat lêers en keys kan spesifiseer wat van backup uitgesluit word:<sup>[[10]](#references)[[11]](#references)</sup>

![Herwinningsdrom - Volume Shadow Copies: Die registry-inskrywing HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore bevat die lêers en keys wat nie gebackup moet word nie](<../../../images/image (254).png>)

Die `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`-key bevat ook VSS-dienskonfigurasie.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover-liggings verskil volgens Office-toepassing, weergawe en konfigurasie. Vir Word dokumenteer Microsoft `%APPDATA%\Microsoft\Word` as die verstekligging; kontroleer die toepassingsinstellings vir die aktiewe pad.<sup>[[12]](#references)</sup>

## Shell Items

’n Shell item is ’n item wat inligting bevat oor hoe om toegang tot ’n ander lêer te verkry.

### Recent Documents (LNK)

Windows skep gewoonlik shortcuts vir onlangse items wanneer ’n gebruiker ’n item oopmaak of dit op enige ander manier verkry:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Toegang tot ’n vouer kan ook links vir die vouer en verwante ouervouers skep.

Hierdie link-lêers kan die teikentipe, teiken-MAC-tye, volume-inligting en teikenpad bevat. Daardie metadata kan help om ’n verwyderde teiken te identifiseer, maar die artifact is nie op sigself bewys dat die teiken deur ’n spesifieke gebruiker oopgemaak is nie.<sup>[[13]](#references)[[14]](#references)</sup>

Die LNK se eie lêerstelsel-tydstempels en sy ingebedde teikentydstempels is onderskeidelik. Moenie link-skepping as die eerste gebruik of link-wysiging as die laaste gebruik interpreteer sonder stawende artifacts nie; die formaat stoor teikentydstempels afsonderlik van die link-lêer se tydstempels.<sup>[[13]](#references)[[14]](#references)</sup>

Die bestaande [**LinkParser**](http://4discovery.com/our-tools/) link word as ’n historiese opsie behou, maar die dokumentasie daarvan was nie tydens die hersiening beskikbaar nie. Vir ’n gedokumenteerde command-line parser, gebruik [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Hierdie tools stel gewoonlik twee stelle tydstempels bloot:

- **Teikentydstempels:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-lêertydstempels:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die eerste stel verwys na die teiken; die tweede stel verwys na die LNK-lêer self. Interpreteer albei volgens die parser se dokumentasie en lêerstelselkonteks.<sup>[[14]](#references)[[15]](#references)</sup>

Jy kan dieselfde inligting verkry deur die Windows CLI-tool te laat loop: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In hierdie geval gaan die inligting binne 'n CSV-lêer gestoor word.

### Jumplists

Jump Lists is per-toepassing-lyste van onlangse of taakspesifieke items en kan outomaties of pasgemaak wees.<sup>[[13]](#references)</sup>

Automatic Jump Lists word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` en gebruik name soos `{id}.automaticDestinations-ms`, waar die ID die toepassing identifiseer.

Custom Jump Lists word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; die toepassing bepaal watter taak- of it 항inskrywings dit skep.

Die lêerstelsel se skeppings- en wysigingstye beskryf die Jump List-lêer, nie outomaties die eerste en laaste toegang tot elke gelyste teiken nie. Korrelleer geparseerde inskrywings met die lêer se tydstempels en ander artefakte.<sup>[[13]](#references)</sup>

Jy kan die Jump Lists inspekteer met [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: You can inspect the jumplists using JumplistExplorer](<../../../images/image (168).png>)

(_Let daarop dat die tydstempels wat deur JumplistExplorer verskaf word, met die jumplist-lêer self verband hou_)

### Shellbags

[**Volg hierdie skakel om te leer wat shellbags is.**](interesting-windows-registry-keys.md#shellbags)

## Gebruik van Windows-USB's

USB-gebruik kan soms gestaaf word deur artefakte wat geskep word wanneer lêers vanaf verwyderbare media verkry word, insluitend:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Tools soos [**USBDetective**](https://usbdetective.com) korreleer hierdie artefakte met USB-toestelrekords, maar die beskikbaarheid van artefakte hang van die Windows-weergawe en toepassing af.<sup>[[18]](#references)</sup>

In toetsing wat vir Windows XP- en Windows 7-MTP-werkvloeie gedokumenteer is, het sommige LNK's na 'n `WPDNSE`-lêergids gewys eerder as na die oorspronklike pad.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: Note that some LNK file instead of pointing to the original path, points to the WPDNSE folder](<../../../images/image (218).png>)

Daardie studie het kopieë onder `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` waargeneem; die tydelike inhoud het in sy toetse nie 'n herbegin oorleef nie, en die GUID kon met shellbag-data gekorreleer word. Behandel dit as gedrag wat van die bedryfstelsel, toestel en toepassing afhang, eerder as 'n universele reël.<sup>[[16]](#references)</sup>

### Registerinligting

[Kontroleer hierdie bladsy om te leer](interesting-windows-registry-keys.md#usb-information) watter registersleutels interessante inligting oor USB-gekoppelde toestelle bevat.

### setupapi

Op Vista en later, inspekteer `C:\Windows\inf\setupapi.dev.log` vir toestelinstallasie-aktiwiteit. Afdelingsopskrifte sluit `Section start`-tydstempels in; dit dokumenteer opstellingsverwerking en behoort met ander verbindingsbewyse gekorreleer te word, eerder as om as 'n presiese fisiese invoegtyd beskou te word.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Check the file C: Windows inf setupapi.dev.log to get the timestamps about when the USB connection was produced (search for Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kan gebruik word om inligting te verkry oor die USB-toestelle wat aan 'n image gekoppel was.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective can be used to obtain information about the USB devices that have been connected to an image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geskeduleerde taak bekend as `Plug and Play Cleanup` verwyder verouderde drywerweergawes. 'n Windows 10-taakdefinisie wat deur Adam Harrison gedokumenteer is, teiken ook drywers wat vir 30 dae onaktief was, dus kan bewyse van verwyderbare-toestel-drywers skoongemaak word; bevestig die plaaslike taakdefinisie en Windows-build voordat hierdie gedrag veralgemeen word.<sup>[[1]](#references)</sup>

Die taak is by die volgende pad geleë: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Sleutelkomponente en instellings van die taak:**

- **pnpclean.dll**: Hierdie DLL is verantwoordelik vir die werklike opruimingsproses.
- **UseUnifiedSchedulingEngine**: Gestel op `TRUE`, wat aandui dat die generiese taakskeduleringsenjin gebruik word.
- **MaintenanceSettings**:
- **Period ('P1M')**: Gee die Task Scheduler opdrag om die opruimingstaak maandeliks tydens gewone Automatic maintenance te begin.
- **Deadline ('P2M')**: Gee die Task Scheduler opdrag om die taak tydens nood- Automatic maintenance uit te voer indien die taak vir twee opeenvolgende maande misluk.

Hierdie konfigurasie skeduleer gereelde instandhouding en probeer weer ná opeenvolgende mislukkings; die presiese XML en gedrag hang van die weergawe af.<sup>[[1]](#references)</sup>

**Vir meer inligting, kyk na:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-posse

E-posse bevat **2 interessante dele: Die opskrifte en die inhoud** van die e-pos. In die **opskrifte** kan jy inligting vind soos:

- **Wie** die e-posse gestuur het (e-posadres, IP, posbedieners wat die e-pos herlei het)
- **Wanneer** die e-pos gestuur is

Die `References`- en `In-Reply-To`-opskrifte kan ook boodskap-ID's bevat wat gebruik word om antwoorde met 'n gesprek te assosieer.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: When was the email sent](<../../../images/image (593).png>)

### Windows Mail App

Hierdie toepassing stoor e-posinhoud in aanvullende teks- of HTML-lêers onder paaie soos `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; die presiese genommerde vouer- en lêeruitleg kan volgens die artefak verskil.<sup>[[75]](#references)</sup>

Die **metadata** van die e-posse en die **kontakte** kan binne die **ESE-databasis** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` gevind word.<sup>[[75]](#references)</sup>

`store.vol` gebruik die Extensible Storage Engine (ESE)-formaat. Werk op 'n kopie en gebruik 'n ESE-parser soos [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); indien 'n tool 'n `.edb`-agtervoegsel vereis, hernoem slegs die kopie, en verifieer die tabelskema voordat jy op 'n `Message`-tabel staatmaak.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Wanneer Outlook MAPI-eienskappe geïnspekteer word, sluit kanonieke eienskappe die volgende in:

- `PidTagClientSubmitTime`: die UTC-tyd waarop die kliënt die boodskap ingedien het.
- `PidTagConversationIndex`: die boodskap se relatiewe posisie binne 'n gesprekdraad.
- `PidTagEntryId`: 'n identifiseerder vir die boodskapobjek.
- `PidTagMessageFlags`: statusvlae soos ingedien, gelees, ongelees of met aanhegsels.
- `PidTagLastVerbExecuted`: die laaste bewerking wat vir die boodskap aangeteken is, soos oopmaak, antwoord of aanstuur.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook-datalêerliggings verskil volgens weergawe en rekeningtipe. Microsoft dokumenteer hierdie algemene liggings vir PST/OST-lêers:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Die registerpad `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` kan die Outlook-profiel en geassosieerde datalêerkonfigurasie identifiseer.

PST-lêers kan boodskappe, kontakte, kalenderdata en ander Outlook-items bevat. Jy kan 'n kopie inspekteer met [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: You can open the PST file using the tool Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

'n **OST-lêer** is 'n plaaslike kas vir Exchange- of Microsoft 365-rekeninge; Cached Exchange Mode is nie van toepassing op POP- of IMAP-rekeninge nie. Die vanlynperiode is konfigureerbaar en is dikwels by verstek 12 maande, terwyl PST/OST-groottebeperkings afsonderlike konfigureerbare instellings is. Om 'n OST-lêer te bekyk, kan die [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) gebruik word.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Herwinning van aanhegsels

Verlore aanhegsels kan moontlik herwin word vanaf:

- Vir legacy Outlook/IE-konfigurasies: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Vir nuwer Outlook/IE11-konfigurasies: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** stoor profieldata onder `%APPDATA%\Thunderbird\Profiles`; posvouers gebruik gewoonlik mbox-lêers sonder 'n uitbreiding onder rekening-spesifieke `Mail`- of `ImapMail`-gidse.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Duimnaelvoorskoue is gewoonlik in per-vouer `thumbs.db`-lêers gestoor.
- **Network folders**: 'n `thumbs.db`-lêer kan steeds vir 'n UNC-vouer geskep word wanneer die toepaslike duimnaelgedrag geaktiveer is; moenie aanvaar dat elke Windows-weergawe of -beleid een skep nie.
- **Windows Vista and newer**: Die stelsel se duimnaelkas is gesentraliseer onder `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` met lêers soos **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) kan legacy `Thumbs.db`-lêers parse, terwyl [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) moderne duimnaelkas-databasisse kan parse.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Die Windows Registry, wat stelsel- en gebruiker-konfigurasiedata stoor, is vervat in hive-lêers in:

- `%WINDIR%\System32\Config` vir die masjien-hives wat verskeie `HKEY_LOCAL_MACHINE`-subsleutels ondersteun.
- `%USERPROFILE%\NTUSER.DAT` vir 'n gebruiker se `HKEY_CURRENT_USER`-hive.
- Sommige ouer Windows-installasies bevat kopieë in `%WINDIR%\System32\Config\RegBack\`; Windows 10 weergawe 1803 en later vul hierdie gids nie outomaties nie, tensy periodieke rugsteun geaktiveer is.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-gebruiker shell- en klasregistrasiedata word ook gewoonlik in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` op moderne Windows gestoor.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Sommige tools is nuttig om register-hives te ontleed; bevestig elke tool se ondersteunde hive-formate en weergawe voordat jy op 'n afvoer staatmaak:

- **Registry Editor**: Dit is in Windows geïnstalleer. Dit is 'n GUI om deur die Windows Registry van die huidige sessie te navigeer.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Dit laat jou toe om die registerlêer te laai en met 'n GUI daardeur te navigeer. Dit bevat ook Bookmarks wat sleutels met interessante inligting uitlig.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Weereens het dit 'n GUI waarmee jy deur die gelaaide register kan navigeer en bevat dit ook plugins wat interessante inligting binne die gelaaide register uitlig.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Nog 'n GUI-toepassing wat inligting uit 'n gelaaide register-hive kan onttrek.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Herwinning van geskrapte elemente

Geskrapte hive-selle kan bly bestaan totdat hul spasie hergebruik word, maar herwinning hang van die hive se toestand en parser af; behandel herwonne geskrapte sleutels as bewyse wat validering vereis, eerder as gewaarborgde rekords.

### Laaste skryftyd

Registersleutels bevat 'n laaste-skryftydstempel; Windows stel dit vir die sleutel of enige van sy waarde-inskrywings bloot, dus het 'n waarde nie noodwendig sy eie onafhanklike wysigingstydstempel nie.<sup>[[69]](#references)</sup>

### SAM

Die **SAM**-hive bevat plaaslike gebruiker- en groeprekeningdata, insluitend wagwoord-hashes wat deur die stelsel se boot-key-materiaal beskerm word.<sup>[[38]](#references)[[39]](#references)</sup>

In `SAM\Domains\Account\Users` kan jy rekeningidentifiseerders en sommige aanmeldings- en beleidsvelde verkry. Vanlyn hash-onttrekking vereis ook die `SYSTEM`-hive om die toepaslike boot-key-materiaal te herwin.<sup>[[38]](#references)[[39]](#references)</sup>

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programme wat uitgevoer is

### Basiese Windows-prosesse

'n Bestaande [plasing oor algemene Windows-prosesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) word as aanvullende leesstof behou; staaf enige aansprake oor prosesgedrag met huidige Windows-dokumentasie en plaaslike bewyse.<sup>[[2]](#references)</sup>

### Onlangse Windows-toepassings

Op Windows 10-weergawes wat dit blootstel, bevat `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` per-toepassing-subsleutels met velde soos 'n laaste-gebruik-tyd en bekendstellingstelling; die artefak is uit latere vrystellings verwyder, dus moet die teiken-build gevalideer word.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Op stelsels wat die Background Activity Moderator blootstel, inspekteer `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` of die nuwer `...\bam\State\UserSettings\{SID}`-pad. Waardes word volgens gebruiker-SID gesleutel en kan nagespoorde uitvoerbare paaie en FILETIME-agtige uitvoeringsdata bevat; die artefak is weergawe-afhanklik en behoort met ander bewyse gestaaf te word.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch kas hulpbronne en bekendstellingmetadata sodat programme vinniger kan begin.

Prefetch-lêers word as `.pf`-lêers in `C:\Windows\Prefetch` gestoor; formaat, behoud en lêertellingbeperkings verskil volgens Windows-weergawe. Microsoft dokumenteer die behoud van die laaste agt uitvoeringstye en tot 1024 lêers op Windows 8 en later, dus behoort ouer opsommings met vaste limiete nie veralgemeen te word nie.<sup>[[13]](#references)</sup>

Die lêernaam gebruik gewoonlik `{program_name}-{hash}.pf`, waar die hash afgelei word van uitvoeringskonteks soos pad en argumente; Windows 10 en later kan die lêer saampers. Teenwoordigheid is nuttige uitvoeringsbewys, maar is nie op sigself bewys dat 'n gebruiker dit uitgevoer het nie en behoort met ander artefakte gekorreleer te word.<sup>[[13]](#references)</sup>

Om hierdie lêers te inspekteer, kan jy [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) gebruik, wat gidsparsing, CSV/HTML-afvoer en dekompressie-ondersteuning vir toepaslike Windows 10-Prefetch-lêers dokumenteer.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** vul Prefetch aan deur historiese gebruikspatrone te gebruik om laaiwerk te verbeter. Op stelsels wat dit genereer, word sy databasislêers gewoonlik gevind as `C:\Windows\Prefetch\Ag*.db`; die formaat en teenwoordigheid daarvan hang van die weergawe af.<sup>[[41]](#references)</sup>

Hierdie databasisse kan toepassingname, gebruikstellings, toegangverkrygde lêers of volumes, paaie en tydreekse bevat, maar hulle moet nie as ’n presiese uitvoeringslogboek beskou word nie.<sup>[[41]](#references)</sup>

Die bestaande [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) skakel word behou as ’n moontlike parser; verifieer die huidige beskikbaarheid en ondersteunde uitvoer daarvan teen die hulpmiddel se dokumentasie voordat dit gebruik word.

### SRUM

**System Resource Usage Monitor** (SRUM) teken hulpbrongebruik deur toepassings en gebruikers aan. Dit is in Windows 8 bekendgestel en stoor data in die ESE-databasis `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Dit verskaf die volgende inligting:

- AppID en pad
- Gebruiker/SID wat met die rekord geassosieer word
- Gestuurde grepe
- Ontvangde grepe
- Netwerkkoppelvlak
- Verbindingsduur
- Prosesduur

Die versamelingsfrekwensie en behoud daarvan is afhanklik van die implementering; moenie aanvaar dat elke rekord ’n presiese uitvoeringsinterval van 60 minute verteenwoordig nie.<sup>[[13]](#references)</sup>

Jy kan data onttrek en hersien met [**srum_dump**](https://github.com/MarkBaggett/srum-dump), deur die opsies te gebruik wat deur die huidige weergawe van die hulpmiddel gedokumenteer word.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

Die **AppCompatCache**, ook bekend as **ShimCache**, is deel van Windows se toepassingsversoenbaarheidsinfrastruktuur en teken lêermetadata aan vir versoenbaarheidsbesluite. Die hive-pad, rekordformaat, behoue kapasiteit en velde verskil volgens Windows-vrystelling; op moderne Windows kan **ShimCache** alleen nie bewys dat ’n gebruiker ’n lêer uitgevoer het nie. Ontleed die relevante `SYSTEM`-hive met die [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) en bevestig die uitvoer daarvan met uitvoeringsartefakte.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Om die gestoorde inligting te ontleed, word die AppCompatCacheParser tool aanbeveel](<../../../images/image (75).png>)

### Amcache

Die **Amcache.hve**-lêer is ’n register-hive wat toepassings en lêers inventariseer wat deur Windows waargeneem is. Dit word tipies gevind by `C:\Windows\AppCompat\Programs\Amcache.hve`.

Dit kan geassosieerde en ongeassosieerde lêerinskrywings, paaie en SHA1-waardes bevat, maar die teenwoordigheid daarvan is inventarisbewyse en bewys nie op sigself dat ’n proses uitgevoer is nie.<sup>[[13]](#references)[[44]](#references)</sup>

Om **Amcache.hve** te onttrek en te ontleed, gebruik die [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)-tool. Hierdie opdrag ontleed die hive en skryf CSV-uitvoer.<sup>[[44]](#references)</sup>

Byvoorbeeld:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Onder die gegenereerde CSV-lêers kan `Amcache_Unassociated file entries` nuttig wees wanneer lêers ondersoek word wat nie met ’n herkende program geassosieer word nie.<sup>[[44]](#references)</sup>

### RecentFileCache

Op Windows 7-stelsels kan `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` inligting bevat oor binaries wat onlangs waargeneem is; beskikbaarheid en semantiek hang van die weergawe af.

Jy kan [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) gebruik om die lêer te ontleed.<sup>[[45]](#references)</sup>

### Geskeduleerde take

Bewyse van geskeduleerde take kan in `C:\Windows\System32\Tasks` vir moderne take en in `C:\Windows\Tasks` met `.job`-lêers vir legacy-take gevind word; ondersoek die taakdefinisieformaat wat by die bedryfstelsel pas.<sup>[[73]](#references)[[74]](#references)</sup>

### Dienste

Die Service Control Manager-databasis is onder `SYSTEM\CurrentControlSet\Services` (vir ’n offline SYSTEM-hive, ondersoek die ooreenstemmende control-set-sleutel); dit bevat diens- en drywerkonfigurasie, soos uitvoerbare paaie en start types.<sup>[[72]](#references)</sup>

### **Windows Store**

Geïnstalleerde Windows Store-toepassings kan onder `\ProgramData\Microsoft\Windows\AppRepository\` voorgestel word, insluitend die databasis **`StateRepository-Machine.srd`**. Die skema en paaie verskil volgens Windows-vrystelling.<sup>[[71]](#references)</sup>

Die databasis kan toepassing-identifiseerders, pakketnommers en vertoonname bevat. Gapings in identifiseerders is nie op sigself bewys dat ’n toepassing gedeïnstalleer is nie; bevestig dit met pakket- en registry-toestand.

Pakketregistrasies kan ook onder `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` voorkom. Microsoft dokumenteer ’n weergawe-spesifieke `Deprovisioned`-subsleutel vir verwyderde provisioned apps; moenie aanvaar dat ’n `Deleted`-subsleutel op elke build bestaan nie.<sup>[[70]](#references)</sup>

## Windows-gebeurtenisse

Afhangend van die provider, kan Windows-gebeurtenisse die volgende bevat:

- Wat gebeur het
- ’n `TimeCreated`-tydstempel wat met die gebeurtenisskema en die gasheertydkonteks geïnterpreteer moet word
- Betrokke gebruikers
- Betrokke hosts (gasheernaam, IP)
- Toegang verkry tot bates (lêers, vouers, drukkers of dienste).<sup>[[49]](#references)</sup>

Voor Windows Vista het gebeurtenislogs gewoonlik die legacy-binary-formaat onder `C:\Windows\System32\config` gebruik; Vista en later gebruik die Windows Event Log-formaat, gewoonlik onder `C:\Windows\System32\winevt\Logs`, met `.evtx`-lêers wat XML-gerenderde gebeurtenisdata bevat.<sup>[[46]](#references)[[47]](#references)</sup>

Die SYSTEM-registry stoor kanaalkonfigurasie onder **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, insluitend die gekonfigureerde lêerpad en retensie-instellings.<sup>[[47]](#references)</sup>

Dit kan met Windows Event Viewer (**`eventvwr.msc`**) of tools soos [**Event Log Explorer**](https://eventlogxp.com) en [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) bekyk word.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Verstaan van Windows Security Event Logging

Op Vista en later word die Security-kanaal algemeen by `C:\Windows\System32\winevt\Logs\Security.evtx` gestoor. Die maksimumgrootte en retensiebeleid daarvan is konfigureerbaar; met circular logging kan ouer rekords oorgeskryf word wanneer die lêer sy limiet bereik. Die kanaal kan authentication-, logoff-, privilege-, audit-policy- en object-access-gebeurtenisse aanteken wanneer die toepaslike auditing geaktiveer is.<sup>[[46]](#references)[[47]](#references)</sup>

### Sleutelgebeurtenis-ID’s vir gebruikersauthentication:

- **Event ID 4624**: ’n Suksesvolle account logon.<sup>[[50]](#references)</sup>
- **Event ID 4625**: ’n Mislukte account logon.<sup>[[51]](#references)</sup>
- **Event ID 4634**: ’n Logon-sessie is beëindig.<sup>[[52]](#references)</sup>
- **Event ID 4647**: ’n Gebruiker het ’n logoff geïnisieer.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Spesiale privileges is aan ’n nuwe logon toegeken; dit is algemeen vir system- en administrator-accounts, dus is dit nie op sigself bewys van kwaadwillige aktiwiteit nie.<sup>[[54]](#references)</sup>

#### Logon types wat algemeen in 4624, 4625, 4634 en 4647 aangeteken word:

- **Interactive (2)**: ’n Interaktiewe plaaslike logon.
- **Network (3)**: Toegang tot ’n gedeelde resource.
- **Batch (4)**: ’n Batch-process-logon.
- **Service (5)**: ’n Dienslogon.
- **Unlock (7)**: ’n Werkstasie-ontsluiting.
- **NetworkCleartext (8)**: ’n Network-logon wat credentials in cleartext aan die authentication package verskaf.
- **NewCredentials (9)**: ’n Logon wat verskafde alternatiewe credentials vir outbound connections gebruik.
- **RemoteInteractive (10)**: Remote Desktop- of Terminal Services-logon.
- **CachedInteractive (11)**: ’n Interaktiewe logon wat cached domain credentials gebruik.
- **CachedRemoteInteractive (12)**: ’n Cached remote-interactive-logon.
- **CachedUnlock (13)**: ’n Ontsluiting wat cached credentials gebruik.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status- en Sub Status Codes vir EventID 4625:

- **0xC0000064**: Geen sodanige gebruiker nie.
- **0xC000006A**: Korrekte gebruikersnaam, maar verkeerde wagwoord.
- **0xC0000234**: Account uitgesluit.
- **0xC0000072**: Account gedeaktiveer.
- **0xC000006F**: Logon buite toegelate ure.
- **0xC0000070**: Oortreding van werkstasiebeperking.
- **0xC0000193**: Account het verval.
- **0xC0000071**: Wagwoord het verval.
- **0xC0000133**: Die tydsverskil tussen die client en server is te groot.
- **0xC0000224**: Die account moet sy wagwoord verander.
- **0xC0000225**: `STATUS_NOT_FOUND`; die code alleen identifiseer nie ’n system bug of ’n aanval nie.
- **0xC000015B**: Die aangevraagde logon type word nie aan die account toegestaan nie.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Die system time is verander. Baie gebeurtenisse weerspieël roetine-korreksies deur die time service, dus moet die actor en time source gekorreleer word voordat dit as tampering beskou word.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 en 6009:

- **Power and service context**: Event 12 teken OS-start aan, 13 teken OS-shutdown aan, 1074 teken ’n beplande shutdown of restart aan, 6008 dui op ’n onverwagte shutdown, en 6009 teken die Windows-weergawe tydens boot aan. Events 6005 en 6006 dui onderskeidelik aan dat die Event Log-diens begin en gestop het; hulle is nie op sigself bewys van OS-startup en -shutdown nie.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 teken aan dat die Security audit log skoongemaak is; ondersoek die actor en omliggende gebeurtenisse eerder as om intentie slegs op grond van hierdie gebeurtenis te aanvaar.<sup>[[62]](#references)</sup>

#### EventIDs vir USB Device Tracking:

- **20001 / 20003**: `UserPnp`-device-installation-events wat kan help om first-use- of installation-aktiwiteit vas te stel.
- **10000 / 10100**: `DriverFrameworks-UserMode`-events wat device-aktiwiteit kan vergesel.
- **Event ID 112**: `DeviceSetupManager/Admin`-aktiwiteit wat insertion-verwante tydstempels kan verskaf.
- Provider, channel en event semantics verskil volgens Windows-weergawe; ondersoek die provider name en event payload voordat betekenis daaraan toegeken word.<sup>[[59]](#references)</sup>

Vir praktiese voorbeelde van logon types en hul geassosieerde credential material, sien [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Gebeurtenisbesonderhede, insluitend die logon type, status, substatus, source address en process fields, verskaf konteks vir Event ID 4625; ’n status code of herhaalde failure pattern is ’n ondersoekingsaanwyser, nie ’n gevolgtrekking nie.<sup>[[51]](#references)[[55]](#references)</sup>

### Herstel van Windows-gebeurtenisse

Omdat gebeurtenislogs gewoonlik circular is, kan rekords wat deur die logger oorgeskryf is, onherwinbaar wees. Bewaar ’n forensic image of working copy voordat daar met ’n live system interaksie is; gebruik ’n gevalideerde parser of carver soos **Bulk_extractor** slegs nadat bevestig is dat die tool-weergawe die teiken-`.evtx`-data ondersteun, en moenie ’n lopende system ontkoppel bloot om gebeurtenisse te probeer herwin nie.<sup>[[46]](#references)</sup>

### Identifisering van algemene aanvalle via Windows-gebeurtenisse

Vir ’n praktiese event-ID-verwysing, sien die bestaande [Red Team Recipe](https://redteamrecipe.com/event-codes/)-skakel en valideer die voorbeelde daarvan teen die provider-dokumentasie hierbo.

#### Brute Force Attacks

Korreleer herhaalde Event ID 4625-failures met ’n latere 4624-success, logon type, status, source en account context; die volgorde is ’n aanwyser vir ondersoek, nie bewys van ’n aanval nie.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 teken system-time changes aan, wat timeline analysis kan bemoeilik; vergelyk dit met time-service- en host evidence.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs is provider-specific; korreleer `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 en `DeviceSetupManager/Admin` 112 met SetupAPI- en registry-artifacts.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Gebruik 12/13/1074/6008/6009 vir OS-start-, shutdown-, restart- en unexpected-power-context; 6005/6006 dui Event Log-diensstart/-stop aan.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 teken aan dat die Security audit log skoongemaak is en moet met die verantwoordelike account en process gekorreleer word.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Ondersoek van algemene Windows-prosesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [’n Digitale forensiese beskouing van Windows 10-notifikasies](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman se forensiese tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier en Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Registry-rugsteun- en -herstelbewerkings onder VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry-sleutels vir rugsteun en herstel](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word-werkverrigtingprobleem met AutoRecover-ligging](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Identifisering van data-exfiltrasie-artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI-device-installation-loginskrywings](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID en verwante tipes](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Vind en dra Outlook-data-lêers oor](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Skakel Cached Exchange Mode aan](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Slegs ’n subset items word gesinkroniseer](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Konfigureer groottelimiete vir Outlook-data-lêers](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Waar Thunderbird gebruikersdata stoor](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird-accountinstellings en mbox-gidse](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache-koppelvlak](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry nie na RegBack gerugsteun nie](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Wysig die registry op afstand](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Tegniese oorsig van wagwoorde](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch-bewyse](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log-lêerformaat](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog-registry-sleutel](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated-gebeurteniseienskap](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS-waardes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Foutsporing van onverwagte herstarts met system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Foutsporing van shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics for Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Agtergrondaktiwiteitsmoderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print hou op om PDF-aanhangsels in Outlook Desktop te druk](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry-lêers](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Verhoed dat verwyderde apps tydens ’n update terugkeer](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK- en Registry Viewer-toetsresultate](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Databasis van geïnstalleerde dienste](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Take](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Geskeduleerde take misluk met fout: Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigating the Windows Mail database](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
