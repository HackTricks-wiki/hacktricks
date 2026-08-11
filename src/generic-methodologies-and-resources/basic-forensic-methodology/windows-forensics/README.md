# Windows-artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Algemene Windows-artefakte

### Windows 10-kennisgewings

Die per-gebruiker-kennisgewingdatabasis is onder `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (byvoorbeeld, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Vroeë Windows 10-vrystellings het `appdb.dat` gebruik; die Anniversary Update (1607) het `wpndatabase.db` bekendgestel. Die SQLite-databasis bevat ’n `Notification`-tabel met kennisgewingspayloads en tydsvelde, hoewel retensie en beskikbare data volgens vrystelling en opruimingsbeleid verskil.<sup>[[3]](#references)</sup>

### Tydlyn

Windows Timeline is ’n aktiwiteitgeskiedenisfunksie wat rekords vir ondersteunde toepassings, dokumente en ander gebruikeraktiwiteit kan bevat; die dekking daarvan hang van die toepassing en Windows-weergawe af.<sup>[[4]](#references)</sup>

Die databasis is geleë by `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Dit kan met SQLite oopgemaak of met [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) ontleed word, waarvan die uitvoer met [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) nagegaan kan word.<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Lêers wat van buite die plaaslike vertrouensgrens afgelaai word, kan die **`Zone.Identifier` alternate data stream** bevat, wat sone-inligting aanteken en oorsprongmetadata soos ’n URL kan insluit. Die teenwoordigheid en velde daarvan hang van die vervaardiger en stelselbeleid af.<sup>[[6]](#references)</sup>

## **Lêerrugsteun**

### Asblik

Op Vista en later kan die **Asblik** gevind word in die **`$Recycle.bin`**-lêergids in die wortel van die skyf (byvoorbeeld, `C:\$Recycle.bin`).\
Wanneer ’n lêer in hierdie lêergids uitgevee word, word 2 spesifieke lêers geskep:

- `$I{id}`: Lêerinligting, insluitend die uitveetyd en oorspronklike pad
- `$R{id}`: Inhoud van die lêer

![Lêerrugsteun - Asblik: $R{id}: Inhoud van die lêer](<../../../images/image (1029).png>)

Met hierdie lêers kan jy [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) gebruik om die oorspronklike pad en uitveetyd te onttrek (gebruik die weergawe wat geskik is vir die teiken se Windows-vrystelling).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) kan punt-in-tyd-skadu-kopieë van volumes skep terwyl lêers in gebruik is; ’n skadu-kopie is nie ’n plaasvervanger vir ’n forensiese image nie.<sup>[[8]](#references)</sup>

Die kopie se metadata word normaalweg met `\System Volume Information` by die volume se wortel geassosieer, met identifiseerders wat volgens die stelsel verskil:

![Recycle Bin - Volume Shadow Copies: These backups are usually located in the System Volume Information from the root of the file system and the name is composed of UIDs shown in the...](<../../../images/image (94).png>)

Nadat ’n image met ’n geskikte forensiese mounter gemount is, kan [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) beskikbare VSS-snapshots optel en lêers daaruit blaai of kopieer.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Mounting the forensics image with the ArsenalImageMounter , the tool ShadowCopyView can be used to inspect a shadow copy and even extract the files...](<../../../images/image (576).png>)

Die VSS registry writer-konfigurasie sluit `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` in, wat lêers en sleutels kan spesifiseer wat van die backup uitgesluit word:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: The registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contains the files and keys to not backup](<../../../images/image (254).png>)

Die `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`-sleutel bevat ook VSS-dienskonfigurasie.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover-liggings verskil volgens Office-toepassing, weergawe en konfigurasie. Vir Word dokumenteer Microsoft `%APPDATA%\Microsoft\Word` as die verstekligging; kontroleer die toepassing se instellings vir die aktiewe pad.<sup>[[12]](#references)</sup>

## Shell Items

’n Shell item is ’n item wat inligting bevat oor hoe om toegang tot ’n ander lêer te verkry.

### Recent Documents (LNK)

Windows skep gewoonlik shortcuts vir onlangse items wanneer ’n gebruiker ’n item oopmaak of andersins toegang daartoe verkry:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Toegang tot ’n folder kan ook links vir die folder en verwante ouerfolders skep.

Hierdie link-lêers kan die teikentipe, teiken-MAC-tye, volume-inligting en teikenpad bevat. Daardie metadata kan help om ’n verwyderde teiken te identifiseer, maar die artifact is nie op sigself bewys dat die teiken deur ’n spesifieke gebruiker oopgemaak is nie.<sup>[[13]](#references)[[14]](#references)</sup>

Die LNK se eie filesystem-timestamps en sy ingebedde teiken-timestamps is afsonderlik. Moenie link-skepping as die eerste gebruik of link-wysiging as die laaste gebruik interpreteer sonder bevestigende artifacts nie; die formaat stoor teiken-timestamps afsonderlik van die link-lêer se timestamps.<sup>[[13]](#references)[[14]](#references)</sup>

Die bestaande [**LinkParser**](http://4discovery.com/our-tools/) link word as ’n historiese opsie behou, maar die dokumentasie daarvan was nie tydens die hersiening beskikbaar nie. Vir ’n gedokumenteerde command-line parser, gebruik [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Hierdie tools stel gewoonlik twee stelle timestamps bloot:

- **Teiken-timestamps:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-lêer-timestamps:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die eerste stel verwys na die teiken; die tweede stel verwys na die LNK-lêer self. Interpreteer albei volgens die parser se dokumentasie en die filesystem-konteks.<sup>[[14]](#references)[[15]](#references)</sup>

Jy kan dieselfde inligting kry deur die Windows CLI-tool te gebruik: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In hierdie geval gaan die inligting binne 'n CSV-lêer gestoor word.

### Jumplists

Jump Lists is per-toepassing-lyste van onlangse of taakspesifieke items en kan outomaties of pasgemaak wees.<sup>[[13]](#references)</sup>

Automatic Jump Lists word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` en gebruik name soos `{id}.automaticDestinations-ms`, waar die ID die toepassing identifiseer.

Custom Jump Lists word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; die toepassing beheer watter taak- of itementries dit skep.

Die lêerstelsel se skeppings- en wysigingstye beskryf die Jump List-lêer, nie outomaties die eerste en laaste toegang tot elke gelyste teiken nie. Vergelyk ontleedde inskrywings met die lêer se tydstempels en ander artefakte.<sup>[[13]](#references)</sup>

Jy kan die Jump Lists met [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) inspekteer.<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Jy kan die jumplists met JumplistExplorer inspekteer](<../../../images/image (168).png>)

(_Let daarop dat die tydstempels wat deur JumplistExplorer verskaf word, met die jumplist-lêer self verband hou_)

### Shellbags

[**Volg hierdie skakel om uit te vind wat shellbags is.**](interesting-windows-registry-keys.md#shellbags)

## Gebruik van Windows-USB-toestelle

USB-gebruik kan soms bevestig word deur artefakte wat geskep word wanneer lêers vanaf verwyderbare media verkry word, insluitend:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Nutsgoed soos [**USBDetective**](https://usbdetective.com) vergelyk hierdie artefakte met USB-toestelrekords, maar die beskikbaarheid van artefakte hang van die Windows-weergawe en toepassing af.<sup>[[18]](#references)</sup>

In toetse wat vir Windows XP- en Windows 7-MTP-werkvloeie gedokumenteer is, het sommige LNK's na 'n `WPDNSE`-lêergids eerder as die oorspronklike pad gewys.<sup>[[16]](#references)</sup>

![Shellbags - Gebruik van Windows-USB-toestelle: Let daarop dat sommige LNK-lêers, in plaas daarvan om na die oorspronklike pad te wys, na die WPDNSE-lêergids wys](<../../../images/image (218).png>)

Die studie het kopieë onder `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` waargeneem; die tydelike inhoud het in die toetse nie 'n herbegin oorleef nie, en die GUID kon met shellbag-data vergelyk word. Behandel dit as gedrag wat van die bedryfstelsel, toestel en toepassing afhang, eerder as 'n universele reël.<sup>[[16]](#references)</sup>

### Registerinligting

[Lees hierdie bladsy](interesting-windows-registry-keys.md#usb-information) om uit te vind watter registersleutels interessante inligting oor USB-toestelle wat gekoppel is bevat.

### setupapi

Op Vista en later, inspekteer `C:\Windows\inf\setupapi.dev.log` vir toestelinstallasie-aktiwiteit. Afdelingsopskrifte bevat `Section start`-tydstempels; dit dokumenteer opstelverwerking en moet met ander verbindingsbewyse vergelyk word, eerder as om as 'n presiese fisiese invoegtyd behandel te word.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Gaan die lêer C: Windows inf setupapi.dev.log na om die tydstempels te kry van wanneer die USB-verbinding gemaak is (soek vir Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kan gebruik word om inligting te verkry oor die USB-toestelle wat aan 'n image gekoppel was.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective kan gebruik word om inligting te verkry oor die USB-toestelle wat aan 'n image gekoppel was](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geskeduleerde taak bekend as `Plug and Play Cleanup` verwyder verouderde drywerweergawes. 'n Windows 10-taakdefinisie wat deur Adam Harrison gedokumenteer is, teiken ook drywers wat vir 30 dae onaktief was, dus kan bewyse van verwyderbare-toestel-drywers skoongemaak word; bevestig die plaaslike taakdefinisie en Windows-build voordat hierdie gedrag veralgemeen word.<sup>[[1]](#references)</sup>

Die taak is by die volgende pad geleë: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML definition of the Windows Plug and Play Cleanup scheduled task](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Sleutelkomponente en -instellings van die taak:**

- **pnpclean.dll**: Hierdie DLL is verantwoordelik vir die werklike skoonmaakproses.
- **UseUnifiedSchedulingEngine**: Gestel op `TRUE`, wat aandui dat die generiese taakskedulering-enjin gebruik word.
- **MaintenanceSettings**:
- **Period ('P1M')**: Gee die Task Scheduler opdrag om die skoonmaaktaak maandeliks tydens gereelde Automatic maintenance te begin.
- **Deadline ('P2M')**: Gee die Task Scheduler opdrag om, indien die taak vir twee opeenvolgende maande misluk, die taak tydens nood- Automatic maintenance uit te voer.

Hierdie konfigurasie skeduleer gereelde onderhoud en probeer weer ná opeenvolgende mislukkings; die presiese XML en gedrag verskil volgens weergawe.<sup>[[1]](#references)</sup>

**Vir meer inligting, kyk na:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-posse

E-posse bevat **2 interessante dele: Die opskrifte en die inhoud** van die e-pos. In die **opskrifte** kan jy inligting vind soos:

- **Wie** die e-posse gestuur het (e-posadres, IP, posbedieners wat die e-pos herlei het)
- **Wanneer** die e-pos gestuur is

Die `References`- en `In-Reply-To`-opskrifte kan ook boodskap-ID's bevat wat gebruik word om antwoorde met 'n gesprek te assosieer.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-posse: Wanneer is die e-pos gestuur](<../../../images/image (593).png>)

### Windows Mail App

Hierdie toepassing stoor e-posinhoud in aanvullende teks- of HTML-lêers onder paaie soos `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; die presiese genommerde vouer- en lêeruitleg kan volgens artefak verskil.<sup>[[75]](#references)</sup>

Die **metadata** van die e-posse en die **kontakte** kan binne die **ESE-databasis** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` gevind word.<sup>[[75]](#references)</sup>

`store.vol` gebruik die Extensible Storage Engine (ESE)-formaat. Werk op 'n kopie en gebruik 'n ESE-parser soos [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); indien 'n nutsding 'n `.edb`-agtervoegsel vereis, hernoem slegs die kopie, en verifieer die tabelskema voordat jy op 'n `Message`-tabel staatmaak.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Wanneer Outlook MAPI-eienskappe geïnspekteer word, sluit kanonieke eienskappe die volgende in:

- `PidTagClientSubmitTime`: die UTC-tyd waarop die kliënt die boodskap ingedien het.
- `PidTagConversationIndex`: die boodskap se relatiewe posisie in 'n gesprekdraad.
- `PidTagEntryId`: 'n identifiseerder vir die boodskapobjek.
- `PidTagMessageFlags`: statusvlae soos ingedien, gelees, ongelees of met aanhegsels.
- `PidTagLastVerbExecuted`: die laaste bewerking wat vir die boodskap aangeteken is, soos oopmaak, antwoord of aanstuur.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook-datalêerliggings verskil volgens weergawe en rekeningtipe. Microsoft dokumenteer hierdie algemene liggings vir PST/OST-lêers:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Die registerpad `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` kan die Outlook-profiel en geassosieerde datalêerkonfigurasie identifiseer.

PST-lêers kan boodskappe, kontakte, kalenderdata en ander Outlook-items bevat. Jy kan 'n kopie met [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) inspekteer.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Jy kan die PST-lêer met die Kernel PST Viewer-nutsding oopmaak](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

'n **OST-lêer** is 'n plaaslike kas vir Exchange- of Microsoft 365-rekeninge; Cached Exchange Mode is nie op POP- of IMAP-rekeninge van toepassing nie. Die vanlynperiode is konfigureerbaar en is dikwels standaard 12 maande, terwyl PST/OST-groottebeperkings afsonderlike konfigureerbare instellings is. Om 'n OST-lêer te sien, kan die [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) gebruik word.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Herwinning van aanhegsels

Verlore aanhegsels kan moontlik herwin word vanaf:

- Vir verouderde Outlook/IE-konfigurasies: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Vir nuwer Outlook/IE11-konfigurasies: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** stoor profieldata onder `%APPDATA%\Thunderbird\Profiles`; posvouers gebruik gewoonlik lêers sonder 'n uitbreiding in mbox-formaat onder rekening-spesifieke `Mail`- of `ImapMail`-vouers.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Miniatuurvoorskoue is gewoonlik in per-vouer `thumbs.db`-lêers gestoor.
- **Network folders**: 'n `thumbs.db`-lêer kan steeds vir 'n UNC-vouer geskep word wanneer die toepaslike miniatuu gedrag geaktiveer is; moenie aanvaar dat elke Windows-weergawe of beleid een skep nie.
- **Windows Vista en nuwer**: Die stelsel se miniatuurkas is gesentraliseer onder `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` met lêers soos **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) kan verouderde `Thumbs.db` ontleed, terwyl [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) moderne miniatuurkasdatabasisse kan ontleed.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Die Windows Registry, wat stelsel- en gebruikerskonfigurasiedata stoor, is vervat in hive-lêers in:

- `%WINDIR%\System32\Config` vir die masjien-hives wat verskeie `HKEY_LOCAL_MACHINE`-subsleutels ondersteun.
- `%USERPROFILE%\NTUSER.DAT` vir 'n gebruiker se `HKEY_CURRENT_USER`-hive.
- Sommige ouer Windows-installasies bevat kopieë in `%WINDIR%\System32\Config\RegBack\`; Windows 10 weergawe 1803 en later vul hierdie vouer nie outomaties nie, tensy periodieke rugsteun geaktiveer is.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-gebruiker shell- en klasregistrasiedata word ook algemeen in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` op moderne Windows gestoor.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Sommige nutsgoed is nuttig vir die ontleding van register-hives; bevestig elke nutsding se ondersteunde hive-formate en weergawe voordat jy op 'n uitvoer staatmaak:

- **Registry Editor**: Dit is in Windows geïnstalleer. Dit is 'n GUI om deur die Windows-register van die huidige sessie te navigeer.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Dit laat jou toe om die registerlêer te laai en met 'n GUI daardeur te navigeer. Dit bevat ook Bookmarks wat sleutels met interessante inligting uitlig.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Weereens het dit 'n GUI waarmee jy deur die gelaaide register kan navigeer en bevat dit ook plugins wat interessante inligting binne die gelaaide register uitlig.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Nog 'n GUI-toepassing wat in staat is om inligting uit 'n gelaaide register-hive te onttrek.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Herwinning van geskrapte elemente

Geskrapte hive-selle kan oorbly totdat hul spasie hergebruik word, maar herwinning hang van die hive-toestand en parser af; behandel herwonne geskrapte sleutels as bewyse wat validering vereis, eerder as gewaarborgde rekords.

### Laaste skryftyd

Register-sleutels bevat 'n laaste-skryftydstempel; Windows stel dit vir die sleutel of enige van sy waarde-inskrywings bloot, dus het 'n waarde nie noodwendig sy eie onafhanklike wysigingstydstempel nie.<sup>[[69]](#references)</sup>

### SAM

Die **SAM**-hive bevat plaaslike gebruiker- en groeprekeningdata, insluitend wagwoord-hashes wat deur die stelsel se boot-key-materiaal beskerm word.<sup>[[38]](#references)[[39]](#references)</sup>

In `SAM\Domains\Account\Users` kan jy rekeningidentifiseerders en sommige aanmeldings- en beleidsvelde verkry. Vanlyn hash-onttrekking vereis ook die `SYSTEM`-hive om die relevante boot-key-materiaal te herwin.<sup>[[38]](#references)[[39]](#references)</sup>

### Interessante inskrywings in die Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programme wat uitgevoer is

### Basiese Windows-prosesse

'n Bestaande [plasing oor algemene Windows-prosesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) word as bykomende leesstof behou; bevestig enige aansprake oor prosesgedrag met huidige Windows-dokumentasie en plaaslike bewyse.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Op Windows 10-weergawes wat dit blootstel, bevat `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` per-toepassing-subsleutels met velde soos 'n laaste-gebruik-tyd en bekendstellingstelling; die artefak is uit latere vrystellings verwyder, dus moet jy die teiken-build valideer.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Op stelsels wat die Background Activity Moderator blootstel, inspekteer `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` of die nuwer `...\bam\State\UserSettings\{SID}`-pad. Waardes word volgens gebruiker-SID gesleutel en kan nagespoorde uitvoerbare paaie en FILETIME-agtige uitvoeringsdata bevat; die artefak is weergawe-afhanklik en moet met ander bewyse bevestig word.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch kas hulpbronne en bekendstellingsmetadata sodat programme vinniger kan begin.

Prefetch-lêers word as `.pf`-lêers in `C:\Windows\Prefetch` gestoor; formaat, bewaring en lêertellingbeperkings verskil volgens Windows-weergawe. Microsoft dokumenteer die bewaring van die laaste agt uitvoeringstye en tot 1024 lêers op Windows 8 en later, dus moet ouer opsommings met vaste limiete nie veralgemeen word nie.<sup>[[13]](#references)</sup>

Die lêernaam gebruik gewoonlik `{program_name}-{hash}.pf`, met die hash afgelei van uitvoeringskonteks soos pad en argumente; Windows 10 en later kan die lêer saampers. Die teenwoordigheid daarvan is nuttige uitvoeringsbewys, maar is op sigself nie bewys dat 'n gebruiker dit uitgevoer het nie en moet met ander artefakte vergelyk word.<sup>[[13]](#references)</sup>

Om hierdie lêers te inspekteer, kan jy [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) gebruik, wat gidsontleding, CSV/HTML-uitvoer en dekompressie-ondersteuning vir toepaslike Windows 10-Prefetch-lêers dokumenteer.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** vul **Prefetch** aan deur historiese gebruikspatrone te gebruik om laaiwerk te verbeter. Op stelsels wat dit genereer, word die databasislêers gewoonlik gevind as `C:\Windows\Prefetch\Ag*.db`; die formaat en teenwoordigheid daarvan is weergawe-afhanklik.<sup>[[41]](#references)</sup>

Hierdie databasisse kan toepassingname, gebruikstellings, toegang verkryde lêers of volumes, paaie en tydreekse bevat, maar hulle moet nie as ’n presiese uitvoeringslogboek beskou word nie.<sup>[[41]](#references)</sup>

Die bestaande [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) skakel word behou as ’n moontlike parser; verifieer die huidige beskikbaarheid en ondersteunde uitvoer daarvan teen die nutsprogram se dokumentasie voordat dit gebruik word.

### SRUM

**System Resource Usage Monitor** (SRUM) teken hulpbrongebruik deur toepassings en gebruikers aan. Dit is in Windows 8 bekendgestel en stoor data in die ESE-databasis `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Dit verskaf die volgende inligting:

- AppID en Path
- Gebruiker/SID wat met die rekord geassosieer word
- Gestuurde grepe
- Ontvange grepe
- Netwerkkoppelvlak
- Verbindingsduur
- Prosesduur

Die versamelingsfrekwensie en behoud is implementeringafhanklik; moenie aanvaar dat elke rekord ’n presiese uitvoeringsinterval van 60 minute verteenwoordig nie.<sup>[[13]](#references)</sup>

Jy kan data onttrek en hersien met [**srum_dump**](https://github.com/MarkBaggett/srum-dump), deur die opsies te gebruik wat deur die huidige weergawe van die nutsprogram gedokumenteer word.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

Die **AppCompatCache**, ook bekend as **ShimCache**, is deel van Windows se toepassingsversoenbaarheidsinfrastruktuur en teken lêermetadata aan vir versoenbaarheidsbesluite. Die hive-pad, rekordformaat, behoue kapasiteit en velde verskil volgens Windows-vrystelling; op moderne Windows kan ShimCache alleen nie bewys dat ’n gebruiker ’n lêer uitgevoer het nie. Ontleed die relevante `SYSTEM`-hive met die [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) en bevestig die uitvoer daarvan met uitvoeringsartefakte.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Om die gestoorde inligting te ontleed, word die AppCompatCacheParser tool aanbeveel](<../../../images/image (75).png>)

### Amcache

Die **Amcache.hve**-lêer is ’n register-hive wat toepassings en lêers inventariseer wat deur Windows waargeneem is. Dit word tipies gevind by `C:\Windows\AppCompat\Programs\Amcache.hve`.

Dit kan geassosieerde en nie-geassosieerde lêerinskrywings, paaie en SHA1-waardes bevat, maar die teenwoordigheid daarvan is inventarisbewyse en bewys nie op sigself dat ’n proses uitgevoer is nie.<sup>[[13]](#references)[[44]](#references)</sup>

Gebruik die [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)-tool om **Amcache.hve** te onttrek en te ontleed. Hierdie opdrag ontleed die hive en skryf CSV-uitvoer.<sup>[[44]](#references)</sup>

Byvoorbeeld:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Onder die gegenereerde CSV-lêers kan `Amcache_Unassociated file entries` nuttig wees wanneer lêers ondersoek word wat nie met ’n herkende program geassosieer is nie.<sup>[[44]](#references)</sup>

### RecentFileCache

Op Windows 7-stelsels kan `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` inligting bevat oor binaries wat onlangs waargeneem is; beskikbaarheid en semantiek is weergawe-afhanklik.

Jy kan [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) gebruik om die lêer te parse.<sup>[[45]](#references)</sup>

### Geskeduleerde take

Bewyse van geskeduleerde take kan in `C:\Windows\System32\Tasks` vir moderne take en in `C:\Windows\Tasks` met `.job`-lêers vir legacy-take gevind word; ondersoek die taakdefinisieformaat wat by die bedryfstelsel pas.<sup>[[73]](#references)[[74]](#references)</sup>

### Dienste

Die Service Control Manager-databasis is onder `SYSTEM\CurrentControlSet\Services` (vir ’n offline SYSTEM-hive, ondersoek die ooreenstemmende control-set-sleutel); dit bevat diens- en drywerkonfigurasie soos uitvoerbare paaie en starttipes.<sup>[[72]](#references)</sup>

### **Windows Store**

Geïnstalleerde Windows Store-toepassings kan onder `\ProgramData\Microsoft\Windows\AppRepository\` voorgestel word, insluitend die databasis **`StateRepository-Machine.srd`**. Die skema en paaie verskil volgens Windows-vrystelling.<sup>[[71]](#references)</sup>

Die databasis kan toepassingsidentifiseerders, pakketnommers en vertoonname bevat. Gapings in identifiseerders is nie op sigself bewys dat ’n toepassing gedeïnstalleer is nie; staaf dit met pakket- en registertoestand.

Pakketregistrasies kan ook onder `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` voorkom. Microsoft dokumenteer ’n weergawe-spesifieke `Deprovisioned`-subsleutel vir verwyderde provisioned apps; moenie aanvaar dat ’n `Deleted`-subsleutel op elke build bestaan nie.<sup>[[70]](#references)</sup>

## Windows-gebeurtenisse

Afhangend van die provider, kan Windows-gebeurtenisse die volgende bevat:

- Wat gebeur het
- ’n `TimeCreated`-tydstempel wat met die gebeurtenisskema en die gasheertydkonteks geïnterpreteer moet word
- Betrokke gebruikers
- Betrokke hosts (gasheernaam, IP)
- Toegang verkry tot bates (lêers, vouers, drukkers of dienste).<sup>[[49]](#references)</sup>

Voor Windows Vista het event logs gewoonlik die legacy-binêre formaat onder `C:\Windows\System32\config` gebruik; Vista en later gebruik die Windows Event Log-formaat, normaalweg onder `C:\Windows\System32\winevt\Logs`, met `.evtx`-lêers wat XML-gerenderde gebeurtenisdata bevat.<sup>[[46]](#references)[[47]](#references)</sup>

Die SYSTEM-register stoor kanaalkonfigurasie onder **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, insluitend die gekonfigureerde lêerpad en retensie-instellings.<sup>[[47]](#references)</sup>

Dit kan met Windows Event Viewer (**`eventvwr.msc`**) of tools soos [**Event Log Explorer**](https://eventlogxp.com) en [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) besigtig word.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Verstaan Windows Security Event Logging

Op Vista en later word die Security-kanaal gewoonlik by `C:\Windows\System32\winevt\Logs\Security.evtx` gestoor. Die maksimumgrootte en retensiebeleid daarvan is konfigureerbaar; met circular logging kan ouer rekords oorskryf word wanneer die lêer sy limiet bereik. Die kanaal kan authentication-, logoff-, privilege-, ouditbeleid- en object-access-gebeurtenisse aanteken wanneer die relevante auditing geaktiveer is.<sup>[[46]](#references)[[47]](#references)</sup>

### Sleutelgebeurtenis-ID’s vir gebruikersauthentication:

- **Event ID 4624**: ’n Suksesvolle account logon.<sup>[[50]](#references)</sup>
- **Event ID 4625**: ’n Mislukte account logon.<sup>[[51]](#references)</sup>
- **Event ID 4634**: ’n Logon-sessie is beëindig.<sup>[[52]](#references)</sup>
- **Event ID 4647**: ’n Gebruiker het ’n logoff geïnisieer.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Spesiale privileges is aan ’n nuwe logon toegeken; dit is algemeen vir system- en administrator-accounts, dus is dit nie op sigself bewys van kwaadwillige aktiwiteit nie.<sup>[[54]](#references)</sup>

#### Logon-tipes wat algemeen in 4624, 4625, 4634 en 4647 aangeteken word:

- **Interactive (2)**: ’n Interaktiewe plaaslike logon.
- **Network (3)**: Toegang tot ’n gedeelde resource.
- **Batch (4)**: ’n Batch-process-logon.
- **Service (5)**: ’n Dienslogon.
- **Unlock (7)**: Die ontsluiting van ’n werkstasie.
- **NetworkCleartext (8)**: ’n Netwerklogon wat credentials in cleartext aan die authentication package verskaf.
- **NewCredentials (9)**: ’n Logon wat verskafde alternatiewe credentials vir outbound connections gebruik.
- **RemoteInteractive (10)**: Remote Desktop- of Terminal Services-logon.
- **CachedInteractive (11)**: ’n Interaktiewe logon wat cached domain credentials gebruik.
- **CachedRemoteInteractive (12)**: ’n Cached remote-interactive-logon.
- **CachedUnlock (13)**: ’n Ontsluiting wat cached credentials gebruik.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status- en Sub Status-kodes vir EventID 4625:

- **0xC0000064**: Geen sodanige gebruiker nie.
- **0xC000006A**: Korrekte gebruikersnaam maar verkeerde wagwoord.
- **0xC0000234**: Account is uitgesluit.
- **0xC0000072**: Account is gedeaktiveer.
- **0xC000006F**: Logon buite toegelate ure.
- **0xC0000070**: Oortreding van werkstasiebeperking.
- **0xC0000193**: Account het verval.
- **0xC0000071**: Wagwoord het verval.
- **0xC0000133**: Die tydsverskil tussen die kliënt en bediener is te groot.
- **0xC0000224**: Die account moet sy wagwoord verander.
- **0xC0000225**: `STATUS_NOT_FOUND`; die kode alleen identifiseer nie ’n system bug of ’n aanval nie.
- **0xC000015B**: Die aangevraagde logon-tipe word nie aan die account toegestaan nie.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Die system time is verander. Baie gebeurtenisse weerspieël roetine time-service-korreksie, dus moet die actor en time source gekorreleer word voordat dit as tampering beskou word.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 en 6009:

- **Power and service context**: Event 12 teken OS-start aan, 13 teken OS-shutdown aan, 1074 teken ’n beplande shutdown of restart aan, 6008 dui op ’n onverwagte shutdown, en 6009 teken die Windows-weergawe tydens boot aan. Events 6005 en 6006 dui onderskeidelik aan dat die Event Log-diens begin en gestop het; hulle is nie op sigself bewys van OS-startup en -shutdown nie.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 teken aan dat die Security audit log skoongemaak is; ondersoek die actor en omliggende gebeurtenisse eerder as om intentie slegs op grond van hierdie gebeurtenis aan te neem.<sup>[[62]](#references)</sup>

#### EventIDs vir USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events wat kan help om eerste gebruik of installasie-aktiwiteit vas te stel.
- **10000 / 10100**: `DriverFrameworks-UserMode`-gebeurtenisse wat met device-aktiwiteit gepaard kan gaan.
- **Event ID 112**: `DeviceSetupManager/Admin`-aktiwiteit wat insertion-related timestamps kan verskaf.
- Provider, kanaal en gebeurtenissemantiek verskil volgens Windows-weergawe; ondersoek die provider-naam en gebeurtenispayload voordat betekenis daaraan toegeken word.<sup>[[59]](#references)</sup>

Vir praktiese voorbeelde van logon-tipes en die geassosieerde credential material, sien [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Gebeurtenisbesonderhede, insluitend die logon-tipe, status, substatus, source address en process fields, verskaf konteks vir Event ID 4625; ’n statuskode of herhaalde failure pattern is ’n ondersoekingsleidraad, nie ’n gevolgtrekking nie.<sup>[[51]](#references)[[55]](#references)</sup>

### Herwinning van Windows-gebeurtenisse

Omdat event logs gewoonlik circular is, kan rekords wat deur die logger oorskryf is, onherwinbaar wees. Bewaar ’n forensiese image of werkskopie voordat jy met ’n live system interaksie het; gebruik ’n gevalideerde parser of carver soos **Bulk_extractor** slegs nadat bevestig is dat die tool-weergawe die teiken-`.evtx`-data ondersteun, en moenie ’n lopende system ontkoppel net om gebeurtenisse te probeer herwin nie.<sup>[[46]](#references)</sup>

### Identifisering van algemene aanvalle deur Windows-gebeurtenisse

Vir ’n praktiese event-ID-verwysing, sien die bestaande [Red Team Recipe](https://redteamrecipe.com/event-codes/) link en valideer sy voorbeelde teen die provider-dokumentasie hier bo.

#### Brute Force Attacks

Korrelleer herhaalde Event ID 4625-failures met ’n latere 4624-success, logon-tipe, status, source en account context; die volgorde is ’n indikator vir ondersoek, nie bewys van ’n aanval nie.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 teken system-time changes aan, wat timeline analysis kan bemoeilik; vergelyk dit met time-service- en host evidence.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs is provider-specific; korreleer `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 en `DeviceSetupManager/Admin` 112 met SetupAPI- en registerartefakte.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Gebruik 12/13/1074/6008/6009 vir OS-start-, shutdown-, restart- en unexpected-power-context; 6005/6006 merk die start/stop van die Event Log-diens.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 teken aan dat die Security audit log skoongemaak is en met die verantwoordelike account en process gekorreleer moet word.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Ondersoek van algemene Windows-prosesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [’n Digitale forensiese perspektief op Windows 10-notifikasies](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier en Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Register-rugsteun- en herstelbewerkings onder VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Register-sleutels vir rugsteun en herstel](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word-prestasieprobleem by AutoRecover-ligging](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Identifying Data Exfiltration Artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID en verwante tipes](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Vind en dra Outlook-datafiles oor](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Skakel Cached Exchange Mode aan](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Slegs ’n subset van items word gesinchroniseer](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Konfigureer groottebeperkings vir Outlook-datafiles](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Waar Thunderbird gebruikersdata stoor](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird-accountinstellings en mbox-gidse](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Register-hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry not backed up to RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Wysig die register op afstand](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog-registersleutel](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Foutoplossing vir onverwagte herstarts met system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Foutoplossing vir shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
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
- [70] [Hou verwyderde apps daarvan terugkeer tydens ’n update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK and Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Fail with Error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigating the Windows Mail database](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
