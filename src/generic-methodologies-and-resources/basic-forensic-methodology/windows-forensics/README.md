# Windows-artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Algemene Windows-artefakte

### Windows 10-kennisgewings

Die kennisgewingdatabasis per gebruiker is onder `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (byvoorbeeld, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Vroeë Windows 10-weergawes het `appdb.dat` gebruik; die Anniversary Update (1607) het `wpndatabase.db` bekendgestel. Die SQLite-databasis bevat ’n `Notification`-tabel met kennisgewinginhoud en tydsvelde, hoewel die bewaringstydperk en beskikbare data volgens weergawe en opruimingsbeleid verskil.<sup>[[3]](#references)</sup>

### Tydlyn

Windows Timeline is ’n aktiwiteitsgeskiedenisfunksie wat rekords kan bevat van ondersteunde toepassings, dokumente en ander gebruikersaktiwiteit; die omvang daarvan hang af van die toepassing en Windows-weergawe.<sup>[[4]](#references)</sup>

Die databasis is by `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Dit kan met SQLite oopgemaak word of met [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) ontleed word; die uitvoer daarvan kan met [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) nagegaan word.<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall-momentopnames (Copilot+ PCs)

Recall is opsioneel op ondersteunde Windows 11 Copilot+ PCs. Huidige weergawes enkripteer momentopnames en hul indeks met sleutels wat aan Windows Hello en ’n VBS-enklave gekoppel is. Moenie ’n vanlyn kopie van die stoorspasie as ’n SQLite-databasis in gewone teks beskou nie; die voorskouweergawe van 2024 en die vrygestelde ontwerp het verskillende toegangskenmerke.<sup>[[77]](#references)</sup>

Vir ’n **aktiewe, geaktiveerde Recall-sessie** is die weergaweproses `AIXHost.exe` van dieselfde gebruiker ’n ander toegangsvlak. Die TotalRecall Reloaded-bewys-van-konsep spuit ’n DLL in daardie proses in en roep sy Recall COM-koppelvlakke aan. Om die volledige geskiedenis te onttrek, moet die gebruiker steeds met Windows Hello verifieer; dit is nie vanlyn dekripsie of ’n Hello-omseiling nie. Die navorser het die hulpmiddel op Windows 11 ARM64 gedokumenteer, so bevestig versoenbaarheid met die teikenweergawe voordat jy daarop staatmaak.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` gebruik `GetRecentCaptureThumbnail` om ’n groot weergawe van die jongste opname aan te vra sonder Hello. Ná magtiging kan `--wait` skermkiekies, OCR-teks en metadata per opname onttrek, insluitend die toepassing- en vensterkonteks. Die uitvoer word in ’n tydstempel-`extraction_*`-gids geskryf. Dit is bouweergawe-afhanklike bevindings uit die proof of concept, nie ’n waarborg dat Recall geaktiveer is of dat elke skerm vasgelê is nie.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

Lêers wat van buite die plaaslike vertrouensgrens afgelaai word, kan die **`Zone.Identifier` alternate data stream** bevat, wat sone-inligting aanteken en oorsprongmetadata soos ’n URL kan insluit. Die teenwoordigheid en velde daarvan hang af van die program wat dit skep en die stelselbeleid.<sup>[[6]](#references)</sup>

## **Lêerrugsteun**

### Asblik

Op Vista en later kan die **Asblik** gevind word in die vouer **`$Recycle.bin`** in die wortel van die skyf (byvoorbeeld, `C:\$Recycle.bin`).\
Wanneer ’n lêer in hierdie vouer uitgevee word, word 2 spesifieke lêers geskep:

- `$I{id}`: Lêerinligting, insluitend die uitveetyd en oorspronklike pad
- `$R{id}`: Inhoud van die lêer

![Lêerrugsteun - Asblik: $R{id}: Inhoud van die lêer](<../../../images/image (1029).png>)

Met hierdie lêers kan jy [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) gebruik om die oorspronklike pad en uitveetyd te onttrek (gebruik die weergawe wat geskik is vir die teiken se Windows-vrystelling).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Lêerrugsteun - Asblik: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) kan skadukopieë van volumes op ’n spesifieke tydstip skep terwyl lêers in gebruik is; ’n skadukopie is nie ’n plaasvervanger vir ’n forensiese beeld nie.<sup>[[8]](#references)</sup>

Die kopiemetadata word gewoonlik geassosieer met `\System Volume Information` in die volume se wortelgids, met identifiseerders wat van stelsel tot stelsel verskil:

![Asblik - Volume Shadow Copies: Hierdie rugsteun is gewoonlik in System Volume Information in die wortel van die lêerstelsel geleë, en die naam bestaan uit UID's wat in die... gewys word](<../../../images/image (94).png>)

Nadat ’n beeld met ’n geskikte forensiese mountprogram gemonteer is, kan [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) beskikbare VSS-momentopnames lys en lêers daarin deurblaai of kopieer.<sup>[[9]](#references)</sup>

![Asblik - Volume Shadow Copies: Nadat die forensiese beeld met die ArsenalImageMounter gemonteer is, kan die ShadowCopyView-instrument gebruik word om ’n skadukopie te ondersoek en selfs die lêers daaruit te onttrek...](<../../../images/image (576).png>)

Die VSS-registerskrywer se konfigurasie sluit `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` in, waar lêers en sleutels gespesifiseer kan word wat van rugsteun uitgesluit moet word:<sup>[[10]](#references)[[11]](#references)</sup>

![Asblik - Volume Shadow Copies: Die registerinskrywing HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore bevat die lêers en sleutels waarvan daar nie rugsteun gemaak moet word nie](<../../../images/image (254).png>)

Die `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`-sleutel bevat ook VSS-dienskonfigurasie.<sup>[[8]](#references)</sup>

### Office-lêers wat outomaties gestoor is

AutoRecover-liggings verskil na gelang van die Office-toepassing, weergawe en konfigurasie. Vir Word dokumenteer Microsoft `%APPDATA%\Microsoft\Word` as die verstekligging; raadpleeg die toepassing se instellings vir die aktiewe pad.<sup>[[12]](#references)</sup>

## Shell-items

’n Shell-item is ’n item wat inligting bevat oor hoe om toegang tot ’n ander lêer te kry.

### Onlangse dokumente (LNK)

Windows skep gewoonlik kortpaaie na onlangse items wanneer ’n gebruiker ’n item oopmaak of andersins toegang daartoe verkry:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Toegang tot ’n vouer kan ook skakels vir die vouer en verwante ouervouers skep.

Hierdie skakellêers kan die teikentipe, teiken se MAC-tye, volume-inligting en teikenpad bevat. Daardie metadata kan help om ’n verwyderde teiken te identifiseer, maar die artefak is nie op sigself ’n bewys dat die teiken deur ’n spesifieke gebruiker oopgemaak is nie.<sup>[[13]](#references)[[14]](#references)</sup>

Die LNK se eie lêerstelseltydstempels en die ingeslote teikentydstempels verskil van mekaar. Moenie die skep van ’n skakel as die eerste gebruik, of die wysiging van ’n skakel as die laaste gebruik interpreteer sonder stawende artefakte nie; die formaat stoor teikentydstempels afsonderlik van die skakellêer se tydstempels.<sup>[[13]](#references)[[14]](#references)</sup>

Die bestaande [**LinkParser**](http://4discovery.com/our-tools/)-skakel word as ’n historiese opsie behou, maar die dokumentasie daarvan was nie tydens die hersiening beskikbaar nie. Gebruik [**LECmd**](https://github.com/EricZimmerman/LECmd) vir ’n gedokumenteerde opdragreëlontleder.<sup>[[15]](#references)</sup>

Hierdie nutsgoed wys gewoonlik twee stelle tydstempels:

- **Teikentydstempels:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Skakellêertydstempels:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Die eerste stel verwys na die teiken; die tweede stel verwys na die LNK-lêer self. Interpreteer albei met inagneming van die ontleder se dokumentasie en die lêerstelselkonteks.<sup>[[14]](#references)[[15]](#references)</sup>

Jy kan dieselfde inligting kry deur die Windows CLI-nutsding [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) uit te voer.<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

In hierdie geval gaan die inligting in ’n CSV-lêer gestoor word.

### Jumplists

Jump Lists is toepassingspesifieke lyste van onlangse items of items wat met ’n spesifieke taak verband hou, en kan outomaties of pasgemaak wees.<sup>[[13]](#references)</sup>

Automatic Jump Lists word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` en gebruik name soos `{id}.automaticDestinations-ms`, waar die ID die toepassing identifiseer.

Custom Jump Lists word gestoor in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; die toepassing bepaal watter taak- of iteminskrywings dit skep.

Die lêerstelsel se skeppings- en wysigingstye beskryf die Jump List-lêer, nie outomaties die eerste en laaste toegang tot elke gelyste teiken nie. Vergelyk geparseerde inskrywings met die lêer se tydstempels en ander artefakte.<sup>[[13]](#references)</sup>

Jy kan die Jump Lists met [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) ondersoek.<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Jy kan die jumplists met JumplistExplorer ondersoek](<../../../images/image (168).png>)

(_Let daarop dat die tydstempels wat JumplistExplorer verskaf, verband hou met die jumplist-lêer self_)

### Shellbags

[**Volg hierdie skakel om uit te vind wat shellbags is.**](interesting-windows-registry-keys.md#shellbags)

## Gebruik van Windows-USB's

USB-gebruik kan soms bevestig word deur artefakte wat geskep word wanneer lêers vanaf verwyderbare media verkry word, insluitend:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Gereedskap soos [**USBDetective**](https://usbdetective.com) vergelyk hierdie artefakte met USB-toestelrekords, maar die beskikbaarheid van artefakte hang af van die Windows-weergawe en toepassing.<sup>[[18]](#references)</sup>

In toetse wat vir Windows XP- en Windows 7-MTP-werkvloeie gedokumenteer is, het sommige LNK's na ’n `WPDNSE`-lêergids verwys eerder as na die oorspronklike pad.<sup>[[16]](#references)</sup>

![Shellbags - Gebruik van Windows-USB's: Let daarop dat sommige LNK-lêers na die WPDNSE-lêergids verwys in plaas van na die oorspronklike pad](<../../../images/image (218).png>)

Daardie studie het kopieë onder `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` waargeneem; die tydelike inhoud het in die toetse nie ’n herbegin oorleef nie, en die GUID kon met shellbag-data vergelyk word. Beskou dit as gedrag wat van die bedryfstelsel, toestel en toepassing afhang, nie as ’n universele reël nie.<sup>[[16]](#references)</sup>

### Registerinligting

[Kyk op hierdie bladsy](interesting-windows-registry-keys.md#usb-information) om uit te vind watter registersleutels interessante inligting oor USB-gekoppelde toestelle bevat.

### setupapi

Op Vista en nuwer weergawes, ondersoek `C:\Windows\inf\setupapi.dev.log` vir aktiwiteit met betrekking tot toestelinstallasie. Seksie-opskrifte bevat `Section start`-tydstempels; dit dokumenteer opstellingverwerking en moet met ander bewyse van ’n verbinding vergelyk word, eerder as om as die presiese fisiese invoegtyd beskou te word.<sup>[[17]](#references)</sup>

![Registerinligting - setupapi: Gaan die lêer C: Windows inf setupapi.dev.log na vir tydstempels wat wys wanneer die USB-verbinding plaasgevind het (soek na Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kan gebruik word om inligting te verkry oor die USB-toestelle wat aan ’n image gekoppel was.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective kan gebruik word om inligting te verkry oor die USB-toestelle wat aan ’n image gekoppel was](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geskeduleerde taak met die naam `Plug and Play Cleanup` verwyder verouderde drywerweergawes. ’n Windows 10-taakdefinisie wat deur Adam Harrison gedokumenteer is, teiken ook drywers wat 30 dae lank onaktief was, dus kan bewyse van drywers vir verwyderbare toestelle opgeruim word; bevestig die plaaslike taakdefinisie en Windows-bou voordat jy hierdie gedrag veralgemeen.<sup>[[1]](#references)</sup>

Die taak is op die volgende pad geleë: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML-definisie van die Windows Plug and Play Cleanup-geskeduleerde taak](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Sleutelkomponente en instellings van die taak:**

- **pnpclean.dll**: Hierdie DLL is verantwoordelik vir die werklike opruimingsproses.
- **UseUnifiedSchedulingEngine**: Gestel op `TRUE`, wat aandui dat die generiese taakskeduleringsenjin gebruik word.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Gee die Task Scheduler opdrag om die opruimingstaak maandeliks tydens gewone Automatic maintenance te begin.
  - **Deadline ('P2M')**: Gee die Task Scheduler opdrag om die taak tydens nood- Automatic maintenance uit te voer as dit vir twee opeenvolgende maande misluk.

Hierdie konfigurasie skeduleer gereelde instandhouding en probeer weer ná opeenvolgende mislukkings; die presiese XML en gedrag hang van die weergawe af.<sup>[[1]](#references)</sup>

**Vir meer inligting, kyk na:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-posse

E-posse bevat **2 interessante dele: die opskrifte en die inhoud** van die e-pos. In die **opskrifte** kan jy inligting vind soos:

- **Wie** die e-posse gestuur het (e-posadres, IP, e-posbedieners wat die e-pos aangestuur het)
- **Wanneer** die e-pos gestuur is

Die `References`- en `In-Reply-To`-opskrifte kan ook boodskap-ID's bevat wat gebruik word om antwoorde met ’n gesprek te verbind.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-posse: Wanneer die e-pos gestuur is](<../../../images/image (593).png>)

### Windows Mail App

Hierdie toepassing stoor e-posinhoud in bykomende teks- of HTML-lêers onder paaie soos `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; die presiese genommerde lêergids- en lêeruitleg kan per artefak verskil.<sup>[[75]](#references)</sup>

Die **metadata** van die e-posse en die **kontakte** kan in die **ESE-databasis** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` gevind word.<sup>[[75]](#references)</sup>

`store.vol` gebruik die Extensible Storage Engine (ESE)-formaat. Werk met ’n kopie en gebruik ’n ESE-parser soos [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); as ’n nutsprogram ’n `.edb`-agtervoegsel vereis, hernoem slegs die kopie en verifieer die tabelskema voordat jy op ’n `Message`-tabel staatmaak.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Wanneer jy Outlook MAPI-eienskappe ondersoek, sluit kanonieke eienskappe die volgende in:

- `PidTagClientSubmitTime`: die UTC-tyd waarop die kliënt die boodskap ingedien het.
- `PidTagConversationIndex`: die boodskap se relatiewe posisie in ’n gesprekdraad.
- `PidTagEntryId`: ’n identifiseerder vir die boodskapobjek.
- `PidTagMessageFlags`: statusvlae soos ingedien, gelees, ongelees of met aanhegsels.
- `PidTagLastVerbExecuted`: die laaste handeling wat vir die boodskap aangeteken is, soos oopmaak, antwoord of aanstuur.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook-datalêerliggings verskil volgens weergawe en rekeningtipe. Microsoft dokumenteer hierdie algemene liggings vir PST/OST-lêers:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Die registerpad `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` kan die Outlook-profiel en gepaardgaande datalêerkonfigurasie identifiseer.

PST-lêers kan boodskappe, kontakte, kalenderdata en ander Outlook-items bevat. Jy kan ’n kopie met [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) ondersoek.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Jy kan die PST-lêer met die Kernel PST Viewer-nutsprogram oopmaak](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

’n **OST-lêer** is ’n plaaslike kas vir Exchange- of Microsoft 365-rekeninge; Cached Exchange Mode is nie van toepassing op POP- of IMAP-rekeninge nie. Die vanlyn tydperk is verstelbaar en is dikwels by verstek 12 maande, terwyl PST/OST-groottebeperkings afsonderlike verstelbare instellings is. Om ’n OST-lêer te bekyk, kan die [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) gebruik word.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Aanhegsels herwin

Verlore aanhegsels kan moontlik uit die volgende herwin word:

- Vir ouer Outlook/IE-konfigurasies: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Vir nuwer Outlook/IE11-konfigurasies: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** stoor profieldata onder `%APPDATA%\Thunderbird\Profiles`; posvouers gebruik gewoonlik mbox-lêers sonder lêeruitbreidings in rekeningspesifieke `Mail`- of `ImapMail`-lêergidse.<sup>[[29]](#references)[[30]](#references)</sup>

### Beeldkleinkiekies

- **Windows XP**: Voorskoue van kleinkiekies is gewoonlik in `thumbs.db`-lêers per lêergids gestoor.
- **Netwerklêergidse**: ’n `thumbs.db`-lêer kan steeds vir ’n UNC-lêergids geskep word wanneer die toepaslike kleinkiekiegedrag geaktiveer is; moenie aanvaar dat elke Windows-weergawe of beleid een skep nie.
- **Windows Vista en nuwer**: Die stelsel se kleinkiekiekas is gesentraliseer onder `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, met lêers soos **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) kan ouer `Thumbs.db` parseer, terwyl [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) moderne kleinkiekiekasdatabasisse kan parseer.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows-registerinligting

Die Windows-register, wat stelsel- en gebruiker-konfigurasiedata stoor, is vervat in hive-lêers in:

- `%WINDIR%\System32\Config` vir die masjien-hives wat verskeie `HKEY_LOCAL_MACHINE`-subsleutels ondersteun.
- `%USERPROFILE%\NTUSER.DAT` vir ’n gebruiker se `HKEY_CURRENT_USER`-hive.
- Sommige ouer Windows-installasies bevat kopieë in `%WINDIR%\System32\Config\RegBack\`; Windows 10 weergawe 1803 en later vul hierdie lêergids nie outomaties nie, tensy periodieke rugsteun geaktiveer is.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-gebruiker-shell- en klasregistrasiedata word ook gewoonlik op moderne Windows in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` gestoor.<sup>[[34]](#references)[[66]](#references)</sup>

### Gereedskap

Sommige gereedskap is nuttig om register-hives te ontleed; bevestig elke nutsprogram se ondersteunde hive-formate en weergawes voordat jy op ’n uitvoer staatmaak:

- **Registry Editor**: Dit is in Windows geïnstalleer. Dit is ’n GUI waarmee jy deur die huidige sessie se Windows-register kan navigeer.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Dit laat jou toe om die registerlêer te laai en met ’n GUI daardeur te navigeer. Dit bevat ook boekmerke wat sleutels met interessante inligting uitlig.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Dit het ook ’n GUI waarmee jy deur die gelaaide register kan navigeer, en bevat ook plugins wat interessante inligting in die gelaaide register uitlig.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Nog ’n GUI-toepassing wat inligting uit ’n gelaaide register-hive kan onttrek.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Herwinning van geskrapte elemente

Geskrapte hive-selle kan bly bestaan totdat hul spasie hergebruik word, maar herstel hang af van die toestand van die hive en die parser; beskou herwinde geskrapte sleutels as bewyse wat bekragtig moet word, nie as gewaarborgde rekords nie.

### Laaste skryftyd

Registersleutels het ’n laaste-skryftydstempel; Windows stel dit vir die sleutel of enige van sy waarde-inskrywings beskikbaar, dus het ’n waarde nie noodwendig sy eie onafhanklike wysigingstydstempel nie.<sup>[[69]](#references)</sup>

### SAM

Die **SAM**-hive bevat plaaslike gebruikers- en groeprekeningdata, insluitend wagwoord-hashes wat deur die stelsel se boot-key-materiaal beskerm word.<sup>[[38]](#references)[[39]](#references)</sup>

In `SAM\Domains\Account\Users` kan jy rekeningidentifiseerders en sommige aanmeld- en beleidsvelde verkry. Om hashes vanlyn te onttrek, vereis ook die `SYSTEM`-hive om die relevante boot-key-materiaal te herwin.<sup>[[38]](#references)[[39]](#references)</sup>

### Interessante inskrywings in die Windows-register


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programme wat uitgevoer is

### Basiese Windows-prosesse

’n Bestaande [plasing oor algemene Windows-prosesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) word as bykomende leesstof behou; bevestig enige bewerings oor prosesgedrag met huidige Windows-dokumentasie en plaaslike bewyse.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Op Windows 10-weergawes waar dit beskikbaar is, bevat `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` sub-sleutels per toepassing met velde soos ’n laaste-gebruik-tyd en ’n aantal kere wat dit begin is; die artefak is in latere vrystellings verwyder, dus moet jy die teikenbou nagaan.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Op stelsels waar die Background Activity Moderator beskikbaar is, ondersoek die pad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` of die nuwer `...\bam\State\UserSettings\{SID}`-pad. Waardes word volgens gebruiker-SID gerangskik en kan nagespoorde uitvoerbare lêerpaaie en FILETIME-agtige uitvoeringsdata bevat; die artefak is weergawe-afhanklik en moet met ander bewyse bevestig word.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching kas hulpbronne en bekendstellingsmetadata sodat programme vinniger kan begin.

Prefetch-lêers word as `.pf`-lêers in `C:\Windows\Prefetch` gestoor; die formaat, bewaring en lêeraantalbeperkings verskil volgens Windows-weergawe. Microsoft dokumenteer die bewaring van die laaste agt uitvoeringstye en tot 1024 lêers op Windows 8 en later, dus moet ouer opsommings van vaste beperkings nie veralgemeen word nie.<sup>[[13]](#references)</sup>

Die lêernaam gebruik gewoonlik `{program_name}-{hash}.pf`, met die hash afgelei van uitvoeringskonteks soos die pad en argumente; Windows 10 en later kan die lêer saampers. Die teenwoordigheid daarvan is nuttige bewys van uitvoering, maar bewys op sigself nie dat ’n gebruiker dit uitgevoer het nie en moet met ander artefakte vergelyk word.<sup>[[13]](#references)</sup>

Om hierdie lêers te ondersoek, kan jy [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) gebruik, wat dokumentasie bevat oor gidsontleding, CSV/HTML-uitvoer en ondersteuning vir dekompressie van toepaslike Windows 10-Prefetch-lêers.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** vul Prefetch aan deur historiese gebruikspatrone te gebruik om laaiwerk te verbeter. Op stelsels wat hierdie lêers genereer, word die databasislêers gewoonlik gevind as `C:\Windows\Prefetch\Ag*.db`; die formaat en teenwoordigheid daarvan hang van die weergawe af.<sup>[[41]](#references)</sup>

Hierdie databasisse kan toepassingname, gebruikstellings, lêers of volumes waartoe toegang verkry is, paaie en tydreekse bevat, maar moet nie as ’n presiese uitvoeringslogboek beskou word nie.<sup>[[41]](#references)</sup>

Die bestaande [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) skakel word behou as ’n moontlike ontleder; verifieer die huidige beskikbaarheid en ondersteunde uitvoer daarvan aan die hand van die nutsprogram se dokumentasie voordat jy dit gebruik.

### SRUM

**System Resource Usage Monitor** (SRUM) teken hulpbronverbruik deur toepassings en gebruikers aan. Dit is in Windows 8 bekendgestel en stoor data in die ESE-databasis `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Dit verskaf die volgende inligting:

- AppID and Path
- User/SID associated with the record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Die insamelingsfrekwensie en bewaring hang van die implementering af; moenie aanvaar dat elke rekord ’n presiese uitvoeringsinterval van 60 minute verteenwoordig nie.<sup>[[13]](#references)</sup>

Jy kan data onttrek en nagaan met [**srum_dump**](https://github.com/MarkBaggett/srum-dump), deur die opsies te gebruik wat in die huidige weergawe van die nutsprogram gedokumenteer word.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

Die **AppCompatCache**, ook bekend as **ShimCache**, is deel van Windows se infrastruktuur vir toepassingsversoenbaarheid en teken lêermetadata vir versoenbaarheidsbesluite aan. Die hive-pad, rekordformaat, behoue kapasiteit en velde verskil na gelang van die Windows-weergawe; op moderne Windows kan ShimCache alleen nie bewys dat ’n gebruiker ’n lêer uitgevoer het nie. Ontleed die relevante `SYSTEM`-hive met die [**AppCompatCacheParser**-nutsding](https://github.com/EricZimmerman/AppCompatCacheParser) en bevestig die uitvoer met uitvoeringsartefakte.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Die AppCompatCacheParser-nutsding word aanbeveel om die gestoorde inligting te ontleed](<../../../images/image (75).png>)

### Amcache

Die **Amcache.hve**-lêer is ’n register-hive wat toepassings en lêers inventariseer wat deur Windows waargeneem is. Dit word gewoonlik gevind by `C:\Windows\AppCompat\Programs\Amcache.hve`.

Dit kan geassosieerde en ongeassosieerde lêerinskrywings, paaie en SHA1-waardes bevat, maar die teenwoordigheid daarvan is bewys van inventarisering en bewys nie op sigself dat ’n proses uitgevoer is nie.<sup>[[13]](#references)[[44]](#references)</sup>

Gebruik die [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)-nutsding om **Amcache.hve** te onttrek en te ontleed. Hierdie opdrag ontleed die hive en skryf CSV-uitvoer.<sup>[[44]](#references)</sup>

Byvoorbeeld:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Onder die gegenereerde CSV-lêers kan `Amcache_Unassociated file entries` nuttig wees wanneer lêers ondersoek word wat nie met ’n herkende program geassosieer word nie.<sup>[[44]](#references)</sup>

### RecentFileCache

Op Windows 7-stelsels kan `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` inligting bevat oor binaries wat onlangs waargeneem is; beskikbaarheid en semantiek hang van die weergawe af.

Jy kan [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) gebruik om die lêer te ontleed.<sup>[[45]](#references)</sup>

### Geskeduleerde take

Bewyse van geskeduleerde take kan vir moderne take in `C:\Windows\System32\Tasks` en vir verouderde take in `C:\Windows\Tasks` in `.job`-lêers gevind word; ondersoek die taakdefinisieformaat wat by die bedryfstelsel pas.<sup>[[73]](#references)[[74]](#references)</sup>

### Dienste

Die databasis van die Service Control Manager is onder `SYSTEM\CurrentControlSet\Services` (ondersoek die ooreenstemmende control-set-sleutel vir ’n vanlyn SYSTEM-hive); dit bevat diens- en drywerkonfigurasie, soos uitvoerbare lêerpaaie en aanvangstipes.<sup>[[72]](#references)</sup>

### **Windows Store**

Geïnstalleerde Windows Store-toepassings kan onder `\ProgramData\Microsoft\Windows\AppRepository\` voorgestel word, insluitend die databasis **`StateRepository-Machine.srd`**. Die skema en paaie verskil tussen Windows-vrystellings.<sup>[[71]](#references)</sup>

Die databasis kan toepassing-identifiseerders, pakketnommers en vertoonname bevat. Gapings in identifiseerders is nie op sigself bewys dat ’n toepassing verwyder is nie; bevestig dit met pakket- en registertoestand.

Pakketregistrasies kan ook onder `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` voorkom. Microsoft dokumenteer ’n weergawe-spesifieke `Deprovisioned`-subsleutel vir verwyderde voorafbepaalde toepassings; moenie aanvaar dat ’n `Deleted`-subsleutel op elke bouweergawe bestaan nie.<sup>[[70]](#references)</sup>

## Windows-gebeurtenisse

Afhangend van die verskaffer, kan Windows-gebeurtenisse die volgende bevat:

- Wat gebeur het
- ’n `TimeCreated`-tydstempel wat volgens die gebeurtenisskema en die gasheer se tydkonteks geïnterpreteer moet word
- Betrokke gebruikers
- Betrokke gashere (gasheernaam, IP)
- Bates waartoe toegang verkry is (lêers, vouers, drukkers of dienste).<sup>[[49]](#references)</sup>

Voor Windows Vista het gebeurtenislogboeke gewoonlik die verouderde binêre formaat onder `C:\Windows\System32\config` gebruik; Vista en later gebruik die Windows Event Log-formaat, gewoonlik onder `C:\Windows\System32\winevt\Logs`, met `.evtx`-lêers wat XML-weergegewe gebeurtenisdata bevat.<sup>[[46]](#references)[[47]](#references)</sup>

Die SYSTEM-register stoor kanaalkonfigurasie onder **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, insluitend die gekonfigureerde lêerpad en behoudinstellings.<sup>[[47]](#references)</sup>

Dit kan met Windows Event Viewer (**`eventvwr.msc`**) of nutsgoed soos [**Event Log Explorer**](https://eventlogxp.com) en [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) bekyk word.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Begrip van Windows Security Event-logging

Op Vista en later word die Security-kanaal gewoonlik by `C:\Windows\System32\winevt\Logs\Security.evtx` gestoor. Die maksimum grootte en behoudbeleid kan gekonfigureer word; met sirkelvormige logging kan ouer rekords oorskryf word wanneer die lêer sy limiet bereik. Die kanaal kan gebeurtenisse vir stawing, afmelding, voorregte, ouditbeleid en objektoegang aanteken wanneer die toepaslike ouditering geaktiveer is.<sup>[[46]](#references)[[47]](#references)</sup>

### Belangrike gebeurtenis-ID's vir gebruikerstawing:

- **Event ID 4624**: ’n Suksesvolle rekeningaanmelding.<sup>[[50]](#references)</sup>
- **Event ID 4625**: ’n Mislukte rekeningaanmelding.<sup>[[51]](#references)</sup>
- **Event ID 4634**: ’n Aanmeldingsessie is beëindig.<sup>[[52]](#references)</sup>
- **Event ID 4647**: ’n Gebruiker het ’n afmelding begin.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Spesiale voorregte is aan ’n nuwe aanmelding toegeken; dit is algemeen vir stelsel- en administrateurrekeninge en is dus nie op sigself bewys van kwaadwillige aktiwiteit nie.<sup>[[54]](#references)</sup>

#### Aanmeldingstipes wat algemeen in 4624, 4625, 4634 en 4647 aangeteken word:

- **Interactive (2)**: ’n Interaktiewe plaaslike aanmelding.
- **Network (3)**: Toegang tot ’n gedeelde hulpbron.
- **Batch (4)**: ’n Aanmelding vir ’n bondelproses.
- **Service (5)**: ’n Diensaanmelding.
- **Unlock (7)**: Ontsluiting van ’n werkstasie.
- **NetworkCleartext (8)**: ’n Netwerkaanmelding wat geloofsbriewe in gewone teks aan die stawingspakket verskaf.
- **NewCredentials (9)**: ’n Aanmelding wat verskafde alternatiewe geloofsbriewe vir uitgaande verbindings gebruik.
- **RemoteInteractive (10)**: ’n Remote Desktop- of Terminal Services-aanmelding.
- **CachedInteractive (11)**: ’n Interaktiewe aanmelding wat gekaste domeingeloofsbriewe gebruik.
- **CachedRemoteInteractive (12)**: ’n Gaste afstandinteraktiewe aanmelding.
- **CachedUnlock (13)**: Ontsluiting met gekaste geloofsbriewe.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status- en Sub Status-kodes vir EventID 4625:

- **0xC0000064**: Geen gebruiker met dié naam nie.
- **0xC000006A**: Gebruikersnaam is korrek, maar wagwoord is verkeerd.
- **0xC0000234**: Rekening is gesluit.
- **0xC0000072**: Rekening is gedeaktiveer.
- **0xC000006F**: Aanmelding buite toegelate ure.
- **0xC0000070**: Oortreding van werkstasiebeperking.
- **0xC0000193**: Rekening het verval.
- **0xC0000071**: Wagwoord het verval.
- **0xC0000133**: Die tydsverskil tussen die kliënt en bediener is te groot.
- **0xC0000224**: Die rekening moet sy wagwoord verander.
- **0xC0000225**: `STATUS_NOT_FOUND`; die kode alleen identifiseer nie ’n stelselfout of aanval nie.
- **0xC000015B**: Die aangevraagde aanmeldingstipe is nie aan die rekening toegestaan nie.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Tydverandering**: Die stelseltyd is verander. Baie gebeurtenisse weerspieël gewone regstellings deur die tyddiens; vergelyk dus die rolspeler en tydbron voordat jy dit as peutery beskou.<sup>[[56]](#references)</sup>

#### Event ID's 12, 13, 1074, 6005, 6006, 6008 en 6009:

- **Krag- en dienskonteks**: Gebeurtenis 12 teken OS-aanvang aan, 13 teken OS-afsluiting aan, 1074 teken ’n beplande afsluiting of herbegin aan, 6008 dui op ’n onverwagte afsluiting, en 6009 teken die Windows-weergawe tydens selflaai aan. Gebeurtenisse 6005 en 6006 dui onderskeidelik aan dat die Event Log-diens begin en gestop het; hulle is nie op sigself bewys dat die OS begin en afgesluit het nie.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Vee van logboek**: Gebeurtenis 1102 teken aan dat die Security-ouditlogboek skoongemaak is; ondersoek die rolspeler en omliggende gebeurtenisse eerder as om net op grond van hierdie gebeurtenis ’n bedoeling af te lei.<sup>[[62]](#references)</sup>

#### EventID's vir USB-toestelnasporing:

- **20001 / 20003**: `UserPnp`-gebeurtenisse vir toestelinstallasie wat kan help om eerste gebruik of installasie-aktiwiteit vas te stel.
- **10000 / 10100**: `DriverFrameworks-UserMode`-gebeurtenisse wat met toestelaktiwiteit kan saamval.
- **Event ID 112**: `DeviceSetupManager/Admin`-aktiwiteit wat tydstempels met betrekking tot invoeging kan verskaf.
- Verskaffer, kanaal en gebeurtenissemantiek verskil volgens Windows-weergawe; ondersoek die verskaffernaam en gebeurtenisinhoud voordat jy betekenis daaraan toeken.<sup>[[59]](#references)</sup>

Vir praktiese voorbeelde van aanmeldingstipes en die geloofsbriewemateriaal wat daarmee verband hou, sien [Altered Security se gedetailleerde gids](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Gebeurtenisbesonderhede, insluitend die aanmeldingstipe, status, substaat, bronadres en prosesvelde, verskaf konteks vir Event ID 4625; ’n statuskode of herhaalde mislukkingspatroon is ’n leidraad vir ondersoek, nie ’n gevolgtrekking nie.<sup>[[51]](#references)[[55]](#references)</sup>

### Herstel van Windows-gebeurtenisse

Omdat gebeurtenislogboeke gewoonlik sirkelvormig is, kan rekords wat deur die logger oorskryf is, moontlik nie herstel word nie. Bewaar ’n forensiese beeld of werkskopie voordat jy met ’n lewendige stelsel interaksie het; gebruik ’n bekragtigde ontleder of carver soos **Bulk_extractor** eers nadat jy bevestig het dat die weergawe van die nutsding die teiken `.evtx`-data ondersteun, en moenie ’n lopende stelsel ontkoppel net om gebeurtenisse te probeer herstel nie.<sup>[[46]](#references)</sup>

### Identifisering van algemene aanvalle met Windows-gebeurtenisse

Vir ’n praktiese verwysing na gebeurtenis-ID's, sien die bestaande [Red Team Recipe](https://redteamrecipe.com/event-codes/)-skakel en bekragtig die voorbeelde daarvan aan die hand van die verskafferdokumentasie hierbo.

#### Brute-force-aanvalle

Vergelyk herhaalde Event ID 4625-mislukkings met ’n latere suksesvolle 4624, die aanmeldingstipe, status, bron en rekeningkonteks; dié volgorde is ’n aanduiding wat ondersoek moet word, nie bewys van ’n aanval nie.<sup>[[50]](#references)[[51]](#references)</sup>

#### Tydverandering

Event ID 4616 teken veranderinge aan die stelseltyd aan, wat tydlyne-ontleding kan bemoeilik; vergelyk dit met bewyse van die tyddiens en gasheer.<sup>[[56]](#references)</sup>

#### USB-toestelnasporing

USB-gebeurtenis-ID's is verskafferspesifiek; vergelyk `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 en `DeviceSetupManager/Admin` 112 met SetupAPI- en registerartefakte.<sup>[[17]](#references)[[59]](#references)</sup>

#### Stelselkraggebeurtenisse

Gebruik 12/13/1074/6008/6009 vir konteks oor OS-aanvang, afsluiting, herbegin en onverwagte kragverlies; 6005/6006 dui die begin/stop van die Event Log-diens aan.<sup>[[57]](#references)[[58]](#references)</sup>

#### Vee van logboek

Security Event ID 1102 teken aan dat die Security-ouditlogboek skoongemaak is en moet met die verantwoordelike rekening en proses vergelyk word.<sup>[[62]](#references)</sup>



## References

- [1] [Windows Plug and Play-opruiming](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Ondersoek van algemene Windows-prosesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [’n Digitale forensiese blik op Windows 10-kennisgewings](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman se forensiese nutsgoed](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier en alternatiewe datastrome](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Registerrugsteun- en herstelbewerkings onder VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registersleutels vir rugsteun en herstel](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word-werkverrigtingprobleem met AutoRecover-ligging](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Gids vir insidentreaksie](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Binêre Shell Link-lêerformaat](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP-forensiese ondersoek: Identifisering van data-eksfiltrasieartefakte](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI-inskrywings vir toestelinstallasielogboeke](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID en verwante tipes](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Vind en dra Outlook-datalêers oor](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Skakel Cached Exchange Mode aan](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Slegs ’n deelversameling items word gesinkroniseer](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Stel groottelimiete vir Outlook-datalêers op](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiele - Waar Thunderbird gebruikersdata stoor](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird-rekeninginstellings en mbox-gidse](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache-koppelvlak](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Register-hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Stelselregister word nie na RegBack gerugsteun nie](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows-registerherstel](https://www.mitec.cz/wrr.html)
- [38] [Wysig die register op afstand](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Tegniese oorsig van wagwoorde](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch-bewyse](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Gebeurtenisloglêerformaat](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog-registersleutel](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated-gebeurteniseienskap](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Gebeurtenis 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Gebeurtenis 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Gebeurtenis 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Gebeurtenis 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Gebeurtenis 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS-waardes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Gebeurtenis 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Foutsporing van onverwagte herselflaaie met stelselgebeurtenislogboeke](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Foutsporing van afsluiting tydens proses](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forensiese ondersoek van USB-bergingstoestelle vir Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastiese Windows-aanmeldingstipes](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Gebeurtenis 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Agtergrondaktiwiteitsmoderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Register - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print hou op om PDF-aanhegsels in Outlook Desktop te druk](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows-registerlêers](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Verhoed dat verwyderde toepassings tydens ’n opdatering terugkeer](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Toetsresultate vir FTK en Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Databasis van geïnstalleerde dienste](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Take](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Geskeduleerde take faal met die fout dat die Task Scheduler-diens nie beskikbaar is nie](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigeer deur die Windows Mail-databasis](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internetboodskapformaat](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Bestuur Recall vir Windows-kliënte](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
