# macOS-lêers, vouers, binaries & geheue

{{#include ../../../banners/hacktricks-training.md}}

## Lêerhiërargie-uitleg

Apple dokumenteer die macOS-lêerstelsel as ’n hiërargie van stelsel-, plaaslike-, netwerk- en gebruikersdomeine. Die presiese inhoud wissel volgens die OS-vrystelling, en stelselliggings word toenemend beskerm of gesintetiseer. <sup>[[1]](#references)</sup>

- **/Applications**: Die geïnstalleerde apps behoort hier te wees. Al die gebruikers sal toegang daartoe hê.
- **/bin**: Command line binaries
- **/cores**: Indien dit bestaan, word dit gebruik om core dumps te stoor
- **/dev**: Alles word as ’n lêer behandel, dus kan jy hardewaretoestelle sien wat hier gestoor word.
- **/etc**: Konfigurasielêers
- **/Library**: Baie subgidse en lêers wat met voorkeure, caches en logs verband hou, kan hier gevind word. ’n Library-vouer bestaan in die wortel en in elke gebruiker se gids.
- **/private**: Ongedokumenteer, maar baie van die genoemde vouers is simboliese skakels na die private-gids.
- **/sbin**: Noodsaaklike stelselbinaries (verwant aan administrasie)
- **/System**: Lêers wat deur macOS benodig word; hierdie boom bevat hoofsaaklik komponente wat deur Apple verskaf word.
- **/tmp**: Tydelike lêers (’n simboliese skakel na `/private/tmp`). Historiese installasies het gewoonlik ou tydelike lêers volgens ’n periodieke skedule skoongemaak, soms beskryf as drie dae, maar die huidige skoonmaaktydsberekening hang van die stelsel en beleid af; moenie daarop staatmaak dat data daar behoue bly nie.
- **/Users**: Tuisgids vir gebruikers.
- **/usr**: Konfigurasie- en stelselbinaries
- **/var**: Loglêers
- **/Volumes**: Gemonteerde volumes verskyn hier.
- **/.vol**: Wanneer jy `stat a.txt` uitvoer, kry jy iets soos `16777223 7545753 -rw-r--r-- 1 username wheel ...`, waar die eerste getal die ID-nommer is van die volume waar die lêer bestaan en die tweede een die inode-nommer is. Jy kan toegang tot die inhoud van hierdie lêer verkry deur /.vol/ met daardie inligting te gebruik en `cat /.vol/16777223/7545753` uit te voer.

### Applications-vouers

- **Stelseltoepassings** is onder `/System/Applications` geleë
- **Geïnstalleerde** toepassings word gewoonlik in `/Applications` of in `~/Applications` geïnstalleer
- **Toepassingsdata** kan gevind word in `/Library/Application Support` vir die toepassings wat as root loop, en `~/Library/Application Support` vir toepassings wat as die gebruiker loop.
- Derdeparty-toepassings-**daemons** wat **as root moet loop**, is gewoonlik in `/Library/PrivilegedHelperTools/` geleë.
- **Sandboxed** apps word na die `~/Library/Containers`-vouer gemap. Elke app het ’n vouer wat volgens die toepassing se bundle ID benoem is (`com.apple.Safari`).
- Die **kernel** is in `/System/Library/Kernels/kernel` geleë
- **Apple se kernel extensions** is in `/System/Library/Extensions` geleë
- **Derdeparty-kernel extensions** word in `/Library/Extensions` gestoor

### Lêers met sensitiewe inligting

macOS stoor sensitiewe inligting, insluitend credentials, op verskeie plekke:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Kwesbare pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X-spesifieke uitbreidings

- **`.dmg`**: Apple Disk Image-lêers word baie gereeld vir installers gebruik.
- **`.kext`**: Dit moet ’n spesifieke struktuur volg en is die OS X-weergawe van ’n driver. (dit is ’n bundle)
- **`.plist`**: ’n Property list stoor gestruktureerde inligting in XML- of binary-formaat.
- Kan XML of binary wees. Binary-lêers kan met die volgende gelees word:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: ’n Application bundle wat die standaard macOS-gidsstruktuur volg.
- **`.dylib`**: Dynamic libraries (soos Windows DLL-lêers)
- **`.pkg`**: Is dieselfde as xar (eXtensible Archive format). Die installer-opdrag kan gebruik word om die inhoud van hierdie lêers te installeer.
- **`.DS_Store`**: Hierdie lêer is in elke gids en stoor die eienskappe en pasmaakopsies van die gids.
- **`.Spotlight-V100`**: Hierdie vouer verskyn in die wortelgids van elke volume op die stelsel.
- **`.metadata_never_index`**: Indien hierdie lêer in die wortel van ’n volume is, sal Spotlight daardie volume nie indekseer nie.
- **`.noindex`**: Lêers en vouers met hierdie uitbreiding sal nie deur Spotlight geïndekseer word nie.
- **`.sdef`**: ’n Scripting definition file wat beskryf hoe AppleScript met ’n toepassing kan kommunikeer.

### macOS Bundles

’n Bundle is ’n gids met ’n gestandaardiseerde hiërargie wat Finder as ’n enkele objek kan vertoon; application bundles gebruik die `.app`-uitbreiding. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Op macOS en iOS word algemeen gebruikte stelselbiblioteke en frameworks vooraf aan die **dyld shared cache** gekoppel, wat die werkverrigting van toepassingbegin verbeter. Hoewel dit as een logiese cache behandel word, kan huidige vrystellings dit as ’n hoofcache plus verskeie subcache-lêers stoor eerder as letterlik een lêer. Die formaat en ligging daarvan is implementasiebesonderhede wat tussen OS-vrystellings verander. <sup>[[3]](#references)</sup>

Dit is op macOS in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` geleë, en in ouer weergawes kon jy moontlik die **shared cache** in **`/System/Library/dyld/`** vind.\
Op iOS kan jy hulle in **`/System/Library/Caches/com.apple.dyld/`** vind.

Soortgelyk aan die dyld shared cache word die kernel en kernel extensions ook in ’n kernel cache saamgestel, wat tydens boot gelaai word.

Ouer vrystellings kon met [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) onttrek word. Daardie build ondersteun moontlik nie huidige cache-formate nie; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) is nog ’n opsie:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Let daarop dat selfs al werk die `dyld_shared_cache_util`-nutsprogram nie, jy die **shared dyld binary na Hopper** kan stuur, en Hopper sal al die biblioteke kan identifiseer en jou toelaat om te **kies watter een** jy wil ondersoek:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Sommige extractors sal nie werk nie, aangesien dylibs vooraf gekoppel is met hardgekodeerde adresse; daarom kan hulle moontlik na onbekende adresse spring.

> [!TIP]
> Dit is ook moontlik om die Shared Library Cache van ander \*OS-toestelle in macos af te laai deur ’n emulator in Xcode te gebruik. Hulle sal binne die volgende afgelaai word: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, soos: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Kartering van SLC

**`dyld`** gebruik die syscall **`shared_region_check_np`** om te bepaal of die SLC gekarteer is (wat die adres terugstuur), en **`shared_region_map_and_slide_np`** om die SLC te karteer.

Let daarop dat selfs al word die SLC met die eerste gebruik geskuif, alle **prosesse** dieselfde **kopie** gebruik, wat die **ASLR**-beskerming uitskakel indien die aanvaller prosesse op die stelsel kon uitvoer. Dit is in die verlede uitgebuit en met shared region pager reggestel.

Branch pools is klein Mach-O-dylibs wat klein spasies tussen beeldkarterings skep, wat dit onmoontlik maak om die funksies te interpose.

### Oorskryf van SLC's

Gebruik die omgewingsveranderlikes:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Dit sal toelaat dat ’n nuwe shared library cache gelaai word.
- **`DYLD_SHARED_CACHE_DIR=avoid`** en vervang die biblioteke handmatig met simlinks na die shared cache met die werklike biblioteke (jy sal hulle moet onttrek).

## Spesiale lêertoestemmings

### Gidstoestemmings

Vir ’n gids laat **lees** toe dat inskrywings gelys word, laat **skryf** toe dat inskrywings geskep of verwyder word, en laat **uitvoering** deurkruising toe. Gevolglik kan ’n gebruiker wat ’n lêer kan lees maar nie ’n ouergids kan deurkruis nie, nie toegang tot daardie lêer via sy pad verkry nie. <sup>[[4]](#references)</sup>

### Vlagwysigers

Lêers kan vlae bevat wat hul gedrag verander. Inspekteer vlae in ’n gids met `ls -lO /path/directory`.

- **`uchg`**: Bekend as die **uchange**-vlag, sal dit **enige handeling verhoed** wat die **lêer** verander of uitvee. Om dit te stel, doen: `chflags uchg file.txt`
- Die root-gebruiker kan die **vlag verwyder** en die lêer wysig.
- **`restricted`**: Hierdie vlag maak die lêer **deur SIP beskerm** (jy kan nie hierdie vlag by ’n lêer voeg nie).
- **`Sticky bit`**: In ’n gids waar die sticky bit gestel is, kan slegs die lêereienaar, gidseienaar of root ’n inskrywing hernoem of uitvee. Dit word tipies op `/tmp` geaktiveer om te verhoed dat gebruikers ander gebruikers se lêers uitvee of verskuif.

Al die vlae kan in die lêer `sys/stat.h` gevind word (vind dit met `mdfind stat.h | grep stat.h`) en is:

- `UF_SETTABLE` 0x0000ffff: Masker van vlae wat deur die eienaar verander kan word.
- `UF_NODUMP` 0x00000001: Moenie lêer dump nie.
- `UF_IMMUTABLE` 0x00000002: Lêer mag nie verander word nie.
- `UF_APPEND` 0x00000004: Skrywings na lêer mag slegs bygevoeg word.
- `UF_OPAQUE` 0x00000008: Gids is ondeursigtig met betrekking tot union.
- `UF_COMPRESSED` 0x00000020: Lêer is saamgepers (sommige lêerstelsels).
- `UF_TRACKED` 0x00000040: Geen kennisgewings vir uitvee/hernoem van lêers waarop dit gestel is nie.
- `UF_DATAVAULT` 0x00000080: Entitlement word vereis vir lees en skryf.
- `UF_HIDDEN` 0x00008000: Wenk dat hierdie item nie in ’n GUI vertoon moet word nie.
- `SF_SUPPORTED` 0x009f0000: Masker van vlae wat deur die supergebruiker ondersteun word.
- `SF_SETTABLE` 0x3fff0000: Masker van vlae wat deur die supergebruiker verander kan word.
- `SF_SYNTHETIC` 0xc0000000: Masker van sintetiese vlae wat slegs deur die stelsel gelees kan word.
- `SF_ARCHIVED` 0x00010000: Lêer is geargiveer.
- `SF_IMMUTABLE` 0x00020000: Lêer mag nie verander word nie.
- `SF_APPEND` 0x00040000: Skrywings na lêer mag slegs bygevoeg word.
- `SF_RESTRICTED` 0x00080000: Entitlement word vereis om te skryf.
- `SF_NOUNLINK` 0x00100000: Item mag nie verwyder, hernoem of daarop gemount word nie.
- `SF_FIRMLINK` 0x00800000: Lêer is ’n firmlink.
- `SF_DATALESS` 0x40000000: Lêer is ’n dataless-objek.

### **Lêer-ACL's**

Lêer-**ACL's** bevat **ACE's** (Access Control Entries) waar meer **fynkorrelige toestemmings** aan verskillende gebruikers toegeken kan word.

Dit is moontlik om ’n **gids** hierdie toestemmings te gee: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Vir ’n **lêer**: `read`, `write`, `append` en `execute`.

Wanneer die lêer ACL's bevat, sal jy **’n "+" vind wanneer die toestemmings gelys word, soos in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Jy kan die **ACLs** van die lêer lees met:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Jy kan **alle lêers met ACL's** vind met die volgende opdrag (dit is baie stadig):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Uitgebreide attributes

Uitgebreide attributes is benoemde metadatawaardes wat apart van 'n lêer se gewone attributes gestoor word. Lys hulle met `ls -l@` en inspekteer of wysig hulle met `xattr`. <sup>[[5]](#references)</sup> Sommige algemene uitgebreide attributes is:

- `com.apple.resourceFork`: Verenigbaarheid met resource forks. Ook sigbaar as `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS Gatekeeper-quarantainemetadata
- `metadata:*`: macOS-metadata, soos `_backup_excludeItem` of `kMD*`
- `com.apple.lastuseddate` (#PS): Datum waarop die lêer laas gebruik is
- `com.apple.FinderInfo`: macOS Finder-inligting, soos kleurtags
- `com.apple.TextEncoding`: Spesifiseer teksenkodering van ASCII-tekslêers
- `com.apple.logd.metadata`: Word deur logd gebruik op lêers in `/var/db/diagnostics`
- `com.apple.genstore.*`: Generasionele berging (`/.DocumentRevisions-V100` in die wortel van die lêerstelsel)
- `com.apple.rootless`: macOS-metadata wat met System Integrity Protection geassosieer word
- `com.apple.uuidb.boot-uuid`: logd-merktekens van selflaaitydperke met unieke UUID
- `com.apple.decmpfs`: macOS-metadata vir deursigtige lêerkompressie
- `com.apple.cprotect`: \*OS: Enkripsiedata per lêer (III/11)
- `com.apple.installd.*`: \*OS: Metadata wat deur installd gebruik word, bv. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks verskaf 'n alternatiewe datastroom op macOS. Inhoud kan in die `com.apple.ResourceFork`-uitgebreide attribute gestoor en deur `file/..namedfork/rsrc` verkry word.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Jy kan **alle lêers wat hierdie uitgebreide attribuut bevat, vind** met:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Die uitgebreide kenmerk `com.apple.decmpfs` stoor metadata vir deursigtige kompressie; dit dui nie op enkripsie nie. Afhangend van die kompressieformaat kan saamgeperste data in die kenmerk of in ’n resource fork gestoor word, en dit word deursigtig gedekomprimeer wanneer dit gelees word.

Die `UF_COMPRESSED`-vlag verskyn as `compressed` in `ls -lO`. Moenie dit handmatig uitvee nie: dit kan veroorsaak dat die stelsel die saamgeperste voorstelling verkeerd interpreteer.

Die opdrag wat die vlag uitvee, word hier getoon omdat dit nuttig is tydens forensiese ondersoek, maar as dit teen ’n saamgeperste lêer uitgevoer word, kan daardie lêer leeg of ontoeganklik lyk totdat sy metadata herstel is:
```bash
chflags nocompressed /path/to/file
```
Die ingeboude `/usr/bin/afscexpand`-nutsprogram kan deursigtig saamgeperste lêers se uitbreiding afdwing. Die afsonderlike derdeparty-`afsctool`-nutsprogram kan Apple-lêerstelselkompressie ook inspekteer of dekomprimeer, maar dit moet nie met die ingeboude opdrag verwar word nie. <sup>[[8]](#references)</sup>


### Interessante konfigurasieliggings (macOS)

| Pad / Ligging | Doel / Wat dit konfigureer | Sekuriteit / Aanvalspotensiaal |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Stoor Apple se feature-flag plist-lêers wat opsionele of eksperimentele gedrag in stelseldaemons / frameworks beheer | As 'n aanvaller SIP kan omseil of voorregte kan verkry, kan peutering hiermee verborge kodepaaie aktiveer of beveiligingsmaatreëls deaktiveer |
| `/System/Library/CoreServices/systemVersion.plist` | Bevat macOS-weergawe-metadata (ProductVersion, BuildVersion) wat deur apps / installers gebruik word om gedrag te beheer | Wysiging kan apps of installers mislei om nie-ondersteunde OS-weergawes te aanvaar of features te ontsluit |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Toepassings- / stelselwye voorkeure | Indien skryfbaar, kan aanvallers instellings inspuit om app-gedrag te stuur, beskerming te deaktiveer of verkeerde konfigurasie te veroorsaak |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist-definisies vir agtergronddaemons en agents | Kwaadwillige plist-invoeging of -manipulasie (indien toestemmings dit toelaat) maak persistence of privilege escalations moontlik |
| `/etc/hosts` | Gasheernaam ↔ IP-karterings wat deur die stelsel se DNS-resolver gebruik word | Herleiding van domeinname, onderskepping van verkeer en spoofing van dienste onder plaaslike beheer |
| `/etc/sudoers` | Definieer wie opdragte met `sudo` kan uitvoer en onder watter voorwaardes | 'n Beskadigde sudoers-lêer kan root- of onbehoorlike voorregte aan aanvallerrekeninge verleen |
| `/private/var/db/dslocal/nodes/Default/users/` | Plists met definisies van plaaslike gebruikerrekeninge | Peuterwerk maak die skepping of wysiging van gebruikerrekeninge, wagwoord-hashes of gebruikermetadata moontlik |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drywers | Die installering of wysiging van kexts kan tot beheer op kernvlak lei; dit word sterk deur SIP- / handtekeningbeleide beskerm |
| `/private/var/db/SystemPolicyConfiguration/` | Stoor konfigurasie vir stelselbeleidafdwinging (bv. Gatekeeper, notarization) | Peuterwerk hiermee kan die omseiling van beleidskontroles of trust-reëls moontlik maak |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH-helper-binaries en konfigurasielêers | Verkeerde konfigurasie lei tot swak SSH-sekuriteit, ongemagtigde toegang of onveilige algoritmes |
| `/System/Library/Sandbox/Profiles` | Stelsel-sandbox-profiele (SBPL) wat gebruik word om prosesaksies te beperk | Die vervanging of wysiging van profiele kan sandbox escape-vektore oopmaak of containment verswak |

> **Nota**: Baie van hierdie paaie lê onder SIP-beskermde gidse (bv. `/System`) en word teen skryfaksies beskerm tensy SIP gedeaktiveer of omseil word.


## Universele Binaries En Mach-O-formaat

Mach-O is die oorspronklike uitvoerbare formaat op macOS. 'n Universele, of fat, binary verpak verskeie argitektuurspesifieke Mach-O-slices in een lêer; die toegewyde bladsy verduidelik albei formate:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS-geheuestorting

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Lêerrisiko- en Handler-metadata

LaunchServices, lêer-quarantine en Gatekeeper beïnvloed gesamentlik hoe macOS afgelaaide lêers hanteer en toepassings vir uitbreidings en URL-skemas kies. Hul databasisse en interne hulpbronlêers verander tussen vrystellings; gebruik die toegewyde bladsye eerder as om 'n private CoreTypes-pad as 'n stabiele beleidskoppelvlak te behandel:

Op vrystellings wat die legacy CoreTypes-risikometadata onder `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` blootstel, is die kategorieë wat die meeste teëgekom word:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: inhoud wat veilig genoeg geag word om outomaties oopgemaak te word onder die toepaslike toepassingsbeleid.
- **`LSRiskCategoryNeutral`**: inhoud wat normaalweg nie 'n waarskuwing aktiveer nie en nie outomaties oopgemaak word nie.
- **`LSRiskCategoryUnsafeExecutable`**: uitvoerbare inhoud waarvoor die gebruiker 'n toepassingswaarskuwing behoort te ontvang.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: houers soos argiewe wat uitvoerbare inhoud kan bevat en verdere inspeksie vereis.

Hierdie is implementasiebesonderhede, nie 'n stabiele publieke beleids-API nie; bevestig die werklike metadata en Safari/Gatekeeper-gedrag op die macOS-weergawe wat getoets word.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Loglêers

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Bevat inligting oor afgelaaide lêers, soos die URL waarvandaan hulle afgelaai is.
- **Unified log**: Op huidige macOS-weergawes kan stelsel- en toepassinggebeurtenisse met `log show` en `log stream` bevraagteken word. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** en **`/private/var/log/asl/*.asl`**: Legacy-logartefakte wat steeds op ouer stelsels relevant kan wees. Op daardie vrystellings konfigureer `/System/Library/LaunchDaemons/com.apple.syslogd.plist` `syslogd`; `launchctl list | grep com.apple.syslogd` kan help bepaal of die diens gelaai is.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stoor lêers en toepassings wat onlangs deur "Finder" gebruik is.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Legacy-voorkeurpad wat met login items geassosieer word; moderne macOS-weergawes gebruik bykomende meganismes.
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility-log wat inligting oor aandrywers kan bevat, insluitend USB-toestelle.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data oor wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd-override-data.

## References

- [1] [Apple - Gids vir lêerstelselprogrammering](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Gids vir bundle-programmering](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Oorsig van die dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Gids vir lêerstelselprogrammering: macOS-lêerstelsekuriteit](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS-handleidingbladsy](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS-handleidingbladsy](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS-handleidingbladsy](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
