# macOS-lêers, vouers, binaries en geheue

{{#include ../../../banners/hacktricks-training.md}}

## Lêerhiërargie-uitleg

Apple dokumenteer die macOS-lêerstelsel as ’n hiërargie van stelsel-, plaaslike, netwerk- en gebruiker-domeine. Die presiese inhoud wissel volgens die OS-vrystelling, en stelselliggings word al hoe meer beskerm of gesintetiseer. <sup>[[1]](#references)</sup>

- **/Applications**: Die geïnstalleerde apps behoort hier te wees. Alle gebruikers sal toegang daartoe hê.
- **/bin**: Opdragreël-binaries
- **/cores**: Indien dit bestaan, word dit gebruik om core dumps te stoor
- **/dev**: Alles word as ’n lêer behandel, dus kan hardeware-toestelle hier gestoor wees.
- **/etc**: Konfigurasielêers
- **/Library**: Baie subgidse en lêers wat met voorkeure, caches en logs verband hou, kan hier gevind word. ’n Library-vouer bestaan in die root en in elke gebruiker se gids.
- **/private**: Ongedokumenteer, maar baie van die genoemde vouers is simboliese skakels na die private-gids.
- **/sbin**: Noodsaaklike stelselbinaries (verwant aan administrasie)
- **/System**: Lêers wat macOS benodig; hierdie boom bevat hoofsaaklik komponente wat deur Apple verskaf word.
- **/tmp**: Tydelike lêers (’n simboliese skakel na `/private/tmp`). Historiese installasies het ou tydelike lêers dikwels volgens ’n periodieke skedule verwyder, soms beskryf as elke drie dae, maar die huidige opruimingstydsberekening hang van die stelsel en beleid af; moenie daarop staatmaak dat data daar behoue bly nie.
- **/Users**: Tuisgids vir gebruikers.
- **/usr**: Konfigurasie- en stelselbinaries
- **/var**: Loglêers
- **/Volumes**: Gemonteerde volumes verskyn hier.
- **/.vol**: Wanneer jy `stat a.txt` uitvoer, kry jy iets soos `16777223 7545753 -rw-r--r-- 1 username wheel ...`, waar die eerste getal die ID-nommer is van die volume waarop die lêer bestaan en die tweede een die inode-nommer is. Jy kan toegang tot die inhoud van hierdie lêer kry deur `cat /.vol/16777223/7545753` uit te voer met daardie inligting in `/.vol/`.

### Toepassingsvouers

- **Stelseltoepassings** is in `/System/Applications` geleë
- **Geïnstalleerde** toepassings word gewoonlik in `/Applications` of `~/Applications` geïnstalleer
- **Toepassingsdata** kan gevind word in `/Library/Application Support` vir toepassings wat as root loop en in `~/Library/Application Support` vir toepassings wat as die gebruiker loop.
- **Daemons** van derdeparty-toepassings wat **as root moet loop**, is gewoonlik in `/Library/PrivilegedHelperTools/` geleë.
- **Sandboxed** apps word na die `~/Library/Containers`-vouer gekarteer. Elke app het ’n vouer wat volgens die toepassings se bundle ID benoem is (`com.apple.Safari`).
- Die **kernel** is in `/System/Library/Kernels/kernel` geleë
- **Apple se kernel extensions** is in `/System/Library/Extensions` geleë
- **Derdeparty-kernel extensions** word in `/Library/Extensions` gestoor

### Lêers met sensitiewe inligting

macOS stoor sensitiewe inligting, insluitend aanmeldbewyse, op verskeie plekke:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Kwesbare pkg-installeerders


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Vir die onderskeid tussen die skryfbare Data-volume en die verseëlde System-volume wat in hierdie hiërargie sigbaar is, sien [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## OS X-spesifieke uitbreidings

- **`.dmg`**: Apple Disk Image-lêers is baie algemeen vir installeerders.
- **`.kext`**: Dit moet ’n spesifieke struktuur volg en is die OS X-weergawe van ’n drywer. (dit is ’n bundle)
- **`.plist`**: ’n Property list stoor gestruktureerde inligting in XML- of binêre formaat.
  - Kan XML of binêr wees. Binêre lêers kan gelees word met:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: ’n Toepassingsbundle wat die standaard macOS-gidsstruktuur volg.
- **`.dylib`**: Dinamiese libraries (soos Windows-DLL-lêers)
- **`.pkg`**: Moderne plat installeerderpakkette is XAR-argiewe, maar `.pkg` is ’n installeerderformaat, nie ’n sinoniem vir XAR nie. Ouer bundle-styl-installeerderpakkette is gidse. Sien [macOS installers](macos-installers-abuse.md) vir pakketstruktuur en inspeksie. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Hierdie lêer is in elke gids en stoor die eienskappe en aanpassings van die gids.
- **`.Spotlight-V100`**: Hierdie vouer verskyn in die root-gids van elke volume op die stelsel.
- **`.metadata_never_index`**: As hierdie lêer in die root van ’n volume is, sal Spotlight nie daardie volume indekseer nie.
- **`.noindex`**: Lêers en vouers met hierdie uitbreiding sal nie deur Spotlight geïndekseer word nie.
- **`.sdef`**: ’n Skripdefinisielêer wat beskryf hoe AppleScript met ’n toepassing kan kommunikeer.

### macOS-bundles

’n Bundle is ’n gids met ’n gestandaardiseerde hiërargie wat Finder as ’n enkele objek kan vertoon; toepassingsbundles gebruik die `.app`-uitbreiding. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld-gedeelde library-cache (SLC)

Op macOS en iOS word algemeen gebruikte stelsellibraries en frameworks vooraf in die **dyld shared cache** geskakel, wat die werkverrigting van toepassings se opstart verbeter. Alhoewel dit as een logiese cache behandel word, kan huidige vrystellings dit as ’n hoof-cache plus verskeie subcache-lêers stoor, eerder as letterlik as een lêer. Die formaat en ligging is implementeringsbesonderhede wat tussen OS-vrystellings verander. <sup>[[3]](#references)</sup>

Dit is op macOS in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` geleë, en in ouer weergawes kan jy dalk die **shared cache** in **`/System/Library/dyld/`** vind.\
Op iOS kan jy dit in **`/System/Library/Caches/com.apple.dyld/`** vind.

Soortgelyk aan die dyld shared cache word die kernel en kernel extensions ook in ’n kernel-cache saamgestel, wat tydens selflaai gelaai word.

Ouer vrystellings kon met [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) uitgepak word. Daardie bouweergawe ondersteun moontlik nie huidige cache-formate nie; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) is ’n ander opsie:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Let daarop dat selfs as die `dyld_shared_cache_util`-nutsding nie werk nie, jy die **shared dyld-binary na Hopper kan stuur**, en Hopper sal al die libraries kan identifiseer en jou laat **kies watter een** jy wil ondersoek:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Sommige extractors sal nie werk nie, aangesien dylibs vooraf gekoppel is met hardgekodeerde adresse; daarom spring hulle dalk na onbekende adresse.

> [!TIP]
> Dit is ook moontlik om die Shared Library Cache van ander \*OS-toestelle in macos af te laai deur 'n emulator in Xcode te gebruik. Hulle word afgelaai na: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, soos: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Kartering van SLC

**`dyld`** gebruik die syscall **`shared_region_check_np`** om vas te stel of die SLC gekarteer is (wat die adres terugstuur), en **`shared_region_map_and_slide_np`** om die SLC te karteer.

Let daarop dat selfs as die SLC met die eerste gebruik geskuif word, gebruik al die **prosesse** dieselfde **kopie**, wat **ASLR-beskerming uitgeskakel het** as die aanvaller prosesse op die stelsel kon laat loop. Dit is inderdaad in die verlede uitgebuit en met shared region pager reggestel.

Branch pools is klein Mach-O-dylibs wat klein spasies tussen beeldkarterings skep, wat dit onmoontlik maak om funksies te interpose.

### Beperkings van die shared-cache-omgewing

`DYLD_SHARED_CACHE_DIR` dui 'n kasgids aan, terwyl `DYLD_SHARED_REGION` 'n shared-region-modus kies. Die vorige spelling `DYLD_DHARED_REGION` was ongeldig, en `avoid` is nie 'n waarde vir `DYLD_SHARED_CACHE_DIR` nie. Huidige dyld laat die `private`-modus slegs toe met AMFI-toestemming om pasgemaakte shared caches te gebruik; die instel van omgewingsveranderlikes alleen bewys dus nie dat 'n proses 'n vervangende kas kan laai nie. <sup>[[10]](#references)</sup>

## Spesiale lêertoestemmings

### Gidstoestemmings

Vir 'n gids laat **lees** toe dat inskrywings gelys word, laat **skryf** toe dat inskrywings geskep of verwyder word, en laat **uitvoer** toe dat daar deur die gids navigeer word. Gevolglik kan 'n gebruiker wat 'n lêer kan lees, maar nie deur 'n ouergids kan navigeer nie, nie via die pad toegang tot daardie lêer kry nie. <sup>[[4]](#references)</sup>

### Vlagwysigers

Lêers kan vlae hê wat hul gedrag verander. Inspekteer vlae in 'n gids met `ls -lO /path/directory`.

- **`uchg`**: Die **uchange**-vlag, soos dit bekend staan, **verhoed enige handeling** wat die **lêer** verander of uitvee. Stel dit só in: `chflags uchg file.txt`
  - Die lêereienaar of root kan hierdie **gebruikersvlag** verwyder met `chflags nouchg file.txt`; dit beskerm dus nie teen een van hulle nie. Die afsonderlike **stelsel**-onveranderlike vlag (`schg`) is beperk tot root. <sup>[[11]](#references)</sup>
- **`restricted`**: Hierdie vlag maak die lêer **deur SIP beskerm** (jy kan nie hierdie vlag by 'n lêer voeg nie).
- **`Sticky bit`**: In 'n gids met die sticky bit gestel, kan slegs die lêereienaar, gidseienaar of root 'n inskrywing hernoem of uitvee. Dit is gewoonlik op `/tmp` geaktiveer om te keer dat gebruikers ander gebruikers se lêers uitvee of verskuif.

Al die vlae kan in die lêer `sys/stat.h` gevind word (vind dit met `mdfind stat.h | grep stat.h`), en is:

- `UF_SETTABLE` 0x0000ffff: Masker van vlae wat deur die eienaar verander kan word.
- `UF_NODUMP` 0x00000001: Moenie die lêer dump nie.
- `UF_IMMUTABLE` 0x00000002: Die lêer mag nie verander word nie.
- `UF_APPEND` 0x00000004: Skryfbewerkings na die lêer mag slegs byvoeg.
- `UF_OPAQUE` 0x00000008: Gids is ondeursigtig ten opsigte van union.
- `UF_COMPRESSED` 0x00000020: Lêer is saamgepers (sommige lêerstelsels).
- `UF_TRACKED` 0x00000040: Geen kennisgewings oor uitvee/hernoem vir lêers waarop dit gestel is nie.
- `UF_DATAVAULT` 0x00000080: 'n Entitlement word vereis om te lees en skryf.
- `UF_HIDDEN` 0x00008000: Aanduiding dat hierdie item nie in 'n GUI vertoon moet word nie.
- `SF_SUPPORTED` 0x009f0000: Masker van vlae wat deur supergebruikers ondersteun word.
- `SF_SETTABLE` 0x3fff0000: Masker van vlae wat deur supergebruikers verander kan word.
- `SF_SYNTHETIC` 0xc0000000: Masker van sintetiese vlae wat slegs deur die stelsel gelees kan word.
- `SF_ARCHIVED` 0x00010000: Lêer is geargiveer.
- `SF_IMMUTABLE` 0x00020000: Die lêer mag nie verander word nie.
- `SF_APPEND` 0x00040000: Skryfbewerkings na die lêer mag slegs byvoeg.
- `SF_RESTRICTED` 0x00080000: 'n Entitlement word vereis om te skryf.
- `SF_NOUNLINK` 0x00100000: Item mag nie verwyder, hernoem of op gemonteer word nie.
- `SF_FIRMLINK` 0x00800000: Lêer is 'n firmlink.
- `SF_DATALESS` 0x40000000: Lêer is 'n dataless-objek.

### **Lêer-ACL's**

Lêer-**ACL's** bevat **ACE's** (Access Control Entries) waarmee meer **fyn ingestelde toestemmings** aan verskillende gebruikers toegeken kan word.

Dit is moontlik om 'n **gids** hierdie toestemmings te gee: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Vir 'n **lêer**: `read`, `write`, `append` en `execute`.

Wanneer die lêer ACL's bevat, sal jy **'n "+" sien wanneer die toestemmings gelys word, soos in**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

Jy kan die ACL's van die lêer lees met:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

Jy kan **alle lêers met ACL's** vind met die volgende opdrag (dit is baie stadig):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Uitgebreide eienskappe

Uitgebreide eienskappe is benoemde metadatawaardes wat apart van ’n lêer se gewone eienskappe gestoor word. Lys hulle met `ls -l@` en ondersoek of wysig hulle met `xattr`. <sup>[[5]](#references)</sup> Enkele algemene uitgebreide eienskappe is:

- `com.apple.resourceFork`: Verenigbaarheid met resource forks. Ook sigbaar as `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS Gatekeeper-kwarantynmetadata
- `metadata:*`: macOS-metadata, soos `_backup_excludeItem` of `kMD*`
- `com.apple.lastuseddate` (#PS): Datum waarop die lêer laas gebruik is
- `com.apple.FinderInfo`: macOS Finder-inligting, soos kleuretikette
- `com.apple.TextEncoding`: Spesifiseer teksenkodering van ASCII-tekslêers
- `com.apple.logd.metadata`: Word deur logd gebruik op lêers in `/var/db/diagnostics`
- `com.apple.genstore.*`: Generasieberging (`/.DocumentRevisions-V100` in die wortel van die lêerstelsel)
- `com.apple.rootless`: macOS-metadata wat met System Integrity Protection verband hou
- `com.apple.uuidb.boot-uuid`: logd-merkers van selflaaitydperke met unieke UUID's
- `com.apple.decmpfs`: macOS-metadata vir deursigtige lêerkompressie
- `com.apple.cprotect`: \*OS: Enkripsiedata per lêer (III/11)
- `com.apple.installd.*`: \*OS: Metadata wat deur installd gebruik word, bv. `installType`, `uniqueInstallID`

### Resource forks | macOS ADS

Resource forks verskaf ’n alternatiewe datastroom op macOS. Inhoud kan in die uitgebreide eienskap `com.apple.ResourceFork` gestoor word en via `file/..namedfork/rsrc` verkry word.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Jy kan **al die lêers vind wat hierdie uitgebreide kenmerk bevat** met:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

Die uitgebreide attribuut `com.apple.decmpfs` stoor metadata vir deursigtige kompressie; dit dui nie op enkripsie nie. Afhangend van die kompressieformaat, kan saamgeperste data in die attribuut of in ’n resource fork gestoor word, en word dit deursigtig gedekomprimeer wanneer dit gelees word.

Die `UF_COMPRESSED`-vlag verskyn as `compressed` in `ls -lO`. Moenie dit handmatig uitvee nie: dit kan veroorsaak dat die stelsel die saamgeperste voorstelling verkeerd interpreteer.

Die opdrag wat die vlag uitvee, word hier gewys omdat dit nuttig is tydens forensiese ondersoeke, maar as jy dit op ’n saamgeperste lêer uitvoer, kan die lêer leeg of ontoeganklik lyk totdat sy metadata herstel is:

```bash
chflags nocompressed /path/to/file
```

Die ingeboude hulpprogram `/usr/bin/afscexpand` kan die uitbreiding van deursigtig saamgeperste lêers afdwing. Die afsonderlike derdeparty-hulpprogram `afsctool` kan Apple-lêerstelselkompressie ook inspekteer of dekomprimeer, maar moet nie met die ingeboude opdrag verwar word nie. <sup>[[8]](#references)</sup>


### Interessante konfigurasieliggings (macOS)

| Pad / Ligging | Doel / Wat dit konfigureer | Sekuriteit / Aanvalspotensiaal |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Stoor Apple se feature-flag-plist-lêers wat opsionele of eksperimentele gedrag in stelseldienste / raamwerke beheer | As ’n aanvaller SIP kan omseil of verhoogde voorregte kan verkry, kan die peuter daarmee verborge kodepaaie aktiveer of beveiligingsmaatreëls deaktiveer |
| `/System/Library/CoreServices/systemVersion.plist` | Bevat macOS-weergawemetadata (ProductVersion, BuildVersion) wat programme / installeerders gebruik om gedrag te bepaal | Wysiging kan programme of installeerders mislei om nie-ondersteunde OS-weergawes te aanvaar of kenmerke te ontsluit |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Program- / stelselwye voorkeure | As dit skryfbaar is, kan aanvallers instellings invoeg om programgedrag te stuur, beveiligingsmaatreëls te deaktiveer of verkeerde konfigurasie te veroorsaak |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist-definisies vir agtergronddienste en agente | Kwaadwillige plist-invoeging of -manipulasie (indien toestemmings dit toelaat) maak persistence of privilege escalation moontlik |
| `/etc/hosts` | Gasheernaam ↔ IP-karterings wat die stelsel se DNS-oplosser gebruik | Omleiding van domeinname, onderskepping van verkeer, vervalsing van dienste onder plaaslike beheer |
| `/etc/sudoers` | Bepaal wie opdragte met `sudo` kan uitvoer en onder watter voorwaardes | ’n Beskadigde sudoers-lêer kan root- of onbehoorlike voorregte aan aanvallerrekeninge toeken |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist-definisies van plaaslike gebruikersrekeninge | Peuterwerk maak dit moontlik om gebruikersrekeninge, wagwoordhashes of gebruikersmetadata te skep of te wysig |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel-uitbreidings / drywers | Die installering of wysiging van kexts kan tot beheer op kernvlak lei; streng beskerm deur SIP / handtekeningbeleide |
| `/private/var/db/SystemPolicyConfiguration/` | Stoor konfigurasie vir die afdwinging van stelselbeleide (bv. Gatekeeper, notarization) | Peuterwerk hiermee kan dit moontlik maak om beleidskontroles of vertrouensreëls te omseil |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH-hulpprogramlêers en konfigurasielêers | Verkeerde konfigurasie lei tot swak SSH-sekuriteit, ongemagtigde toegang of onveilige algoritmes |
| `/System/Library/Sandbox/Profiles` | Stelselsandbox-profiele (SBPL) wat prosesaksies beperk | Deur profiele te vervang of te wysig, kan sandbox-ontsnappingsroetes geskep of insluiting verswak word |

> **Nota**: Baie van hierdie paaie is in SIP-beskermde gidse (bv. `/System`) en word teen skryf beskerm, tensy SIP gedeaktiveer of omseil word.  


## Universele Binaries en Mach-O-formaat

Mach-O is die inheemse uitvoerbare formaat op macOS. ’n Universele, of vet, binary verpak verskeie argitektuurspesifieke Mach-O-skywe in een lêer; die toegewyde bladsy verduidelik albei formate:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS-geheuestorting

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Lêerrisiko en hanteerdermetadata

LaunchServices, lêerkwarantyn en Gatekeeper beïnvloed gesamentlik hoe macOS afgelaaide lêers hanteer en toepassings vir lêeruitbreidings en URL-skemas kies. Hul databasisse en interne hulpbronlêers verander tussen vrystellings; gebruik die toegewyde bladsye eerder as om ’n private CoreTypes-pad as ’n stabiele beleidskoppelvlak te beskou:

Op vrystellings wat die verouderde CoreTypes-risikometadata by `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` beskikbaar stel, is die algemeen aangetroffe kategorieë:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: inhoud wat veilig genoeg geag word om outomaties oopgemaak te word onder die toepaslike toepassingsbeleid.
- **`LSRiskCategoryNeutral`**: inhoud wat normaalweg nie ’n waarskuwing aktiveer nie en nie outomaties oopgemaak word nie.
- **`LSRiskCategoryUnsafeExecutable`**: uitvoerbare inhoud waarvoor die gebruiker ’n toepassingswaarskuwing behoort te ontvang.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: houers soos argiewe wat uitvoerbare inhoud kan bevat en verdere inspeksie vereis.

Dit is implementeringsbesonderhede, nie ’n stabiele openbare beleids-API nie; bevestig die werklike metadata en Safari/Gatekeeper-gedrag op die macOS-weergawe wat getoets word.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Loglêers

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Bevat inligting oor afgelaaide lêers, soos die URL waarvandaan hulle afgelaai is.
- **Unified log**: Op huidige macOS-weergawes kan jy stelsel- en toepassingsgebeurtenisse navraag met `log show` en `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** en **`/private/var/log/asl/*.asl`**: Verouderde logartefakte wat steeds op ouer stelsels relevant kan wees. Op daardie vrystellings konfigureer `/System/Library/LaunchDaemons/com.apple.syslogd.plist` `syslogd`; `launchctl list | grep com.apple.syslogd` kan help bepaal of die diens gelaai is.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stoor onlangs besoekte lêers en toepassings deur "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Verouderde voorkeurepad wat met aanmelditems geassosieer word; moderne macOS-weergawes gebruik bykomende meganismes.
- **`$HOME/Library/Logs/DiskUtility.log`**: Verouderde Disk Utility-log wat inligting oor aandrywers kan bevat, insluitend USB-toestelle.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data oor draadlose toegangspunte.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Verouderde launchd-oorheersingsdata.



## References

- [1] [Apple - Gids vir lêerstelselprogrammering](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Gids vir bondelprogrammering](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Oorsig van die dyld-gedeelde kas](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Gids vir lêerstelselprogrammering: macOS-lêerstelselsekuriteit](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS-manbladsy](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS-manbladsy](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS-manbladsy](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Apple-argiewe uitpak](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Sekuriteit van skelderskripte: spesiale lêertoestemmingsvlae](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Kodesigneringstake: installeerderpakkette](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
