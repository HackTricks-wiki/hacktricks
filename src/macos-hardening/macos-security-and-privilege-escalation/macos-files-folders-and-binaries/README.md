# macOS Lêrs, Mappes, Binaries & Geheue

{{#include ../../../banners/hacktricks-training.md}}

## Lêer hiërargie uitleg

- **/Applications**: Die geïnstalleerde toepassings behoort hier te wees. Alle gebruikers sal toegang tot hulle hê.
- **/bin**: Opdraglyn binaries
- **/cores**: As dit bestaan, word dit gebruik om kernaflae te stoor
- **/dev**: Alles word as 'n lêer behandel, so jy mag hardeware toestelle hier gestoor sien.
- **/etc**: Konfigurasielêers
- **/Library**: 'n Baie aantal submappes en lêers wat verband hou met voorkeure, kas en logboeke kan hier gevind word. 'n Biblioteekmap bestaan in die wortel en op elke gebruiker se gids.
- **/private**: Nie gedokumenteer nie, maar baie van die genoemde mappes is simboliese skakels na die privaat gids.
- **/sbin**: Essensiële stelselbinaries (verwant aan administrasie)
- **/System**: Lêer om OS X te laat loop. Jy behoort meestal net Apple spesifieke lêers hier te vind (nie derdeparty nie).
- **/tmp**: Lêers word na 3 dae verwyder (dit is 'n sagte skakel na /private/tmp)
- **/Users**: Tuisgids vir gebruikers.
- **/usr**: Konfig en stelselbinaries
- **/var**: Log lêers
- **/Volumes**: Die gemonteerde skywe sal hier verskyn.
- **/.vol**: Deur `stat a.txt` te loop, kry jy iets soos `16777223 7545753 -rw-r--r-- 1 username wheel ...` waar die eerste nommer die id-nommer van die volume is waar die lêer bestaan en die tweede die inode-nommer is. Jy kan die inhoud van hierdie lêer deur /.vol/ met daardie inligting verkry deur `cat /.vol/16777223/7545753` te loop.

### Toepassings Mappes

- **Stelsel toepassings** is geleë onder `/System/Applications`
- **Geïnstalleerde** toepassings word gewoonlik in `/Applications` of in `~/Applications` geïnstalleer
- **Toepassing data** kan gevind word in `/Library/Application Support` vir die toepassings wat as root loop en `~/Library/Application Support` vir toepassings wat as die gebruiker loop.
- Derdeparty toepassings **daemons** wat **as root moet loop** is gewoonlik geleë in `/Library/PrivilegedHelperTools/`
- **Sandboxed** toepassings is in die `~/Library/Containers` gids gemap. Elke toepassing het 'n gids wat volgens die toepassing se bundel ID genoem word (`com.apple.Safari`).
- Die **kernel** is geleë in `/System/Library/Kernels/kernel`
- **Apple se kernel uitbreidings** is geleë in `/System/Library/Extensions`
- **Derdeparty kernel uitbreidings** word gestoor in `/Library/Extensions`

### Lêers met Sensitiewe Inligting

MacOS stoor inligting soos wagwoorde op verskeie plekke:

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Kwetsbare pkg installers

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X Spesifieke Uitbreidings

- **`.dmg`**: Apple Disk Image lêers is baie algemeen vir installers.
- **`.kext`**: Dit moet 'n spesifieke struktuur volg en dit is die OS X weergawe van 'n bestuurder. (dit is 'n bundel)
- **`.plist`**: Ook bekend as eiendom lys stoor inligting in XML of binêre formaat.
- Kan XML of binêr wees. Binêre kan gelees word met:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple toepassings wat die gidsstruktuur volg (Dit is 'n bundel).
- **`.dylib`**: Dinamiese biblioteke (soos Windows DLL lêers)
- **`.pkg`**: Is dieselfde as xar (eXtensible Archive formaat). Die installer opdrag kan gebruik word om die inhoud van hierdie lêers te installeer.
- **`.DS_Store`**: Hierdie lêer is op elke gids, dit stoor die eienskappe en aanpassings van die gids.
- **`.Spotlight-V100`**: Hierdie gids verskyn op die wortelgids van elke volume op die stelsel.
- **`.metadata_never_index`**: As hierdie lêer op die wortel van 'n volume is, sal Spotlight daardie volume nie indekseer nie.
- **`.noindex`**: Lêers en mappes met hierdie uitbreiding sal nie deur Spotlight geïndekseer word nie.
- **`.sdef`**: Lêers binne bundels wat spesifiseer hoe dit moontlik is om met die toepassing van 'n AppleScript te kommunikeer.

### macOS Bundels

'n Bundel is 'n **gids** wat **soos 'n objek in Finder lyk** (n Bundel voorbeeld is `*.app` lêers).

{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Gedeelde Biblioteek Kas (SLC)

Op macOS (en iOS) is alle stelsel gedeelde biblioteke, soos raamwerke en dylibs, **gecombineer in 'n enkele lêer**, genoem die **dyld gedeelde kas**. Dit verbeter die prestasie, aangesien kode vinniger gelaai kan word.

Dit is geleë in macOS in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` en in ouer weergawes mag jy die **gedeelde kas** in **`/System/Library/dyld/`** vind.\
In iOS kan jy dit in **`/System/Library/Caches/com.apple.dyld/`** vind.

Soos die dyld gedeelde kas, is die kernel en die kernel uitbreidings ook saamgecompileer in 'n kernel kas, wat by opstarttyd gelaai word.

Om die biblioteke uit die enkele lêer dylib gedeelde kas te onttrek, was dit moontlik om die binêre [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) te gebruik wat dalk nie vandag werk nie, maar jy kan ook [**dyldextractor**](https://github.com/arandomdev/dyldextractor) gebruik:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Let daarop dat selfs al werk die `dyld_shared_cache_util` hulpmiddel nie, kan jy die **gedeelde dyld-binary aan Hopper** oorhandig en Hopper sal in staat wees om al die biblioteke te identifiseer en jou te laat **kies watter een** jy wil ondersoek:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Sommige ekstraktors sal nie werk nie aangesien dylibs vooraf gekoppel is met hard-gecodeerde adresse, daarom kan hulle na onbekende adresse spring.

> [!TIP]
> Dit is ook moontlik om die Gedeelde Biblioteekkas van ander \*OS toestelle in macos af te laai deur 'n emulator in Xcode te gebruik. Hulle sal binne afgelaai word: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, soos: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** gebruik die syscall **`shared_region_check_np`** om te weet of die SLC gemap is (wat die adres teruggee) en **`shared_region_map_and_slide_np`** om die SLC te map.

Let daarop dat selfs al is die SLC op die eerste gebruik geskuif, gebruik al die **prosesse** die **dieselfde kopie**, wat die **ASLR** beskerming uitgeskakel het as die aanvaller in staat was om prosesse in die stelsel te laat loop. Dit is eintlik in die verlede uitgebuit en reggestel met 'n gedeelde streek pager.

Branch pools is klein Mach-O dylibs wat klein ruimtes tussen beeldmappings skep wat dit onmoontlik maak om die funksies te interpose.

### Oorskry SLCs

Gebruik die omgewingsveranderlikes:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Dit sal toelaat om 'n nuwe gedeelde biblioteekkas te laai.
- **`DYLD_SHARED_CACHE_DIR=avoid`** en vervang handmatig die biblioteke met symlinks na die gedeelde kas met die werklike een (jy sal dit moet ekstrak).

## Spesiale Lêer Toestemmings

### Gids toestemmings

In 'n **gids**, **lees** laat jou toe om dit te **lys**, **skryf** laat jou toe om **te verwyder** en **te skryf** lêers daarop, en **uitvoer** laat jou toe om die gids te **deursoek**. So, byvoorbeeld, 'n gebruiker met **lees toestemming oor 'n lêer** binne 'n gids waar hy **nie uitvoer** toestemming het nie, **sal nie in staat wees om** die lêer te lees nie.

### Vlag modifiers

Daar is 'n paar vlag wat in die lêers gestel kan word wat die lêer anders kan laat optree. Jy kan die **vlag** van die lêers binne 'n gids nagaan met `ls -lO /path/directory`

- **`uchg`**: Bekend as **uchange** vlag sal **enige aksie** wat die **lêer** verander of verwyder, **voorkom**. Om dit in te stel, doen: `chflags uchg file.txt`
- Die wortelgebruiker kan die **vlag verwyder** en die lêer wysig.
- **`restricted`**: Hierdie vlag maak die lêer **beskerm deur SIP** (jy kan nie hierdie vlag aan 'n lêer toevoeg nie).
- **`Sticky bit`**: As 'n gids met sticky bit, kan **slegs** die **gids se eienaar of wortel lêers hernoem of verwyder**. Tipies word dit op die /tmp gids gestel om gewone gebruikers te verhoed om ander gebruikers se lêers te verwyder of te skuif.

Al die vlae kan in die lêer `sys/stat.h` gevind word (vind dit met `mdfind stat.h | grep stat.h`) en is:

- `UF_SETTABLE` 0x0000ffff: Masker van eienaar veranderbare vlae.
- `UF_NODUMP` 0x00000001: Moet nie lêer dump nie.
- `UF_IMMUTABLE` 0x00000002: Lêer mag nie verander word nie.
- `UF_APPEND` 0x00000004: Skrywe na lêer mag slegs bygevoeg word.
- `UF_OPAQUE` 0x00000008: Gids is ondoorgrondelik ten opsigte van unie.
- `UF_COMPRESSED` 0x00000020: Lêer is gecomprimeer (sommige lêerstelsels).
- `UF_TRACKED` 0x00000040: Geen kennisgewings vir verwyderings/hernames vir lêers met hierdie ingestel nie.
- `UF_DATAVAULT` 0x00000080: Regte vereis vir lees en skryf.
- `UF_HIDDEN` 0x00008000: Wenke dat hierdie item nie in 'n GUI vertoon moet word nie.
- `SF_SUPPORTED` 0x009f0000: Masker van supergebruiker ondersteun vlae.
- `SF_SETTABLE` 0x3fff0000: Masker van supergebruiker veranderbare vlae.
- `SF_SYNTHETIC` 0xc0000000: Masker van stelsels lees-alleen sintetiese vlae.
- `SF_ARCHIVED` 0x00010000: Lêer is geargiveer.
- `SF_IMMUTABLE` 0x00020000: Lêer mag nie verander word nie.
- `SF_APPEND` 0x00040000: Skrywe na lêer mag slegs bygevoeg word.
- `SF_RESTRICTED` 0x00080000: Regte vereis vir skryf.
- `SF_NOUNLINK` 0x00100000: Item mag nie verwyder, hernoem of gemonteer word nie.
- `SF_FIRMLINK` 0x00800000: Lêer is 'n firmlink.
- `SF_DATALESS` 0x40000000: Lêer is 'n dataloos objek.

### **Lêer ACLs**

Lêer **ACLs** bevat **ACE** (Toegang Beheer Inskrywings) waar meer **fynere toestemmings** aan verskillende gebruikers toegeken kan word.

Dit is moontlik om 'n **gids** hierdie toestemmings te gee: `lys`, `soek`, `voeg_lêer_by`, `voeg_subgids_by`, `verwyder_kind`, `verwyder_kind`.\
En aan 'n **lêer**: `lees`, `skryf`, `voeg_by`, `uitvoer`.

Wanneer die lêer ACLs bevat, sal jy **'n "+" vind wanneer jy die toestemmings lys soos in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Jy kan **die ACLs** van die lêer lees met:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
U kan **alle lêers met ACL's** vind met (dit is baie stadig):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Uitgebreide Attribuut

Uitgebreide attribuut het 'n naam en enige gewenste waarde, en kan gesien word met `ls -@` en gemanipuleer word met die `xattr` opdrag. Sommige algemene uitgebreide attribuut is:

- `com.apple.resourceFork`: Hulpbronvork kompatibiliteit. Ook sigbaar as `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Gatekeeper kwarantynmeganisme (III/6)
- `metadata:*`: MacOS: verskeie metadata, soos `_backup_excludeItem`, of `kMD*`
- `com.apple.lastuseddate` (#PS): Laaste lêer gebruik datum
- `com.apple.FinderInfo`: MacOS: Finder inligting (bv., kleur Etikette)
- `com.apple.TextEncoding`: Gee die tekskodering van ASCII tekslêers aan
- `com.apple.logd.metadata`: Gebruik deur logd op lêers in `/var/db/diagnostics`
- `com.apple.genstore.*`: Generasionele berging (`/.DocumentRevisions-V100` in die wortel van die lêerstelsel)
- `com.apple.rootless`: MacOS: Gebruik deur Stelselintegriteitbeskerming om lêer te merk (III/10)
- `com.apple.uuidb.boot-uuid`: logd merkings van opstart epoches met unieke UUID
- `com.apple.decmpfs`: MacOS: Deursigtige lêer kompressie (II/7)
- `com.apple.cprotect`: \*OS: Per-lêer enkripsie data (III/11)
- `com.apple.installd.*`: \*OS: Metadata gebruik deur installd, bv., `installType`, `uniqueInstallID`

### Hulpbronvorke | macOS ADS

Dit is 'n manier om **Alternatiewe Data Strome in MacOS** masjiene te verkry. Jy kan inhoud binne 'n uitgebreide attribuut genaamd **com.apple.ResourceFork** binne 'n lêer stoor deur dit in **file/..namedfork/rsrc** te stoor.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Jy kan **alle lêers wat hierdie uitgebreide attribuut bevat** vind met:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Die uitgebreide attribuut `com.apple.decmpfs` dui aan dat die lêer versleuteld gestoor is, `ls -l` sal 'n **grootte van 0** rapporteer en die gecomprimeerde data is binne hierdie attribuut. Wanneer die lêer toegang verkry, sal dit in geheue ontsleutel word.

Hierdie attribuut kan gesien word met `ls -lO` wat as gecomprimeerd aangedui word omdat gecomprimeerde lêers ook met die vlag `UF_COMPRESSED` gemerk is. As 'n gecomprimeerde lêer verwyder word met hierdie vlag met `chflags nocompressed </path/to/file>`, sal die stelsel nie weet dat die lêer gecomprimeerd was nie en daarom sal dit nie in staat wees om die data te ontsleutel en toegang te verkry nie (dit sal dink dat dit eintlik leeg is).

Die hulpmiddel afscexpand kan gebruik word om 'n lêer te dwing om te ontsleutel.

## **Universal binaries &** Mach-o Formaat

Mac OS lêers word gewoonlik gecompileer as **universal binaries**. 'n **universal binary** kan **meerdere argitekture in dieselfde lêer ondersteun**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOS Proses Geheue

## macOS geheue dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risiko Kategorief lêers Mac OS

Die gids `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` is waar inligting oor die **risiko geassosieer met verskillende lêer extensies gestoor word**. Hierdie gids kategoriseer lêers in verskillende risikoniveaus, wat beïnvloed hoe Safari hierdie lêers hanteer wanneer hulle afgelaai word. Die kategorieë is soos volg:

- **LSRiskCategorySafe**: Lêers in hierdie kategorie word beskou as **heeltemal veilig**. Safari sal hierdie lêers outomaties oopmaak nadat hulle afgelaai is.
- **LSRiskCategoryNeutral**: Hierdie lêers kom sonder waarskuwings en word **nie outomaties oopgemaak** deur Safari nie.
- **LSRiskCategoryUnsafeExecutable**: Lêers onder hierdie kategorie **aktiveer 'n waarskuwing** wat aandui dat die lêer 'n toepassing is. Dit dien as 'n sekuriteitsmaatreël om die gebruiker te waarsku.
- **LSRiskCategoryMayContainUnsafeExecutable**: Hierdie kategorie is vir lêers, soos argiewe, wat 'n uitvoerbare lêer mag bevat. Safari sal **'n waarskuwing aktiveer** tensy dit kan verifieer dat alle inhoud veilig of neutraal is.

## Log lêers

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Bevat inligting oor afgelaaide lêers, soos die URL waarvandaan hulle afgelaai is.
- **`/var/log/system.log`**: Hooflog van OSX stelsels. com.apple.syslogd.plist is verantwoordelik vir die uitvoering van syslogging (jy kan kyk of dit gedeaktiveer is deur te soek na "com.apple.syslogd" in `launchctl list`).
- **`/private/var/log/asl/*.asl`**: Dit is die Apple Stelsellogs wat interessante inligting kan bevat.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stoor onlangs toeganklike lêers en toepassings deur "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stoor items om te begin by stelselaanvang.
- **`$HOME/Library/Logs/DiskUtility.log`**: Log lêer vir die DiskUtility App (inligting oor skywe, insluitend USB's).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data oor draadlose toegangspunte.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lys van gedeaktiveerde daemons.

{{#include ../../../banners/hacktricks-training.md}}
