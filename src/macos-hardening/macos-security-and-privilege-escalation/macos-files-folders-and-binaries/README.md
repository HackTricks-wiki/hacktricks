# macOS-lêers, vouers, Binaries & geheue

{{#include ../../../banners/hacktricks-training.md}}

## Lêerhiërargie-uitleg

- **/Applications**: Die geïnstalleerde apps behoort hier te wees. Alle gebruikers sal toegang daartoe hê.
- **/bin**: Command line-binaries
- **/cores**: Indien dit bestaan, word dit gebruik om core dumps te stoor
- **/dev**: Alles word as 'n lêer behandel, dus kan jy hardewaretoestelle sien wat hier gestoor word.
- **/etc**: Konfigurasielêers
- **/Library**: Baie subgidse en lêers wat met voorkeure, caches en logs verband hou, kan hier gevind word. 'n Library-vouer bestaan in die root en in elke gebruiker se gids.
- **/private**: Ongedokumenteer, maar baie van die genoemde vouers is simboliese skakels na die private-gids.
- **/sbin**: Essensiële stelselbinaries (verwant aan administrasie)
- **/System**: Lêers wat OS X laat loop. Jy behoort meestal net Apple-spesifieke lêers hier te vind (nie derdeparty-lêers nie).
- **/tmp**: Lêers word ná 3 dae uitgevee (dit is 'n soft link na /private/tmp)
- **/Users**: Tuisgids vir gebruikers.
- **/usr**: Konfigurasie- en stelselbinaries
- **/var**: Loglêers
- **/Volumes**: Die gemounte dryfwerke sal hier verskyn.
- **/.vol**: Wanneer jy `stat a.txt` uitvoer, kry jy iets soos `16777223 7545753 -rw-r--r-- 1 username wheel ...`, waar die eerste getal die ID-nommer is van die volume waar die lêer bestaan en die tweede een die inode-nommer is. Jy kan toegang tot die inhoud van hierdie lêer verkry deur /.vol/ met daardie inligting te gebruik en `cat /.vol/16777223/7545753` uit te voer.

### Applications-vouers

- **Stelseltoepassings** is onder `/System/Applications` geleë
- **Geïnstalleerde** toepassings word gewoonlik in `/Applications` of in `~/Applications` geïnstalleer
- **Toepassingsdata** kan gevind word in `/Library/Application Support` vir toepassings wat as root loop en `~/Library/Application Support` vir toepassings wat as die gebruiker loop.
- Derdeparty-toepassings-**daemons** wat **as root moet loop**, is gewoonlik in `/Library/PrivilegedHelperTools/` geleë
- **Sandboxed** apps word na die `~/Library/Containers`-vouer gemap. Elke app het 'n vouer wat volgens die toepassing se bundle-ID benoem is (`com.apple.Safari`).
- Die **kernel** is geleë in `/System/Library/Kernels/kernel`
- **Apple se kernel extensions** is geleë in `/System/Library/Extensions`
- **Derdeparty-kernel extensions** word in `/Library/Extensions` gestoor

### Lêers met sensitiewe inligting

MacOS stoor inligting soos wagwoorde op verskeie plekke:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Kwesbare pkg-installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X-spesifieke uitbreidings

- **`.dmg`**: Apple Disk Image-lêers kom baie gereeld voor vir installers.
- **`.kext`**: Dit moet 'n spesifieke struktuur volg en dit is die OS X-weergawe van 'n driver. (dit is 'n bundle)
- **`.plist`**: Ook bekend as property lists, stoor dit inligting in XML- of binary-formaat.
- Kan XML of binary wees. Binary-lêers kan gelees word met:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple-toepassings wat 'n gidsstruktuur volg (dit is 'n bundle).
- **`.dylib`**: Dynamic libraries (soos Windows DLL-lêers)
- **`.pkg`**: Is dieselfde as xar (eXtensible Archive-formaat). Die installer-opdrag kan gebruik word om die inhoud van hierdie lêers te installeer.
- **`.DS_Store`**: Hierdie lêer is in elke gids en stoor die eienskappe en aanpassings van die gids.
- **`.Spotlight-V100`**: Hierdie vouer verskyn in die root-gids van elke volume op die stelsel.
- **`.metadata_never_index`**: Indien hierdie lêer in die root van 'n volume is, sal Spotlight nie daardie volume indekseer nie.
- **`.noindex`**: Lêers en vouers met hierdie uitbreiding sal nie deur Spotlight geïndekseer word nie.
- **`.sdef`**: Lêers binne bundles wat spesifiseer hoe dit moontlik is om vanaf 'n AppleScript met die toepassing te kommunikeer.

### macOS-bundles

'n Bundle is 'n **gids** wat **soos 'n objek in Finder lyk** ('n Voorbeeld van 'n bundle is `*.app`-lêers).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Op macOS (en iOS) word alle gedeelde stelselbiblioteke, soos frameworks en dylibs, **in 'n enkele lêer gekombineer**, wat die **dyld shared cache** genoem word. Dit het werkverrigting verbeter, aangesien kode vinniger gelaai kan word.

Dit is op macOS geleë in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` en in ouer weergawes kan jy moontlik die **shared cache** in **`/System/Library/dyld/`** vind.\
In iOS kan jy dit in **`/System/Library/Caches/com.apple.dyld/`** vind.

Soortgelyk aan die dyld shared cache, word die kernel en die kernel extensions ook in 'n kernel cache saamgestel, wat tydens boot gelaai word.

Om die libraries uit die enkele dylib shared cache-lêer te onttrek, was dit moontlik om die binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) te gebruik, wat moontlik deesdae nie werk nie, maar jy kan ook [**dyldextractor**](https://github.com/arandomdev/dyldextractor) gebruik:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Let daarop dat selfs indien die `dyld_shared_cache_util`-tool nie werk nie, jy die **shared dyld binary na Hopper kan stuur**, en Hopper sal al die biblioteke kan identifiseer en jou laat **kies watter een** jy wil ondersoek:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Sommige extractors sal nie werk nie, aangesien dylibs vooraf met hardgekodeerde adresse gelink is en dus moontlik na onbekende adresse spring.

> [!TIP]
> Dit is ook moontlik om die Shared Library Cache van ander \*OS-toestelle in macOS af te laai deur ’n emulator in Xcode te gebruik. Hulle sal binne: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/` afgelaai word, soos:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Kartering van SLC

**`dyld`** gebruik die syscall **`shared_region_check_np`** om te weet of die SLC gekarteer is (wat die adres terugstuur), en **`shared_region_map_and_slide_np`** om die SLC te karteer.

Let daarop dat selfs al word die SLC met die eerste gebruik geslide, al die **prosesse** dieselfde kopie gebruik, wat die **ASLR**-beskerming uitskakel indien die aanvaller prosesse in die stelsel kon uitvoer. Dit is in die verlede uitgebuit en met shared region pager reggestel.

Branch pools is klein Mach-O-dylibs wat klein spasies tussen image mappings skep, wat dit onmoontlik maak om die funksies te interpose.

### Oorskryf van SLC's

Deur die omgewingsveranderlikes te gebruik:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Dit sal toelaat dat ’n nuwe shared library cache gelaai word.
- **`DYLD_SHARED_CACHE_DIR=avoid`** en vervang die biblioteke handmatig met simlinks na die shared cache met die werklike biblioteke (jy sal hulle moet ekstrakteer).

## Spesiale lêertoestemmings

### Gidstoestemmings

In ’n **gids** laat **lees** jou toe om dit te **lys**, laat **skryf** jou toe om lêers daarin te **verwyder** en **te skryf**, en laat **uitvoer** jou toe om deur die gids te **navigeer**. ’n Gebruiker met **leestoestemming oor ’n lêer** binne ’n gids waar hy **geen uitvoertoestemming** het nie, sal byvoorbeeld **nie die lêer kan lees nie**.

### Vlagwysigers

Daar is sekere vlae wat op lêers gestel kan word en wat die lêer se gedrag verander. Jy kan die **vlae** van die lêers binne ’n gids nagaan met `ls -lO /path/directory`

- **`uchg`**: Die **uchange**-vlag verhoed enige handeling wat die **lêer** verander of verwyder. Om dit te stel, doen: `chflags uchg file.txt`
- Die root-gebruiker kan die **vlag verwyder** en die lêer wysig.
- **`restricted`**: Hierdie vlag maak die lêer **deur SIP beskerm** (jy kan nie hierdie vlag op ’n lêer stel nie).
- **`Sticky bit`**: Indien ’n gids ’n sticky bit het, kan slegs die **gids se eienaar of root** lêers hernoem of verwyder. Dit word tipies op die /tmp-gids gestel om te voorkom dat gewone gebruikers ander gebruikers se lêers verwyder of verskuif.

Al die vlae kan in die lêer `sys/stat.h` gevind word (vind dit met `mdfind stat.h | grep stat.h`) en is:

- `UF_SETTABLE` 0x0000ffff: Masker van vlae wat deur die eienaar verander kan word.
- `UF_NODUMP` 0x00000001: Moenie die lêer dump nie.
- `UF_IMMUTABLE` 0x00000002: Die lêer mag nie verander word nie.
- `UF_APPEND` 0x00000004: Skrywings na die lêer mag slegs aangeheg word.
- `UF_OPAQUE` 0x00000008: Gids is ondeursigtig met betrekking tot union.
- `UF_COMPRESSED` 0x00000020: Lêer is saamgepers (sommige lêerstelsels).
- `UF_TRACKED` 0x00000040: Geen kennisgewings vir verwyderings/hernoemings van lêers waarop dit gestel is nie.
- `UF_DATAVAULT` 0x00000080: Entitlement word vir lees en skryf vereis.
- `UF_HIDDEN` 0x00008000: Wenk dat hierdie item nie in ’n GUI vertoon moet word nie.
- `SF_SUPPORTED` 0x009f0000: Masker van vlae wat deur die superuser ondersteun word.
- `SF_SETTABLE` 0x3fff0000: Masker van vlae wat deur die superuser verander kan word.
- `SF_SYNTHETIC` 0xc0000000: Masker van sintetiese, leesalleen-vlae wat deur die stelsel gebruik word.
- `SF_ARCHIVED` 0x00010000: Lêer is geargiveer.
- `SF_IMMUTABLE` 0x00020000: Die lêer mag nie verander word nie.
- `SF_APPEND` 0x00040000: Skrywings na die lêer mag slegs aangeheg word.
- `SF_RESTRICTED` 0x00080000: Entitlement word vir skryf vereis.
- `SF_NOUNLINK` 0x00100000: Item mag nie verwyder, hernoem of op gemount word nie.
- `SF_FIRMLINK` 0x00800000: Lêer is ’n firmlink.
- `SF_DATALESS` 0x40000000: Lêer is ’n dataless-objek.

### **Lêer-ACL's**

Lêer-**ACL's** bevat **ACE's** (Access Control Entries), waar meer **fynkorrelige toestemmings** aan verskillende gebruikers toegeken kan word.

Dit is moontlik om ’n **gids** die volgende toestemmings te gee: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
En ’n **lêer**: `read`, `write`, `append`, `execute`.

Wanneer die lêer ACL's bevat, sal jy ’n **"+" vind wanneer die toestemmings gelys word, soos in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Jy kan die ACL's van die lêer **lees met:**
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Jy kan **al die lêers met ACL's** vind met (dit is baaaie stadig):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Uitgebreide eienskappe

Uitgebreide eienskappe het ’n naam en enige gewenste waarde, en kan met `ls -@` bekyk en met die `xattr`-opdrag gemanipuleer word. Sommige algemene uitgebreide eienskappe is:

- `com.apple.resourceFork`: Verenigbaarheid met Resource fork. Ook sigbaar as `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS: Gatekeeper-quarantainemeganisme (III/6)
- `metadata:*`: macOS: verskeie metadata, soos `_backup_excludeItem` of `kMD*`
- `com.apple.lastuseddate` (#PS): Datum waarop die lêer laas gebruik is
- `com.apple.FinderInfo`: macOS: Finder-inligting (bv. kleur-etikette)
- `com.apple.TextEncoding`: Spesifiseer teksenkodering van ASCII-tekslêers
- `com.apple.logd.metadata`: Word deur logd gebruik op lêers in `/var/db/diagnostics`
- `com.apple.genstore.*`: Generasionele berging (`/.DocumentRevisions-V100` in die wortel van die lêerstelsel)
- `com.apple.rootless`: macOS: Word deur System Integrity Protection gebruik om ’n lêer te etiketteer (III/10)
- `com.apple.uuidb.boot-uuid`: logd-aanduidings van selflaaitydperke met unieke UUID
- `com.apple.decmpfs`: macOS: Deursigtige lêerkompressie (II/7)
- `com.apple.cprotect`: \*OS: Enkripsiedata per lêer (III/11)
- `com.apple.installd.*`: \*OS: Metadata wat deur installd gebruik word, bv. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Dit is ’n manier om **Alternate Data Streams op macOS**-masjiene te verkry. Jy kan inhoud binne ’n uitgebreide eienskap genaamd **com.apple.ResourceFork** in ’n lêer stoor deur dit in **file/..namedfork/rsrc** te stoor.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Jy kan **al die lêers wat hierdie uitgebreide kenmerk bevat, vind** met:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Die uitgebreide attribuut `com.apple.decmpfs` dui aan dat die lêer encrypted gestoor word; `ls -l` sal ’n **grootte van 0** rapporteer en die compressed data is binne hierdie attribuut. Wanneer die lêer verkry word, sal dit in memory decrypted word.

Hierdie attr kan met `ls -lO` gesien word, waar dit as compressed aangedui word omdat compressed lêers ook met die vlag `UF_COMPRESSED` gemerk word. Indien ’n compressed lêer hierdie vlag met `chflags nocompressed </path/to/file>` verwyder, sal die system nie weet dat die lêer compressed was nie en sal dit dus nie die data kan decompress en access nie (dit sal dink dat dit eintlik leeg is).

Die tool afscexpand kan gebruik word om ’n lêer se compression te forceer.


### Interessante configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Stoor Apple se feature-flag plist-lêers wat optional of experimental gedrag in system daemons / frameworks beheer | Indien ’n attacker SIP kan bypass of privilege kan verkry, kan die manipulation hiervan hidden code paths enable of safeguards disable |
| `/System/Library/CoreServices/systemVersion.plist` | Bevat macOS version metadata (ProductVersion, BuildVersion) wat deur apps / installers gebruik word om gedrag te gate | Modification kan apps of installers mislei om unsupported OS versions te aanvaar of features te unlock |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | Indien writable, kan attackers settings inject om app-gedrag te stuur, protections te disable of misconfiguration te veroorsaak |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist-definisies vir background daemons en agents | Malicious plist-invoeging of manipulation (indien permissions dit toelaat) enable persistence of privilege escalations |
| `/etc/hosts` | Hostname ↔ IP mappings wat deur die system DNS resolver gebruik word | Redirecting van domain names, intercepting van traffic, spoofing van services onder local control |
| `/etc/sudoers` | Definieer wie commands met `sudo` kan run en onder watter conditions | ’n Corrupted sudoers-lêer kan root of improper privileges aan attacker accounts grant |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account definition plists | Tampering laat die creation of modification van user accounts, password hashes of user metadata toe |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Installing of modifying van kexts kan tot kernel-level control lei; sterk protected deur SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Stoor configuration vir system policy enforcement (bv. Gatekeeper, notarization) | Tampering hiermee kan die circumvention van policy checks of trust rules toelaat |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries en config files | Misconfiguration lei tot weak SSH security, unauthorized access of insecure algorithms |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) wat gebruik word om process actions te restrict | Replacing of altering van profiles kan sandbox escape vectors open of containment weaken |

> **Nota**: Baie van hierdie paths is binne SIP-protected directories (bv. `/System`) en is teen writes protected, tensy SIP disabled of bypassed is.


## **Universal binaries &** Mach-o Format

Mac OS binaries word gewoonlik as **universal binaries** compiled. ’n **universal binary** kan **multiple architectures in dieselfde lêer support**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Die directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` is waar information oor die **risk associated with different file extensions stored word**. Hierdie directory categorizes lêers in verskeie risk levels, wat beïnvloed hoe Safari hierdie lêers hanteer wanneer dit downloaded word. Die categories is soos volg:

- **LSRiskCategorySafe**: Lêers in hierdie category word as **completely safe** beskou. Safari sal hierdie lêers outomaties open nadat dit downloaded is.
- **LSRiskCategoryNeutral**: Hierdie lêers bevat geen warnings nie en word **not automatically opened** deur Safari.
- **LSRiskCategoryUnsafeExecutable**: Lêers onder hierdie category **trigger ’n warning** wat aandui dat die lêer ’n application is. Dit dien as ’n security measure om die user te alert.
- **LSRiskCategoryMayContainUnsafeExecutable**: Hierdie category is vir lêers, soos archives, wat moontlik ’n executable kan contain. Safari sal **’n warning trigger** tensy dit kan verify dat alle contents safe of neutral is.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Bevat information oor downloaded lêers, soos die URL waarvandaan hulle downloaded is.
- **`/var/log/system.log`**: Main log van OSX systems. com.apple.syslogd.plist is responsible vir die execution van syslogging (jy kan check of dit disabled is deur vir "com.apple.syslogd" in `launchctl list` te search.
- **`/private/var/log/asl/*.asl`**: Dit is die Apple System Logs wat interesting information kan contain.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stoor onlangs accessed lêers en applications deur middel van "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stoor items wat met system startup geloods moet word
- **`$HOME/Library/Logs/DiskUtility.log`**: Log file vir die DiskUtility App (information oor drives, insluitend USBs)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data oor wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: List van daemons wat deactivated is.

{{#include ../../../banners/hacktricks-training.md}}
