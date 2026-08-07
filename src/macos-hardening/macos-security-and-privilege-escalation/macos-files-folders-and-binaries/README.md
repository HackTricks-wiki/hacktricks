# Files, Folda, Binaries na Memory za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mpangilio wa hierarchy ya files

- **/Applications**: Apps zilizosakinishwa zinapaswa kuwa hapa. Users wote wataweza kuzifikia.
- **/bin**: Command line binaries
- **/cores**: Ikiwepo, hutumika kuhifadhi core dumps
- **/dev**: Kila kitu huchukuliwa kama file, kwa hivyo unaweza kuona hardware devices zilizohifadhiwa hapa.
- **/etc**: Configuration files
- **/Library**: Subdirectories na files nyingi zinazohusiana na preferences, caches na logs zinaweza kupatikana hapa. Folda ya Library ipo kwenye root na kwenye directory ya kila user.
- **/private**: Haijaandikwa kwenye documentation, lakini folda nyingi zilizotajwa ni symbolic links zinazoelekeza kwenye private directory.
- **/sbin**: Essential system binaries (zinazohusiana na administration)
- **/System**: Files za kufanya OS X ifanye kazi. Hapa unapaswa kupata hasa files maalum za Apple (si za third party).
- **/tmp**: Files hufutwa baada ya siku 3 (ni soft link ya /private/tmp)
- **/Users**: Home directory ya users.
- **/usr**: Config na system binaries
- **/var**: Log files
- **/Volumes**: Drives zilizomountiwa zitaonekana hapa.
- **/.vol**: Ukiendesha `stat a.txt` unapata kitu kama `16777223 7545753 -rw-r--r-- 1 username wheel ...` ambapo namba ya kwanza ni id number ya volume ambako file ipo, na ya pili ni inode number. Unaweza kufikia content ya file hili kupitia /.vol/ ukitumia taarifa hizo kwa kuendesha `cat /.vol/16777223/7545753`

### Folda za Applications

- **System applications** zinapatikana chini ya `/System/Applications`
- Applications **zilizosakinishwa** kwa kawaida husakinishwa kwenye `/Applications` au `~/Applications`
- Application data inaweza kupatikana kwenye `/Library/Application Support` kwa applications zinazoendeshwa kama root na `~/Library/Application Support` kwa applications zinazoendeshwa kama user.
- Third-party applications **daemons** ambazo **zinahitaji kuendeshwa kama root** kwa kawaida hupatikana kwenye `/Library/PrivilegedHelperTools/`
- Apps za **Sandboxed** hupangwa kwenye folda ya `~/Library/Containers`. Kila app ina folda yenye jina linalofuata bundle ID ya application (`com.apple.Safari`).
- **kernel** iko kwenye `/System/Library/Kernels/kernel`
- **Apple's kernel extensions** zinapatikana kwenye `/System/Library/Extensions`
- **Third-party kernel extensions** huhifadhiwa kwenye `/Library/Extensions`

### Files zenye Taarifa Nyeti

MacOS huhifadhi taarifa kama passwords katika maeneo kadhaa:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Vulnerable pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensions Maalum za OS X

- **`.dmg`**: Apple Disk Image files hutumiwa mara nyingi kwa installers.
- **`.kext`**: Lazima ifuate structure maalum na ni toleo la OS X la driver. (ni bundle)
- **`.plist`**: Pia hujulikana kama property list na huhifadhi taarifa katika XML au binary format.
- Inaweza kuwa XML au binary. Zilizo binary zinaweza kusomwa kwa:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple applications zinazofuata directory structure (Ni bundle).
- **`.dylib`**: Dynamic libraries (kama Windows DLL files)
- **`.pkg`**: Ni sawa na xar (eXtensible Archive format). Installer command inaweza kutumika kusakinisha contents za files hizi.
- **`.DS_Store`**: File hii ipo kwenye kila directory na huhifadhi attributes na customisations za directory.
- **`.Spotlight-V100`**: Folda hii huonekana kwenye root directory ya kila volume kwenye mfumo.
- **`.metadata_never_index`**: Ikiwa file hii iko kwenye root ya volume, Spotlight haitai-index volume hiyo.
- **`.noindex`**: Files na folda zenye extension hii hazita-indexiwa na Spotlight.
- **`.sdef`**: Files zilizo ndani ya bundles zinazobainisha jinsi inavyowezekana kuingiliana na application kupitia AppleScript.

### macOS Bundles

Bundle ni **directory** ambayo **huonekana kama object kwenye Finder** (Mfano wa Bundle ni files za `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Kwenye macOS (na iOS), system shared libraries zote, kama frameworks na dylibs, **huunganishwa kuwa file moja**, linaloitwa **dyld shared cache**. Hii huongeza performance, kwa sababu code inaweza kupakiwa kwa haraka zaidi.

Kwenye macOS, hii inapatikana kwenye `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` na kwenye versions za zamani unaweza kupata **shared cache** kwenye **`/System/Library/dyld/`**.\
Kwenye iOS unaweza kuzipata kwenye **`/System/Library/Caches/com.apple.dyld/`**.

Sawa na dyld shared cache, kernel na kernel extensions pia hukompilewa kuwa kernel cache, ambayo hupakiwa wakati wa boot.

Ili kutoa libraries kutoka kwenye file moja la dylib shared cache, ilikuwa inawezekana kutumia binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), ambayo huenda haifanyi kazi siku hizi, lakini pia unaweza kutumia [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Kumbuka kwamba hata kama tool ya `dyld_shared_cache_util` haifanyi kazi, unaweza kupitisha **shared dyld binary kwa Hopper** na Hopper itaweza kutambua libraries zote na kukuruhusu **kuchagua ipi** unayotaka kuchunguza:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Baadhi ya extractors hazitafanya kazi kwa sababu dylibs zimekuwa prelinked kwa hard coded addresses ndani yake, hivyo huenda zikaruka kwenda kwenye anwani zisizojulikana

> [!TIP]
> Pia inawezekana kupakua Shared Library Cache ya vifaa vingine vya \*OS katika macOS kwa kutumia emulator ndani ya Xcode. Vitapakuliwa ndani ya: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kama:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** hutumia syscall **`shared_region_check_np`** kujua ikiwa SLC imechorwa (ambayo hurudisha anwani) na **`shared_region_map_and_slide_np`** kuchora SLC.

Kumbuka kwamba hata kama SLC inaslide wakati wa matumizi ya kwanza, **processes** zote hutumia **copy** ileile, jambo ambalo **liliondoa ulinzi wa ASLR** ikiwa mshambuliaji aliweza kuendesha processes kwenye mfumo. Hili liliexploit-iwa hapo awali na kurekebishwa kwa shared region pager.

Branch pools ni Mach-O dylibs ndogo zinazounda nafasi ndogo kati ya image mappings, na kufanya iwe vigumu ku-interpose functions.

### Override SLCs

Kwa kutumia environment variables:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Hii itaruhusu kupakia shared library cache mpya
- **`DYLD_SHARED_CACHE_DIR=avoid`** na kubadilisha libraries mwenyewe kwa symlinks zinazoelekeza kwenye shared cache pamoja na libraries halisi (utahitaji kuzitoa)

## Special File Permissions

### Folder permissions

Katika **folder**, **read** huruhusu **kuiorodhesha**, **write** huruhusu **kufuta** na **kuandika** files ndani yake, na **execute** huruhusu **kupitia** directory. Kwa hiyo, kwa mfano, user aliye na **read permission kwenye file** iliyo ndani ya directory ambamo **hana** permission ya **execute** **hataweza kusoma** file hiyo.

### Flag modifiers

Kuna flags ambazo zinaweza kuwekwa kwenye files na kufanya file ifanye kazi kwa njia tofauti. Unaweza **kuangalia flags** za files zilizo ndani ya directory kwa kutumia `ls -lO /path/directory`

- **`uchg`**: Inajulikana kama flag ya **uchange** na **itazuia action yoyote** ya kubadilisha au kufuta **file**. Kuiweka, tumia: `chflags uchg file.txt`
- User root anaweza **kuondoa flag** na kurekebisha file
- **`restricted`**: Flag hii hufanya file **ilindwe na SIP** (huwezi kuongeza flag hii kwenye file).
- **`Sticky bit`**: Ikiwa directory ina sticky bit, **mwenye directory au root pekee ndiye anayeweza kubadilisha jina au kufuta** files. Kwa kawaida huwekwa kwenye directory ya /tmp ili kuzuia users wa kawaida kufuta au kuhamisha files za users wengine.

Flags zote zinaweza kupatikana kwenye file `sys/stat.h` (itafute kwa kutumia `mdfind stat.h | grep stat.h`) na ni:

- `UF_SETTABLE` 0x0000ffff: Mask ya flags zinazoweza kubadilishwa na owner.
- `UF_NODUMP` 0x00000001: Usifanye dump ya file.
- `UF_IMMUTABLE` 0x00000002: File haiwezi kubadilishwa.
- `UF_APPEND` 0x00000004: Writes kwenye file zinaweza kuwa append pekee.
- `UF_OPAQUE` 0x00000008: Directory ni opaque kuhusiana na union.
- `UF_COMPRESSED` 0x00000020: File imebanwa (kwenye baadhi ya file-systems).
- `UF_TRACKED` 0x00000040: Hakuna notifications za deletes/renames kwa files zilizo na hii set.
- `UF_DATAVAULT` 0x00000080: Entitlement inahitajika kwa kusoma na kuandika.
- `UF_HIDDEN` 0x00008000: Hint kwamba item hii haipaswi kuonyeshwa kwenye GUI.
- `SF_SUPPORTED` 0x009f0000: Mask ya flags zinazoungwa mkono na superuser.
- `SF_SETTABLE` 0x3fff0000: Mask ya flags zinazoweza kubadilishwa na superuser.
- `SF_SYNTHETIC` 0xc0000000: Mask ya synthetic flags za mfumo za read-only.
- `SF_ARCHIVED` 0x00010000: File imewekwa kwenye archive.
- `SF_IMMUTABLE` 0x00020000: File haiwezi kubadilishwa.
- `SF_APPEND` 0x00040000: Writes kwenye file zinaweza kuwa append pekee.
- `SF_RESTRICTED` 0x00080000: Entitlement inahitajika kwa writing.
- `SF_NOUNLINK` 0x00100000: Item haiwezi kuondolewa, kubadilishwa jina au kuwekwa mount.
- `SF_FIRMLINK` 0x00800000: File ni firmlink.
- `SF_DATALESS` 0x40000000: File ni dataless object.

### **File ACLs**

File **ACLs** huwa na **ACE** (Access Control Entries), ambapo **granular permissions** zaidi zinaweza kupewa users tofauti.

Inawezekana kuipa **directory** permissions hizi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Na **file**: `read`, `write`, `append`, `execute`.

File ikiwa na ACLs utaona **"+" wakati wa kuorodhesha permissions kama ilivyo kwenye**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Unaweza **kusoma ACLs** za faili kwa:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Unaweza kupata **faili zote zenye ACLs** kwa kutumia (hii ni polepole sana):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes zina jina na value yoyote inayotakiwa, na zinaweza kuonekana kwa kutumia `ls -@` na kudhibitiwa kwa kutumia command ya `xattr`. Baadhi ya extended attributes zinazotumika sana ni:

- `com.apple.resourceFork`: Utangamano wa resource fork. Pia huonekana kama `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Utaratibu wa quarantine wa Gatekeeper (III/6)
- `metadata:*`: MacOS: metadata mbalimbali, kama vile `_backup_excludeItem`, au `kMD*`
- `com.apple.lastuseddate` (#PS): Tarehe ya mwisho ya matumizi ya faili
- `com.apple.FinderInfo`: MacOS: Taarifa za Finder (kwa mfano, color Tags)
- `com.apple.TextEncoding`: Hubainisha text encoding ya faili za maandishi za ASCII
- `com.apple.logd.metadata`: Hutumiwa na logd kwenye faili zilizo katika `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` kwenye mzizi wa filesystem)
- `com.apple.rootless`: MacOS: Hutumiwa na System Integrity Protection kuweka label kwenye faili (III/10)
- `com.apple.uuidb.boot-uuid`: Alama za logd za vipindi vya boot zenye UUID ya kipekee
- `com.apple.decmpfs`: MacOS: Transparent file compression (II/7)
- `com.apple.cprotect`: \*OS: Data ya encryption kwa kila faili (III/11)
- `com.apple.installd.*`: \*OS: Metadata inayotumiwa na installd, kwa mfano `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Hii ni njia ya kupata **Alternate Data Streams katika** mashine za **MacOS**. Unaweza kuhifadhi content ndani ya extended attribute inayoitwa **com.apple.ResourceFork** ndani ya faili kwa kuihifadhi katika **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Unaweza **kupata faili zote zilizo na extended attribute hii** kwa kutumia:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Extended attribute `com.apple.decmpfs` inaonyesha kuwa faili limehifadhiwa likiwa encrypted, `ls -l` itaripoti **size ya 0** na data iliyobanwa iko ndani ya attribute hii. Kila faili linapofikiwa lita-decryptiwa kwenye memory.

Attr hii inaweza kuonekana kwa `ls -lO`, ikionyeshwa kama compressed kwa sababu mafaili yaliyobanwa pia huwekewa flag `UF_COMPRESSED`. Ikiwa faili lililobanwa litaondolewa flag hii kwa `chflags nocompressed </path/to/file>`, mfumo hautajua kuwa faili lilikuwa limebanwa na hivyo hautaweza kulifungua na kufikia data (utafikiri kwamba kwa kweli ni tupu).

Tool afscexpand inaweza kutumika kulazimisha decompress faili.


### Maeneo ya kuvutia ya configuration (macOS)

| Path / Location | Purpose / Inachoconfigure | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Huhifadhi mafaili ya feature-flag plist ya Apple yanayodhibiti tabia za hiari au za majaribio katika system daemons / frameworks | Ikiwa attacker anaweza kubypass SIP au kupata privilege, kuyachezea kunaweza kuwezesha code paths zilizofichwa au kuzima safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Huhifadhi metadata ya toleo la macOS (ProductVersion, BuildVersion) inayotumiwa na apps / installers kudhibiti tabia | Kubadilisha kunaweza kudanganya apps au installers zikubali OS versions zisizotumika au zifungue features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferences za application / mfumo mzima | Ikiwa zinaweza kuandikwa, attackers wanaweza kuingiza settings za kuelekeza tabia ya app, kuzima protections, au kusababisha misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist definitions za background daemons na agents | Kuingiza au kubadilisha plist kwa uharibifu (ikiwa permissions zinaruhusu) huwezesha persistence au privilege escalations |
| `/etc/hosts` | Hostname ↔ IP mappings zinazotumiwa na system DNS resolver | Kuelekeza upya domain names, intercept traffic, na spoof services zilizo chini ya local control |
| `/etc/sudoers` | Hufafanua ni nani anayeweza kuendesha commands kwa `sudo` na kwa masharti gani | Sudoers file iliyoharibiwa inaweza kumpa attacker account root au privileges zisizofaa |
| `/private/var/db/dslocal/nodes/Default/users/` | Plists za definitions za local user accounts | Kuyachezea kunaruhusu kuunda au kubadilisha user accounts, password hashes, au user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Kuweka au kubadilisha kexts kunaweza kusababisha kernel-level control; zinalindwa sana na SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Huhifadhi configuration ya system policy enforcement (k.m. Gatekeeper, notarization) | Kuyachezea kunaweza kuruhusu circumvention ya policy checks au trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries na config files | Misconfiguration husababisha SSH security dhaifu, unauthorized access, au insecure algorithms |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) zinazotumiwa kuzuia vitendo vya process | Kubadilisha au ku-replace profiles kunaweza kufungua sandbox escape vectors au kudhoofisha containment |

> **Note**: Nyingi ya paths hizi ziko chini ya directories zinazolindwa na SIP (k.m. `/System`) na zinalindwa dhidi ya writes isipokuwa SIP izimwe au ibypassiwe.


## **Universal binaries &** Mach-o Format

Mac OS binaries kwa kawaida hukompile kama **universal binaries**. **Universal binary** inaweza **ku-support architectures nyingi ndani ya file moja**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ndiyo mahali ambapo information kuhusu **risk inayohusishwa na file extensions tofauti huhifadhiwa**. Directory hii huweka mafaili katika risk levels mbalimbali, jambo linaloathiri jinsi Safari inavyoshughulikia mafaili haya baada ya download. Categories ni kama ifuatavyo:

- **LSRiskCategorySafe**: Mafaili katika category hii huchukuliwa kuwa **salama kabisa**. Safari itafungua mafaili haya automatically baada ya kudownloadiwa.
- **LSRiskCategoryNeutral**: Mafaili haya hayana warnings na **hayafunguliwi automatically** na Safari.
- **LSRiskCategoryUnsafeExecutable**: Mafaili yaliyo chini ya category hii **husababisha warning** inayoonyesha kuwa faili ni application. Hii ni security measure ya kumtahadharisha user.
- **LSRiskCategoryMayContainUnsafeExecutable**: Category hii ni ya mafaili, kama archives, ambayo huenda yakawa na executable. Safari **itasababisha warning** isipokuwa iweze kuthibitisha kuwa contents zote ni safe au neutral.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Ina taarifa kuhusu mafaili yaliyodownloadiwa, kama URL ambayo yalidownloadiwa kutoka.
- **`/var/log/system.log`**: Main log ya OSX systems. com.apple.syslogd.plist inawajibika kwa execution ya syslogging (unaweza kuangalia ikiwa imezimwa kwa kutafuta "com.apple.syslogd" katika `launchctl list`.
- **`/private/var/log/asl/*.asl`**: Hizi ni Apple System Logs ambazo huenda zikawa na information ya kuvutia.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Huhifadhi mafaili na applications zilizofikiwa hivi karibuni kupitia "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Huhifadhi items za ku-launch wakati wa system startup
- **`$HOME/Library/Logs/DiskUtility.log`**: Log file ya DiskUtility App (information kuhusu drives, zikiwemo USBs)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data kuhusu wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: List ya daemons zilizozimwa.

{{#include ../../../banners/hacktricks-training.md}}
