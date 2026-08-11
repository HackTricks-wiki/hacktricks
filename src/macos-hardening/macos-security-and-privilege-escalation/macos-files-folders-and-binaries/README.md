# Faili, Folda, Binaries na Memory za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mpangilio wa hierarchy ya faili

Apple inaandika filesystem ya macOS kama hierarchy ya system, local, network, na user domains. Maudhui halisi hutofautiana kulingana na OS release, na maeneo ya system yanazidi kulindwa au kutengenezwa kwa njia ya synthesized. <sup>[[1]](#references)</sup>

- **/Applications**: Apps zilizosakinishwa zinapaswa kuwa hapa. Users wote wataweza kuzifikia.
- **/bin**: Binaries za command line
- **/cores**: Ikiwa ipo, hutumika kuhifadhi core dumps
- **/dev**: Kila kitu huchukuliwa kama faili, kwa hiyo unaweza kuona hardware devices zikiwa zimehifadhiwa hapa.
- **/etc**: Configuration files
- **/Library**: Subdirectories na files nyingi zinazohusiana na preferences, caches na logs zinaweza kupatikana hapa. Folda ya Library ipo kwenye root na kwenye directory ya kila user.
- **/private**: Haijaandikwa katika documentation, lakini folda nyingi zilizotajwa ni symbolic links zinazoelekeza kwenye private directory.
- **/sbin**: Essential system binaries (zinazohusiana na administration)
- **/System**: Files zinazohitajika na macOS; tree hii kimsingi ina components zilizotolewa na Apple.
- **/tmp**: Temporary files (symbolic link ya `/private/tmp`). Installations za zamani kwa kawaida zilisafisha temporary files za zamani kwa ratiba ya vipindi fulani, wakati mwingine ikielezwa kuwa ni siku tatu, lakini muda wa sasa wa cleanup hutegemea system na policy; usitegemee data kubaki humo.
- **/Users**: Home directory ya users.
- **/usr**: Config na system binaries
- **/var**: Log files
- **/Volumes**: Volumes zilizomountiwa huonekana hapa.
- **/.vol**: Ukiendesha `stat a.txt` unapata kitu kama `16777223 7545753 -rw-r--r-- 1 username wheel ...` ambapo namba ya kwanza ni namba ya ID ya volume ambako faili lipo, na ya pili ni namba ya inode. Unaweza kufikia content ya faili hili kupitia `/.vol/` kwa kutumia taarifa hizo na kuendesha `cat /.vol/16777223/7545753`

### Folda za Applications

- **System applications** ziko chini ya `/System/Applications`
- Applications **zilizosakinishwa** kwa kawaida husakinishwa kwenye `/Applications` au `~/Applications`
- Application data inaweza kupatikana kwenye `/Library/Application Support` kwa applications zinazoendeshwa kama root na `~/Library/Application Support` kwa applications zinazoendeshwa kama user.
- **Daemons** za third-party applications ambazo **zinahitaji kuendeshwa kama root** kwa kawaida ziko kwenye `/Library/PrivilegedHelperTools/`.
- Apps za **Sandboxed** huwekwa kwenye folda ya `~/Library/Containers`. Kila app ina folda iliyopewa jina kulingana na bundle ID ya application (`com.apple.Safari`).
- **Kernel** iko kwenye `/System/Library/Kernels/kernel`
- **Kernel extensions** za **Apple** ziko kwenye `/System/Library/Extensions`
- **Kernel extensions** za **third-party** zimehifadhiwa kwenye `/Library/Extensions`

### Files zenye Taarifa Nyeti

macOS huhifadhi taarifa nyeti, ikiwemo credentials, katika maeneo kadhaa:


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
- **`.plist`**: Property list huhifadhi taarifa zilizopangwa katika XML au binary format.
- Inaweza kuwa XML au binary. Zilizo binary zinaweza kusomwa kwa:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Application bundle inayofuata standard macOS directory structure.
- **`.dylib`**: Dynamic libraries (kama Windows DLL files)
- **`.pkg`**: Ni sawa na xar (eXtensible Archive format). Installer command inaweza kutumika kusakinisha contents za files hizi.
- **`.DS_Store`**: Faili hili lipo kwenye kila directory; huhifadhi attributes na customisations za directory.
- **`.Spotlight-V100`**: Folda hii huonekana kwenye root directory ya kila volume kwenye system.
- **`.metadata_never_index`**: Ikiwa faili hili lipo kwenye root ya volume, Spotlight haitai-index volume hiyo.
- **`.noindex`**: Files na folders zenye extension hii hazita-indexiwa na Spotlight.
- **`.sdef`**: Scripting definition file inayoeleza jinsi AppleScript inavyoweza kuingiliana na application.

### macOS Bundles

Bundle ni directory yenye hierarchy iliyosanifishwa ambayo Finder inaweza kuiwasilisha kama object moja; application bundles hutumia extension ya `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Kwenye macOS na iOS, system libraries na frameworks zinazotumiwa mara nyingi huunganishwa mapema kwenye **dyld shared cache**, jambo linaloboresha performance ya kuanzisha applications. Ingawa huchukuliwa kama cache moja ya kimantiki, releases za sasa zinaweza kuihifadhi kama cache kuu pamoja na subcache files nyingi badala ya kuwa faili moja halisi. Format na location yake ni implementation details zinazobadilika kulingana na OS releases. <sup>[[3]](#references)</sup>

Hii inapatikana kwenye macOS katika `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` na katika versions za zamani unaweza kuipata **shared cache** katika **`/System/Library/dyld/`**.\
Kwenye iOS unaweza kuzipata katika **`/System/Library/Caches/com.apple.dyld/`**.

Kama ilivyo kwa dyld shared cache, kernel na kernel extensions pia huunganishwa kwenye kernel cache, ambayo hupakiwa wakati wa boot.

Releases za zamani zingeweza kutolewa kwa [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Build hiyo huenda isitumie current cache formats; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) ni option nyingine:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Kumbuka kwamba hata kama tool ya `dyld_shared_cache_util` haifanyi kazi, unaweza **kupitisha binary ya shared dyld kwenda Hopper** na Hopper itaweza kutambua libraries zote na kukuruhusu **kuchagua ni ipi** unayotaka kuchunguza:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Baadhi ya extractors hazitafanya kazi kwa sababu dylibs zimeunganishwa awali zikiwa na anwani zilizowekwa moja kwa moja, hivyo huenda zikaruka kwenda kwenye anwani zisizojulikana

> [!TIP]
> Pia inawezekana kupakua Shared Library Cache ya vifaa vingine vya \*OS katika macos kwa kutumia emulator ndani ya Xcode. Vitapakuliwa ndani ya: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kama:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** hutumia syscall **`shared_region_check_np`** kujua kama SLC ime-mapped (ambayo hurudisha anwani) na **`shared_region_map_and_slide_np`** ku-map SLC.

Kumbuka kwamba hata kama SLC ime-slidiwa wakati wa matumizi ya kwanza, **processes** zote hutumia **copy ileile**, jambo ambalo **liliondoa** ulinzi wa ASLR ikiwa mshambuliaji aliweza kuendesha processes kwenye mfumo. Hili lilitumiwa vibaya zamani na kurekebishwa kwa shared region pager.

Branch pools ni Mach-O dylibs ndogo zinazounda nafasi ndogo kati ya image mappings, hivyo kufanya interpose ya functions isiwezekane.

### Override SLCs

Kwa kutumia env variables:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Hii itaruhusu kupakia shared library cache mpya
- **`DYLD_SHARED_CACHE_DIR=avoid`** na kubadilisha libraries mwenyewe kwa symlinks zinazoelekeza kwenye shared cache pamoja na zile halisi (utahitaji kuziextract)

## Ruhusa Maalum za Files

### Ruhusa za Folders

Kwa directory, **read** inaruhusu kuorodhesha entries, **write** inaruhusu kuunda au kuondoa entries, na **execute** inaruhusu traversal. Kwa hiyo, mtumiaji anayeweza kusoma file lakini hawezi kufanya traversal ya parent directory hawezi kufikia file hiyo kupitia path. <sup>[[4]](#references)</sup>

### Virekebishaji vya Flags

Files zinaweza kuwa na flags zinazobadilisha tabia yake. Kagua flags katika directory kwa kutumia `ls -lO /path/directory`.

- **`uchg`**: Inayojulikana kama **uchange** flag itazuia kitendo chochote cha kubadilisha au kufuta **file**. Kuiweka tumia: `chflags uchg file.txt`
- Mtumiaji root anaweza **kuondoa flag** na kurekebisha file
- **`restricted`**: Flag hii hufanya file **ilindwe na SIP** (huwezi kuongeza flag hii kwenye file).
- **`Sticky bit`**: Katika directory yenye sticky bit, ni mmiliki wa file, mmiliki wa directory, au root pekee anayeweza kubadilisha jina au kufuta entry. Kwa kawaida hii huwashwa kwenye `/tmp` ili kuzuia watumiaji kufuta au kuhamisha files za watumiaji wengine.

Flags zote zinaweza kupatikana kwenye file `sys/stat.h` (ipate kwa kutumia `mdfind stat.h | grep stat.h`) na ni:

- `UF_SETTABLE` 0x0000ffff: Mask ya flags ambazo mmiliki anaweza kubadilisha.
- `UF_NODUMP` 0x00000001: Usifanye dump ya file.
- `UF_IMMUTABLE` 0x00000002: File haiwezi kubadilishwa.
- `UF_APPEND` 0x00000004: Writes kwenye file zinaweza kuwa append pekee.
- `UF_OPAQUE` 0x00000008: Directory ni opaque kuhusiana na union.
- `UF_COMPRESSED` 0x00000020: File imecompressiwa (kwenye baadhi ya file-systems).
- `UF_TRACKED` 0x00000040: Hakuna notifications za deletes/renames kwa files zilizo na flag hii.
- `UF_DATAVAULT` 0x00000080: Entitlement inahitajika kwa kusoma na kuandika.
- `UF_HIDDEN` 0x00008000: Kidokezo kwamba item hii haipaswi kuonyeshwa kwenye GUI.
- `SF_SUPPORTED` 0x009f0000: Mask ya flags zinazoungwa mkono na superuser.
- `SF_SETTABLE` 0x3fff0000: Mask ya flags ambazo superuser anaweza kubadilisha.
- `SF_SYNTHETIC` 0xc0000000: Mask ya flags synthetic za mfumo za kusoma pekee.
- `SF_ARCHIVED` 0x00010000: File imewekwa kwenye archive.
- `SF_IMMUTABLE` 0x00020000: File haiwezi kubadilishwa.
- `SF_APPEND` 0x00040000: Writes kwenye file zinaweza kuwa append pekee.
- `SF_RESTRICTED` 0x00080000: Entitlement inahitajika kwa kuandika.
- `SF_NOUNLINK` 0x00100000: Item haiwezi kuondolewa, kupewa jina jipya, au kuwekewa mount.
- `SF_FIRMLINK` 0x00800000: File ni firmlink.
- `SF_DATALESS` 0x40000000: File ni dataless object.

### **File ACLs**

File **ACLs** zina **ACE** (Access Control Entries), ambapo **granular permissions** zaidi zinaweza kupewa users tofauti.

Inawezekana kuipa **directory** permissions hizi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Kwa **file**: `read`, `write`, `append`, na `execute`.

File inapokuwa na ACLs utaona **"+" wakati wa kuorodhesha permissions kama ilivyo kwenye**:
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
Unaweza kupata **faili zote zilizo na ACLs** kwa amri ifuatayo (hii ni ya polepole sana):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes ni thamani za metadata zilizopewa majina ambazo huhifadhiwa kando na attributes za kawaida za faili. Ziorodheshe kwa `ls -l@` na zikague au uzirekebishe kwa `xattr`. <sup>[[5]](#references)</sup> Baadhi ya extended attributes za kawaida ni:

- `com.apple.resourceFork`: Utangamano wa resource fork. Pia huonekana kama `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadata ya quarantine ya macOS Gatekeeper
- `metadata:*`: Metadata ya macOS, kama vile `_backup_excludeItem` au `kMD*`
- `com.apple.lastuseddate` (#PS): Tarehe ya mwisho ya matumizi ya faili
- `com.apple.FinderInfo`: Taarifa za macOS Finder, kama vile color tags
- `com.apple.TextEncoding`: Hubainisha encoding ya maandishi ya faili za ASCII
- `com.apple.logd.metadata`: Hutumiwa na logd kwenye faili za `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` kwenye root ya filesystem)
- `com.apple.rootless`: Metadata ya macOS inayohusishwa na System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Alama za logd za vipindi vya boot zenye UUID ya kipekee
- `com.apple.decmpfs`: Metadata ya macOS ya transparent file compression
- `com.apple.cprotect`: \*OS: Data ya encryption kwa kila faili (III/11)
- `com.apple.installd.*`: \*OS: Metadata inayotumiwa na installd, kwa mfano, `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks hutoa alternate data stream kwenye macOS. Maudhui yanaweza kuhifadhiwa kwenye extended attribute ya `com.apple.ResourceFork` na kufikiwa kupitia `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Unaweza **kupata faili zote zilizo na extended attribute hii** kwa kutumia:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Sifa iliyopanuliwa `com.apple.decmpfs` huhifadhi metadata ya transparent compression; haionyeshi encryption. Kulingana na muundo wa compression, data iliyobanwa inaweza kuhifadhiwa kwenye sifa hiyo au kwenye resource fork na hufunguliwa transparently inaposomwa.

Bendera ya `UF_COMPRESSED` huonekana kama `compressed` katika `ls -lO`. Usiiondoe manually: kufanya hivyo kunaweza kuufanya mfumo utambue representation iliyobanwa isivyo sahihi.

Command inayoondoa bendera imeonyeshwa hapa kwa sababu ni muhimu wakati wa forensic review, lakini kuiendesha dhidi ya faili iliyobanwa kunaweza kufanya faili hiyo ionekane tupu au isiweze kufikiwa hadi metadata yake irekebishwe:
```bash
chflags nocompressed /path/to/file
```
Huduma iliyojengwa ndani ya `/usr/bin/afscexpand` inaweza kulazimisha upanuzi wa mafaili yaliyobanwa kwa uwazi. Huduma tofauti ya third-party `afsctool` pia inaweza kukagua au kufinyua compression ya Apple filesystem, lakini haipaswi kuchanganywa na command iliyojengwa ndani. <sup>[[8]](#references)</sup>


### Maeneo ya kuvutia ya configuration (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Huhifadhi mafaili ya plist ya feature-flag za Apple yanayodhibiti tabia za hiari au za majaribio katika system daemons / frameworks | Ikiwa attacker anaweza kukwepa SIP au kupata privilege, kuyabadilisha kunaweza kuwezesha code paths zilizofichwa au kuzima safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Huhifadhi metadata ya toleo la macOS (ProductVersion, BuildVersion) inayotumiwa na apps / installers kudhibiti tabia | Kubadilishwa kunaweza kudanganya apps au installers zikubali matoleo ya OS yasiyoungwa mkono au kufungua features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferences za application / mfumo mzima | Ikiwa zinaweza kuandikwa, attackers wanaweza kuingiza settings za kuelekeza tabia ya app, kuzima protections, au kusababisha misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Ufafanuzi wa plist wa background daemons na agents | Kuingiza au kubadilisha plist kwa nia hasidi (ikiwa permissions zinaruhusu) huwezesha persistence au privilege escalations |
| `/etc/hosts` | Mappings za hostname ↔ IP zinazotumiwa na system DNS resolver | Kuelekeza upya domain names, kuintercept traffic, na ku-spoof services zilizo chini ya local control |
| `/etc/sudoers` | Hufafanua nani anaweza kuendesha commands kwa `sudo` na chini ya masharti gani | Faili ya sudoers iliyoharibiwa inaweza kuwapa root au privileges zisizofaa attacker accounts |
| `/private/var/db/dslocal/nodes/Default/users/` | Mafaili ya plist yanayofafanua local user accounts | Kuyabadilisha huruhusu kuunda au kurekebisha user accounts, password hashes, au user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Kusakinisha au kubadilisha kexts kunaweza kusababisha kernel-level control; zinalindwa sana na SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Huhifadhi configuration ya system policy enforcement (k.m. Gatekeeper, notarization) | Kuyabadilisha kunaweza kuruhusu kukwepa policy checks au trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries na config files | Misconfiguration husababisha SSH security dhaifu, unauthorized access, au algorithms zisizo salama |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) zinazotumiwa kuzuia actions za process | Kubadilisha au kureplace profiles kunaweza kufungua sandbox escape vectors au kudhoofisha containment |

> **Note**: Nyingi za paths hizi ziko chini ya directories zinazolindwa na SIP (k.m. `/System`) na zinalindwa dhidi ya writes isipokuwa SIP izimwe au ikwepwe.


## Universal Binaries And Mach-O Format

Mach-O ndiyo native executable format ya macOS. Universal, au fat, binary hufunga Mach-O slices nyingi maalum kwa architecture tofauti ndani ya faili moja; ukurasa maalum unaeleza formats zote mbili:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

LaunchServices, file quarantine, na Gatekeeper kwa pamoja huathiri jinsi macOS inavyoshughulikia mafaili yaliyopakuliwa na kuchagua applications kwa extensions na URL schemes. Databases zao na mafaili ya ndani ya resources hubadilika kati ya releases; tumia kurasa maalum badala ya kuchukulia CoreTypes path ya private kuwa stable policy interface:

Kwenye releases zinazoonyesha legacy CoreTypes risk metadata chini ya `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, categories zinazopatikana mara nyingi ni:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Content inayochukuliwa kuwa salama vya kutosha kufunguliwa automatically chini ya application policy inayotumika.
- **`LSRiskCategoryNeutral`**: Content ambayo kwa kawaida haisababishi warning na haifunguliwi automatically.
- **`LSRiskCategoryUnsafeExecutable`**: Executable content ambayo mtumiaji anapaswa kupewa application warning.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Containers kama archives ambazo zinaweza kuwa na executable content na zinahitaji ukaguzi zaidi.

Hizi ni implementation details, si stable public policy API; thibitisha metadata halisi na tabia ya Safari/Gatekeeper kwenye toleo la macOS linalofanyiwa test.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Ina taarifa kuhusu mafaili yaliyopakuliwa, kama URL ambako yalipakuliwa.
- **Unified log**: Kwenye matoleo ya sasa ya macOS, query system na application events kwa kutumia `log show` na `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** na **`/private/var/log/asl/*.asl`**: Legacy logging artifacts ambazo bado zinaweza kuwa muhimu kwenye systems za zamani. Kwenye releases hizo, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` hu-configure `syslogd`; `launchctl list | grep com.apple.syslogd` inaweza kusaidia kubaini ikiwa service imepakiwa.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Huhifadhi mafaili na applications zilizofikiwa hivi karibuni kupitia "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Legacy preference path inayohusishwa na login items; matoleo ya kisasa ya macOS hutumia mechanisms za ziada.
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility log ambayo inaweza kuwa na taarifa kuhusu drives, pamoja na USB devices.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data kuhusu wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override data.

## References

- [1] [Apple - Mwongozo wa Programming wa File System](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Mwongozo wa Programming wa Bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Muhtasari wa dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Mwongozo wa Programming wa File System: Usalama wa macOS File System](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - Ukurasa wa mwongozo wa macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - Ukurasa wa mwongozo wa macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - Ukurasa wa mwongozo wa macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
