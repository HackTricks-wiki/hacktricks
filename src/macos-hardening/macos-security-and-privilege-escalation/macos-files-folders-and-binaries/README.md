# macOS Files, Folders, Binaries & Memory

{{#include ../../../banners/hacktricks-training.md}}

## File hierarchy layout

- **/Applications**: Programu zilizowekwa zinapaswa kuwa hapa. Watumiaji wote wataweza kuzipata.
- **/bin**: Binaries za mstari wa amri
- **/cores**: Ikiwa ipo, inatumika kuhifadhi core dumps
- **/dev**: Kila kitu kinachukuliwa kama faili hivyo unaweza kuona vifaa vya vifaa vikiwa hapa.
- **/etc**: Faili za usanidi
- **/Library**: Maktaba nyingi za ndogo na faili zinazohusiana na mapendeleo, caches na logi zinaweza kupatikana hapa. Folda ya Maktaba ipo kwenye mzizi na kwenye kila directory ya mtumiaji.
- **/private**: Haijandikwa lakini folda nyingi zilizotajwa ni viungo vya alama kwa directory ya kibinafsi.
- **/sbin**: Binaries muhimu za mfumo (zinahusiana na usimamizi)
- **/System**: Faili za kufanya OS X ifanye kazi. Unapaswa kupata hasa faili maalum za Apple hapa (sio za wahusika wengine).
- **/tmp**: Faili zinafuta baada ya siku 3 (ni kiungo laini kwa /private/tmp)
- **/Users**: Directory ya nyumbani kwa watumiaji.
- **/usr**: Usanidi na binaries za mfumo
- **/var**: Faili za logi
- **/Volumes**: Drives zilizowekwa zitakuwa hapa.
- **/.vol**: Ukikimbia `stat a.txt` unapata kitu kama `16777223 7545753 -rw-r--r-- 1 username wheel ...` ambapo nambari ya kwanza ni nambari ya kitambulisho cha volume ambapo faili ipo na ya pili ni nambari ya inode. Unaweza kufikia maudhui ya faili hii kupitia /.vol/ kwa kutumia taarifa hiyo ukikimbia `cat /.vol/16777223/7545753`

### Applications Folders

- **Programu za mfumo** ziko chini ya `/System/Applications`
- **Programu zilizowekwa** kawaida huwekwa katika `/Applications` au katika `~/Applications`
- **Data za programu** zinaweza kupatikana katika `/Library/Application Support` kwa programu zinazokimbia kama root na `~/Library/Application Support` kwa programu zinazokimbia kama mtumiaji.
- Programu za wahusika wengine **daemons** ambazo **zinahitaji kukimbia kama root** kawaida ziko katika `/Library/PrivilegedHelperTools/`
- Programu **Sandboxed** zimepangwa katika folda `~/Library/Containers`. Kila programu ina folda iliyopewa jina kulingana na ID ya bundle ya programu (`com.apple.Safari`).
- **Kernel** iko katika `/System/Library/Kernels/kernel`
- **Marekebisho ya kernel ya Apple** yako katika `/System/Library/Extensions`
- **Marekebisho ya kernel ya wahusika wengine** yanahifadhiwa katika `/Library/Extensions`

### Files with Sensitive Information

MacOS inahifadhi taarifa kama nywila katika maeneo kadhaa:

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Vulnerable pkg installers

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X Specific Extensions

- **`.dmg`**: Faili za Apple Disk Image ni za kawaida kwa wawekaji.
- **`.kext`**: Inapaswa kufuata muundo maalum na ni toleo la OS X la dereva. (ni bundle)
- **`.plist`**: Pia inajulikana kama orodha ya mali inahifadhi taarifa katika muundo wa XML au binary.
- Inaweza kuwa XML au binary. Zile za binary zinaweza kusomwa kwa:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Programu za Apple ambazo zinafuata muundo wa directory (ni bundle).
- **`.dylib`**: Maktaba za dynamic (kama faili za Windows DLL)
- **`.pkg`**: Ni sawa na xar (eXtensible Archive format). Amri ya wawekaji inaweza kutumika kufunga maudhui ya faili hizi.
- **`.DS_Store`**: Faili hii iko kwenye kila directory, inaokoa sifa na marekebisho ya directory.
- **`.Spotlight-V100`**: Folda hii inaonekana kwenye directory ya mzizi ya kila volume kwenye mfumo.
- **`.metadata_never_index`**: Ikiwa faili hii iko kwenye mzizi wa volume Spotlight haitai index hiyo volume.
- **`.noindex`**: Faili na folda zenye kiambishi hiki hazitakuwa indexed na Spotlight.
- **`.sdef`**: Faili ndani ya bundles zinazoelezea jinsi inavyowezekana kuingiliana na programu kutoka kwa AppleScript.

### macOS Bundles

Bundle ni **directory** ambayo **inaonekana kama kitu katika Finder** (mfano wa Bundle ni faili za `*.app`).

{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Katika macOS (na iOS) maktaba zote za pamoja za mfumo, kama frameworks na dylibs, zime **unganishwa katika faili moja**, inayoitwa **dyld shared cache**. Hii iliboresha utendaji, kwani msimbo unaweza kupakiwa haraka zaidi.

Hii iko katika macOS katika `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` na katika toleo za zamani unaweza kuweza kupata **shared cache** katika **`/System/Library/dyld/`**.\
Katika iOS unaweza kuzipata katika **`/System/Library/Caches/com.apple.dyld/`**.

Kama ilivyo kwa dyld shared cache, kernel na marekebisho ya kernel pia yameandaliwa katika cache ya kernel, ambayo inapakuliwa wakati wa kuanzisha.

Ili kutoa maktaba kutoka kwa faili moja ya dylib shared cache ilikuwa inawezekana kutumia binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) ambayo huenda isifanye kazi siku hizi lakini unaweza pia kutumia [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Kumbuka kwamba hata kama zana ya `dyld_shared_cache_util` haifanyi kazi, unaweza kupitisha **binary ya dyld iliyoshirikiwa kwa Hopper** na Hopper itakuwa na uwezo wa kubaini maktaba zote na kukuruhusu **uchague ambayo** unataka kuchunguza:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Baadhi ya extractor hazitafanya kazi kwani dylibs zimeunganishwa kwa anwani zilizowekwa kwa hivyo zinaweza kuruka kwenye anwani zisizojulikana.

> [!TIP]
> Pia inawezekana kupakua Cache ya Maktaba ya Shirika la vifaa vingine \*OS katika macos kwa kutumia emulator katika Xcode. Zitawekwa ndani ya: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kama:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Ramani ya SLC

**`dyld`** inatumia syscall **`shared_region_check_np`** kujua kama SLC imepangwa (ambayo inarudisha anwani) na **`shared_region_map_and_slide_np`** kupanga SLC.

Kumbuka kwamba hata kama SLC imehamishwa kwenye matumizi ya kwanza, **mchakato** wote hutumia **nakala ile ile**, ambayo **imeondoa ulinzi wa ASLR** ikiwa mshambuliaji alikuwa na uwezo wa kuendesha michakato katika mfumo. Hii kwa kweli ilitumiwa katika siku za nyuma na kurekebishwa na pager ya eneo lililosambazwa.

Branch pools ni Mach-O dylibs ndogo ambazo zinaunda nafasi ndogo kati ya ramani za picha na kufanya iwe vigumu kuingilia kazi.

### Kubadilisha SLCs

Kwa kutumia mabadiliko ya env:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Hii itaruhusu kupakia cache mpya ya maktaba iliyoshirikiwa.
- **`DYLD_SHARED_CACHE_DIR=avoid`** na kubadilisha maktaba kwa mikono kwa symlinks kwa cache iliyoshirikiwa na zile halisi (utahitaji kuzitoa).

## Ruhusa Maalum za Faili

### Ruhusa za Folda

Katika **folda**, **kusoma** inaruhusu **kuorodhesha**, **kuandika** inaruhusu **kufuta** na **kuandika** faili ndani yake, na **kutekeleza** inaruhusu **kupita** kwenye directory. Hivyo, kwa mfano, mtumiaji mwenye **ruhusa ya kusoma juu ya faili** ndani ya directory ambapo hana **ruhusa ya kutekeleza** **hataweza kusoma** faili hiyo.

### Marekebisho ya Bendera

Kuna bendera kadhaa ambazo zinaweza kuwekwa kwenye faili ambazo zitaifanya faili itende tofauti. Unaweza **kuangalia bendera** za faili ndani ya directory kwa `ls -lO /path/directory`

- **`uchg`**: Inajulikana kama **uchange** bendera itazuia **kitendo chochote** kubadilisha au kufuta **faili**. Ili kuipatia, fanya: `chflags uchg file.txt`
- Mtumiaji wa root anaweza **kuondoa bendera** na kubadilisha faili.
- **`restricted`**: Bendera hii inafanya faili kuwa **lindwa na SIP** (huwezi kuongeza bendera hii kwenye faili).
- **`Sticky bit`**: Ikiwa directory ina sticky bit, **tu** mmiliki wa **directory au root anaweza kubadilisha jina au kufuta** faili. Kawaida hii huwekwa kwenye directory ya /tmp ili kuzuia watumiaji wa kawaida kufuta au kuhamasisha faili za watumiaji wengine.

Bendera zote zinaweza kupatikana katika faili `sys/stat.h` (ipate kwa kutumia `mdfind stat.h | grep stat.h`) na ni:

- `UF_SETTABLE` 0x0000ffff: Mask ya bendera zinazoweza kubadilishwa na mmiliki.
- `UF_NODUMP` 0x00000001: Usifute faili.
- `UF_IMMUTABLE` 0x00000002: Faili haiwezi kubadilishwa.
- `UF_APPEND` 0x00000004: Maandishi kwenye faili yanaweza tu kuongezwa.
- `UF_OPAQUE` 0x00000008: Directory ni opaque kuhusiana na umoja.
- `UF_COMPRESSED` 0x00000020: Faili imepigwa.
- `UF_TRACKED` 0x00000040: Hakuna arifa za kufuta/kubadilisha jina kwa faili zilizo na hii.
- `UF_DATAVAULT` 0x00000080: Haki inahitajika kwa kusoma na kuandika.
- `UF_HIDDEN` 0x00008000: Kidokezo kwamba kipengele hiki hakipaswi kuonyeshwa kwenye GUI.
- `SF_SUPPORTED` 0x009f0000: Mask ya bendera zinazoungwa mkono na superuser.
- `SF_SETTABLE` 0x3fff0000: Mask ya bendera zinazoweza kubadilishwa na superuser.
- `SF_SYNTHETIC` 0xc0000000: Mask ya bendera za mfumo zisizoweza kubadilishwa.
- `SF_ARCHIVED` 0x00010000: Faili imehifadhiwa.
- `SF_IMMUTABLE` 0x00020000: Faili haiwezi kubadilishwa.
- `SF_APPEND` 0x00040000: Maandishi kwenye faili yanaweza tu kuongezwa.
- `SF_RESTRICTED` 0x00080000: Haki inahitajika kwa kuandika.
- `SF_NOUNLINK` 0x00100000: Kipengele hakiwezi kuondolewa, kubadilishwa jina au kuunganishwa.
- `SF_FIRMLINK` 0x00800000: Faili ni firmlink.
- `SF_DATALESS` 0x40000000: Faili ni kitu kisichokuwa na data.

### **ACLs za Faili**

**ACLs** za faili zina **ACE** (Entries za Udhibiti wa Ufikiaji) ambapo ruhusa **za kina zaidi** zinaweza kutolewa kwa watumiaji tofauti.

Inawezekana kutoa **directory** hizi ruhusa: `orodhesha`, `tafuta`, `ongeza_faili`, `ongeza_subdirectory`, `futa_mtoto`, `futa_mtoto`.\
Na kwa **faili**: `soma`, `andika`, `ongeza`, `tekeleza`.

Wakati faili ina ACLs utapata **"+" unapoorodhesha ruhusa kama katika**:
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
### Sifa Zilizopanuliwa

Sifa zilizopanuliwa zina jina na thamani yoyote inayotakiwa, na zinaweza kuonekana kwa kutumia `ls -@` na kubadilishwa kwa kutumia amri `xattr`. Baadhi ya sifa za kawaida zilizopanuliwa ni:

- `com.apple.resourceFork`: Ufanisi wa rasilimali. Pia inaonekana kama `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Mekanismu ya karantini ya Gatekeeper (III/6)
- `metadata:*`: MacOS: metadata mbalimbali, kama vile `_backup_excludeItem`, au `kMD*`
- `com.apple.lastuseddate` (#PS): Tarehe ya matumizi ya mwisho ya faili
- `com.apple.FinderInfo`: MacOS: Taarifa za Finder (mfano, alama za rangi)
- `com.apple.TextEncoding`: Inabainisha uandishi wa faili za maandiko ya ASCII
- `com.apple.logd.metadata`: Inatumika na logd kwenye faili katika `/var/db/diagnostics`
- `com.apple.genstore.*`: Hifadhi ya kizazi (`/.DocumentRevisions-V100` katika mzizi wa mfumo wa faili)
- `com.apple.rootless`: MacOS: Inatumika na Ulinzi wa Uadilifu wa Mfumo kuweka lebo ya faili (III/10)
- `com.apple.uuidb.boot-uuid`: alama za logd za nyakati za boot zenye UUID ya kipekee
- `com.apple.decmpfs`: MacOS: Usawazishaji wa faili wa uwazi (II/7)
- `com.apple.cprotect`: \*OS: Takwimu za usimbaji wa faili (III/11)
- `com.apple.installd.*`: \*OS: Metadata inayotumika na installd, mfano, `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Hii ni njia ya kupata **Mito Mbadala ya Takwimu katika Mashine za MacOS**. Unaweza kuhifadhi maudhui ndani ya sifa iliyopanuliwa inayoitwa **com.apple.ResourceFork** ndani ya faili kwa kuihifadhi katika **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Unaweza **kupata faili zote zinazokuwa na sifa hii ya ziada** kwa:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Sifa ya kupanua `com.apple.decmpfs` inaonyesha kwamba faili imehifadhiwa kwa njia ya usimbaji, `ls -l` itaripoti **kiasi cha 0** na data iliyoshinikizwa iko ndani ya sifa hii. Kila wakati faili inapoingia, itafunguliwa katika kumbukumbu.

Sifa hii inaweza kuonekana na `ls -lO` ikionyeshwa kama iliyoshinikizwa kwa sababu faili zilizoshinikizwa pia zimewekwa alama na bendera `UF_COMPRESSED`. Ikiwa faili iliyoshinikizwa itafutwa bendera hii kwa `chflags nocompressed </path/to/file>`, mfumo hautajua kwamba faili ilikuwa imepandwa na kwa hivyo hautaweza kuifungua na kufikia data (utadhani kwamba ni tupu).

Zana afscexpand inaweza kutumika kulazimisha kufungua faili.

## **Universal binaries &** Mach-o Format

Mac OS binaries kawaida huandikwa kama **universal binaries**. **Universal binary** inaweza **kuunga mkono usanifu mbalimbali katika faili moja**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOS Process Memory

## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Direktori `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ndiko ambapo taarifa kuhusu **hatari inayohusiana na nyongeza tofauti za faili inahifadhiwa**. Direktori hii inagawanya faili katika viwango mbalimbali vya hatari, ikishawishi jinsi Safari inavyoshughulikia faili hizi wakati wa kupakua. Kategoria ni kama ifuatavyo:

- **LSRiskCategorySafe**: Faili katika kategoria hii zinachukuliwa kuwa **salama kabisa**. Safari itafungua faili hizi moja kwa moja baada ya kupakuliwa.
- **LSRiskCategoryNeutral**: Faili hizi hazina onyo lolote na **hazifunguliwi moja kwa moja** na Safari.
- **LSRiskCategoryUnsafeExecutable**: Faili chini ya kategoria hii **zinatoa onyo** linaloashiria kwamba faili ni programu. Hii inatumika kama hatua ya usalama kumjulisha mtumiaji.
- **LSRiskCategoryMayContainUnsafeExecutable**: Kategoria hii ni kwa faili, kama vile archives, ambazo zinaweza kuwa na executable. Safari itatoa **onyo** isipokuwa inaweza kuthibitisha kwamba maudhui yote ni salama au ya kawaida.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Inahifadhi taarifa kuhusu faili zilizopakuliwa, kama URL kutoka ambapo zilipakuliwa.
- **`/var/log/system.log`**: Kumbukumbu kuu ya mifumo ya OSX. com.apple.syslogd.plist inawajibika kwa utekelezaji wa syslogging (unaweza kuangalia ikiwa imezimwa kwa kutafuta "com.apple.syslogd" katika `launchctl list`).
- **`/private/var/log/asl/*.asl`**: Hizi ni Apple System Logs ambazo zinaweza kuwa na taarifa za kuvutia.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Inahifadhi faili na programu zilizofikiwa hivi karibuni kupitia "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Inahifadhi vitu vya kuzindua wakati wa kuanzisha mfumo.
- **`$HOME/Library/Logs/DiskUtility.log`**: Faili ya kumbukumbu ya programu ya DiskUtility (taarifa kuhusu diski, ikiwa ni pamoja na USB).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Taarifa kuhusu maeneo ya upatikanaji wa wireless.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Orodha ya daemons zilizozimwa.

{{#include ../../../banners/hacktricks-training.md}}
