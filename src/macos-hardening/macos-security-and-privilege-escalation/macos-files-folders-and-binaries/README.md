# macOS Files, Folders, Binaries & Memory

{{#include ../../../banners/hacktricks-training.md}}

## File hierarchy layout

- **/Applications**: Installed apps यहां होने चाहिए। सभी users इन्हें access कर सकेंगे।
- **/bin**: Command line binaries
- **/cores**: यदि मौजूद हो, तो इसका उपयोग core dumps store करने के लिए किया जाता है।
- **/dev**: हर चीज़ को file माना जाता है, इसलिए यहां hardware devices stored दिखाई दे सकते हैं।
- **/etc**: Configuration files
- **/Library**: Preferences, caches और logs से संबंधित कई subdirectories और files यहां मिल सकती हैं। एक Library folder root में और प्रत्येक user की directory में मौजूद होता है।
- **/private**: Undocumented है, लेकिन उल्लेखित कई folders private directory के symbolic links हैं।
- **/sbin**: Essential system binaries (administration से संबंधित)
- **/System**: OS X को run कराने वाली files। यहां मुख्यतः केवल Apple-specific files मिलनी चाहिए (third-party नहीं)।
- **/tmp**: Files 3 दिनों के बाद delete हो जाती हैं (यह /private/tmp की soft link है)
- **/Users**: Users की home directory।
- **/usr**: Config और system binaries
- **/var**: Log files
- **/Volumes**: Mounted drives यहां दिखाई देंगी।
- **/.vol**: `stat a.txt` run करने पर आपको `16777223 7545753 -rw-r--r-- 1 username wheel ...` जैसा कुछ प्राप्त होता है, जहां पहली संख्या उस volume की id number है जिसमें file मौजूद है और दूसरी inode number है। इस जानकारी का उपयोग करके `cat /.vol/16777223/7545753` run करने पर आप इस file के content को `/.vol/` के माध्यम से access कर सकते हैं।

### Applications Folders

- **System applications** `/System/Applications` के अंतर्गत located होती हैं।
- **Installed** applications आमतौर पर `/Applications` या `~/Applications` में installed होती हैं।
- **Application data** root के रूप में run होने वाली applications के लिए `/Library/Application Support` में और user के रूप में run होने वाली applications के लिए `~/Library/Application Support` में मिल सकता है।
- Third-party applications के **daemons** जिन्हें **root के रूप में run करना आवश्यक है**, आमतौर पर `/Library/PrivilegedHelperTools/` में located होते हैं।
- **Sandboxed** apps को `~/Library/Containers` folder में map किया जाता है। प्रत्येक app का folder उसके application के bundle ID (`com.apple.Safari`) के अनुसार named होता है।
- **kernel** `/System/Library/Kernels/kernel` में located होता है।
- **Apple's kernel extensions** `/System/Library/Extensions` में located होती हैं।
- **Third-party kernel extensions** `/Library/Extensions` में stored होती हैं।

### Files with Sensitive Information

MacOS passwords जैसी information को कई locations में store करता है:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Vulnerable pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X Specific Extensions

- **`.dmg`**: Apple Disk Image files installers के लिए बहुत common हैं।
- **`.kext`**: इसे एक specific structure follow करनी होती है और यह driver का OS X version है। (यह एक bundle है)
- **`.plist`**: Property list के रूप में भी जाना जाता है; यह information को XML या binary format में store करता है।
- XML या binary हो सकता है। Binary files को इनसे read किया जा सकता है:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple applications जो directory structure follow करती हैं (यह एक bundle है)।
- **`.dylib`**: Dynamic libraries (Windows DLL files के समान)
- **`.pkg`**: ये xar (eXtensible Archive format) के समान हैं। इन files के contents को install करने के लिए installer command का उपयोग किया जा सकता है।
- **`.DS_Store`**: यह file प्रत्येक directory में होती है और directory के attributes तथा customisations को save करती है।
- **`.Spotlight-V100`**: यह folder system के प्रत्येक volume की root directory में दिखाई देता है।
- **`.metadata_never_index`**: यदि यह file किसी volume की root में हो, तो Spotlight उस volume को index नहीं करेगा।
- **`.noindex`**: इस extension वाली files और folders को Spotlight द्वारा index नहीं किया जाएगा।
- **`.sdef`**: Bundles के अंदर मौजूद files, जो specify करती हैं कि AppleScript से application के साथ interact करना कैसे संभव है।

### macOS Bundles

Bundle एक **directory** होती है जो **Finder में किसी object जैसी दिखाई देती है** (Bundle का एक example `*.app` files हैं)।


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS (और iOS) पर सभी system shared libraries, जैसे frameworks और dylibs, **एक single file में combined** होती हैं, जिसे **dyld shared cache** कहा जाता है। इससे performance बेहतर हुई, क्योंकि code को अधिक तेजी से load किया जा सकता है।

macOS में यह `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` में located होता है और पुराने versions में आपको **shared cache** **`/System/Library/dyld/`** में मिल सकता है।\
iOS में इन्हें **`/System/Library/Caches/com.apple.dyld/`** में पाया जा सकता है।

dyld shared cache के समान, kernel और kernel extensions भी एक kernel cache में compiled होते हैं, जिसे boot time पर load किया जाता है।

Single file dylib shared cache से libraries extract करने के लिए पहले binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) का उपयोग किया जा सकता था, जो आजकल शायद काम न करे; लेकिन आप [**dyldextractor**](https://github.com/arandomdev/dyldextractor) का भी उपयोग कर सकते हैं:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> ध्यान दें कि यदि `dyld_shared_cache_util` tool काम न करे, तो आप **shared dyld binary को Hopper में पास कर सकते हैं** और Hopper सभी libraries की पहचान कर सकेगा तथा आपको यह **चुनने देगा कि किसकी जांच करनी है**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

कुछ extractors काम नहीं करेंगे, क्योंकि dylibs में hard coded addresses के साथ prelinked होते हैं, इसलिए वे unknown addresses पर jump कर सकते हैं।

> [!TIP]
> Xcode में emulator का उपयोग करके macos में अन्य \*OS devices का Shared Library Cache download करना भी संभव है। वे इस स्थान के अंदर download होंगे: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, जैसे:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** यह जानने के लिए syscall **`shared_region_check_np`** का उपयोग करता है कि SLC map किया गया है या नहीं (जो address लौटाता है), और SLC को map करने के लिए **`shared_region_map_and_slide_np`** का उपयोग करता है।

ध्यान दें कि पहली बार उपयोग किए जाने पर SLC के slid होने के बावजूद, सभी **processes** **एक ही copy** का उपयोग करते हैं, जिससे यदि attacker system में processes चलाने में सक्षम हो, तो **ASLR** protection समाप्त हो जाती है। इसका वास्तव में अतीत में exploit किया गया था और shared region pager के साथ इसे ठीक किया गया।

Branch pools छोटी Mach-O dylibs होती हैं, जो image mappings के बीच छोटे spaces बनाती हैं और functions को interpose करना असंभव बना देती हैं।

### Override SLCs

इन env variables का उपयोग करके:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> यह एक नया shared library cache load करने की अनुमति देगा
- **`DYLD_SHARED_CACHE_DIR=avoid`** और libraries को manually shared cache के symlinks से real ones के साथ replace करें (आपको उन्हें extract करना होगा)

## Special File Permissions

### Folder permissions

एक **folder** में **read** उसे **list** करने की अनुमति देता है, **write** उस पर files को **delete** और **write** करने की अनुमति देता है, और **execute** directory को **traverse** करने की अनुमति देता है। इसलिए, उदाहरण के लिए, किसी ऐसे directory के अंदर मौजूद **file पर read permission** रखने वाला user, जिस पर उसके पास **execute** permission नहीं है, वह उस file को **read** नहीं कर पाएगा।

### Flag modifiers

कुछ flags files में set किए जा सकते हैं, जो file के व्यवहार को बदल देते हैं। आप किसी directory के अंदर files के **flags** को `ls -lO /path/directory` से **check** कर सकते हैं।

- **`uchg`**: **uchange** flag के रूप में जाना जाता है और यह **file** को बदलने या delete करने वाली **किसी भी action** को रोकता है। इसे set करने के लिए: `chflags uchg file.txt`
- root user **flag को remove** कर सकता है और file को modify कर सकता है
- **`restricted`**: यह flag file को **SIP द्वारा protected** बनाता है (आप किसी file में यह flag add नहीं कर सकते)।
- **`Sticky bit`**: यदि किसी directory में sticky bit हो, तो केवल **directory का owner या root ही files को rename या delete** कर सकता है। आम तौर पर इसे /tmp directory पर set किया जाता है, ताकि ordinary users अन्य users की files को delete या move न कर सकें।

सभी flags `sys/stat.h` file में मिल सकते हैं (`mdfind stat.h | grep stat.h` का उपयोग करके इसे find करें) और वे हैं:

- `UF_SETTABLE` 0x0000ffff: Owner द्वारा बदले जा सकने वाले flags का mask।
- `UF_NODUMP` 0x00000001: File को dump न करें।
- `UF_IMMUTABLE` 0x00000002: File को बदला नहीं जा सकता।
- `UF_APPEND` 0x00000004: File में writes केवल append की जा सकती हैं।
- `UF_OPAQUE` 0x00000008: Directory union के संबंध में opaque है।
- `UF_COMPRESSED` 0x00000020: File compressed है (कुछ file-systems)।
- `UF_TRACKED` 0x00000040: जिन files में यह set है, उनके deletes/renames के लिए कोई notifications नहीं।
- `UF_DATAVAULT` 0x00000080: Reading और writing के लिए entitlement आवश्यक है।
- `UF_HIDDEN` 0x00008000: संकेत कि यह item GUI में display नहीं किया जाना चाहिए।
- `SF_SUPPORTED` 0x009f0000: Superuser द्वारा supported flags का mask।
- `SF_SETTABLE` 0x3fff0000: Superuser द्वारा बदले जा सकने वाले flags का mask।
- `SF_SYNTHETIC` 0xc0000000: System read-only synthetic flags का mask।
- `SF_ARCHIVED` 0x00010000: File archived है।
- `SF_IMMUTABLE` 0x00020000: File को बदला नहीं जा सकता।
- `SF_APPEND` 0x00040000: File में writes केवल append की जा सकती हैं।
- `SF_RESTRICTED` 0x00080000: Writing के लिए entitlement आवश्यक है।
- `SF_NOUNLINK` 0x00100000: Item को remove, rename या mount नहीं किया जा सकता।
- `SF_FIRMLINK` 0x00800000: File एक firmlink है।
- `SF_DATALESS` 0x40000000: File dataless object है।

### **File ACLs**

File **ACLs** में **ACE** (Access Control Entries) होते हैं, जिनके माध्यम से अलग-अलग users को अधिक **granular permissions** assign की जा सकती हैं।

किसी **directory** को ये permissions देना संभव है: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
और किसी **file** को: `read`, `write`, `append`, `execute`.

जब file में ACLs होते हैं, तो **permissions list करते समय आपको एक "+" दिखाई देगा, जैसा कि यहां है**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
आप फ़ाइल के **ACLs** को इस कमांड से **read** कर सकते हैं:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
आप **ACLs वाली सभी files** को इस command से ढूँढ सकते हैं (यह बहुत ही धीमा है):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes का एक name और कोई भी desired value होता है, और इन्हें `ls -@` का उपयोग करके देखा तथा `xattr` command का उपयोग करके manipulate किया जा सकता है। कुछ common extended attributes हैं:

- `com.apple.resourceFork`: Resource fork compatibility। इसे `filename/..namedfork/rsrc` के रूप में भी देखा जा सकता है।
- `com.apple.quarantine`: MacOS: Gatekeeper quarantine mechanism (III/6)
- `metadata:*`: MacOS: विभिन्न metadata, जैसे `_backup_excludeItem` या `kMD*`
- `com.apple.lastuseddate` (#PS): File के last use की date
- `com.apple.FinderInfo`: MacOS: Finder information (जैसे, color Tags)
- `com.apple.TextEncoding`: ASCII text files की text encoding निर्दिष्ट करता है
- `com.apple.logd.metadata`: `/var/db/diagnostics` में files पर logd द्वारा उपयोग किया जाता है
- `com.apple.genstore.*`: Generational storage (filesystem के root में `/.DocumentRevisions-V100`)
- `com.apple.rootless`: MacOS: System Integrity Protection द्वारा file को label करने के लिए उपयोग किया जाता है (III/10)
- `com.apple.uuidb.boot-uuid`: Unique UUID के साथ boot epochs के logd markings
- `com.apple.decmpfs`: MacOS: Transparent file compression (II/7)
- `com.apple.cprotect`: \*OS: Per-file encryption data (III/11)
- `com.apple.installd.*`: \*OS: installd द्वारा उपयोग किया जाने वाला metadata, जैसे `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

यह **MacOS** machines में **Alternate Data Streams** प्राप्त करने का एक तरीका है। किसी file के अंदर **com.apple.ResourceFork** नामक extended attribute में content को `file/..namedfork/rsrc` में save करके रखा जा सकता है।
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
आप **इस extended attribute वाले सभी files को निम्नलिखित तरीके से खोज सकते हैं**:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

विस्तारित attribute `com.apple.decmpfs` यह दर्शाता है कि file encrypted रूप में stored है, `ls -l` **size 0** report करेगा और compressed data इसी attribute के अंदर होता है। जब भी file को access किया जाएगा, इसे memory में decrypt किया जाएगा।

इस attr को `ls -lO` के साथ देखा जा सकता है, जहाँ इसे compressed के रूप में दर्शाया जाता है क्योंकि compressed files को `UF_COMPRESSED` flag से भी tag किया जाता है। यदि किसी compressed file से `chflags nocompressed </path/to/file>` द्वारा यह flag हटा दिया जाता है, तो system को पता नहीं चलेगा कि file compressed थी और इसलिए वह data को decompress करके access नहीं कर पाएगा (system इसे वास्तव में empty समझेगा)।

Tool afscexpand का उपयोग किसी file को force decompress करने के लिए किया जा सकता है।


### Interesting configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Apple की feature-flag plist files को store करता है, जो system daemons / frameworks में optional या experimental behaviors को control करती हैं | यदि attacker SIP को bypass कर सकता है या privilege प्राप्त कर सकता है, तो इनमें tampering करके hidden code paths enable किए जा सकते हैं या safeguards disable किए जा सकते हैं |
| `/System/Library/CoreServices/systemVersion.plist` | Apps / installers द्वारा behavior को gate करने के लिए उपयोग किए जाने वाले macOS version metadata (ProductVersion, BuildVersion) रखता है | Modification से apps या installers को unsupported OS versions स्वीकार करने या features unlock करने के लिए trick किया जा सकता है |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | यदि writable हों, तो attackers app behavior को steer करने, protections disable करने या misconfiguration उत्पन्न करने के लिए settings inject कर सकते हैं |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Background daemons और agents के लिए plist definitions | Malicious plist insertion या manipulation (यदि permissions अनुमति दें) persistence या privilege escalations को enable करता है |
| `/etc/hosts` | System DNS resolver द्वारा उपयोग किए जाने वाले Hostname ↔ IP mappings | Domain names को redirect करना, traffic intercept करना और local control के अंतर्गत services spoof करना |
| `/etc/sudoers` | यह define करता है कि कौन `sudo` के साथ commands चला सकता है और किन conditions के अंतर्गत | Corrupted sudoers file attacker accounts को root या अनुचित privileges प्रदान कर सकती है |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account definition plists | Tampering से user accounts, password hashes या user metadata create अथवा modify किए जा सकते हैं |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Kexts को install या modify करने से kernel-level control प्राप्त हो सकता है; SIP / signature policies द्वारा कड़ाई से protected |
| `/private/var/db/SystemPolicyConfiguration/` | System policy enforcement (जैसे Gatekeeper, notarization) के लिए configuration store करता है | इनमें tampering करने से policy checks या trust rules को circumvent किया जा सकता है |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries और config files | Misconfiguration से weak SSH security, unauthorized access या insecure algorithms उत्पन्न हो सकते हैं |
| `/System/Library/Sandbox/Profiles` | Process actions को restrict करने के लिए उपयोग किए जाने वाले system sandbox profiles (SBPL) | Profiles को replace या alter करने से sandbox escape vectors खुल सकते हैं या containment कमजोर हो सकता है |

> **Note**: इनमें से कई paths SIP-protected directories (जैसे `/System`) के अंतर्गत हैं और writes से protected हैं, जब तक SIP disable या bypass न किया जाए।


## **Universal binaries &** Mach-o Format

Mac OS binaries आमतौर पर **universal binaries** के रूप में compiled होते हैं। एक **universal binary** **एक ही file में multiple architectures को support कर सकता है**।

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` में अलग-अलग file extensions से जुड़े **risk** की information stored होती है। यह directory files को विभिन्न risk levels में categorize करती है, जिससे download के बाद Safari इन files को कैसे handle करता है, यह प्रभावित होता है। Categories इस प्रकार हैं:

- **LSRiskCategorySafe**: इस category की files **completely safe** मानी जाती हैं। Download होने के बाद Safari इन files को automatically open कर देगा।
- **LSRiskCategoryNeutral**: इन files के साथ कोई warnings नहीं आतीं और Safari इन्हें **automatically open नहीं करता**।
- **LSRiskCategoryUnsafeExecutable**: इस category की files **warning trigger करती हैं**, जिसमें बताया जाता है कि file एक application है। यह user को alert करने के लिए security measure के रूप में कार्य करता है।
- **LSRiskCategoryMayContainUnsafeExecutable**: यह category archives जैसी files के लिए है, जिनमें executable हो सकता है। Safari **warning trigger करेगा**, जब तक कि वह verify न कर सके कि सभी contents safe या neutral हैं।

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Downloaded files के बारे में information रखता है, जैसे वह URL जहाँ से वे download की गई थीं।
- **`/var/log/system.log`**: OSX systems का मुख्य log। com.apple.syslogd.plist syslogging के execution के लिए responsible है (आप `launchctl list` में "com.apple.syslogd" देखकर check कर सकते हैं कि यह disabled है या नहीं)।
- **`/private/var/log/asl/*.asl`**: ये Apple System Logs हैं, जिनमें interesting information हो सकती है।
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" के माध्यम से recently accessed files और applications को store करता है।
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: System startup के समय launch होने वाले items को store करता है
- **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility App की log file (drives, including USBs, के बारे में information)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Wireless access points के बारे में data।
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Deactivated daemons की list।

{{#include ../../../banners/hacktricks-training.md}}
