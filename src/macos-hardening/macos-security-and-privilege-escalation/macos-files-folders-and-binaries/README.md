# macOS Files, Folders, Binaries & Memory

{{#include ../../../banners/hacktricks-training.md}}

## फ़ाइल hierarchy layout

Apple macOS filesystem को system, local, network और user domains की hierarchy के रूप में document करता है। सटीक contents OS release के अनुसार अलग-अलग होते हैं, और system locations को increasingly protected या synthesized किया जा रहा है। <sup>[[1]](#references)</sup>

- **/Applications**: Installed apps यहां होनी चाहिए। सभी users इन तक पहुंच सकेंगे।
- **/bin**: Command line binaries
- **/cores**: यदि मौजूद हो, तो core dumps store करने के लिए उपयोग किया जाता है
- **/dev**: हर चीज़ को file माना जाता है, इसलिए यहां hardware devices stored दिखाई दे सकते हैं।
- **/etc**: Configuration files
- **/Library**: Preferences, caches और logs से संबंधित कई subdirectories और files यहां मिल सकती हैं। एक Library folder root में और प्रत्येक user की directory में मौजूद होता है।
- **/private**: Undocumented है, लेकिन ऊपर बताई गई कई folders, private directory की symbolic links हैं।
- **/sbin**: Essential system binaries (administration से संबंधित)
- **/System**: macOS के लिए आवश्यक files; इस tree में मुख्यतः Apple-provided components होते हैं।
- **/tmp**: Temporary files (एक symbolic link से `/private/tmp` पर)। Historical installations आमतौर पर पुराने temporary files को periodic schedule पर साफ करती थीं, जिसे कभी-कभी three days के रूप में बताया जाता था, लेकिन वर्तमान cleanup timing system और policy पर निर्भर करती है; वहां data के persist होने पर भरोसा न करें।
- **/Users**: Users की home directory।
- **/usr**: Config और system binaries
- **/var**: Log files
- **/Volumes**: Mounted volumes यहां दिखाई देते हैं।
- **/.vol**: `stat a.txt` चलाने पर आपको कुछ ऐसा प्राप्त होता है: `16777223 7545753 -rw-r--r-- 1 username wheel ...`, जहां पहली संख्या उस volume की id number है जिसमें file मौजूद है और दूसरी inode number है। इस information के साथ `cat /.vol/16777223/7545753` चलाकर आप इस file के content को `/.vol/` के माध्यम से access कर सकते हैं।

### Applications Folders

- **System applications** `/System/Applications` के अंतर्गत located होती हैं।
- **Installed** applications आमतौर पर `/Applications` या `~/Applications` में installed होती हैं।
- **Application data** root के रूप में running applications के लिए `/Library/Application Support` में और user के रूप में running applications के लिए `~/Library/Application Support` में मिल सकता है।
- Third-party application **daemons**, जिन्हें **root के रूप में run होना आवश्यक है**, आमतौर पर `/Library/PrivilegedHelperTools/` में located होते हैं।
- **Sandboxed** apps को `~/Library/Containers` folder में map किया जाता है। प्रत्येक app के पास उसके application’s bundle ID (`com.apple.Safari`) के अनुसार नामित एक folder होता है।
- **kernel** `/System/Library/Kernels/kernel` में located होता है।
- **Apple's kernel extensions** `/System/Library/Extensions` में located होती हैं।
- **Third-party kernel extensions** `/Library/Extensions` में stored होती हैं।

### Files with Sensitive Information

macOS credentials सहित sensitive information को कई locations पर store करता है:


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
- **`.plist`**: एक property list structured information को XML या binary format में store करती है।
- XML या binary हो सकता है। Binary files को इनसे read किया जा सकता है:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: एक application bundle जो standard macOS directory structure follow करता है।
- **`.dylib`**: Dynamic libraries (Windows DLL files के समान)
- **`.pkg`**: ये xar (eXtensible Archive format) के समान हैं। इन files के contents को install करने के लिए installer command का उपयोग किया जा सकता है।
- **`.DS_Store`**: यह file प्रत्येक directory में होती है और directory के attributes तथा customisations save करती है।
- **`.Spotlight-V100`**: यह folder system के प्रत्येक volume की root directory में दिखाई देता है।
- **`.metadata_never_index`**: यदि यह file किसी volume की root में हो, तो Spotlight उस volume को index नहीं करेगा।
- **`.noindex`**: इस extension वाली files और folders को Spotlight द्वारा index नहीं किया जाएगा।
- **`.sdef`**: एक scripting definition file जो बताती है कि AppleScript किसी application के साथ किस तरह interact कर सकता है।

### macOS Bundles

Bundle एक standardized hierarchy वाली directory है, जिसे Finder एक single object के रूप में present कर सकता है; application bundles `.app` extension का उपयोग करते हैं। <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS और iOS पर commonly used system libraries और frameworks को **dyld shared cache** में prelink किया जाता है, जिससे application startup performance बेहतर होती है। हालांकि इसे एक logical cache के रूप में treat किया जाता है, current releases इसे main cache और multiple subcache files के रूप में store कर सकते हैं, न कि literally एक ही file के रूप में। इसका format और location implementation details हैं, जो अलग-अलग OS releases में बदलते रहते हैं। <sup>[[3]](#references)</sup>

यह macOS में `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` पर located है और पुराने versions में आप **shared cache** को **`/System/Library/dyld/`** में पा सकते हैं।\
iOS में आप इन्हें **`/System/Library/Caches/com.apple.dyld/`** में पा सकते हैं।

dyld shared cache के समान, kernel और kernel extensions भी kernel cache में compiled होते हैं, जिसे boot time पर load किया जाता है।

Older releases को [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) से extract किया जा सकता था। यह build current cache formats को support नहीं कर सकता; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) एक अन्य option है:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> ध्यान दें कि यदि `dyld_shared_cache_util` tool काम नहीं करता है, तो आप **shared dyld binary को Hopper में पास** कर सकते हैं और Hopper सभी libraries की पहचान कर लेगा तथा आपको यह **चुनने देगा कि किसकी** जाँच करनी है:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

कुछ extractors काम नहीं करेंगे क्योंकि dylibs में hard coded addresses के साथ prelink किया गया होता है, इसलिए वे unknown addresses पर jump कर सकते हैं।

> [!TIP]
> Xcode में emulator का उपयोग करके macos में अन्य \*OS devices का Shared Library Cache डाउनलोड करना भी संभव है। वे यहाँ डाउनलोड होंगे: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, जैसे:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** यह जानने के लिए syscall **`shared_region_check_np`** का उपयोग करता है कि SLC map किया गया है या नहीं (जो address लौटाता है), और SLC को map करने के लिए **`shared_region_map_and_slide_np`** का उपयोग करता है।

ध्यान दें कि पहली बार उपयोग किए जाने पर SLC के slid होने के बावजूद, सभी **processes** **एक ही copy** का उपयोग करते हैं, जिससे यदि attacker system में processes चला पाने में सक्षम हो, तो **ASLR** protection समाप्त हो जाती है। इसका वास्तव में अतीत में exploit किया गया था और shared region pager के साथ इसे ठीक किया गया।

Branch pools छोटी Mach-O dylibs होती हैं, जो image mappings के बीच छोटे spaces बनाती हैं और functions को interpose करना असंभव बना देती हैं।

### Override SLCs

इन env variables का उपयोग करके:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> यह एक नया shared library cache load करने की अनुमति देगा
- **`DYLD_SHARED_CACHE_DIR=avoid`** और libraries को manually shared cache की symlinks से वास्तविक libraries के साथ replace करें (आपको उन्हें extract करना होगा)

## Special File Permissions

### Folder permissions

किसी directory के लिए, **read** entries की listing की अनुमति देता है, **write** entries बनाने या हटाने की अनुमति देता है, और **execute** traversal की अनुमति देता है। इसलिए, जो user किसी file को read कर सकता है लेकिन parent directory को traverse नहीं कर सकता, वह उस file को path के माध्यम से access नहीं कर सकता। <sup>[[4]](#references)</sup>

### Flag modifiers

Files ऐसे flags रख सकती हैं जो उनके behavior को बदलते हैं। किसी directory में flags को `ls -lO /path/directory` से inspect करें।

- **`uchg`**: **uchange** flag के नाम से जाना जाने वाला यह flag **file** को बदलने या delete करने वाली **किसी भी action को रोकता है**। इसे set करने के लिए: `chflags uchg file.txt`
- root user **flag को remove** करके file को modify कर सकता है
- **`restricted`**: यह flag file को **SIP द्वारा protected** बनाता है (आप इस flag को किसी file में add नहीं कर सकते)।
- **`Sticky bit`**: sticky bit set वाली directory में केवल file owner, directory owner या root ही किसी entry का नाम बदल या उसे delete कर सकता है। Users को अन्य users की files delete या move करने से रोकने के लिए इसे आमतौर पर `/tmp` पर enable किया जाता है।

सभी flags `sys/stat.h` file में पाए जा सकते हैं (`mdfind stat.h | grep stat.h` का उपयोग करके इसे खोजें) और वे हैं:

- `UF_SETTABLE` 0x0000ffff: Owner द्वारा change किए जा सकने वाले flags का mask।
- `UF_NODUMP` 0x00000001: File को dump न करें।
- `UF_IMMUTABLE` 0x00000002: File को बदला नहीं जा सकता।
- `UF_APPEND` 0x00000004: File में writes केवल append किए जा सकते हैं।
- `UF_OPAQUE` 0x00000008: Directory union के संबंध में opaque है।
- `UF_COMPRESSED` 0x00000020: File compressed है (कुछ file-systems)।
- `UF_TRACKED` 0x00000040: जिन files पर यह set है, उनके deletes/renames के लिए कोई notifications नहीं।
- `UF_DATAVAULT` 0x00000080: Reading और writing के लिए entitlement आवश्यक है।
- `UF_HIDDEN` 0x00008000: संकेत कि यह item GUI में प्रदर्शित नहीं किया जाना चाहिए।
- `SF_SUPPORTED` 0x009f0000: Superuser द्वारा supported flags का mask।
- `SF_SETTABLE` 0x3fff0000: Superuser द्वारा change किए जा सकने वाले flags का mask।
- `SF_SYNTHETIC` 0xc0000000: System read-only synthetic flags का mask।
- `SF_ARCHIVED` 0x00010000: File archived है।
- `SF_IMMUTABLE` 0x00020000: File को बदला नहीं जा सकता।
- `SF_APPEND` 0x00040000: File में writes केवल append किए जा सकते हैं।
- `SF_RESTRICTED` 0x00080000: Writing के लिए entitlement आवश्यक है।
- `SF_NOUNLINK` 0x00100000: Item को remove, rename या mount नहीं किया जा सकता।
- `SF_FIRMLINK` 0x00800000: File एक firmlink है।
- `SF_DATALESS` 0x40000000: File dataless object है।

### **File ACLs**

File **ACLs** में **ACE** (Access Control Entries) होते हैं, जिनके माध्यम से अलग-अलग users को अधिक **granular permissions** दी जा सकती हैं।

किसी **directory** को ये permissions देना संभव है: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`।\
किसी **file** के लिए: `read`, `write`, `append` और `execute`।

जब file में ACLs होते हैं, तो permissions की listing में आपको **"+" दिखाई देगा, जैसे**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
आप file के **ACLs पढ़** सकते हैं:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
आप निम्न command से **ACLs वाली सभी files** ढूँढ सकते हैं (यह बहुत धीमी है):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes किसी file के सामान्य attributes से अलग stored named metadata values होते हैं। इन्हें `ls -l@` से list करें और `xattr` से inspect या modify करें। <sup>[[5]](#references)</sup> कुछ सामान्य extended attributes हैं:

- `com.apple.resourceFork`: Resource fork compatibility। `filename/..namedfork/rsrc` के रूप में भी दिखाई देता है
- `com.apple.quarantine`: macOS Gatekeeper quarantine metadata
- `metadata:*`: macOS metadata, जैसे `_backup_excludeItem` या `kMD*`
- `com.apple.lastuseddate` (#PS): File के last use की date
- `com.apple.FinderInfo`: macOS Finder information, जैसे color tags
- `com.apple.TextEncoding`: ASCII text files की text encoding निर्दिष्ट करता है
- `com.apple.logd.metadata`: `/var/db/diagnostics` में files पर logd द्वारा उपयोग किया जाता है
- `com.apple.genstore.*`: Generational storage (filesystem के root में `/.DocumentRevisions-V100`)
- `com.apple.rootless`: System Integrity Protection से संबंधित macOS metadata
- `com.apple.uuidb.boot-uuid`: unique UUID के साथ boot epochs के logd markings
- `com.apple.decmpfs`: macOS transparent file compression metadata
- `com.apple.cprotect`: \*OS: Per-file encryption data (III/11)
- `com.apple.installd.*`: \*OS: installd द्वारा उपयोग किया जाने वाला metadata, जैसे `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks macOS पर alternate data stream प्रदान करते हैं। Content को `com.apple.ResourceFork` extended attribute में store किया जा सकता है और `file/..namedfork/rsrc` के माध्यम से access किया जा सकता है।
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
आप इस extended attribute वाली सभी files को इस तरह **find** कर सकते हैं:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Extended attribute `com.apple.decmpfs` transparent compression के लिए metadata store करता है; यह encryption का संकेत नहीं देता। Compression format के आधार पर, compressed data attribute या resource fork में store किया जा सकता है और read किए जाने पर transparently decompress हो जाता है।

`UF_COMPRESSED` flag `ls -lO` में `compressed` के रूप में दिखाई देता है। इसे manually clear न करें: ऐसा करने पर system compressed representation की गलत व्याख्या कर सकता है।

यहाँ flag clear करने वाली command दिखाई गई है क्योंकि यह forensic review के दौरान उपयोगी है, लेकिन इसे compressed file पर चलाने से वह file तब तक empty या inaccessible दिखाई दे सकती है, जब तक उसका metadata repair न कर दिया जाए:
```bash
chflags nocompressed /path/to/file
```
अंतर्निहित `/usr/bin/afscexpand` utility transparently compressed files का expansion force कर सकती है। अलग third-party `afsctool` utility Apple filesystem compression का निरीक्षण या decompression भी कर सकती है, लेकिन इसे अंतर्निहित command समझने की भूल नहीं करनी चाहिए। <sup>[[8]](#references)</sup>


### Interesting configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | system daemons / frameworks में optional या experimental behaviors को नियंत्रित करने वाली Apple की feature-flag plist files संग्रहीत करता है | यदि attacker SIP को bypass कर सकता है या privilege प्राप्त कर सकता है, तो इनमें छेड़छाड़ hidden code paths को enable या safeguards को disable कर सकती है |
| `/System/Library/CoreServices/systemVersion.plist` | apps / installers द्वारा behavior को नियंत्रित करने के लिए उपयोग किया जाने वाला macOS version metadata (ProductVersion, BuildVersion) रखता है | Modification apps या installers को unsupported OS versions स्वीकार करने या features unlock करने के लिए भ्रमित कर सकता है |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | यदि writable हों, तो attackers app behavior को निर्देशित करने, protections को disable करने या misconfiguration उत्पन्न करने के लिए settings inject कर सकते हैं |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Background daemons और agents के लिए plist definitions | Malicious plist insertion या manipulation (यदि permissions अनुमति दें) persistence या privilege escalations सक्षम कर सकती है |
| `/etc/hosts` | System DNS resolver द्वारा उपयोग की जाने वाली Hostname ↔ IP mappings | Domain names redirect करना, traffic intercept करना, local control के अंतर्गत services spoof करना |
| `/etc/sudoers` | यह निर्धारित करता है कि कौन `sudo` के साथ commands चला सकता है और किन conditions के अंतर्गत | Corrupted sudoers file attacker accounts को root या अनुचित privileges दे सकती है |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account definition plists | Tampering से user accounts, password hashes या user metadata बनाए या modified किए जा सकते हैं |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Kexts को install या modify करने से kernel-level control प्राप्त हो सकता है; SIP / signature policies द्वारा कड़ी सुरक्षा की जाती है |
| `/private/var/db/SystemPolicyConfiguration/` | System policy enforcement (जैसे Gatekeeper, notarization) के लिए configuration संग्रहीत करता है | इनमें छेड़छाड़ policy checks या trust rules को circumvent करने की अनुमति दे सकती है |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries और config files | Misconfiguration से weak SSH security, unauthorized access या insecure algorithms हो सकते हैं |
| `/System/Library/Sandbox/Profiles` | Process actions को restrict करने के लिए उपयोग किए जाने वाले system sandbox profiles (SBPL) | Profiles को replace या alter करने से sandbox escape vectors खुल सकते हैं या containment कमजोर हो सकता है |

> **Note**: इनमें से कई paths SIP-protected directories (जैसे `/System`) के अंतर्गत हैं और SIP के disabled या bypass होने तक writes से protected रहते हैं।


## Universal Binaries And Mach-O Format

Mach-O macOS का native executable format है। Universal या fat binary एक ही file में multiple architecture-specific Mach-O slices को wrap करती है; dedicated page दोनों formats की व्याख्या करता है:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

LaunchServices, file quarantine और Gatekeeper मिलकर यह प्रभावित करते हैं कि macOS downloaded files को कैसे handle करता है और extensions तथा URL schemes के लिए applications का चयन कैसे करता है। इनके databases और internal resource files releases के बीच बदलते रहते हैं; किसी private CoreTypes path को stable policy interface मानने के बजाय dedicated pages का उपयोग करें:

जिन releases में legacy CoreTypes risk metadata `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` के अंतर्गत उपलब्ध होता है, उनमें सामान्यतः मिलने वाली categories हैं:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: ऐसा content जिसे लागू application policy के अंतर्गत automatic opening के लिए पर्याप्त रूप से safe माना जाता है।
- **`LSRiskCategoryNeutral`**: ऐसा content जो सामान्यतः warning trigger नहीं करता और automatically open नहीं होता।
- **`LSRiskCategoryUnsafeExecutable`**: ऐसा executable content जिसके लिए user को application warning मिलनी चाहिए।
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Archives जैसे containers जिनमें executable content हो सकता है और जिनकी further inspection आवश्यक है।

ये implementation details हैं, stable public policy API नहीं; test किए जा रहे macOS version पर actual metadata और Safari/Gatekeeper behavior की पुष्टि करें।

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Downloaded files के बारे में information रखता है, जैसे वे किस URL से download की गई थीं।
- **Unified log**: Current macOS versions पर `log show` और `log stream` के साथ system और application events query करें। <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** और **`/private/var/log/asl/*.asl`**: Legacy logging artifacts जो older systems पर अभी भी relevant हो सकते हैं। उन releases पर `/System/Library/LaunchDaemons/com.apple.syslogd.plist` `syslogd` को configure करता है; `launchctl list | grep com.apple.syslogd` यह निर्धारित करने में सहायता कर सकता है कि service loaded है या नहीं।
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" के माध्यम से recently accessed files और applications संग्रहीत करता है।
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Login items से संबद्ध legacy preference path; modern macOS versions additional mechanisms का उपयोग करते हैं।
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility log जिसमें drives, including USB devices, के बारे में information हो सकती है।
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Wireless access points के बारे में data।
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override data।

## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache overview](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS File System Security](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS manual page](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS manual page](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS manual page](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
