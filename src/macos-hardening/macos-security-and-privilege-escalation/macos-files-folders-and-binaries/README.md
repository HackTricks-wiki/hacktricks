# macOS फ़ाइलें, फ़ोल्डर, बाइनरी और मेमोरी

{{#include ../../../banners/hacktricks-training.md}}

## फ़ाइल सिस्टम का पदानुक्रम

Apple, macOS फ़ाइल सिस्टम को system, local, network और user domains के पदानुक्रम के रूप में दस्तावेज़ित करता है। सटीक सामग्री OS रिलीज़ के अनुसार अलग-अलग होती है, और system locations को अब अधिक सुरक्षित या synthesized किया जा रहा है। <sup>[[1]](#references)</sup>

- **/Applications**: इंस्टॉल किए गए ऐप्स यहाँ होने चाहिए। सभी उपयोगकर्ता इन्हें एक्सेस कर सकते हैं।
- **/bin**: Command line binaries
- **/cores**: अगर मौजूद हो, तो इसका उपयोग core dumps स्टोर करने के लिए किया जाता है।
- **/dev**: हर चीज़ को फ़ाइल माना जाता है, इसलिए यहाँ hardware devices दिख सकते हैं।
- **/etc**: Configuration फ़ाइलें
- **/Library**: Preferences, caches और logs से संबंधित कई subdirectories और फ़ाइलें यहाँ मिल सकती हैं। एक Library फ़ोल्डर root में और हर उपयोगकर्ता की directory में मौजूद होता है।
- **/private**: इसका दस्तावेज़ीकरण नहीं है, लेकिन ऊपर बताए गए कई फ़ोल्डर, private directory के symbolic links हैं।
- **/sbin**: ज़रूरी system binaries (administration से संबंधित)
- **/System**: macOS के लिए ज़रूरी फ़ाइलें; इस tree में मुख्य रूप से Apple द्वारा दिए गए components होते हैं।
- **/tmp**: अस्थायी फ़ाइलें (`/private/tmp` का symbolic link)। पुराने installations में आम तौर पर पुरानी temporary फ़ाइलें एक निश्चित समय-सारणी के अनुसार साफ़ की जाती थीं, जिसे कभी-कभी तीन दिन बताया जाता था। लेकिन मौजूदा cleanup का समय system और policy पर निर्भर करता है; यहाँ डेटा बने रहने पर भरोसा न करें।
- **/Users**: उपयोगकर्ताओं की home directory।
- **/usr**: Config और system binaries
- **/var**: Log फ़ाइलें
- **/Volumes**: Mounted volumes यहाँ दिखाई देते हैं।
- **/.vol**: `stat a.txt` चलाने पर आपको कुछ ऐसा मिलता है: `16777223 7545753 -rw-r--r-- 1 username wheel ...`। पहला नंबर उस volume का ID है जहाँ फ़ाइल मौजूद है और दूसरा inode नंबर है। इस जानकारी का उपयोग करके आप `cat /.vol/16777223/7545753` चलाकर `/.vol/` के ज़रिए इस फ़ाइल की सामग्री एक्सेस कर सकते हैं।

### Applications फ़ोल्डर

- **System applications** `/System/Applications` में स्थित होते हैं।
- **इंस्टॉल किए गए** applications आम तौर पर `/Applications` या `~/Applications` में इंस्टॉल होते हैं।
- **Application data**, root के रूप में चलने वाले applications के लिए `/Library/Application Support` में और user के रूप में चलने वाले applications के लिए `~/Library/Application Support` में मिलता है।
- Third-party application **daemons**, जिन्हें **root के रूप में चलना ज़रूरी है**, आम तौर पर `/Library/PrivilegedHelperTools/` में स्थित होते हैं।
- **Sandboxed** apps को `~/Library/Containers` फ़ोल्डर में रखा जाता है। हर app का एक फ़ोल्डर होता है, जिसका नाम application के bundle ID (`com.apple.Safari`) के अनुसार होता है।
- **kernel** `/System/Library/Kernels/kernel` में स्थित है।
- **Apple के kernel extensions** `/System/Library/Extensions` में स्थित होते हैं।
- **Third-party kernel extensions** `/Library/Extensions` में स्टोर होते हैं।

### संवेदनशील जानकारी वाली फ़ाइलें

macOS credentials सहित संवेदनशील जानकारी कई जगहों पर स्टोर करता है:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### कमज़ोर pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

इस hierarchy में दिखने वाले writable Data volume और sealed System volume के अंतर के लिए, [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md) देखें।

## OS X के विशिष्ट Extensions

- **`.dmg`**: Apple Disk Image फ़ाइलें installers के लिए बहुत आम हैं।
- **`.kext`**: इसका एक विशिष्ट structure होना चाहिए और यह OS X का driver संस्करण है। (यह एक bundle है)
- **`.plist`**: Property list, XML या binary format में structured जानकारी स्टोर करती है।
  - यह XML या binary हो सकती है। Binary फ़ाइलें इन तरीकों से पढ़ी जा सकती हैं:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: एक application bundle, जो मानक macOS directory structure का पालन करता है।
- **`.dylib`**: Dynamic libraries (Windows DLL फ़ाइलों की तरह)
- **`.pkg`**: आधुनिक flat installer packages, XAR archives होते हैं, लेकिन `.pkg` एक installer format है, XAR का पर्याय नहीं। पुराने bundle-style installer packages directories होते हैं। Package structure और जाँच के लिए [macOS installers](macos-installers-abuse.md) देखें। <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: यह फ़ाइल हर directory में होती है और directory के attributes और customisations सेव करती है।
- **`.Spotlight-V100`**: यह फ़ोल्डर system के हर volume की root directory में दिखाई देता है।
- **`.metadata_never_index`**: अगर यह फ़ाइल किसी volume के root में हो, तो Spotlight उस volume को index नहीं करेगा।
- **`.noindex`**: इस extension वाली फ़ाइलों और फ़ोल्डरों को Spotlight index नहीं करेगा।
- **`.sdef`**: एक scripting definition फ़ाइल, जो बताती है कि AppleScript किसी application के साथ कैसे इंटरैक्ट कर सकता है।

### macOS Bundles

Bundle एक मानकीकृत hierarchy वाली directory है, जिसे Finder एक ही object के रूप में दिखा सकता है; application bundles में `.app` extension होता है। <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS और iOS पर, आम तौर पर उपयोग की जाने वाली system libraries और frameworks को **dyld shared cache** में prelink किया जाता है, जिससे application startup की performance बेहतर होती है। इसे एक logical cache माना जाता है, लेकिन मौजूदा releases में यह वास्तव में एक फ़ाइल के बजाय एक main cache और कई subcache फ़ाइलों के रूप में स्टोर हो सकता है। इसका format और location implementation details हैं, जो अलग-अलग OS releases में बदलते रहते हैं। <sup>[[3]](#references)</sup>

macOS में यह `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` में स्थित है और पुराने versions में **shared cache** को **`/System/Library/dyld/`** में पाया जा सकता है।\
iOS में इन्हें **`/System/Library/Caches/com.apple.dyld/`** में पाया जा सकता है।

dyld shared cache की तरह, kernel और kernel extensions को भी kernel cache में compile किया जाता है, जिसे boot के समय load किया जाता है।

पुराने releases को [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) से extract किया जा सकता था। हो सकता है कि यह build मौजूदा cache formats को support न करे; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) एक और विकल्प है:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> ध्यान दें कि भले ही `dyld_shared_cache_util` टूल काम न करे, आप **shared dyld binary को Hopper में पास कर सकते हैं** और Hopper सभी libraries की पहचान कर सकेगा और आपको जांच के लिए **किसी एक को चुनने** देगा:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

कुछ extractors काम नहीं करेंगे, क्योंकि dylibs में hard coded addresses के साथ पहले से linking की गई होती है, इसलिए वे अज्ञात addresses पर jump कर सकते हैं।

> [!TIP]
> macos में Xcode के emulator का उपयोग करके अन्य \*OS devices का Shared Library Cache डाउनलोड करना भी संभव है। वे यहाँ डाउनलोड होंगे: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, जैसे:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLC की Mapping

**`dyld`** यह जानने के लिए syscall **`shared_region_check_np`** का उपयोग करता है कि SLC mapped है या नहीं (यह address लौटाता है), और SLC को map करने के लिए **`shared_region_map_and_slide_np`** का उपयोग करता है।

ध्यान दें कि पहली बार उपयोग करने पर SLC slide होने के बावजूद, सभी **processes** एक ही **copy** का उपयोग करते हैं। यदि attacker system में processes चलाने में सक्षम था, तो इससे **ASLR** protection समाप्त हो जाती थी। अतीत में इसका exploitation किया गया था और इसे shared region pager से ठीक किया गया।

Branch pools छोटी Mach-O dylibs होती हैं, जो image mappings के बीच छोटी जगहें बनाती हैं, जिससे functions को interpose करना असंभव हो जाता है।

### Shared-cache environment restrictions

`DYLD_SHARED_CACHE_DIR` cache directory बताता है, जबकि `DYLD_SHARED_REGION` shared-region mode चुनता है। पहले इस्तेमाल की जाने वाली `DYLD_DHARED_REGION` spelling अमान्य थी, और `avoid` `DYLD_SHARED_CACHE_DIR` के लिए मान्य value नहीं है। मौजूदा dyld, `private` mode को custom shared caches इस्तेमाल करने की AMFI permission पर निर्भर करता है; इसलिए केवल environment variables set करने से यह सुनिश्चित नहीं होता कि कोई process replacement cache load कर सकता है। <sup>[[10]](#references)</sup>

## विशेष File Permissions

### Folder permissions

किसी directory के लिए, **read** entries की listing देखने की अनुमति देता है, **write** entries बनाने या हटाने की अनुमति देता है, और **execute** directory में जाने की अनुमति देता है। इसलिए, जो user किसी file को पढ़ सकता है, लेकिन parent directory में जाने की अनुमति नहीं रखता, वह path के ज़रिए उस file को access नहीं कर सकता। <sup>[[4]](#references)</sup>

### Flag modifiers

Files में ऐसे flags हो सकते हैं जो उनके behavior को बदलते हैं। किसी directory में flags देखने के लिए `ls -lO /path/directory` चलाएँ।

- **`uchg`**: **uchange** flag के नाम से जाना जाने वाला यह flag **file** को बदलने या हटाने वाली **किसी भी कार्रवाई को रोकता है**। इसे set करने के लिए: `chflags uchg file.txt`
  - File का owner या root इस **user** flag को `chflags nouchg file.txt` से हटा सकता है; यह उन दोनों से सुरक्षा नहीं देता। अलग **system** immutable flag (`schg`) केवल root के लिए उपलब्ध है। <sup>[[11]](#references)</sup>
- **`restricted`**: यह flag file को **SIP द्वारा protected** बनाता है (आप इस flag को किसी file में add नहीं कर सकते)।
- **`Sticky bit`**: Sticky bit set वाली directory में केवल file का owner, directory का owner या root ही किसी entry का नाम बदल या उसे हटा सकता है। Users को दूसरे users की files हटाने या स्थानांतरित करने से रोकने के लिए यह आमतौर पर `/tmp` पर enabled होता है।

सभी flags `sys/stat.h` file में मिल सकते हैं (`mdfind stat.h | grep stat.h` से खोजें) और ये हैं:

- `UF_SETTABLE` 0x0000ffff: Owner द्वारा बदले जा सकने वाले flags का mask।
- `UF_NODUMP` 0x00000001: File को dump न करें।
- `UF_IMMUTABLE` 0x00000002: File को बदला नहीं जा सकता।
- `UF_APPEND` 0x00000004: File में केवल append करके लिखा जा सकता है।
- `UF_OPAQUE` 0x00000008: Directory union के संबंध में opaque है।
- `UF_COMPRESSED` 0x00000020: File compressed है (कुछ file-systems में)।
- `UF_TRACKED` 0x00000040: यह set होने पर files को delete/rename करने की कोई notification नहीं दी जाती।
- `UF_DATAVAULT` 0x00000080: पढ़ने और लिखने के लिए entitlement आवश्यक है।
- `UF_HIDDEN` 0x00008000: संकेत कि GUI में यह item प्रदर्शित नहीं होना चाहिए।
- `SF_SUPPORTED` 0x009f0000: Superuser द्वारा supported flags का mask।
- `SF_SETTABLE` 0x3fff0000: Superuser द्वारा बदले जा सकने वाले flags का mask।
- `SF_SYNTHETIC` 0xc0000000: System के read-only synthetic flags का mask।
- `SF_ARCHIVED` 0x00010000: File archived है।
- `SF_IMMUTABLE` 0x00020000: File को बदला नहीं जा सकता।
- `SF_APPEND` 0x00040000: File में केवल append करके लिखा जा सकता है।
- `SF_RESTRICTED` 0x00080000: लिखने के लिए entitlement आवश्यक है।
- `SF_NOUNLINK` 0x00100000: Item को हटाया, rename या mount नहीं किया जा सकता।
- `SF_FIRMLINK` 0x00800000: File एक firmlink है।
- `SF_DATALESS` 0x40000000: File एक dataless object है।

### **File ACLs**

File **ACLs** में **ACE** (Access Control Entries) होते हैं, जिनसे अलग-अलग users को अधिक **सूक्ष्म permissions** दी जा सकती हैं।

किसी **directory** को ये permissions देना संभव है: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`।\
किसी **file** के लिए: `read`, `write`, `append`, और `execute`।

जब file में ACLs होते हैं, तो permissions की listing में आपको **"+" दिखाई देगा, जैसे यहाँ**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

आप फ़ाइल के **ACLs** को इस कमांड से पढ़ सकते हैं:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

आप निम्नलिखित कमांड से **ACLs वाली सभी फ़ाइलें** ढूँढ़ सकते हैं (यह बहुत धीमा है):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Extended Attributes

Extended attributes नामित metadata मान होते हैं, जो किसी फ़ाइल के सामान्य attributes से अलग संग्रहीत होते हैं। उन्हें `ls -l@` से सूचीबद्ध करें और `xattr` से जाँचें या संशोधित करें। <sup>[[5]](#references)</sup> कुछ सामान्य extended attributes हैं:

- `com.apple.resourceFork`: Resource fork compatibility। `filename/..namedfork/rsrc` के रूप में भी दिखाई देता है
- `com.apple.quarantine`: macOS Gatekeeper quarantine metadata
- `metadata:*`: macOS metadata, जैसे `_backup_excludeItem` या `kMD*`
- `com.apple.lastuseddate` (#PS): फ़ाइल के अंतिम उपयोग की तारीख
- `com.apple.FinderInfo`: macOS Finder जानकारी, जैसे रंगीन tags
- `com.apple.TextEncoding`: ASCII text files की text encoding निर्दिष्ट करता है
- `com.apple.logd.metadata`: `/var/db/diagnostics` में मौजूद फ़ाइलों पर logd द्वारा उपयोग किया जाता है
- `com.apple.genstore.*`: Generational storage (फ़ाइलसिस्टम के root में `/.DocumentRevisions-V100`)
- `com.apple.rootless`: System Integrity Protection से जुड़ा macOS metadata
- `com.apple.uuidb.boot-uuid`: अद्वितीय UUID के साथ boot epochs पर logd markings
- `com.apple.decmpfs`: macOS transparent file compression metadata
- `com.apple.cprotect`: \*OS: प्रति-फ़ाइल encryption data (III/11)
- `com.apple.installd.*`: \*OS: installd द्वारा उपयोग किया जाने वाला metadata, जैसे `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks macOS पर एक alternate data stream प्रदान करते हैं। Content को `com.apple.ResourceFork` extended attribute में संग्रहीत किया जा सकता है और `file/..namedfork/rsrc` के ज़रिए एक्सेस किया जा सकता है।

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

आप **इस extended attribute वाले सभी files खोज सकते हैं**:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

विस्तारित attribute `com.apple.decmpfs` पारदर्शी compression के लिए metadata संग्रहीत करता है; यह encryption का संकेत नहीं है। Compression format के आधार पर, compressed data attribute या resource fork में संग्रहीत हो सकता है और पढ़ते समय transparently decompress हो जाता है।

`UF_COMPRESSED` flag, `ls -lO` में `compressed` के रूप में दिखाई देता है। इसे manually clear न करें: ऐसा करने से system compressed representation की गलत व्याख्या कर सकता है।

Flag clear करने वाली command यहां इसलिए दिखाई गई है क्योंकि forensic review के दौरान यह उपयोगी है। लेकिन इसे किसी compressed file पर चलाने से वह file खाली या inaccessible दिखाई दे सकती है, जब तक उसका metadata ठीक न कर दिया जाए:

```bash
chflags nocompressed /path/to/file
```

अंतर्निहित `/usr/bin/afscexpand` यूटिलिटी transparently compressed फ़ाइलों को expand करने के लिए बाध्य कर सकती है। अलग third-party `afsctool` यूटिलिटी Apple filesystem compression का निरीक्षण या उसे decompress भी कर सकती है, लेकिन इसे अंतर्निहित command न समझें। <sup>[[8]](#references)</sup>


### दिलचस्प configuration locations (macOS)

| Path / Location | उद्देश्य / यह क्या configure करता है | सुरक्षा / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Apple की feature-flag plist फ़ाइलें रखता है, जो system daemons / frameworks में optional या experimental व्यवहार नियंत्रित करती हैं | यदि attacker SIP को bypass कर सके या privilege हासिल कर सके, तो इनमें बदलाव से छिपे हुए code paths सक्षम हो सकते हैं या safeguards बंद हो सकते हैं |
| `/System/Library/CoreServices/systemVersion.plist` | macOS version metadata (ProductVersion, BuildVersion) रखता है, जिसका उपयोग apps / installers व्यवहार को नियंत्रित करने के लिए करते हैं | बदलाव से apps या installers को unsupported OS versions स्वीकार करने या features अनलॉक करने के लिए गुमराह किया जा सकता है |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | यदि ये writable हों, तो attackers app व्यवहार को प्रभावित करने, protections बंद करने या misconfiguration पैदा करने के लिए settings inject कर सकते हैं |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Background daemons और agents की plist definitions | Malicious plist जोड़ने या उसमें बदलाव करने से (यदि permissions अनुमति दें) persistence या privilege escalations संभव होते हैं |
| `/etc/hosts` | System DNS resolver द्वारा उपयोग की जाने वाली Hostname ↔ IP mappings | Domain names को redirect करना, traffic intercept करना, या local control वाले services को spoof करना |
| `/etc/sudoers` | यह निर्धारित करता है कि कौन `sudo` से commands चला सकता है और किन शर्तों पर | Corrupted sudoers file attacker accounts को root या अनुचित privileges दे सकती है |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account definition plists | छेड़छाड़ से user accounts, password hashes या user metadata बनाए या बदले जा सकते हैं |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Kexts install या modify करने से kernel-level control मिल सकता है; SIP / signature policies इन्हें कड़ी सुरक्षा देती हैं |
| `/private/var/db/SystemPolicyConfiguration/` | System policy enforcement (जैसे Gatekeeper, notarization) की configuration रखता है | इनमें छेड़छाड़ से policy checks या trust rules को bypass किया जा सकता है |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries और config files | Misconfiguration से कमजोर SSH security, unauthorized access या असुरक्षित algorithms हो सकते हैं |
| `/System/Library/Sandbox/Profiles` | Process actions को प्रतिबंधित करने के लिए उपयोग किए जाने वाले system sandbox profiles (SBPL) | Profiles को बदलने या संशोधित करने से sandbox escape vectors खुल सकते हैं या containment कमजोर हो सकता है |

> **नोट**: इनमें से कई paths SIP-सुरक्षित directories (जैसे `/System`) के अंतर्गत हैं और SIP disabled या bypass किए बिना उन पर लिखने से सुरक्षा मिलती है।  


## Universal Binaries और Mach-O Format

Mach-O macOS का native executable format है। Universal, या fat, binary एक फ़ाइल में कई architecture-specific Mach-O slices रखती है; समर्पित पृष्ठ दोनों formats समझाता है:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk और Handler Metadata

LaunchServices, file quarantine और Gatekeeper मिलकर प्रभावित करते हैं कि macOS downloaded files को कैसे संभालता है और extensions तथा URL schemes के लिए applications कैसे चुनता है। इनके databases और internal resource files अलग-अलग releases में बदलते रहते हैं; किसी private CoreTypes path को स्थिर policy interface मानने के बजाय समर्पित पृष्ठों का उपयोग करें:

जिन releases में legacy CoreTypes risk metadata `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` के अंतर्गत उपलब्ध होता है, उनमें आमतौर पर ये categories मिलती हैं:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: ऐसा content जिसे लागू application policy के तहत automatic opening के लिए पर्याप्त रूप से सुरक्षित माना जाता है।
- **`LSRiskCategoryNeutral`**: ऐसा content जो आमतौर पर warning नहीं दिखाता और अपने-आप नहीं खुलता।
- **`LSRiskCategoryUnsafeExecutable`**: Executable content, जिसके लिए user को application warning मिलनी चाहिए।
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Archives जैसे containers, जिनमें executable content हो सकता है और जिनकी आगे जाँच आवश्यक है।

ये implementation details हैं, कोई स्थिर public policy API नहीं; जाँचे जा रहे macOS version पर वास्तविक metadata और Safari/Gatekeeper व्यवहार की पुष्टि करें।

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Downloaded files के बारे में जानकारी रखता है, जैसे वह URL जहाँ से वे download की गई थीं।
- **Unified log**: मौजूदा macOS versions पर, `log show` और `log stream` से system और application events query करें। <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** और **`/private/var/log/asl/*.asl`**: Legacy logging artifacts, जो पुराने systems पर अब भी प्रासंगिक हो सकते हैं। उन releases पर, `/System/Library/LaunchDaemons/com.apple.syslogd.plist`, `syslogd` को configure करता है; `launchctl list | grep com.apple.syslogd` से पता लगाने में मदद मिल सकती है कि service loaded है या नहीं।
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" के ज़रिए हाल ही में access की गई files और applications की जानकारी रखता है।
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Login items से जुड़ा legacy preference path; आधुनिक macOS versions अतिरिक्त mechanisms का उपयोग करते हैं।
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility log, जिसमें drives के बारे में जानकारी हो सकती है, जैसे USB devices।
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Wireless access points के बारे में data।
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override data।



## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache का परिचय](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS फ़ाइल सिस्टम सुरक्षा](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS मैनुअल पृष्ठ](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS मैनुअल पृष्ठ](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS मैनुअल पृष्ठ](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Apple Archives को unpack करना](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Shell Script Security: विशेष file permission flags](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Code Signing Tasks: installer packages](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
