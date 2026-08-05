# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **मूल जानकारी**

macOS में **System Integrity Protection (SIP)** एक ऐसा mechanism है जिसे सबसे अधिक privileged users को भी मुख्य system folders में unauthorized changes करने से रोकने के लिए design किया गया है। यह feature protected areas में files को add, modify या delete करने जैसी actions को restrict करके system की integrity बनाए रखने में महत्वपूर्ण भूमिका निभाता है। SIP द्वारा सुरक्षित किए गए मुख्य folders में शामिल हैं:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP के behavior को नियंत्रित करने वाले rules **`/System/Library/Sandbox/rootless.conf`** में स्थित configuration file में defined होते हैं। इस file में asterisk (\*) से prefixed paths को अन्यथा कड़े SIP restrictions के exceptions के रूप में दर्शाया जाता है।

नीचे दिए गए example पर विचार करें:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
यह snippet दर्शाता है कि SIP सामान्यतः **`/usr`** directory को सुरक्षित करता है, लेकिन कुछ विशिष्ट subdirectories (`/usr/libexec/cups`, `/usr/local`, और `/usr/share/man`) में modifications की अनुमति है, जैसा कि उनके paths से पहले दिए गए asterisk (\*) से संकेत मिलता है।

यह सत्यापित करने के लिए कि कोई directory या file SIP द्वारा protected है या नहीं, आप **`ls -lOd`** command का उपयोग करके **`restricted`** या **`sunlnk`** flag की उपस्थिति जांच सकते हैं। उदाहरण के लिए:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
इस मामले में, **`sunlnk`** flag यह दर्शाता है कि `/usr/libexec/cups` directory को स्वयं **delete नहीं किया जा सकता**, हालांकि इसके भीतर files बनाई, modified या deleted की जा सकती हैं।

दूसरी ओर:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
यहाँ, **`restricted`** flag दर्शाता है कि `/usr/libexec` directory SIP द्वारा protected है। SIP-protected directory में files create, modify या delete नहीं की जा सकतीं।

इसके अलावा, यदि किसी file में **`com.apple.rootless`** extended **attribute** मौजूद है, तो वह file भी **SIP द्वारा protected** होगी।

> [!TIP]
> ध्यान दें कि **Sandbox** hook **`hook_vnode_check_setextattr`**, extended attribute **`com.apple.rootless`** को modify करने के किसी भी प्रयास को रोकता है।

**SIP अन्य root actions को भी सीमित करता है**, जैसे:

- Untrusted kernel extensions को load करना
- Apple-signed processes के लिए task-ports प्राप्त करना
- NVRAM variables को modify करना
- Kernel debugging की अनुमति देना

Options को nvram variable में bitflag के रूप में maintain किया जाता है (`csr-active-config` Intel पर और `lp-sip0` ARM के लिए booted Device Tree से read किया जाता है)। आप XNU source code में `csr.sh` के अंदर flags देख सकते हैं:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Status

आप निम्न command से जांच सकते हैं कि आपके system पर SIP enabled है या नहीं:
```bash
csrutil status
```
यदि आपको SIP को disable करना है, तो आपको अपने computer को recovery mode में restart करना होगा (startup के दौरान Command+R दबाकर), फिर निम्नलिखित command execute करें:
```bash
csrutil disable
```
यदि आप SIP को enabled रखना चाहते हैं, लेकिन debugging protections हटाना चाहते हैं, तो आप यह कर सकते हैं:
```bash
csrutil enable --without debug
```
### अन्य प्रतिबंध

- **Unsigned kernel extensions** (kexts) को लोड करने से रोकता है, जिससे केवल verified extensions ही system kernel के साथ interact कर सकें।
- macOS system processes की **debugging** को रोकता है, जिससे core system components unauthorized access और modification से सुरक्षित रहते हैं।
- system processes का निरीक्षण करने से dtrace जैसे tools को रोकता है, जिससे system operation की integrity को और सुरक्षा मिलती है।

[**SIP info के बारे में इस talk में अधिक जानें**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**।**<sup>[1]</sup>

### **SIP से संबंधित Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd को control करना
- `com.apple.rootless.install[.heritable]`: file system तक access
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT को manage करना
- `com.apple.rootless.xpc.bootstrap`: XPC setup capabilities
- `com.apple.rootless.xpc.effective-root`: launchd XPC के माध्यम से Root
- `com.apple.rootless.restricted-block-devices`: raw block devices तक access
- `com.apple.rootless.internal.installer-equivalent`: बिना प्रतिबंध के filesystem access
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM तक full access
- `com.apple.rootless.storage.label`: संबंधित label वाले com.apple.rootless xattr द्वारा restricted files को modify करना
- `com.apple.rootless.volume.VM.label`: volume पर VM swap को maintain करना

## SIP Bypasses

SIP को bypass करने से attacker निम्न कार्य कर सकता है:

- **User Data तक Access**: सभी user accounts से mail, messages और Safari history जैसे sensitive user data को पढ़ना।
- **TCC Bypass**: webcam, microphone और अन्य resources तक unauthorized access देने के लिए TCC (Transparency, Consent, and Control) database को सीधे manipulate करना।
- **Persistence स्थापित करना**: SIP-protected locations में malware रखना, जिससे वह root privileges द्वारा भी removal के प्रति resistant हो जाता है। इसमें Malware Removal Tool (MRT) के साथ छेड़छाड़ की संभावित क्षमता भी शामिल है।
- **Kernel Extensions लोड करना**: हालांकि अतिरिक्त safeguards मौजूद हैं, SIP को bypass करने से unsigned kernel extensions लोड करने की प्रक्रिया आसान हो जाती है।

### Installer Packages

**Apple's certificate से signed Installer packages** इसके protections को bypass कर सकते हैं। इसका अर्थ है कि standard developers द्वारा signed packages भी block कर दिए जाएंगे, यदि वे SIP-protected directories को modify करने का प्रयास करते हैं।

### Inexistent SIP file

एक संभावित loophole यह है कि यदि **`rootless.conf` में कोई file specified हो लेकिन वर्तमान में मौजूद न हो**, तो उसे create किया जा सकता है। Malware इसका exploit करके system पर **persistence स्थापित** कर सकता है। उदाहरण के लिए, यदि `/System/Library/LaunchDaemons` में कोई .plist file `rootless.conf` में listed हो लेकिन मौजूद न हो, तो malicious program उसे create कर सकता है।

### com.apple.rootless.install.heritable

> [!CAUTION]
> entitlement **`com.apple.rootless.install.heritable`** SIP को bypass करने की अनुमति देता है

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

यह discovered हुआ कि system द्वारा code **signature** verify किए जाने के बाद Installer package को **swap** करना संभव था; इसके बाद system original package के बजाय malicious package install करता। चूंकि ये actions **`system_installd`** द्वारा performed थे, इसलिए इससे SIP bypass करना संभव हो जाता था।<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

यदि कोई package mounted image या external drive से install किया जाता, तो **installer** binary को SIP protected location के बजाय **उस file system से execute** करता, जिससे **`system_installd`** arbitrary binary execute कर सकता था।<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**इस blog post के Researchers**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ने macOS के System Integrity Protection (SIP) mechanism में एक vulnerability discover की, जिसे 'Shrootless' vulnerability नाम दिया गया। यह vulnerability **`system_installd`** daemon पर केंद्रित है, जिसके पास **`com.apple.rootless.install.heritable`** entitlement है। यह entitlement इसके सभी child processes को SIP की file system restrictions bypass करने की अनुमति देता है।<sup>[4]</sup>

**`system_installd`** daemon उन packages को install करेगा जिन्हें **Apple** द्वारा signed किया गया है।

Researchers ने पाया कि Apple-signed package (.pkg file) की installation के दौरान **`system_installd`** package में शामिल किसी भी **post-install** scripts को **run** करता है। ये scripts default shell, **`zsh`**, द्वारा execute की जाती हैं, जो automatically **`/etc/zshenv`** file से commands **run** करती है, यदि वह मौजूद हो, यहां तक कि non-interactive mode में भी। Attackers इस behaviour का exploit कर सकते थे: एक malicious `/etc/zshenv` file create करके और **`system_installd` के `zsh` invoke करने की प्रतीक्षा करके**, वे device पर arbitrary operations perform कर सकते थे।<sup>[4]</sup>

इसके अलावा, यह discovered हुआ कि **`/etc/zshenv` को एक general attack technique के रूप में use किया जा सकता है**, केवल SIP bypass के लिए नहीं। प्रत्येक user profile में `~/.zshenv` file होती है, जो `/etc/zshenv` की तरह ही behave करती है, लेकिन इसके लिए root permissions की आवश्यकता नहीं होती। इस file को persistence mechanism के रूप में use किया जा सकता है, जो हर बार `zsh` start होने पर trigger हो, या elevation of privilege mechanism के रूप में। यदि कोई admin user `sudo -s` या `sudo <command>` का उपयोग करके root तक elevate करता है, तो `~/.zshenv` file trigger होगी और प्रभावी रूप से root तक elevate करेगी।<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) में यह discovered हुआ कि उसी **`system_installd`** process का अभी भी abuse किया जा सकता था, क्योंकि यह **post-install script को `/tmp` के अंदर SIP द्वारा protected random named folder में रख रहा था**। समस्या यह है कि **`/tmp` स्वयं SIP द्वारा protected नहीं है**, इसलिए उस पर **virtual image mount** करना संभव था। इसके बाद **installer** उसमें **post-install script** रखता, virtual image को **unmount** करता, सभी **folders को recreate** करता और execute किए जाने वाले **payload** के साथ **post installation** script add करता।<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

एक vulnerability identify की गई जिसमें **`fsck_cs`** को एक crucial file corrupt करने के लिए mislead किया गया, क्योंकि उसमें **symbolic links** follow करने की क्षमता थी। विशेष रूप से, attackers ने _`/dev/diskX`_ से `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` file तक एक link बनाया। _`/dev/diskX`_ पर **`fsck_cs`** execute करने से `Info.plist` corrupt हो गई। इस file की integrity operating system के SIP (System Integrity Protection) के लिए महत्वपूर्ण है, जो kernel extensions की loading को control करता है। एक बार corrupt होने पर, kernel exclusions manage करने की SIP की क्षमता compromised हो जाती है।<sup>[6]</sup>

इस vulnerability को exploit करने के commands हैं:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
इस vulnerability का exploitation गंभीर प्रभाव डालता है। `Info.plist` फ़ाइल, जो सामान्यतः kernel extensions के लिए permissions प्रबंधित करने के लिए ज़िम्मेदार होती है, अप्रभावी हो जाती है। इसमें कुछ extensions, जैसे `AppleHWAccess.kext`, को blacklist करने में असमर्थता भी शामिल है। परिणामस्वरूप, SIP का control mechanism काम करना बंद कर देता है और यह extension load किया जा सकता है, जिससे system की RAM तक unauthorized read और write access मिल जाता है।<sup>[6]</sup>

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP protected folders पर एक नया file system mount करके protection को bypass करना** संभव था।<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

OS को upgrade करने के लिए system को `Install macOS Sierra.app` के भीतर मौजूद embedded installer disk image से boot करने के लिए set किया गया है, जिसमें `bless` utility का उपयोग किया जाता है। उपयोग की गई command इस प्रकार है:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
यदि boot करने से पहले कोई attacker upgrade image (`InstallESD.dmg`) में बदलाव कर दे, तो इस process की security से समझौता किया जा सकता है। इसमें dynamic loader (dyld) को malicious version (`libBaseIA.dylib`) से बदलना शामिल है। यह replacement installer शुरू होने पर attacker के code को execute करवाता है।<sup>[7]</sup>

Upgrade process के दौरान attacker का code control प्राप्त कर लेता है और installer पर system के trust का फायदा उठाता है। यह attack method swizzling के माध्यम से `InstallESD.dmg` image में बदलाव करके किया जाता है, जिसमें विशेष रूप से `extractBootBits` method को target किया जाता है। इससे disk image के इस्तेमाल से पहले malicious code inject किया जा सकता है।<sup>[7]</sup>

इसके अलावा, `InstallESD.dmg` के अंदर एक `BaseSystem.dmg` होता है, जो upgrade code के root file system के रूप में काम करता है। इसमें एक dynamic library inject करने से malicious code ऐसे process के भीतर operate कर सकता है जो OS-level files में बदलाव करने में सक्षम हो, जिससे system compromise की संभावना काफी बढ़ जाती है।<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) की इस talk में दिखाया गया है कि **`systemmigrationd`** (जो SIP को bypass कर सकता है) एक **bash** और एक **perl** script execute करता है, जिनका env variables **`BASH_ENV`** और **`PERL5OPT`** के माध्यम से दुरुपयोग किया जा सकता है।<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

जैसा कि [**इस blog post में विस्तार से बताया गया है**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` packages की एक `postinstall` script execute हो रही थी:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
और `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` में एक symlink बनाना संभव था, जो किसी user को **किसी भी file पर से restriction हटाने और SIP protection को bypass करने** की अनुमति देता था।<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** SIP को bypass करने की अनुमति देता है

Entitlement `com.apple.rootless.install` को macOS पर System Integrity Protection (SIP) को bypass करने के लिए जाना जाता है। इसका उल्लेख विशेष रूप से [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) के संदर्भ में किया गया था।<sup>[10]</sup>

इस विशिष्ट मामले में, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` पर स्थित system XPC service के पास यह entitlement है। इससे संबंधित process SIP constraints को bypass कर सकता है। इसके अतिरिक्त, यह service विशेष रूप से एक ऐसी method उपलब्ध कराती है, जो किसी भी security measures को लागू किए बिना files को move करने की अनुमति देती है।<sup>[10]</sup>

## Sealed System Snapshots

Sealed System Snapshots एक feature है जिसे Apple ने **macOS Big Sur (macOS 11)** में अपने **System Integrity Protection (SIP)** mechanism के हिस्से के रूप में पेश किया था, ताकि security और system stability की एक अतिरिक्त layer प्रदान की जा सके। ये मूल रूप से system volume के read-only versions होते हैं।

यहां इसका अधिक विस्तृत विवरण दिया गया है:

1. **Immutable System**: Sealed System Snapshots macOS system volume को "immutable" बना देते हैं, जिसका अर्थ है कि इसे modify नहीं किया जा सकता। इससे system में होने वाले unauthorized या accidental changes रुकते हैं, जो security या system stability को compromise कर सकते हैं।
2. **System Software Updates**: जब आप macOS updates या upgrades install करते हैं, तो macOS एक नया system snapshot बनाता है। macOS startup volume फिर इस नए snapshot पर switch करने के लिए **APFS (Apple File System)** का उपयोग करता है। Updates लागू करने की पूरी process अधिक सुरक्षित और reliable हो जाती है, क्योंकि update के दौरान कुछ गलत होने पर system हमेशा पिछले snapshot पर revert कर सकता है।
3. **Data Separation**: macOS Catalina में शुरू की गई Data और System volume separation की concept के साथ, Sealed System Snapshot feature यह सुनिश्चित करता है कि आपका सारा data और settings एक अलग "**Data**" volume में store हो। यह separation आपके data को system से independent बनाती है, जिससे system updates की process सरल होती है और system security बेहतर होती है।

ध्यान रखें कि इन snapshots को macOS automatically manage करता है और APFS की space sharing capabilities के कारण ये आपकी disk पर additional space नहीं लेते। यह भी ध्यान रखना महत्वपूर्ण है कि ये snapshots **Time Machine snapshots** से अलग होते हैं, जो पूरे system के user-accessible backups होते हैं।

### Check Snapshots

Command **`diskutil apfs list`** **APFS volumes** और उनके layout की **details** list करता है:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

पिछले output में यह देखा जा सकता है कि **user-accessible locations** `/System/Volumes/Data` के अंतर्गत mounted हैं।

इसके अलावा, **macOS System volume snapshot** `/` में mounted है और यह **sealed** है (OS द्वारा cryptographically signed)। इसलिए, यदि SIP bypass करके इसमें modification किया जाता है, तो **OS अब boot नहीं होगा**।

यह भी संभव है कि निम्न command चलाकर **seal enabled है या नहीं, verify** किया जाए:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
इसके अलावा, snapshot disk को भी **read-only** के रूप में mount किया गया है:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## संदर्भ

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple's fruitless rootless security broken by code that fits in a tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Bypassing Apple's System Integrity Protection - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple Mitigates Vulnerabilities in Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: The POC for SIP-Bypass Is Even Tweetable](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
