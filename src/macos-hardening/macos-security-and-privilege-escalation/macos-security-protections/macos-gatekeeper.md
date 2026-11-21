# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** Mac ऑपरेटिंग सिस्टम के लिए विकसित एक सुरक्षा सुविधा है, जिसका उद्देश्य यह सुनिश्चित करना है कि उपयोगकर्ता अपने सिस्टम पर **केवल विश्वसनीय सॉफ़्टवेयर चलाएँ**। यह **सॉफ़्टवेयर का सत्यापन** करके काम करता है, जिसे उपयोगकर्ता **App Store के बाहर के स्रोतों** से डाउनलोड करके खोलने का प्रयास करते हैं, जैसे कोई ऐप, प्लग-इन या इंस्टॉलर पैकेज।

Gatekeeper का मुख्य तंत्र इसकी **सत्यापन** प्रक्रिया है। यह जाँचता है कि डाउनलोड किया गया सॉफ़्टवेयर **किसी मान्यता प्राप्त डेवलपर द्वारा हस्ताक्षरित है या नहीं**, जिससे सॉफ़्टवेयर की प्रामाणिकता सुनिश्चित होती है। इसके अलावा, यह पता लगाता है कि सॉफ़्टवेयर **Apple द्वारा notarised है या नहीं**, जिससे पुष्टि होती है कि उसमें कोई ज्ञात दुर्भावनापूर्ण सामग्री नहीं है और notarisation के बाद उसके साथ छेड़छाड़ नहीं की गई है।

इसके अतिरिक्त, Gatekeeper उपयोगकर्ता के नियंत्रण और सुरक्षा को बढ़ाने के लिए, डाउनलोड किए गए सॉफ़्टवेयर को पहली बार खोलने पर **उपयोगकर्ताओं से अनुमति माँगता है**। यह सुरक्षा उपाय उपयोगकर्ताओं को अनजाने में संभावित रूप से हानिकारक executable code चलाने से रोकने में मदद करता है, जिसे वे गलती से एक हानिरहित data file समझ सकते हैं।

### Application Signatures

Application signatures, जिन्हें code signatures भी कहा जाता है, Apple के सुरक्षा ढाँचे का एक महत्वपूर्ण घटक हैं। इनका उपयोग **सॉफ़्टवेयर लेखक (डेवलपर) की पहचान सत्यापित करने** और यह सुनिश्चित करने के लिए किया जाता है कि आखिरी बार हस्ताक्षर किए जाने के बाद से code के साथ छेड़छाड़ नहीं की गई है।

यह इस तरह काम करता है:

1. **एप्लिकेशन पर हस्ताक्षर करना:** जब डेवलपर अपना एप्लिकेशन वितरित करने के लिए तैयार होता है, तो वह **निजी कुंजी का उपयोग करके एप्लिकेशन पर हस्ताक्षर करता है**। यह निजी कुंजी उस **प्रमाणपत्र से जुड़ी होती है जो Apple, Apple Developer Program में नामांकन करने पर डेवलपर को जारी करता है**। हस्ताक्षर प्रक्रिया में ऐप के सभी हिस्सों का एक cryptographic hash बनाना और डेवलपर की निजी कुंजी से इस hash को encrypt करना शामिल है।
2. **एप्लिकेशन वितरित करना:** हस्ताक्षरित एप्लिकेशन को डेवलपर के प्रमाणपत्र के साथ उपयोगकर्ताओं में वितरित किया जाता है, जिसमें संबंधित public key होती है।
3. **एप्लिकेशन का सत्यापन करना:** जब कोई उपयोगकर्ता एप्लिकेशन डाउनलोड करके चलाने का प्रयास करता है, तो उसका Mac ऑपरेटिंग सिस्टम डेवलपर के प्रमाणपत्र में मौजूद public key का उपयोग करके hash को decrypt करता है। फिर यह एप्लिकेशन की मौजूदा स्थिति के आधार पर hash की दोबारा गणना करता है और इसकी तुलना decrypt किए गए hash से करता है। यदि दोनों मेल खाते हैं, तो इसका अर्थ है कि **डेवलपर द्वारा हस्ताक्षर किए जाने के बाद से एप्लिकेशन में बदलाव नहीं किया गया है**, और सिस्टम एप्लिकेशन को चलने देता है।

Application signatures, Apple की Gatekeeper तकनीक का एक अनिवार्य हिस्सा हैं। जब कोई उपयोगकर्ता **इंटरनेट से डाउनलोड किया गया एप्लिकेशन खोलने** का प्रयास करता है, तो Gatekeeper एप्लिकेशन signature का सत्यापन करता है। यदि उस पर Apple द्वारा किसी ज्ञात डेवलपर को जारी किए गए प्रमाणपत्र से हस्ताक्षर किए गए हों और code के साथ छेड़छाड़ न की गई हो, तो Gatekeeper एप्लिकेशन को चलने देता है। अन्यथा, यह एप्लिकेशन को ब्लॉक करके उपयोगकर्ता को सूचित करता है।

macOS Catalina से, **Gatekeeper यह भी जाँचता है कि एप्लिकेशन को Apple द्वारा notarize किया गया है या नहीं**, जिससे सुरक्षा की एक अतिरिक्त परत जुड़ती है। Notarization प्रक्रिया एप्लिकेशन में ज्ञात सुरक्षा समस्याओं और दुर्भावनापूर्ण code की जाँच करती है। यदि ये जाँच सफल होती हैं, तो Apple एप्लिकेशन में एक ticket जोड़ता है, जिसका Gatekeeper सत्यापन कर सकता है।

#### Check Signatures

किसी **malware sample** की जाँच करते समय, आपको हमेशा binary के **signature की जाँच करनी चाहिए**, क्योंकि उस पर हस्ताक्षर करने वाला **डेवलपर** पहले से ही **malware** से **जुड़ा हो सकता है।**

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```

### Notarization

Apple की notarization प्रक्रिया उपयोगकर्ताओं को संभावित रूप से हानिकारक software से बचाने के लिए एक अतिरिक्त सुरक्षा उपाय है। इसमें **developer अपना application जाँच के लिए submit करता है**, जिसे **Apple's Notary Service** द्वारा किया जाता है। इसे App Review न समझें। यह सेवा एक **automated system** है, जो submit किए गए software में **malicious content** और code-signing से जुड़ी संभावित समस्याओं की जाँच करती है।

यदि software बिना किसी चिंता के इस जाँच में **पास** हो जाता है, तो Notary Service एक notarization ticket बनाती है। इसके बाद developer को यह ticket अपने software के साथ **जोड़ना** होता है; इस प्रक्रिया को 'stapling' कहते हैं। इसके अलावा, notarization ticket online भी प्रकाशित किया जाता है, जहाँ Gatekeeper, Apple की security technology, इसे देख सकता है।

जब उपयोगकर्ता पहली बार software install या execute करता है, तब notarization ticket की मौजूदगी—चाहे वह executable के साथ stapled हो या online मिले—**Gatekeeper को बताती है कि Apple ने software को notarize किया है**। इसके परिणामस्वरूप, Gatekeeper पहली बार launch होने वाले dialog में एक विवरणात्मक संदेश दिखाता है, जिसमें बताया जाता है कि Apple ने software में malicious content की जाँच की है। इस तरह यह प्रक्रिया उपयोगकर्ताओं का अपने system पर install या run किए जाने वाले software की security पर भरोसा बढ़ाती है।

### spctl & syspolicyd

> [!CAUTION]
> ध्यान दें कि Sequoia version से, **`spctl`** अब Gatekeeper configuration में बदलाव करने की अनुमति नहीं देता।

**`spctl`** Gatekeeper को enumerate करने और उसके साथ interact करने का CLI tool है (`syspolicyd` daemon के साथ XPC messages के ज़रिए)। उदाहरण के लिए, इससे GateKeeper का **status** देखा जा सकता है:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> ध्यान दें कि GateKeeper signature checks केवल **Quarantine attribute वाली files** पर किए जाते हैं, हर file पर नहीं।

GateKeeper यह जाँचता है कि **preferences और signature** के अनुसार किसी binary को execute किया जा सकता है या नहीं:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** Gatekeeper को लागू करने के लिए ज़िम्मेदार मुख्य daemon है। यह `/var/db/SystemPolicy` में स्थित database को बनाए रखता है। [database के समर्थन वाला code यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) और [SQL template यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) मिल सकता है। ध्यान दें कि database पर SIP की पाबंदी नहीं है और इसे root द्वारा लिखा जा सकता है। अन्य database के corrupted होने पर `/var/db/.SystemPolicy-default` database को original backup के रूप में इस्तेमाल किया जाता है।

इसके अलावा, **`/var/db/gke.bundle`** और **`/var/db/gkopaque.bundle`** bundles में ऐसी files होती हैं जिनके rules database में जोड़े जाते हैं। आप root के रूप में इस database को यहाँ देख सकते हैं:

```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```

**`syspolicyd`** अलग-अलग operations जैसे `assess`, `update`, `record` और `cancel` वाला XPC server भी उपलब्ध कराता है। इन्हें **`Security.framework` के `SecAssessment*`** APIs के ज़रिए भी एक्सेस किया जा सकता है, और **`spctl`** वास्तव में XPC के ज़रिए **`syspolicyd`** से बात करता है।

ध्यान दें कि पहला rule "**App Store**" पर और दूसरा "**Developer ID**" पर समाप्त हुआ था। पिछली image में यह **App Store और पहचाने गए developers से apps चलाने के लिए enabled था**।\
अगर आप उस setting को App Store पर **बदलते** हैं, तो "**Notarized Developer ID" rules गायब हो जाएंगे**।

**GKE** type के हज़ारों rules भी हैं :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

ये hashes इनसे हैं:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

या आप पिछली जानकारी को इस कमांड से सूचीबद्ध कर सकते हैं:

```bash
sudo spctl --list
```

**`spctl`** के **`--master-disable`** और **`--global-disable`** विकल्प इन signature checks को पूरी तरह **disable** कर देंगे:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

पूरी तरह सक्षम होने पर, एक नया विकल्प दिखाई देगा:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

इससे **जाँचना संभव है कि GateKeeper किसी App को अनुमति देगा या नहीं**:

```bash
spctl --assess -v /Applications/App.app
```

macOS 14 और उसके बाद के संस्करणों पर, **`syspolicy_check`** किसी application bundle के लिए वितरण-पूर्व जाँच का एक उपयोगी उच्च-स्तरीय टूल है। यह केवल `spctl` के परिणाम की तुलना में trusted-execution से जुड़े अधिक उपयोगी diagnostics देता है, हालाँकि Apple अब भी वास्तविक download/extraction/first-launch प्रक्रिया की जाँच करने की सलाह देता है, क्योंकि इससे quarantine propagation की भी जाँच होती है।<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

GateKeeper में कुछ apps के execution की अनुमति देने के लिए नए rules जोड़ना संभव है:

```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```

Regarding **kernel extensions**, फ़ोल्डर `/var/db/SystemPolicyConfiguration` में उन kexts की सूचियों वाली फ़ाइलें होती हैं जिन्हें लोड करने की अनुमति है। इसके अलावा, `spctl` के पास `com.apple.private.iokit.nvram-csr` entitlement है, क्योंकि यह नए pre-approved kernel extensions जोड़ सकता है, जिन्हें `kext-allowed-teams` key में NVRAM में भी सहेजना ज़रूरी है।

#### macOS 15 (Sequoia) और बाद के संस्करणों में Gatekeeper प्रबंधित करना

- Finder का पुराना **Ctrl+Open / Right-click → Open** bypass हटा दिया गया है; पहला block dialog दिखने के बाद, उपयोगकर्ताओं को **System Settings → Privacy & Security → Open Anyway** से blocked app को स्पष्ट रूप से अनुमति देनी होगी।<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` को अब unattended policy changes के रूप में स्वीकार नहीं किया जाता। Rule database या global assessment state में बदलाव करने वाले operations deprecated हैं, इसलिए assessment के लिए `spctl` का उपयोग करें और UI या MDM के ज़रिए enforcement configure करें।

macOS 15 Sequoia से, end users अब `spctl` से Gatekeeper policy toggle नहीं कर सकते। प्रबंधन System Settings के ज़रिए या `com.apple.systempolicy.control` payload वाली MDM configuration profile deploy करके किया जाता है। App Store और पहचाने गए developers को अनुमति देने (लेकिन "Anywhere" को नहीं) के लिए profile snippet का उदाहरण:

<details>
<summary>App Store और पहचाने गए developers को अनुमति देने वाली MDM profile</summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.systempolicy.control</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.example.gatekeeper</string>
      <key>EnableAssessment</key>
      <true/>
      <key>AllowIdentifiedDevelopers</key>
      <true/>
    </dict>
  </array>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadIdentifier</key>
  <string>com.example.profile.gatekeeper</string>
  <key>PayloadUUID</key>
  <string>00000000-0000-0000-0000-000000000000</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadDisplayName</key>
  <string>Gatekeeper</string>
</dict>
</plist>
```

</details>

### Quarantine फ़ाइलें

किसी application या फ़ाइल को **डाउनलोड** करने पर, macOS के कुछ विशिष्ट **applications**, जैसे web browsers या email clients, डाउनलोड की गई फ़ाइल में एक extended file attribute **जोड़ते हैं**, जिसे आम तौर पर "**quarantine flag**" कहा जाता है। यह attribute फ़ाइल को **अविश्वसनीय स्रोत** (इंटरनेट) से आई हुई और संभावित जोखिम वाली **चिह्नित करने** के लिए सुरक्षा उपाय के रूप में काम करता है। हालांकि, सभी applications यह attribute नहीं जोड़ते। उदाहरण के लिए, आम BitTorrent client software आम तौर पर इस प्रक्रिया को बायपास करते हैं।

**जब कोई उपयोगकर्ता फ़ाइल चलाने की कोशिश करता है, तो quarantine flag की मौजूदगी macOS के Gatekeeper सुरक्षा फ़ीचर को सक्रिय करती है**।

यदि **quarantine flag मौजूद नहीं है** (जैसा कि कुछ BitTorrent clients से डाउनलोड की गई फ़ाइलों के साथ होता है), तो Gatekeeper की **जाँचें नहीं की जा सकती हैं**। इसलिए, उपयोगकर्ताओं को कम सुरक्षित या अज्ञात स्रोतों से डाउनलोड की गई फ़ाइलें खोलते समय सावधानी बरतनी चाहिए।

> [!NOTE] > Code signatures की **वैधता** **जाँचने** की प्रक्रिया में बहुत अधिक **संसाधन** लगते हैं। इसमें code और उसके साथ bundled सभी resources के cryptographic **hashes** बनाना शामिल है। इसके अलावा, certificate की वैधता जाँचने के लिए Apple के servers पर **online check** करना पड़ता है, ताकि पता चले कि जारी होने के बाद उसे revoke तो नहीं किया गया है। इन्हीं कारणों से, हर बार app launch होने पर code signature और notarization की पूरी जाँच करना **व्यावहारिक नहीं है**।
>
> इसलिए, ये जाँचें **सिर्फ quarantine attribute वाली apps चलाते समय की जाती हैं**।

> [!WARNING]
> यह attribute फ़ाइल बनाने/डाउनलोड करने वाले **application द्वारा सेट किया जाना चाहिए**।
>
> हालांकि, sandboxed फ़ाइलें बनाने वाली files में यह attribute सेट होता है। Non-sandboxed apps इसे खुद सेट कर सकती हैं या **Info.plist** में [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key निर्दिष्ट कर सकती हैं, जिससे system बनाई गई फ़ाइलों पर `com.apple.quarantine` extended attribute सेट कर देगा।

इसके अलावा, **`qtn_proc_apply_to_self`** को call करने वाली process द्वारा बनाई गई सभी फ़ाइलें quarantined होती हैं। या, API **`qtn_file_apply_to_path`** किसी निर्दिष्ट file path में quarantine attribute जोड़ता है।

इसकी **स्थिति जाँचना और इसे enable/disable करना** (इसके लिए root access आवश्यक है) संभव है:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

आप यह भी **जाँच सकते हैं कि किसी फ़ाइल में quarantine extended attribute मौजूद है या नहीं**:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

**extended** **attributes** की **value** जाँचें और पता लगाएँ कि quarantine attr किस app ने लिखा है:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

वास्तव में, कोई process "अपने द्वारा बनाई गई files पर quarantine flags सेट कर सकता है" (मैंने बनाई गई file में USER_APPROVED flag लागू करने की कोशिश की, लेकिन यह लागू नहीं होगा):

<details>

<summary>Source Code: quarantine flags लागू करना</summary>

```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
    QTN_FLAG_DOWNLOAD = 0x0001,
    QTN_FLAG_SANDBOX = 0x0002,
    QTN_FLAG_HARD = 0x0004,
    QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

  qtn_proc_t qp = qtn_proc_alloc();
  qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
  qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
  qtn_proc_apply_to_self(qp);
  qtn_proc_free(qp);

  FILE *fp;
  fp = fopen("thisisquarantined.txt", "w+");
  fprintf(fp, "Hello Quarantine\n");
  fclose(fp);

  return 0;

}
```

</details>

और उस attribute को इस कमांड से **हटाएँ**:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

और इस कमांड से quarantine की गई सभी फ़ाइलें खोजें:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantine की जानकारी LaunchServices द्वारा प्रबंधित एक केंद्रीय डेटाबेस **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** में भी संग्रहीत होती है, जिससे GUI फ़ाइल के स्रोतों के बारे में डेटा प्राप्त कर सकता है। इसके अलावा, ऐसे applications इसे ओवरराइट कर सकते हैं जो अपने स्रोतों को छिपाना चाहते हों। यह LaunchServices APIs के ज़रिए भी किया जा सकता है।

#### **libquarantine.dylib**

यह library कई ऐसे functions export करती है जो extended attribute fields में बदलाव करने की अनुमति देते हैं।

`qtn_file_*` APIs फ़ाइल quarantine policies से संबंधित हैं; `qtn_proc_*` APIs processes पर लागू होती हैं (यानी उन फ़ाइलों पर जो process बनाता है)। Export न किए गए `__qtn_syscall_quarantine*` functions वे हैं जो policies लागू करते हैं। ये पहले argument के रूप में "Quarantine" के साथ `mac_syscall` को call करते हैं, जो requests को `Quarantine.kext` तक भेजता है।

#### **Quarantine.kext**

यह kernel extension केवल **सिस्टम के kernel cache के ज़रिए** उपलब्ध है; हालाँकि, आप [**https://developer.apple.com/**](https://developer.apple.com/) से **Kernel Debug Kit** डाउनलोड कर सकते हैं, जिसमें इस extension का symbolicated version होगा।

यह Kext कई calls को MACF के ज़रिए hook करता है, ताकि फ़ाइल के सभी lifecycle events को intercept किया जा सके: Creation, opening, renaming, hard-linking... यहाँ तक कि `setxattr` को भी, ताकि वह `com.apple.quarantine` extended attribute सेट न कर सके।

यह कुछ MIBs का भी उपयोग करता है:

- `security.mac.qtn.sandbox_enforce`: Sandbox के साथ quarantine लागू करें
- `security.mac.qtn.user_approved_exec`: Quarantined procs केवल approved files को execute कर सकते हैं

#### Provenance xattr (Ventura और बाद के versions)

macOS 13 Ventura ने एक अलग provenance mechanism पेश किया, जो पहली बार किसी quarantined app को चलाने की अनुमति मिलने पर populate होता है।<sup>[[2]](#references)</sup> इससे दो artefacts बनते हैं:

- `.app` bundle directory पर `com.apple.provenance` xattr (एक fixed-size binary value, जिसमें primary key और flags होते हैं)।
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` पर ExecPolicy database के `provenance_tracking` table में एक row, जिसमें app का cdhash और metadata संग्रहीत होते हैं।

Practical usage:

```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```

### XProtect

XProtect macOS में built-in **anti-malware** feature है। XProtect **किसी भी application को पहली बार launch होने या modify होने पर, ज्ञात malware और unsafe file types के अपने database से मिलाकर जांचता है**। जब आप Safari, Mail या Messages जैसे कुछ apps के ज़रिए कोई file download करते हैं, तो XProtect उसे अपने-आप scan करता है। अगर file उसके database में मौजूद किसी ज्ञात malware से मेल खाती है, तो XProtect **उस file को चलने से रोक देगा** और आपको खतरे के बारे में alert करेगा।

Apple नए malware definitions के साथ XProtect database को **नियमित रूप से update करता है**, और ये updates आपके Mac पर अपने-आप download और install हो जाते हैं। इससे XProtect हमेशा नवीनतम ज्ञात खतरों से updated रहता है।

हालांकि, ध्यान देने योग्य बात है कि **XProtect एक पूर्ण-feature वाला antivirus solution नहीं है**। यह केवल ज्ञात खतरों की एक विशिष्ट सूची की जांच करता है और अधिकांश antivirus software की तरह on-access scanning नहीं करता।

आप यह चलाकर नवीनतम XProtect update की जानकारी प्राप्त कर सकते हैं:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect एक SIP-सुरक्षित स्थान **/Library/Apple/System/Library/CoreServices/XProtect.bundle** में स्थित है और bundle के अंदर आपको XProtect द्वारा उपयोग की जाने वाली जानकारी मिल सकती है:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: उन cdhashes वाले code को legacy entitlements का उपयोग करने की अनुमति देता है।
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: उन plugins और extensions की सूची, जिन्हें BundleID और TeamID के आधार पर load होने से रोका गया है या जिनके लिए न्यूनतम version निर्धारित है।
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware का पता लगाने के लिए Yara rules।
- **`XProtect.bundle/Contents/Resources/gk.db`**: blocked applications और TeamIDs के hashes वाला SQLite3 database।

ध्यान दें कि **`/Library/Apple/System/Library/CoreServices/XProtect.app`** में एक अन्य App भी है, जो XProtect से संबंधित है, लेकिन Gatekeeper process में शामिल नहीं है।

> XProtect Remediator: आधुनिक macOS पर, Apple on-demand scanners (XProtect Remediator) उपलब्ध कराता है, जो malware के परिवारों का पता लगाने और उन्हें हटाने के लिए launchd के माध्यम से समय-समय पर चलते हैं। आप इन scans को unified logs में देख सकते हैं:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper नहीं

> [!CAUTION]
> ध्यान दें कि Gatekeeper **हर बार application execute करने पर नहीं चलता**। केवल _**AppleMobileFileIntegrity**_ (AMFI) ही **executable code signatures verify करेगा**, जब आप ऐसा app execute करेंगे जिसे Gatekeeper पहले ही execute और verify कर चुका हो।

इसलिए, पहले किसी app को Gatekeeper से cache कराने के लिए execute करना संभव था, फिर **application की non-executable files में बदलाव करना** (जैसे Electron asar या NIB files) और अगर कोई अन्य protection लागू न हो, तो application को **malicious** additions के साथ **execute** करना।

हालाँकि, अब यह संभव नहीं है क्योंकि macOS **applications bundles के अंदर files में बदलाव करने से रोकता है**। इसलिए, अगर आप [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack आज़माएँगे, तो पाएँगे कि अब इसका दुरुपयोग संभव नहीं है, क्योंकि app को Gatekeeper से cache कराने के लिए execute करने के बाद आप bundle में बदलाव नहीं कर पाएँगे। और अगर आप उदाहरण के लिए Contents directory का नाम बदलकर NotCon कर दें (जैसा कि exploit में बताया गया है), फिर app के main binary को Gatekeeper से cache कराने के लिए execute करें, तो error आएगी और वह execute नहीं होगा।

## Gatekeeper Bypasses

Gatekeeper को bypass करने का कोई भी तरीका (ऐसा कुछ download करवाना और execute करवाना जिसे Gatekeeper को रोकना चाहिए) macOS में vulnerability माना जाता है। अतीत में Gatekeeper को bypass करने की अनुमति देने वाली techniques को दिए गए कुछ CVEs ये हैं:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

यह देखा गया कि अगर extraction के लिए **Archive Utility** का उपयोग किया जाए, तो **886 characters से अधिक लंबे paths** वाली files को com.apple.quarantine extended attribute नहीं मिलता। इस वजह से, वे files अनजाने में Gatekeeper की security checks को **bypass** कर सकती हैं।<sup>[[5]](#references)</sup>

अधिक जानकारी के लिए [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) देखें।<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

जब **Automator** से कोई application बनाया जाता है, तो उसे execute करने के लिए आवश्यक जानकारी executable में नहीं, बल्कि `application.app/Contents/document.wflow` में होती है। Executable बस एक generic Automator binary है, जिसे **Automator Application Stub** कहा जाता है।

इसलिए, आप `application.app/Contents/MacOS/Automator\ Application\ Stub` को **system के अंदर मौजूद किसी अन्य Automator Application Stub की ओर symbolic link से point करा सकते हैं** और यह `document.wflow` (आपकी script) के अंदर मौजूद चीज़ को **Gatekeeper को trigger किए बिना execute करेगा**, क्योंकि असली executable के पास quarantine xattr नहीं होता।<sup>[[6]](#references)</sup>

उदाहरण के लिए अपेक्षित location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

अधिक जानकारी के लिए [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) देखें।<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

इस bypass में एक zip file बनाई गई थी, जिसमें application को `application.app` के बजाय `application.app/Contents` से compress करना शुरू किया गया था। इसलिए **quarantine attr को `application.app/Contents` की सभी files पर लागू किया गया**, लेकिन **`application.app` पर नहीं**, जिसे Gatekeeper check कर रहा था। इस तरह Gatekeeper bypass हो गया, क्योंकि `application.app` trigger होने पर **उसमें quarantine attribute नहीं था।**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) देखें।<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

भले ही components अलग हों, इस vulnerability का exploitation पिछले वाले से बहुत मिलता-जुलता है। इस मामले में, हम **`application.app/Contents`** से Apple Archive बनाएँगे, ताकि **Archive Utility** से decompress किए जाने पर **`application.app`** को quarantine attr न मिले।<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) देखें।<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** का उपयोग किसी को भी फ़ाइल में कोई attribute लिखने से रोकने के लिए किया जा सकता है:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

`com.apple.acl.text`/AppleDouble mechanism और complete sidecar reproduction के लिए, [AppleDouble ACL quarantine bypass reproduction](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md) देखें। Gatekeeper application ZIP variant में यह sequence इस्तेमाल होता है:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।<sup>[[9]](#references)</sup>

ध्यान दें कि इसका AppleArchives के ज़रिए भी exploit किया जा सकता है:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

यह पता चला कि macOS की कुछ आंतरिक समस्याओं के कारण **Google Chrome डाउनलोड की गई फ़ाइलों में quarantine attribute सेट नहीं कर रहा था**।<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble किसी फ़ाइल के attributes को एक अलग फ़ाइल में रखता है, जिसका नाम `._` से शुरू होता है; इससे **macOS मशीनों के बीच** फ़ाइल attributes कॉपी करने में मदद मिलती है। हालाँकि, AppleDouble फ़ाइल को decompress करने के बाद, `._` से शुरू होने वाली फ़ाइल को **quarantine attribute नहीं दिया गया था**।<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Quarantine attribute सेट किए बिना फ़ाइल बनाना संभव होने के कारण, **Gatekeeper को bypass करना संभव था।** तरकीब यह थी कि AppleDouble name convention (नाम की शुरुआत `._` से करके) का उपयोग करके **DMG file application बनाई जाए** और **एक visible file को इस hidden** फ़ाइल के लिए sym link के रूप में बनाया जाए, जिसमें quarantine attribute न हो।\
जब **dmg file execute होती है**, तो उसमें quarantine attribute नहीं होने के कारण वह **Gatekeeper को bypass कर देती है**।

```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```

### [CVE-2023-41067]

Apple ने बेहतर checks के ज़रिए macOS Sonoma 14.0 में LaunchServices की logic error को ठीक किया। सार्वजनिक advisory में केवल यह कहा गया है कि कोई app Gatekeeper को bypass कर सकता है, इसलिए केवल CVE entry के आधार पर किसी खास carrier format या exploitation chain का अनुमान न लगाएँ।<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4 (मार्च 2024 में जारी) में `libarchive` द्वारा malicious ZIPs को handle करने से Gatekeeper bypass संभव था, जिससे apps assessment से बच सकते थे। 14.4 या उसके बाद के version पर update करें, जहाँ Apple ने इस issue को ठीक किया।<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Downloaded app में embedded **Automator Quick Action workflow** Gatekeeper assessment के बिना trigger हो सकता था, क्योंकि workflows को data माना जाता था और Automator helper उन्हें सामान्य notarization prompt path के बाहर execute करता था। इसलिए, shell script चलाने वाला Quick Action bundle करने वाला crafted `.app` (उदाहरण के लिए, `Contents/PlugIns/*.workflow/Contents/document.wflow` के अंदर) launch होते ही execute हो सकता था। Apple ने एक अतिरिक्त consent dialog जोड़ा और Ventura **13.7**, Sonoma **14.7**, तथा Sequoia **15** में assessment path ठीक किया।<sup>[[3]](#references)</sup>

### Extraction और copy boundaries पर quarantine propagation failures

2024 के एक अध्ययन में iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z), और 7z Utility (DMG/ZIP/7Z) के परीक्षण किए गए versions में propagation gaps पाए गए; अध्ययन में VMware Tools के host-to-guest copies के दौरान attribute खोते हुए भी देखा गया। इसके बाद कई vendors ने fixes की घोषणा की, इसलिए इन नामों को **version-specific retesting** के लिए leads मानें, न कि हमेशा vulnerable रहने वाले software की सूची। यही trust-boundary समस्या native Unix workflows पर भी लागू होती है: `curl`/`scp` quarantine नहीं जोड़ते, और command-line `tar`/`unzip` इसे अपने-आप carrier archive से inherit नहीं करते।<sup>[[15]](#references)</sup>

Offensive testing के लिए, browser, mail client, archive, disk-image, cloud-sync, shared-folder, और VM-copy के **हर** transition के बाद carrier और final app की तुलना करें। `spctl` द्वारा स्पष्ट rejection से missing xattr ठीक नहीं होता: quarantine के बिना, पहली बार खोलने पर Gatekeeper का सामान्य path शायद वह assessment माँगे ही नहीं।<sup>[[15]](#references)</sup>

```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
  'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```

### uchg (इस [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf) से)

- एक directory बनाएँ जिसमें एक app हो।
- app में uchg जोड़ें।
- app को tar.gz file में compress करें।
- tar.gz file किसी victim को भेजें।
- victim tar.gz file खोलता है और app चलाता है।
- Gatekeeper app की जाँच नहीं करता।<sup>[[12]](#references)</sup>

### Quarantine xattr को रोकना

अगर किसी ".app" bundle में quarantine xattr नहीं जोड़ा जाता है, तो उसे execute करने पर **Gatekeeper ट्रिगर नहीं होगा**।

filesystem-, flag-, ACL-, और AppleDouble-आधारित primitives के लिए [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) देखें, जो extended attributes को रोक या हटा सकते हैं।





## References

- [1] [Apple Platform Security: macOS Sonoma 14.4 की सुरक्षा सामग्री के बारे में (इसमें CVE-2024-27853 शामिल है)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS अब apps की provenance को कैसे track करता है](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7 की सुरक्षा सामग्री के बारे में (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia ने Control-click “Open” Gatekeeper bypass हटा दिया](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810 की खोज](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper को bypass करना](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs ने Gatekeeper bypass की अनुमति देने वाली Safari vulnerability की पहचान की](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs ने Gatekeeper bypass की अनुमति देने वाली macOS Archive Utility vulnerability की पहचान की (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper की Achilles heel: macOS vulnerability का पता लगाना](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Gatekeeper bypass की खोज (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor की मदद से Gatekeeper bypass exploit ढूँढ़ना और report करना](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security और Privacy Mechanisms को bypass करना — Gatekeeper से System Integrity Protection तक (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14 की सुरक्षा सामग्री के बारे में (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: notarised product की जाँच करना](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper Bypass — macOS Security Mechanism की कमज़ोरियों का पता लगाना](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
