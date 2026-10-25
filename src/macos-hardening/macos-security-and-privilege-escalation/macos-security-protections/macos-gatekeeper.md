# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** Mac operating systems के लिए विकसित एक security feature है, जिसे यह सुनिश्चित करने के लिए बनाया गया है कि users अपने systems पर **केवल trusted software चलाएँ**। यह उस software को **validate** करता है जिसे user डाउनलोड करके **App Store के बाहर के sources** से खोलने की कोशिश करता है, जैसे कोई app, plug-in या installer package।

Gatekeeper का मुख्य mechanism उसकी **verification** प्रक्रिया है। यह जाँचता है कि डाउनलोड किया गया software **किसी मान्यता प्राप्त developer द्वारा signed** है या नहीं, जिससे software की authenticity सुनिश्चित होती है। इसके अलावा, यह पता लगाता है कि software को Apple ने **notarize** किया है या नहीं, जिससे पुष्टि होती है कि उसमें कोई ज्ञात malicious content नहीं है और notarization के बाद उसके साथ छेड़छाड़ नहीं हुई है।

इसके अतिरिक्त, Gatekeeper users को डाउनलोड किए गए software को पहली बार खोलने की **अनुमति देने के लिए prompt** करके user control और security को मज़बूत करता है। यह सुरक्षा users को अनजाने में संभावित रूप से हानिकारक executable code चलाने से रोकने में मदद करती है, जिसे वे गलती से एक harmless data file समझ सकते हैं।

### Application Signatures

Application signatures, जिन्हें code signatures भी कहा जाता है, Apple के security infrastructure का एक अहम हिस्सा हैं। इनका उपयोग **software author (developer) की पहचान सत्यापित करने** और यह सुनिश्चित करने के लिए किया जाता है कि पिछली बार sign किए जाने के बाद से code के साथ छेड़छाड़ नहीं हुई है।

यह इस तरह काम करता है:

1. **Application को sign करना:** जब developer अपना application distribute करने के लिए तैयार होता है, तो वह **एक private key का उपयोग करके application को sign करता है**। यह private key उस **certificate से जुड़ी होती है जो Apple, Apple Developer Program में enrol होने पर developer को जारी करता है**। Signing प्रक्रिया में app के सभी हिस्सों का cryptographic hash बनाना और इस hash को developer की private key से encrypt करना शामिल है।
2. **Application को distribute करना:** इसके बाद signed application को developer के certificate के साथ users तक पहुँचाया जाता है, जिसमें उससे संबंधित public key होती है।
3. **Application को verify करना:** जब कोई user application डाउनलोड करके चलाने की कोशिश करता है, तो उसका Mac operating system developer के certificate की public key का उपयोग करके hash को decrypt करता है। फिर वह application की मौजूदा स्थिति के आधार पर hash दोबारा calculate करता है और इसकी तुलना decrypted hash से करता है। अगर दोनों मेल खाते हैं, तो इसका मतलब है कि **developer द्वारा sign किए जाने के बाद application में बदलाव नहीं किया गया है**, और system उसे चलाने की अनुमति देता है।

Application signatures, Apple की Gatekeeper technology का एक अहम हिस्सा हैं। जब कोई user **internet से डाउनलोड किया गया application खोलने** की कोशिश करता है, तो Gatekeeper उसकी application signature verify करता है। अगर उसे Apple द्वारा किसी ज्ञात developer को जारी किए गए certificate से sign किया गया है और code के साथ छेड़छाड़ नहीं हुई है, तो Gatekeeper application को चलने की अनुमति देता है। अन्यथा, वह application को block करके user को alert करता है।

macOS Catalina से, **Gatekeeper यह भी जाँचता है कि application को Apple ने notarize किया है या नहीं**, जिससे security की एक अतिरिक्त परत जुड़ती है। Notarization प्रक्रिया application में ज्ञात security issues और malicious code की जाँच करती है। अगर ये जाँचें सफल होती हैं, तो Apple application में एक ticket जोड़ता है, जिसे Gatekeeper verify कर सकता है।

#### Signatures की जाँच करें

किसी **malware sample** की जाँच करते समय, आपको हमेशा binary की **signature जाँचनी चाहिए**, क्योंकि उसे sign करने वाला **developer** पहले से ही **malware से जुड़ा** हो सकता है।

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

### नोटराइज़ेशन

Apple की notarization प्रक्रिया संभावित रूप से हानिकारक सॉफ़्टवेयर से उपयोगकर्ताओं की सुरक्षा के लिए एक अतिरिक्त उपाय है। इसमें **डेवलपर अपना application जाँच के लिए सबमिट करता है**, जिसे **Apple की Notary Service** जाँचती है। इसे App Review न समझें। यह सेवा एक **स्वचालित प्रणाली** है, जो सबमिट किए गए सॉफ़्टवेयर में **malicious content** और code-signing से जुड़ी संभावित समस्याओं की जाँच करती है।

यदि सॉफ़्टवेयर बिना किसी समस्या के यह जाँच **पास** कर लेता है, तो Notary Service एक notarization ticket बनाती है। इसके बाद डेवलपर को **यह ticket अपने सॉफ़्टवेयर से जोड़ना होता है**—इस प्रक्रिया को 'stapling' कहते हैं। इसके अलावा, notarization ticket ऑनलाइन भी प्रकाशित किया जाता है, जहाँ Gatekeeper, Apple की security technology, उसे देख सकता है।

जब उपयोगकर्ता पहली बार सॉफ़्टवेयर install या execute करता है, तो notarization ticket की मौजूदगी—चाहे वह executable के साथ stapled हो या ऑनलाइन मिले—**Gatekeeper को बताती है कि Apple ने सॉफ़्टवेयर को notarize किया है**। इसके परिणामस्वरूप, Gatekeeper पहले launch dialog में एक विवरणात्मक संदेश दिखाता है, जिसमें बताया जाता है कि Apple ने सॉफ़्टवेयर में malicious content की जाँच की है। इस तरह यह प्रक्रिया उपयोगकर्ताओं का अपने सिस्टम पर install या run किए जाने वाले सॉफ़्टवेयर की सुरक्षा पर भरोसा बढ़ाती है।

### spctl & syspolicyd

> [!CAUTION]
> ध्यान दें कि Sequoia version से, **`spctl`** अब Gatekeeper configuration में बदलाव करने की अनुमति नहीं देता।

**`spctl`** Gatekeeper की जानकारी देखने और उससे interact करने का CLI tool है (`syspolicyd` daemon के साथ XPC messages के ज़रिए)। उदाहरण के लिए, इससे Gatekeeper का **status** देखा जा सकता है:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> ध्यान दें कि GateKeeper signature checks केवल **Quarantine attribute वाली files** पर किए जाते हैं, हर file पर नहीं।

GateKeeper **preferences और signature** के अनुसार जाँचता है कि किसी binary को execute किया जा सकता है या नहीं:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** Gatekeeper को लागू करने के लिए ज़िम्मेदार मुख्य daemon है। यह `/var/db/SystemPolicy` में मौजूद database को बनाए रखता है। [database को support करने वाला code यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) और [SQL template यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) मिल सकता है। ध्यान दें कि database पर SIP की पाबंदी नहीं है और यह root द्वारा writable है। Database `/var/db/.SystemPolicy-default` को उस स्थिति में original backup के रूप में इस्तेमाल किया जाता है, जब दूसरा database corrupt हो जाए।

इसके अलावा, **`/var/db/gke.bundle`** और **`/var/db/gkopaque.bundle`** bundles में ऐसे rules वाली files हैं जिन्हें database में insert किया जाता है। आप इस database को root के रूप में इस तरह देख सकते हैं:

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

**`syspolicyd`** अलग-अलग operations जैसे `assess`, `update`, `record` और `cancel` वाला XPC server भी उपलब्ध कराता है। इन operations तक **`Security.framework` के `SecAssessment*`** APIs के ज़रिए भी पहुँचा जा सकता है, और **`spctl`** वास्तव में XPC के ज़रिए **`syspolicyd`** से बात करता है।

ध्यान दें कि पहला rule "**App Store**" पर और दूसरा "**Developer ID**" पर समाप्त होता है, और पिछली image में यह **App Store से और पहचाने गए developers से apps चलाने के लिए enabled था**।\
अगर आप उस setting को App Store पर **बदलते** हैं, तो "**Notarized Developer ID" rules गायब हो जाएँगे**।

**GKE** type के हज़ारों rules भी हैं :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

ये hashes इन फ़ाइलों से हैं:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

या आप पिछली जानकारी को इस तरह सूचीबद्ध कर सकते हैं:

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

इससे **जाँचा जा सकता है कि GateKeeper किसी App को अनुमति देगा या नहीं**:

```bash
spctl --assess -v /Applications/App.app
```

macOS 14 और उसके बाद के संस्करणों में, **`syspolicy_check`** किसी एप्लिकेशन बंडल के लिए वितरण-पूर्व एक उपयोगी उच्च-स्तरीय जाँच है। यह साधारण `spctl` परिणाम की तुलना में trusted-execution से जुड़ी अधिक उपयोगी diagnostics देता है, हालांकि Apple अब भी वास्तविक डाउनलोड/एक्सट्रैक्शन/पहली बार लॉन्च करने के पथ का परीक्षण करने की सलाह देता है, क्योंकि इससे quarantine propagation की भी जाँच होती है।<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

GateKeeper में नए नियम जोड़ना संभव है, ताकि कुछ ऐप्स को चलाने की अनुमति दी जा सके:

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

**kernel extensions** के संबंध में, `/var/db/SystemPolicyConfiguration` फ़ोल्डर में उन kexts की सूचियों वाली फ़ाइलें होती हैं जिन्हें लोड करने की अनुमति है। इसके अलावा, `spctl` के पास `com.apple.private.iokit.nvram-csr` entitlement है, क्योंकि यह नए pre-approved kernel extensions जोड़ सकता है, जिन्हें NVRAM में `kext-allowed-teams` key में भी सहेजना होता है।

#### macOS 15 (Sequoia) और बाद के संस्करणों में Gatekeeper का प्रबंधन

- लंबे समय से मौजूद Finder **Ctrl+Open / Right-click → Open** bypass हटा दिया गया है; पहले block dialog के बाद, users को **System Settings → Privacy & Security → Open Anyway** से blocked app को स्पष्ट रूप से अनुमति देनी होगी।<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` को अब unattended policy changes के रूप में स्वीकार नहीं किया जाता। Rule database या global assessment state को बदलने वाले operations deprecated हैं, इसलिए assessment के लिए `spctl` का उपयोग करें और UI या MDM के ज़रिए enforcement configure करें।

macOS 15 Sequoia से, end users अब `spctl` से Gatekeeper policy toggle नहीं कर सकते। प्रबंधन System Settings के ज़रिए या `com.apple.systempolicy.control` payload वाली MDM configuration profile deploy करके किया जाता है। App Store और identified developers को अनुमति देने (लेकिन "Anywhere" को नहीं) वाली profile का उदाहरण:

<details>
<summary>App Store और identified developers को अनुमति देने वाली MDM profile</summary>

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

किसी एप्लिकेशन या फ़ाइल को **डाउनलोड** करने पर, कुछ macOS **applications**, जैसे वेब ब्राउज़र या ईमेल क्लाइंट, डाउनलोड की गई फ़ाइल में एक extended file attribute **जोड़ते हैं**, जिसे आम तौर पर "**quarantine flag**" कहा जाता है। यह attribute फ़ाइल को किसी अविश्वसनीय स्रोत (इंटरनेट) से आई हुई और संभावित रूप से जोखिमपूर्ण **चिह्नित करने** के लिए सुरक्षा उपाय के रूप में काम करता है। हालांकि, सभी applications यह attribute नहीं जोड़ते। उदाहरण के लिए, आम BitTorrent client software आम तौर पर इस प्रक्रिया को छोड़ देता है।

**Quarantine flag की मौजूदगी macOS के Gatekeeper security feature को संकेत देती है, जब कोई उपयोगकर्ता फ़ाइल चलाने की कोशिश करता है**।

अगर **quarantine flag मौजूद नहीं है** (जैसे कुछ BitTorrent clients से डाउनलोड की गई फ़ाइलों के मामले में), तो हो सकता है कि Gatekeeper की **जाँचें न की जाएँ**। इसलिए, उपयोगकर्ताओं को कम सुरक्षित या अज्ञात स्रोतों से डाउनलोड की गई फ़ाइलें खोलते समय सावधानी बरतनी चाहिए।

> [!NOTE] > Code signatures की **वैधता जाँचना** एक **संसाधन-गहन** प्रक्रिया है, जिसमें code और उसके साथ बंडल किए गए सभी resources के cryptographic **hashes** जनरेट करना शामिल है। इसके अलावा, certificate की वैधता जाँचने के लिए Apple के servers पर **ऑनलाइन जाँच** करनी होती है, ताकि पता लगाया जा सके कि जारी होने के बाद उसे revoke तो नहीं किया गया। इन कारणों से, हर बार app लॉन्च होने पर code signature और notarization की पूरी जाँच करना **व्यावहारिक नहीं है**।
>
> इसलिए, ये जाँचें **केवल quarantine attribute वाली apps चलाते समय की जाती हैं**।

> [!WARNING]
> यह attribute फ़ाइल बनाने/डाउनलोड करने वाले **application द्वारा सेट किया जाना चाहिए**।
>
> हालांकि, sandboxed फ़ाइलें उनके द्वारा बनाई गई हर फ़ाइल पर यह attribute सेट करेंगी। और non sandboxed apps इसे खुद सेट कर सकती हैं, या **Info.plist** में [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key निर्दिष्ट कर सकती हैं, जिससे system बनाई गई फ़ाइलों पर `com.apple.quarantine` extended attribute सेट करेगा,

इसके अलावा, **`qtn_proc_apply_to_self`** कॉल करने वाली process द्वारा बनाई गई सभी फ़ाइलें quarantined होती हैं। या **`qtn_file_apply_to_path`** API किसी निर्दिष्ट file path में quarantine attribute जोड़ती है।

इसे इस तरह **जाँचना और सक्षम/अक्षम करना** (इसके लिए root आवश्यक है) संभव है:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

आप यह भी **पता लगा सकते हैं कि किसी फ़ाइल में quarantine extended attribute है या नहीं**:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

**value** को **extended** **attributes** के लिए जाँचें और पता लगाएँ कि quarantine attr किस app ने लिखा है:

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

वास्तव में, कोई process "अपने द्वारा बनाई गई files पर quarantine flags सेट कर सकता है" (मैंने बनाई गई file में USER_APPROVED flag लागू करने की कोशिश की, लेकिन यह लागू नहीं हुआ):

<details>

<summary>quarantine flags लागू करने का source code</summary>

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

और इस attribute को **हटाएँ**:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

और निम्न कमांड से सभी quarantined फ़ाइलें खोजें:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantine की जानकारी LaunchServices द्वारा प्रबंधित एक केंद्रीय डेटाबेस **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** में भी संग्रहीत होती है, जिससे GUI फ़ाइल के origins के बारे में डेटा प्राप्त कर सकता है। इसके अलावा, ऐसे applications इसे overwrite कर सकते हैं जो अपने origins छिपाना चाहते हों। यह LaunchServices APIs से भी किया जा सकता है।

#### **libquarantine.dylib**

यह library कई ऐसे functions export करती है जो extended attribute fields में बदलाव करने की अनुमति देते हैं।

`qtn_file_*` APIs फ़ाइल quarantine policies से संबंधित हैं, जबकि `qtn_proc_*` APIs processes (process द्वारा बनाई गई फ़ाइलों) पर लागू होती हैं। Export न किए गए `__qtn_syscall_quarantine*` functions वे हैं जो policies लागू करते हैं। ये `"Quarantine"` को पहले argument के रूप में देकर `mac_syscall` को call करते हैं, जो requests को `Quarantine.kext` तक भेजता है।

#### **Quarantine.kext**

यह kernel extension केवल **सिस्टम के kernel cache के माध्यम से** उपलब्ध है; हालांकि, आप [**https://developer.apple.com/**](https://developer.apple.com/) से **Kernel Debug Kit** डाउनलोड कर _सकते_ हैं, जिसमें extension का symbolicated version शामिल होगा।

यह Kext, MACF के माध्यम से कई calls को hook करता है, ताकि फ़ाइल lifecycle के सभी events को trap किया जा सके: Creation, opening, renaming, hard-linking... यहां तक कि `setxattr` को भी, ताकि वह `com.apple.quarantine` extended attribute सेट न कर सके।

यह कुछ MIBs का भी उपयोग करता है:

- `security.mac.qtn.sandbox_enforce`: Sandbox के साथ quarantine लागू करें
- `security.mac.qtn.user_approved_exec`: Quarantined procs केवल approved files execute कर सकते हैं

#### Provenance xattr (Ventura and later)

macOS 13 Ventura ने एक अलग provenance mechanism पेश किया, जो पहली बार किसी quarantined app को चलने की अनुमति मिलने पर populate होता है।<sup>[[2]](#references)</sup> इससे दो artefacts बनते हैं:

- `.app` bundle directory पर `com.apple.provenance` xattr (एक fixed-size binary value जिसमें primary key और flags होते हैं)।
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` पर मौजूद ExecPolicy database की `provenance_tracking` table में एक row, जिसमें app का cdhash और metadata संग्रहीत होता है।

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

XProtect macOS में एक अंतर्निहित **anti-malware** सुविधा है। XProtect **हर एप्लिकेशन को पहली बार लॉन्च या संशोधित किए जाने पर, ज्ञात malware और असुरक्षित फ़ाइल प्रकारों के अपने डेटाबेस से मिलाकर जाँचता है**। जब आप Safari, Mail या Messages जैसे कुछ ऐप्स के ज़रिए कोई फ़ाइल डाउनलोड करते हैं, तो XProtect उसे अपने-आप स्कैन करता है। अगर फ़ाइल उसके डेटाबेस में मौजूद किसी ज्ञात malware से मेल खाती है, तो XProtect **फ़ाइल को चलने से रोक देगा** और आपको खतरे के बारे में सूचित करेगा।

Apple XProtect डेटाबेस को नई malware definitions के साथ **नियमित रूप से अपडेट करता है**। ये अपडेट आपके Mac पर अपने-आप डाउनलोड और इंस्टॉल हो जाते हैं। इससे XProtect नवीनतम ज्ञात खतरों से हमेशा अपडेटेड रहता है।

हालाँकि, ध्यान दें कि **XProtect एक पूर्ण-विशेषताओं वाला antivirus समाधान नहीं है**। यह केवल ज्ञात खतरों की एक विशिष्ट सूची की जाँच करता है और अधिकांश antivirus सॉफ़्टवेयर की तरह on-access scanning नहीं करता।

आप नवीनतम XProtect अपडेट की जानकारी इस कमांड से प्राप्त कर सकते हैं:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect एक SIP-सुरक्षित स्थान **/Library/Apple/System/Library/CoreServices/XProtect.bundle** में मौजूद है, और bundle के अंदर आपको वह जानकारी मिल सकती है जिसका XProtect उपयोग करता है:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: उन cdhashes वाले code को legacy entitlements का उपयोग करने की अनुमति देता है।
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: उन plugins और extensions की सूची, जिन्हें BundleID और TeamID के आधार पर लोड करने की अनुमति नहीं है, या जिनके लिए न्यूनतम version निर्धारित है।
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware का पता लगाने के लिए Yara rules।
- **`XProtect.bundle/Contents/Resources/gk.db`**: blocked applications और TeamIDs के hashes वाला SQLite3 database।

ध्यान दें कि **`/Library/Apple/System/Library/CoreServices/XProtect.app`** में एक और App मौजूद है, जो XProtect से संबंधित है, लेकिन Gatekeeper process में शामिल नहीं है।

> XProtect Remediator: आधुनिक macOS पर, Apple ऑन-डिमांड scanners (XProtect Remediator) उपलब्ध कराता है, जो malware के परिवारों का पता लगाने और उन्हें हटाने के लिए launchd के ज़रिए समय-समय पर चलते हैं। आप इन scans को unified logs में देख सकते हैं:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper नहीं

> [!CAUTION]
> ध्यान दें कि हर बार application execute करने पर Gatekeeper **नहीं चलता**। केवल _**AppleMobileFileIntegrity**_ (AMFI) तब **executable code signatures verify** करता है, जब आप ऐसा app execute करते हैं जिसे Gatekeeper पहले ही execute और verify कर चुका हो।

इसलिए, पहले Gatekeeper से किसी app को cache कराने के लिए उसे execute करना संभव था, फिर application की **non-executable files** (जैसे Electron asar या NIB files) **modify** करना। अगर कोई अन्य protection लागू न हो, तो application को इन **malicious** additions के साथ **execute** किया जाता था।

हालाँकि, अब यह संभव नहीं है, क्योंकि macOS applications bundles के अंदर की files को **modify करने से रोकता है**। इसलिए, अगर आप [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack आज़माते हैं, तो पाएँगे कि अब इसका दुरुपयोग संभव नहीं है: app को Gatekeeper से cache कराने के लिए execute करने के बाद आप bundle को modify नहीं कर पाएँगे। और अगर आप, उदाहरण के लिए, exploit में बताए अनुसार `Contents` directory का नाम बदलकर `NotCon` कर देते हैं, फिर app की main binary को Gatekeeper से cache कराने के लिए execute करते हैं, तो error आएगा और वह execute नहीं होगी।

## Gatekeeper Bypasses

Gatekeeper को bypass करने का कोई भी तरीका (user से कुछ download करवाकर उसे execute करवाना, जबकि Gatekeeper को इसकी अनुमति नहीं देनी चाहिए) macOS में vulnerability माना जाता है। ये उन techniques को दिए गए कुछ CVEs हैं जिनसे पहले Gatekeeper bypass किया जा सकता था:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

यह देखा गया कि अगर extraction के लिए **Archive Utility** का उपयोग किया जाता है, तो **886 characters से लंबे paths** वाली files को com.apple.quarantine extended attribute नहीं मिलता। इस वजह से, वे files अनजाने में Gatekeeper की security checks को **bypass** कर सकती हैं।<sup>[[5]](#references)</sup>

अधिक जानकारी के लिए [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) देखें।<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

जब **Automator** से कोई application बनाई जाती है, तो उसे execute करने के लिए आवश्यक जानकारी executable में नहीं, बल्कि `application.app/Contents/document.wflow` में होती है। Executable केवल एक generic Automator binary होती है, जिसे **Automator Application Stub** कहते हैं।

इसलिए, आप `application.app/Contents/MacOS/Automator\ Application\ Stub` को **system में मौजूद किसी दूसरे Automator Application Stub की symbolic link पर point** करा सकते हैं। इससे `document.wflow` (आपकी script) में मौजूद चीज़ execute होगी, **बिना Gatekeeper trigger किए**, क्योंकि actual executable में quarantine xattr नहीं होता।<sup>[[6]](#references)</sup>

उदाहरण के लिए अपेक्षित location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

अधिक जानकारी के लिए [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) देखें।<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

इस bypass में एक zip file बनाई गई थी, जिसमें compression `application.app` के बजाय `application.app/Contents` से शुरू हुआ था। इसलिए **quarantine attr**, `application.app/Contents` की सभी **files पर** लागू हुआ, लेकिन `application.app` पर **नहीं**। Gatekeeper इसी की जाँच कर रहा था, इसलिए Gatekeeper bypass हो गया: जब `application.app` trigger हुआ, तो **उसमें quarantine attribute नहीं था।**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) देखें।<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

भले ही components अलग हों, इस vulnerability का exploitation पिछली vulnerability से बहुत मिलता-जुलता है। इस मामले में, हम **`application.app/Contents`** से Apple Archive बनाएँगे, ताकि **Archive Utility** द्वारा decompress किए जाने पर **`application.app` को quarantine attr न मिले**।<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

[**मूल रिपोर्ट**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) में अधिक जानकारी देखें।<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** का उपयोग किसी को भी किसी फ़ाइल में attribute लिखने से रोकने के लिए किया जा सकता है:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

इसके अलावा, **AppleDouble** file format किसी file को उसके ACEs सहित copy करता है।<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में देखा जा सकता है कि **`com.apple.acl.text`** नाम के xattr में stored ACL का text representation, decompressed file पर ACL के रूप में set किया जाएगा। इसलिए, अगर आपने किसी application को ऐसे ACL वाले **AppleDouble** file format के साथ zip file में compress किया, जो उस पर अन्य xattrs को लिखे जाने से रोकता है... तो application पर quarantine xattr set नहीं हुआ:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।<sup>[[9]](#references)</sup> sidecar बनाने और सत्यापन के चरणों के लिए [AppleDouble/ACL reproduction](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) देखें।

ध्यान दें कि इसका AppleArchives के ज़रिए भी शोषण किया जा सकता है:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

पता चला कि macOS की कुछ आंतरिक समस्याओं के कारण **Google Chrome डाउनलोड की गई फ़ाइलों पर quarantine attribute सेट नहीं कर रहा था**।<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble किसी फ़ाइल के attributes को `._` से शुरू होने वाले अलग फ़ाइल में संग्रहीत करता है; इससे **macOS मशीनों के बीच** फ़ाइल के attributes कॉपी किए जा सकते हैं। हालांकि, AppleDouble फ़ाइल को decompress करने के बाद, `._` से शुरू होने वाली फ़ाइल को **quarantine attribute नहीं दिया गया था**।<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Quarantine attribute सेट नहीं होने वाली file बनाने में सक्षम होने के कारण, **Gatekeeper को bypass करना संभव था।** तरकीब यह थी कि AppleDouble नामकरण परंपरा का उपयोग करके एक **DMG file application बनाई जाए** (नाम `._` से शुरू करें) और एक **दिखाई देने वाली file को इस hidden file के sym link के रूप में बनाया जाए**, जिसमें quarantine attribute न हो।\
जब **DMG file execute की जाती है**, तो उसमें quarantine attribute न होने के कारण यह **Gatekeeper को bypass कर देती है**।

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

Apple ने बेहतर जाँचों के ज़रिए macOS Sonoma 14.0 में LaunchServices की logic error को ठीक किया। सार्वजनिक advisory में केवल यह बताया गया है कि कोई app Gatekeeper को bypass कर सकता है, इसलिए सिर्फ़ CVE entry के आधार पर किसी खास carrier format या exploitation chain का अनुमान न लगाएँ।<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4 (मार्च 2024 में जारी) में `libarchive` द्वारा malicious ZIPs को संभालने के तरीके से Gatekeeper bypass संभव था, जिससे apps assessment से बच सकते थे। Apple ने इस समस्या को ठीक कर दिया है; इसलिए 14.4 या उसके बाद के version पर update करें।<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

किसी downloaded app में एम्बेड किया गया **Automator Quick Action workflow**, Gatekeeper assessment के बिना trigger हो सकता था, क्योंकि workflows को data माना जाता था और Automator helper उन्हें सामान्य notarization prompt path के बाहर execute करता था। इसलिए, shell script चलाने वाले Quick Action के साथ बनाया गया `.app` (उदाहरण के लिए, `Contents/PlugIns/*.workflow/Contents/document.wflow` के अंदर) launch होते ही execute हो सकता था। Apple ने एक अतिरिक्त consent dialog जोड़ा और Ventura **13.7**, Sonoma **14.7**, और Sequoia **15** में assessment path ठीक किया।<sup>[[3]](#references)</sup>

### Extraction और copy boundaries पर Quarantine propagation failures

2024 के एक अध्ययन में iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z), और 7z Utility (DMG/ZIP/7Z) के परीक्षण किए गए versions में propagation gaps पाए गए; अध्ययन में VMware Tools के host-to-guest copies के दौरान attribute खोने की समस्या भी देखी गई। इसके बाद कई vendors ने fixes की घोषणा की, इसलिए इन नामों को **version-specific retesting** के लिए संभावित सुराग मानें, न कि हमेशा vulnerable रहने वाले software की सूची। यही trust-boundary समस्या native Unix workflows पर भी लागू होती है: `curl`/`scp` quarantine नहीं जोड़ते, और command-line `tar`/`unzip` इसे carrier archive से अपने-आप inherit नहीं करते।<sup>[[15]](#references)</sup>

Offensive testing के लिए, **हर** browser, mail client, archive, disk-image, cloud-sync, shared-folder, और VM-copy transition के बाद carrier और अंतिम app की तुलना करें। `spctl` द्वारा स्पष्ट रूप से अस्वीकार किए जाने से missing xattr ठीक नहीं होता: quarantine न होने पर, पहली बार खोलने पर Gatekeeper का सामान्य path शायद वह assessment माँगे ही नहीं।<sup>[[15]](#references)</sup>

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

- एक app वाली directory बनाएँ।
- App में uchg जोड़ें।
- App को tar.gz फ़ाइल में compress करें।
- tar.gz फ़ाइल victim को भेजें।
- Victim tar.gz फ़ाइल खोलता है और app चलाता है।
- Gatekeeper app की जाँच नहीं करता।<sup>[[12]](#references)</sup>

### Quarantine xattr को रोकना

".app" bundle में अगर quarantine xattr नहीं जोड़ा जाता है, तो उसे execute करने पर **Gatekeeper सक्रिय नहीं होगा**।

उन filesystem-, flag-, ACL- और AppleDouble-आधारित primitives के लिए [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) देखें, जो extended attributes को जुड़ने से रोक सकते हैं या हटा सकते हैं।





## References

- [1] [Apple Platform Security: macOS Sonoma 14.4 की सुरक्षा सामग्री के बारे में (इसमें CVE-2024-27853 शामिल है)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS अब apps की provenance को कैसे track करता है](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7 की सुरक्षा सामग्री के बारे में (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia ने Control-click “Open” वाले Gatekeeper bypass को हटा दिया](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810 की खोज](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper को bypass करना](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs ने Gatekeeper bypass की अनुमति देने वाली Safari vulnerability की पहचान की](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs ने Gatekeeper bypass की अनुमति देने वाली macOS Archive Utility vulnerability की पहचान की (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper की Achilles heel: macOS vulnerability का पता लगाना](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Gatekeeper bypass की खोज (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor की मदद से Gatekeeper bypass exploit खोजना और report करना](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS सुरक्षा और गोपनीयता तंत्रों को bypass करना — Gatekeeper से System Integrity Protection तक (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14 की सुरक्षा सामग्री के बारे में (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: notarised product का परीक्षण करना](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper bypass — macOS सुरक्षा तंत्र की कमज़ोरियों का पता लगाना](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
