# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** Mac ऑपरेटिंग सिस्टम के लिए विकसित की गई एक सुरक्षा सुविधा है, जिसका उद्देश्य यह सुनिश्चित करना है कि उपयोगकर्ता अपने सिस्टम पर केवल भरोसेमंद सॉफ़्टवेयर ही चलाएँ। यह उस सॉफ़्टवेयर का सत्यापन करके काम करता है जिसे उपयोगकर्ता **App Store** के बाहर से डाउनलोड करता है और खोलने का प्रयास करता है—उदाहरण के लिए कोई ऐप, प्लग-इन, या इंस्टॉलर पैकेज।

Gatekeeper का मुख्य तंत्र इसकी **verification** प्रक्रिया में निहित है। यह जांचता है कि डाउनलोड किया गया सॉफ़्टवेयर किसी मान्यता प्राप्त डेवलपर द्वारा **signed** है या नहीं, जिससे सॉफ़्टवेयर की प्रामाणिकता सुनिश्चित होती है। इसके अलावा, यह यह भी सत्यापित करता है कि सॉफ़्टवेयर Apple द्वारा **notarised** है या नहीं, जिससे यह सुनिश्चित होता है कि इसमें ज्ञात हानिकारक सामग्री नहीं है और notarisation के बाद इसमें छेड़छाड़ नहीं हुई है।

अतिरिक्त रूप से, Gatekeeper उपयोगकर्ता नियंत्रण और सुरक्षा को मजबूत करता है—यह डाउनलोड किए गए सॉफ़्टवेयर को पहली बार खोलने पर उपयोगकर्ता से अनुमति माँगता है। यह सुरक्षा उपाय उपयोगकर्ताओं को अनजाने में संभावित रूप से हानिकारक executable कोड चलाने से रोकने में मदद करता है, जिसे वे किसी harmless डेटा फ़ाइल समझ बैठे हों।

### एप्लिकेशन सिग्नेचर

एप्लिकेशन सिग्नेचर, जिन्हें code signatures भी कहा जाता है, Apple की सुरक्षा इन्फ्रास्ट्रक्चर का एक महत्वपूर्ण हिस्सा हैं। इन्हें सॉफ़्टवेयर के लेखक (डेवलपर) की पहचान सत्यापित करने और यह सुनिश्चित करने के लिए उपयोग किया जाता है कि कोड को उसके अंतिम साइन के बाद से छेड़छाड़ नहीं की गई है।

यह इस प्रकार काम करता है:

1. **Signing the Application:** जब कोई डेवलपर अपने एप्लिकेशन को वितरित करने के लिए तैयार होता है, तो वह private key का उपयोग करके एप्लिकेशन पर साइन करता है। यह private key उस certificate से जुड़ी होती है जो Apple डेवलपर प्रोग्राम में नामांकन के समय डेवलपर को जारी करता है। साइनिंग प्रक्रिया में ऐप के सभी हिस्सों का एक क्रिप्टोग्राफिक hash बनाना और इस hash को डेवलपर की private key से एन्क्रिप्ट करना शामिल है।
2. **Distributing the Application:** साइन किया गया एप्लिकेशन फिर डेवलपर के certificate के साथ उपयोगकर्ताओं तक वितरित किया जाता है, जिसमें संबंधित public key होती है।
3. **Verifying the Application:** जब कोई उपयोगकर्ता एप्लिकेशन डाउनलोड कर के चलाने का प्रयास करता है, तो उसका Mac operating system डेवलपर के certificate से public key का उपयोग करके hash को decrypt करता है। इसके बाद यह एप्लिकेशन की वर्तमान स्थिति के आधार पर फिर से hash की गणना करता है और इसे decrypted hash से तुलना करता है। यदि वे मेल खाते हैं, तो इसका अर्थ है कि एप्लिकेशन को डेवलपर द्वारा साइन किए जाने के बाद संशोधित नहीं किया गया है, और सिस्टम एप्लिकेशन को चलने की अनुमति देता है।

एप्लिकेशन सिग्नेचर Apple की Gatekeeper तकनीक का एक अनिवार्य हिस्सा हैं। जब कोई उपयोगकर्ता इंटरनेट से डाउनलोड किए गए एप्लिकेशन को खोलने का प्रयास करता है, तो Gatekeeper एप्लिकेशन सिग्नेचर की पुष्टि करता है। यदि यह उस प्रमाणपत्र से साइन किया गया है जो Apple ने किसी ज्ञात डेवलपर को जारी किया है और कोड में छेड़छाड़ नहीं हुई है, तो Gatekeeper एप्लिकेशन को चलने की अनुमति देता है। अन्यथा, यह एप्लिकेशन को ब्लॉक कर देता है और उपयोगकर्ता को चेतावनी देता है।

macOS Catalina से, Gatekeeper यह भी जांचता है कि क्या एप्लिकेशन Apple द्वारा notarized है, जो एक अतिरिक्त सुरक्षा परत जोड़ता है। notarization प्रक्रिया एप्लिकेशन की जाँच करती है कि उसमें ज्ञात सुरक्षा समस्याएँ या malicious कोड तो नहीं हैं, और यदि ये जाँचें पास हो जाती हैं, तो Apple एप्लिकेशन में एक टिकट जोड़ देता है जिसे Gatekeeper सत्यापित कर सकता है।

#### सिग्नेचर की जाँच

जब आप किसी **malware sample** की जाँच कर रहे हों तो आपको हमेशा बाइनरी के **सिग्नेचर की जाँच** करनी चाहिए क्योंकि जिसने इसे साइन किया हुआ **डेवलपर** पहले से ही **malware** से **संबंधित** हो सकता है।
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
### नोटरीकरण

Apple का नोटरीकरण प्रक्रिया संभावित हानिकारक सॉफ़्टवेयर से उपयोगकर्ताओं की रक्षा करने के लिए एक अतिरिक्त सुरक्षा कवच का काम करती है। इसमें **डेवलपर द्वारा अपनी एप्लिकेशन की जाँच के लिए सबमिट करना** शामिल है जिसे **Apple's Notary Service** द्वारा किया जाता है, जिसे App Review से भ्रमित नहीं करना चाहिए। यह सेवा एक **स्वचालित प्रणाली** है जो सबमिट किए गए सॉफ़्टवेयर में मौजूद **दुर्भावनापूर्ण सामग्री** और code-signing से जुड़ी किसी भी संभावित समस्या की जांच करती है।

यदि सॉफ़्टवेयर इस निरीक्षण को बिना किसी चिंता के **पास** कर लेता है, तो Notary Service एक notarization ticket उत्पन्न करती है। फिर डेवलपर को आवश्यक होता है कि वे **यह टिकट अपने सॉफ़्टवेयर के साथ जोड़ें**, एक प्रक्रिया जिसे 'stapling' कहा जाता है। इसके अलावा, notarization ticket ऑनलाइन भी प्रकाशित की जाती है जहाँ Gatekeeper, Apple की सुरक्षा तकनीक, इसे एक्सेस कर सकता है।

उपयोगकर्ता द्वारा सॉफ़्टवेयर की पहली इंस्टॉलेशन या निष्पादन के समय, notarization ticket की उपस्थिति — चाहे वह executable के साथ stapled हो या ऑनलाइन मिले — **Gatekeeper को सूचित करती है कि सॉफ़्टवेयर Apple द्वारा नोटराइज़ किया गया है**। परिणामस्वरूप, Gatekeeper प्रारंभिक लॉन्च डायलॉग में एक विवरणात्मक संदेश दिखाता है, जो संकेत देता है कि सॉफ़्टवेयर पर Apple द्वारा दुर्भावनापूर्ण सामग्री की जाँच की गई है। यह प्रक्रिया उपयोगकर्ता के उस सॉफ़्टवेयर की सुरक्षा में उनके विश्वास को बढ़ाती है जिसे वे अपने सिस्टम पर इंस्टॉल या चला रहे होते हैं।

### spctl & syspolicyd

> [!CAUTION]
> ध्यान दें कि Sequoia संस्करण से, **`spctl`** अब Gatekeeper configuration को संशोधित करने की अनुमति नहीं देता।

**`spctl`** Gatekeeper के साथ enumerate और interact करने का CLI टूल है ( `syspolicyd` daemon के साथ XPC messages के माध्यम से)। उदाहरण के लिए, GateKeeper की **स्थिति** को निम्नलिखित के साथ देखा जा सकता है:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> ध्यान दें कि GateKeeper सिग्नेचर चेक केवल उन **files with the Quarantine attribute** पर किए जाते हैं, न कि हर फाइल पर।

GateKeeper यह जाँच करता है कि **preferences & the signature** के अनुसार कोई binary चलाया जा सकता है या नहीं:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** GateKeeper को लागू करने वाला मुख्य डेमन है। यह `/var/db/SystemPolicy` में स्थित एक डेटाबेस बनाए रखता है और डेटाबेस को सपोर्ट करने वाला कोड आप [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) पर और [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) पर देख सकते हैं। ध्यान दें कि यह डेटाबेस SIP द्वारा अनियंत्रित है और root द्वारा लिखने योग्य है तथा मूल बैकअप के रूप में `/var/db/.SystemPolicy-default` का उपयोग किया जाता है यदि अन्य डेटाबेस भ्रष्ट हो जाए।

इसके अतिरिक्त, बंडल **`/var/db/gke.bundle`** और **`/var/db/gkopaque.bundle`** में ऐसी फाइलें होती हैं जिनमें नियम होते हैं जो डेटाबेस में डाले जाते हैं। आप root के रूप में इस डेटाबेस को निम्नलिखित तरीके से जाँच सकते हैं:
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
**`syspolicyd`** भी एक XPC सर्वर एक्सपोज़ करता है जिसमें `assess`, `update`, `record` और `cancel` जैसे विभिन्न ऑपरेशन्स होते हैं, जिन्हें **`Security.framework`'s `SecAssessment*`** APIs के माध्यम से भी एक्सेस किया जा सकता है और **`spctl`** वास्तव में XPC के जरिए **`syspolicyd`** से बात करता है।

ध्यान दें कि पहले नियम का अंत "**App Store**" में हुआ और दूसरे का "**Developer ID**" में, और पिछली इमेज में यह **App Store और पहचाने गए डेवलपर्स से ऐप्स चलाने के लिए सक्षम था**।\  
यदि आप उस सेटिंग को App Store में **संशोधित** करते हैं, तो "**Notarized Developer ID" नियम गायब हो जाएंगे**।

इसके अलावा **type GKE** के हजारों नियम भी हैं :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
ये hashes हैं जो निम्न फाइलों से हैं:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

या आप पिछली जानकारी को निम्न के साथ सूचीबद्ध कर सकते हैं:
```bash
sudo spctl --list
```
**`spctl`** के विकल्प **`--master-disable`** और **`--global-disable`** इन सिग्नेचर चेक्स को पूरी तरह से **disable** कर देंगे:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
जब पूरी तरह सक्षम होगा, एक नया विकल्प दिखाई देगा:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

यह संभव है कि **जाँचें कि कोई App GateKeeper द्वारा अनुमत होगा या नहीं**:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper में कुछ ऐप्स को चलाने की अनुमति देने के लिए नए नियम जोड़ना संभव है:
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
Regarding **kernel extensions**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

#### macOS 15 (Sequoia) और बाद के संस्करणों में Gatekeeper का प्रबंधन

- दीर्घकालिक Finder **Ctrl+Open / Right‑click → Open** बायपास हटा दी गई है; उपयोगकर्ताओं को पहले ब्लॉक डायलॉग के बाद प्रतिबंधित ऐप को स्पष्ट रूप से **System Settings → Privacy & Security → Open Anyway** से अनुमति देनी होगी।
- `spctl --master-disable/--global-disable` अब स्वीकार नहीं किए जाते; `spctl` आकलन और लेबल प्रबंधन के लिए प्रभावी रूप से read‑only है जबकि नीति प्रवर्तन UI या MDM के माध्यम से कॉन्फ़िगर किया जाता है।

macOS 15 Sequoia से शुरू होकर, end users अब `spctl` से Gatekeeper नीति टॉगल नहीं कर सकते। प्रबंधन System Settings के माध्यम से किया जाता है या `com.apple.systempolicy.control` payload वाले एक MDM configuration profile को deploy करके। App Store और identified developers को अनुमति देने (लेकिन "Anywhere" को नहीं) के लिए उदाहरण प्रोफ़ाइल स्निपेट:

<details>
<summary>App Store और identified developers को अनुमति देने के लिए MDM प्रोफ़ाइल</summary>
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

### क्वारंटीन फ़ाइलें

किसी भी एप्लिकेशन या फ़ाइल को **downloading** करने पर, कुछ macOS **applications** जैसे वेब ब्राउज़र या ईमेल क्लाइंट डाउनलोड की गई फ़ाइल पर एक विस्तारित फ़ाइल एट्रिब्यूट जोड़ते हैं, जिसे आमतौर पर "**quarantine flag**" कहा जाता है। यह एट्रिब्यूट एक सुरक्षा उपाय के रूप में फ़ाइल को एक अविश्वसनीय स्रोत (इंटरनेट) से आने के रूप में **मार्क करता है**, और संभावित जोखिम दर्शा सकता है। हालांकि, सभी applications यह एट्रिब्यूट नहीं जोड़ते — उदाहरण के लिए, सामान्य BitTorrent क्लाइंट सॉफ़्टवेयर आमतौर पर इस प्रक्रिया को बायपास कर देता है।

**quarantine flag की उपस्थिति उस समय macOS के Gatekeeper सुरक्षा फीचर को सूचित करती है जब उपयोगकर्ता फ़ाइल को execute करने का प्रयास करता है।**

यदि **quarantine flag मौजूद नहीं है** (जैसे कुछ BitTorrent क्लाइंट्स द्वारा डाउनलोड की गई फ़ाइलों के साथ), तो Gatekeeper के **checks संभवतः लागू नहीं किए जाएंगे**। इसलिए, उपयोगकर्ताओं को कम सुरक्षित या अज्ञात स्रोतों से डाउनलोड की गई फ़ाइलें खोलते समय सतर्क रहना चाहिए।

> [!NOTE] > **Checking** the **validity** of code signatures is a **resource-intensive** process that includes generating cryptographic **hashes** of the code and all its bundled resources. Furthermore, checking certificate validity involves doing an **online check** to Apple's servers to see if it has been revoked after it was issued. For these reasons, a full code signature and notarization check is **impractical to run every time an app is launched**.
>
> Therefore, these checks are **only run when executing apps with the quarantined attribute.**

> [!WARNING]
> यह एट्रिब्यूट उस application द्वारा **set** किया जाना चाहिए जो फ़ाइल बना रहा/डाउनलोड कर रहा है।
>
> हालांकि, sandboxed प्रक्रियाएँ जिस किसी भी फ़ाइल को बनाती हैं उस पर यह एट्रिब्यूट स्वचालित रूप से सेट हो जाएगा। और non sandboxed apps इसे स्वयं सेट कर सकते हैं, या **Info.plist** में [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key निर्दिष्ट कर सकते हैं, जिससे सिस्टम बनाए गए फ़ाइलों पर `com.apple.quarantine` विस्तारित एट्रिब्यूट सेट कर देगा।

इसके अलावा, किसी प्रक्रिया द्वारा **`qtn_proc_apply_to_self`** को कॉल करने पर बनाई गई सभी फ़ाइलें क्वारंटीन होती हैं। या API **`qtn_file_apply_to_path`** निर्दिष्ट फ़ाइल पथ पर quarantine एट्रिब्यूट जोड़ देता है।

यह संभव है कि आप इसकी स्थिति **check कर सकें और enable/disable** कर सकें (root आवश्यक) साथ:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
आप यह भी पता कर सकते हैं कि किसी फ़ाइल में **quarantine extended attribute** है या नहीं, इसके लिए:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** के **value** की जाँच करें और पता लगाएँ कि किस ऐप ने quarantine attr लिखा था:
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
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
वास्तव में एक process "could set quarantine flags to the files it creates" कर सकता है (मैंने पहले एक बनाए गए फ़ाइल पर USER_APPROVED flag लागू करने की कोशिश की, लेकिन यह लागू नहीं हुआ):

<details>

<summary>Source Code apply quarantine flags</summary>
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

और **हटाएँ** उस attribute को इस तरह:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
और सभी क्वारंटीन की गई फ़ाइलें खोजने के लिए:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine जानकारी LaunchServices द्वारा प्रबंधित एक केंद्रीय डेटाबेस में भी संग्रहीत की जाती है **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, जो GUI को फ़ाइल के स्रोत के बारे में डेटा प्राप्त करने की अनुमति देती है। इसके अलावा इसे उन एप्लिकेशन्स द्वारा अधिलेखित (overwrite) किया जा सकता है जो अपने स्रोत छिपाना चाहती हैं। यह LaunchServices APIS के माध्यम से भी किया जा सकता है।

#### **libquarantine.dylib**

यह लाइब्रेरी कई फ़ंक्शन एक्सपोर्ट करती है जो extended attribute फ़ील्ड्स को मेनिपुलेट करने की अनुमति देती हैं।

`qtn_file_*` APIs फ़ाइल क्वारंटीन नीतियों से संबंधित हैं, `qtn_proc_*` APIs प्रोसेसेस पर लागू होते हैं (प्रोसेस द्वारा बनाए गए फ़ाइलों पर)। अनएक्सपोर्टेड `__qtn_syscall_quarantine*` फ़ंक्शन्स वे हैं जो नीतियों को लागू करते हैं और `mac_syscall` को "Quarantine" पहले आर्गुमेंट के साथ कॉल करते हैं, जो अनुरोधों को `Quarantine.kext` तक भेजता है।

#### **Quarantine.kext**

kernel extension केवल सिस्टम के **kernel cache on the system** के माध्यम से उपलब्ध है; हालाँकि, आप _can_ [**https://developer.apple.com/**](https://developer.apple.com/) से **Kernel Debug Kit** डाउनलोड कर सकते हैं, जिसमें extension का symbolicated संस्करण शामिल होगा।

यह Kext MACF के जरिए कई कॉल्स को हुक करेगा ताकि सभी फ़ाइल लाइफसाइकल घटनाओं को ट्रैप किया जा सके: Creation, opening, renaming, hard-linkning... यहाँ तक कि `setxattr` भी, ताकि यह `com.apple.quarantine` extended attribute सेट होने से रोके।

यह कुछ MIBs भी उपयोग करता है:

- `security.mac.qtn.sandbox_enforce`: Sandbox के साथ quarantine को लागू करना
- `security.mac.qtn.user_approved_exec`: Quarantined procs केवल approved फ़ाइलें ही execute कर सकते हैं

#### Provenance xattr (Ventura and later)

macOS 13 Ventura ने एक अलग provenance mechanism पेश किया है जिसे तब भरा जाता है जब किसी quarantined app को पहली बार चलने की अनुमति दी जाती है। दो artefacts बनाए जाते हैं:

- `.app` bundle डायरेक्टरी पर `com.apple.provenance` xattr (fixed-size binary value जिसमें एक primary key और flags होते हैं)।
- ExecPolicy database के अंदर `provenance_tracking` तालिका में एक रो `/var/db/SystemPolicyConfiguration/ExecPolicy/` पर, जो ऐप का cdhash और मेटाडेटा स्टोर करती है।

प्रायोगिक उपयोग:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect macOS में एक बिल्ट-इन **anti-malware** फीचर है। XProtect **किसी भी एप्लिकेशन की पहली बार लॉन्च या संशोधित होने पर उसे अपने ज्ञात malware और unsafe file types की database के खिलाफ जाँचता है।**

जब आप Safari, Mail, या Messages जैसे कुछ ऐप्स के माध्यम से कोई फ़ाइल डाउनलोड करते हैं, तो XProtect फ़ाइल को स्वचालित रूप से स्कैन करता है। यदि यह इसकी database में किसी ज्ञात malware से मेल खाती है, तो XProtect फ़ाइल के चलने को **रोक देगा** और आपको खतरे के बारे में चेतावनी देगा।

XProtect database को Apple द्वारा नए malware definitions के साथ **नियमित रूप से अपडेट** किया जाता है, और ये अपडेट आपके Mac पर स्वचालित रूप से डाउनलोड और इंस्टॉल हो जाते हैं। यह सुनिश्चित करता है कि XProtect हमेशा नवीनतम ज्ञात खतरों के साथ अप-टू-डेट रहे।

हालाँकि, यह ध्यान देने योग्य है कि **XProtect एक पूर्ण-विशेषताओं वाला antivirus समाधान नहीं है**। यह केवल ज्ञात खतरों की एक सीमित सूची के लिए जाँच करता है और अधिकांश antivirus सॉफ़्टवेयर की तरह on-access scanning नहीं करता।

आप चल रहे नवीनतम XProtect अपडेट के बारे में जानकारी प्राप्त कर सकते हैं:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect SIP protected स्थान पर स्थित है: **/Library/Apple/System/Library/CoreServices/XProtect.bundle** और bundle के अंदर आप XProtect द्वारा उपयोग की जाने वाली जानकारी पा सकते हैं:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: उन cdhashes वाले कोड को legacy entitlements का उपयोग करने की अनुमति देता है।
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: उन plugins और extensions की सूची जो BundleID और TeamID के माध्यम से लोड होने से प्रतिबंधित हैं या जिनके लिए न्यूनतम संस्करण निर्दिष्ट है।
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara नियम जो malware का पता लगाते हैं।
- **`XProtect.bundle/Contents/Resources/gk.db`**: ब्लॉक किए गए applications और TeamIDs के hashes के साथ एक SQLite3 डेटाबेस।

ध्यान दें कि **`/Library/Apple/System/Library/CoreServices/XProtect.app`** में XProtect से संबंधित एक और App है जो Gatekeeper प्रक्रिया में शामिल नहीं है।

> XProtect Remediator: आधुनिक macOS पर, Apple ऑन-डिमांड स्कैनर्स (XProtect Remediator) देती है जो launchd के माध्यम से समय-समय पर चलती हैं ताकि malware परिवारों का पता लग सके और उन्हें remediate किया जा सके। आप इन स्कैनों को unified logs में देख सकते हैं:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Not Gatekeeper

> [!CAUTION]
> ध्यान दें कि Gatekeeper **हर बार** जब आप कोई application execute करते हैं तो चलाया नहीं जाता; सिर्फ _AppleMobileFileIntegrity_ (AMFI) executable code signatures को verify करेगा जब आप ऐसा app execute करते हैं जिसे पहले Gatekeeper द्वारा execute और verified किया जा चुका हो।

इसलिए, पहले ऐसा संभव था कि किसी app को Gatekeeper के साथ cache करने के लिए execute किया जाए, फिर application की non-executable फ़ाइलों (जैसे Electron asar या NIB फ़ाइलें) को modify किया जाए और यदि अन्य सुरक्षा मौजूद न हों, तो application उन malicious जोड़-घटाव के साथ **execute** हो जाता था।

हालाँकि, अब यह संभव नहीं है क्योंकि macOS applications bundles के अंदर फ़ाइलें modify करने से रोकता है। इसलिए, यदि आप [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack आजमाते हैं, तो आप पाएंगे कि अब इसे abuse करना संभव नहीं है क्योंकि Gatekeeper के साथ app को cache करने के बाद आप bundle को modify नहीं कर पाएँगे। और यदि आप उदाहरण के लिए Contents directory का नाम NotCon (जैसा exploit में दिखाया गया है) में बदलते हैं, और फिर Gatekeeper के साथ cache करने के लिए app के main binary को execute करते हैं, तो यह एक error ट्रिगर करेगा और execute नहीं होगा।

## Gatekeeper Bypasses

Gatekeeper को bypass करने का कोई भी तरीका (यानी उपयोगकर्ता को कुछ download कराकर और उसे execute कराना जब Gatekeeper उसे disallow करना चाहिए) macOS में एक vulnerability माना जाता है। ये कुछ CVEs हैं जो अतीत में Gatekeeper को bypass करने की अनुमति देने वाली techniques के लिए असाइन की गई थीं:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

यह देखा गया कि यदि extraction के लिए **Archive Utility** का उपयोग किया जाता है, तो ऐसे फ़ाइलों को जिनके paths 886 characters से अधिक हैं, उन्हें com.apple.quarantine extended attribute नहीं मिलता। यह स्थिति अनजाने में उन फ़ाइलों को Gatekeeper के security checks से **बचने** की अनुमति देती है।

Check the [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) for more information.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

जब कोई application **Automator** से बनाया जाता है, तो उसे execute करने के लिए जो जानकारी चाहिए वह `application.app/Contents/document.wflow` के अंदर होती है न कि executable में। executable बस एक generic Automator binary होता है जिसे **Automator Application Stub** कहा जाता है।

इसलिए, आप `application.app/Contents/MacOS/Automator\ Application\ Stub` को symbolic link के द्वारा सिस्टम के किसी अन्य Automator Application Stub की तरफ point करवा सकते हैं और यह `document.wflow` (आपका script) के अंदर जो है उसे execute कर देगा **बिना Gatekeeper को trigger किए** क्योंकि वास्तविक executable पर quarantine xattr नहीं होता।

Example os expected location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Check the [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) for more information.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

इस bypass में एक zip फ़ाइल बनाई गई थी जिसमें application को `application.app/Contents` से compress करना शुरू किया गया था न कि `application.app` से। इसलिए, **quarantine attr** `application.app/Contents` की सभी फ़ाइलों पर लागू किया गया था पर **`application.app`** पर नहीं, जो Gatekeeper चेक कर रहा था, इसलिए Gatekeeper bypass हो गया क्योंकि जब `application.app` trigger हुआ तो उस पर quarantine attribute मौजूद नहीं था।
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

हालांकि घटक अलग हैं, इस भेद्यता का शोषण पिछले वाले की तरह ही है। इस मामले में हम **`application.app/Contents`** से एक Apple Archive बनाएँगे, इसलिए जब **Archive Utility** द्वारा डीकंप्रेस किया जाएगा तो **`application.app` won't get the quarantine attr**।
```bash
aa archive -d test.app/Contents -o test.app.aar
```
अधिक जानकारी के लिए [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) देखें।

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** का उपयोग किसी भी व्यक्ति को फ़ाइल में attribute लिखने से रोकने के लिए किया जा सकता है:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Moreover, **AppleDouble** file format copies a file including its ACEs.

In the [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) it's possible to see that the ACL text representation stored inside the xattr called **`com.apple.acl.text`** is going to be set as ACL in the decompressed file. So, if you compressed an application into a zip file with **AppleDouble** file format with an ACL that prevents other xattrs to be written to it... the quarantine xattr wasn't set into de application:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।

ध्यान दें कि इसे AppleArchives के साथ भी शोषित किया जा सकता है:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

खोज हुआ कि **Google Chrome डाउनलोड की गई फ़ाइलों पर quarantine attribute सेट नहीं कर रहा था** क्योंकि macOS के कुछ आंतरिक समस्याओं की वजह से।

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file formats फ़ाइल के attributes को एक अलग फ़ाइल में संग्रहित करते हैं जो `._` से शुरू होती है; यह **macOS मशीनों के बीच** फ़ाइल attributes को कॉपी करने में मदद करता है। हालांकि, यह देखा गया कि AppleDouble फ़ाइल को decompress करने के बाद `._` से शुरू होने वाली फ़ाइल **quarantine attribute नहीं दी गई थी**।
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
ऐसा फ़ाइल बनाने में सक्षम होने पर जिसका quarantine attribute सेट न हो, यह **Gatekeeper को बायपास करना संभव था।** चालाकी यह थी कि AppleDouble name convention का उपयोग करके (नाम `._` से शुरू करें) **एक DMG file application बनाना** और इस hidden फ़ाइल के बिना quarantine attribute के लिए एक **visible file को इस hidden का sym link** बनाना।\
जब **dmg file is executed**, चूँकि उसके पास quarantine attribute नहीं होता, यह **Gatekeeper को बायपास कर देगा।**
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

macOS Sonoma 14.0 में फिक्स किए गए Gatekeeper बायपास ने विशेष रूप से तैयार किए गए ऐप्स को बिना किसी प्रम्प्ट के चलने की अनुमति दी। पैच लागू करने के बाद विवरण सार्वजनिक किए गए और फिक्स होने से पहले यह समस्या वास्तविक दुनिया में सक्रिय रूप से शोषित की जा रही थी। सुनिश्चि करें कि Sonoma 14.0 या उससे नया संस्करण इंस्टॉल हो।

### [CVE-2024-27853]

macOS 14.4 (March 2024 में रिलीज़) में `libarchive` द्वारा दुर्भावनापूर्ण ZIPs को हैंडल करने से उत्पन्न Gatekeeper बायपास ने ऐप्स को मूल्यांकन से बचने की अनुमति दी। Apple ने इस मुद्दे को संबोधित किया है — इसलिए 14.4 या उसके बाद के संस्करण में अपडेट करें।

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

एक **Automator Quick Action workflow** जो डाउनलोड किए गए ऐप में एम्बेड था, Gatekeeper मूल्यांकन के बिना ट्रिगर हो सकता था, क्योंकि workflows को डेटा के रूप में माना जाता था और Automator helper द्वारा सामान्य notarization prompt path के बाहर executed किया जाता था। इसलिए एक विशेष रूप से तैयार `.app` जो एक Quick Action बंडल करता है जो shell script चलाता है (उदा., `Contents/PlugIns/*.workflow/Contents/document.wflow` के अंदर) लॉन्च पर तुरंत निष्पादित हो सकता था। Apple ने एक अतिरिक्त consent dialog जोड़ा और Ventura **13.7**, Sonoma **14.7**, और Sequoia **15** में assessment path को ठीक किया।

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

कई लोकप्रिय extraction tools (उदा., The Unarchiver) में vulnerabilities ने आर्काइव से निकाले गए फ़ाइलों में `com.apple.quarantine` xattr न जोड़ने का कारण बनाया, जिससे Gatekeeper बायपास की संभावनाएँ पैदा हुईं। टेस्टिंग करते समय हमेशा macOS Archive Utility या पैच किए गए टूल्स पर भरोसा करें, और extraction के बाद xattrs को सत्यापित करें।

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- एक डायरेक्टरी बनाएं जिसमें एक app हो।
- app में uchg जोड़ें।
- app को tar.gz फ़ाइल में compress करें।
- tar.gz फ़ाइल को लक्ष्य को भेजें।
- लक्ष्य tar.gz फ़ाइल खोलता है और app चलाता है।
- Gatekeeper app की जाँच नहीं करता।

### Prevent Quarantine xattr

एक ".app" बंडल में यदि quarantine xattr जोड़ा नहीं गया है, तो इसे execute करते समय **Gatekeeper won't be triggered**।

## References

- Apple Platform Security: macOS Sonoma 14.4 की सुरक्षा सामग्री के बारे में (इसमें CVE-2024-27853 शामिल है) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: macOS अब ऐप्स की उत्पत्ति का पता कैसे रखता है – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: macOS Sonoma 14.7 / Ventura 13.7 की सुरक्षा सामग्री के बारे में (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia Control‑click “Open” Gatekeeper बायपास को हटाता है – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
