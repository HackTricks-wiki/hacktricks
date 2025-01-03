# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

**Gatekeeper** एक सुरक्षा विशेषता है जो Mac ऑपरेटिंग सिस्टम के लिए विकसित की गई है, जिसका उद्देश्य यह सुनिश्चित करना है कि उपयोगकर्ता अपने सिस्टम पर **केवल विश्वसनीय सॉफ़्टवेयर** चलाएँ। यह **सॉफ़्टवेयर को मान्य करके** कार्य करता है जो उपयोगकर्ता डाउनलोड करता है और **App Store के बाहर के स्रोतों** से खोलने का प्रयास करता है, जैसे कि एक ऐप, एक प्लग-इन, या एक इंस्टॉलर पैकेज।

Gatekeeper का मुख्य तंत्र इसके **सत्यापन** प्रक्रिया में निहित है। यह जांचता है कि क्या डाउनलोड किया गया सॉफ़्टवेयर **एक मान्यता प्राप्त डेवलपर द्वारा हस्ताक्षरित** है, जो सॉफ़्टवेयर की प्रामाणिकता सुनिश्चित करता है। इसके अलावा, यह यह सुनिश्चित करता है कि सॉफ़्टवेयर **Apple द्वारा नोटराइज किया गया है**, यह पुष्टि करते हुए कि यह ज्ञात दुर्भावनापूर्ण सामग्री से मुक्त है और नोटराइजेशन के बाद इसमें छेड़छाड़ नहीं की गई है।

इसके अतिरिक्त, Gatekeeper उपयोगकर्ता नियंत्रण और सुरक्षा को **पहली बार डाउनलोड किए गए सॉफ़्टवेयर को खोलने के लिए उपयोगकर्ताओं से अनुमोदन प्राप्त करके** मजबूत करता है। यह सुरक्षा उपाय उपयोगकर्ताओं को संभावित हानिकारक निष्पादन योग्य कोड को अनजाने में चलाने से रोकने में मदद करता है जिसे वे एक हानिरहित डेटा फ़ाइल समझ सकते हैं।

### Application Signatures

Application signatures, जिन्हें कोड हस्ताक्षर भी कहा जाता है, Apple की सुरक्षा अवसंरचना का एक महत्वपूर्ण घटक हैं। इन्हें **सॉफ़्टवेयर लेखक की पहचान की पुष्टि करने** और यह सुनिश्चित करने के लिए उपयोग किया जाता है कि कोड को अंतिम बार हस्ताक्षरित किए जाने के बाद से इसमें छेड़छाड़ नहीं की गई है।

यहाँ यह कैसे काम करता है:

1. **एप्लिकेशन पर हस्ताक्षर करना:** जब एक डेवलपर अपने एप्लिकेशन को वितरित करने के लिए तैयार होता है, तो वे **एक निजी कुंजी का उपयोग करके एप्लिकेशन पर हस्ताक्षर करते हैं**। यह निजी कुंजी एक **प्रमाणपत्र से जुड़ी होती है जो Apple डेवलपर प्रोग्राम में नामांकित होने पर डेवलपर को जारी की जाती है**। हस्ताक्षर प्रक्रिया में ऐप के सभी भागों का एक क्रिप्टोग्राफिक हैश बनाना और इस हैश को डेवलपर की निजी कुंजी के साथ एन्क्रिप्ट करना शामिल है।
2. **एप्लिकेशन का वितरण:** हस्ताक्षरित एप्लिकेशन फिर उपयोगकर्ताओं को डेवलपर के प्रमाणपत्र के साथ वितरित किया जाता है, जिसमें संबंधित सार्वजनिक कुंजी होती है।
3. **एप्लिकेशन का सत्यापन:** जब एक उपयोगकर्ता एप्लिकेशन डाउनलोड करता है और इसे चलाने का प्रयास करता है, तो उनका Mac ऑपरेटिंग सिस्टम डेवलपर के प्रमाणपत्र से सार्वजनिक कुंजी का उपयोग करके हैश को डिक्रिप्ट करता है। फिर यह एप्लिकेशन की वर्तमान स्थिति के आधार पर हैश की पुनः गणना करता है और इसे डिक्रिप्टेड हैश के साथ तुलना करता है। यदि वे मेल खाते हैं, तो इसका मतलब है कि **एप्लिकेशन में संशोधन नहीं किया गया है** जब से डेवलपर ने इसे हस्ताक्षरित किया था, और सिस्टम एप्लिकेशन को चलाने की अनुमति देता है।

Application signatures Apple की Gatekeeper तकनीक का एक आवश्यक हिस्सा हैं। जब एक उपयोगकर्ता **इंटरनेट से डाउनलोड किए गए एप्लिकेशन को खोलने का प्रयास करता है**, तो Gatekeeper एप्लिकेशन हस्ताक्षर की पुष्टि करता है। यदि इसे एक ज्ञात डेवलपर को Apple द्वारा जारी किए गए प्रमाणपत्र के साथ हस्ताक्षरित किया गया है और कोड में छेड़छाड़ नहीं की गई है, तो Gatekeeper एप्लिकेशन को चलाने की अनुमति देता है। अन्यथा, यह एप्लिकेशन को ब्लॉक कर देता है और उपयोगकर्ता को सूचित करता है।

macOS Catalina से शुरू होकर, **Gatekeeper यह भी जांचता है कि क्या एप्लिकेशन को Apple द्वारा नोटराइज किया गया है**, जो सुरक्षा की एक अतिरिक्त परत जोड़ता है। नोटराइजेशन प्रक्रिया एप्लिकेशन की ज्ञात सुरक्षा समस्याओं और दुर्भावनापूर्ण कोड की जांच करती है, और यदि ये जांच पास होती हैं, तो Apple एप्लिकेशन में एक टिकट जोड़ता है जिसे Gatekeeper सत्यापित कर सकता है।

#### Check Signatures

जब आप कुछ **malware sample** की जांच कर रहे हों, तो आपको हमेशा **signature** की जांच करनी चाहिए क्योंकि **developer** जिसने इसे हस्ताक्षरित किया है, वह पहले से ही **malware** से **संबंधित** हो सकता है।
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

Apple की नोटरीकरण प्रक्रिया उपयोगकर्ताओं को संभावित हानिकारक सॉफ़्टवेयर से बचाने के लिए एक अतिरिक्त सुरक्षा उपाय के रूप में कार्य करती है। इसमें **डेवलपर द्वारा उनके आवेदन को** **Apple की नोटरी सेवा** द्वारा परीक्षा के लिए प्रस्तुत करना शामिल है, जिसे ऐप समीक्षा के साथ भ्रमित नहीं किया जाना चाहिए। यह सेवा एक **स्वचालित प्रणाली** है जो प्रस्तुत सॉफ़्टवेयर की जांच करती है कि उसमें **दुष्ट सामग्री** और कोड-हस्ताक्षर के साथ कोई संभावित समस्याएँ हैं या नहीं।

यदि सॉफ़्टवेयर इस निरीक्षण को बिना किसी चिंता के **पास** कर लेता है, तो नोटरी सेवा एक नोटरीकरण टिकट उत्पन्न करती है। फिर डेवलपर को **इस टिकट को अपने सॉफ़्टवेयर से संलग्न करना आवश्यक है**, जिसे 'स्टेपलिंग' के रूप में जाना जाता है। इसके अलावा, नोटरीकरण टिकट को ऑनलाइन भी प्रकाशित किया जाता है जहाँ गेटकीपर, Apple की सुरक्षा तकनीक, इसे एक्सेस कर सकता है।

उपयोगकर्ता के पहले सॉफ़्टवेयर के इंस्टॉलेशन या निष्पादन पर, नोटरीकरण टिकट की उपस्थिति - चाहे वह निष्पादन योग्य के साथ स्टेपल किया गया हो या ऑनलाइन पाया गया हो - **गेटकीपर को सूचित करती है कि सॉफ़्टवेयर को Apple द्वारा नोटरीकरण किया गया है**। परिणामस्वरूप, गेटकीपर प्रारंभिक लॉन्च संवाद में एक वर्णनात्मक संदेश प्रदर्शित करता है, जो यह संकेत करता है कि सॉफ़्टवेयर ने Apple द्वारा दुष्ट सामग्री के लिए जांच की है। यह प्रक्रिया उपयोगकर्ताओं के लिए उस सॉफ़्टवेयर की सुरक्षा में विश्वास को बढ़ाती है जिसे वे अपने सिस्टम पर इंस्टॉल या चलाते हैं।

### spctl & syspolicyd

> [!CAUTION]
> ध्यान दें कि सेकोइया संस्करण से, **`spctl`** अब गेटकीपर कॉन्फ़िगरेशन को संशोधित करने की अनुमति नहीं देता।

**`spctl`** गेटकीपर के साथ बातचीत करने और उसे सूचीबद्ध करने के लिए CLI उपकरण है (जो `syspolicyd` डेमन के माध्यम से XPC संदेशों के साथ है)। उदाहरण के लिए, गेटकीपर की **स्थिति** देखने के लिए:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> ध्यान दें कि GateKeeper सिग्नेचर जांच केवल **Quarantine विशेषता वाले फ़ाइलों** के लिए की जाती है, न कि हर फ़ाइल के लिए।

GateKeeper यह जांचेगा कि **प्राथमिकताएँ और सिग्नेचर** के अनुसार एक बाइनरी को निष्पादित किया जा सकता है:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** मुख्य डेमन है जो Gatekeeper को लागू करने के लिए जिम्मेदार है। यह `/var/db/SystemPolicy` में स्थित एक डेटाबेस बनाए रखता है और आप [डेटाबेस का कोड यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) और [SQL टेम्पलेट यहाँ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) पा सकते हैं। ध्यान दें कि डेटाबेस SIP द्वारा अनियंत्रित है और इसे रूट द्वारा लिखा जा सकता है और डेटाबेस `/var/db/.SystemPolicy-default` का उपयोग एक मूल बैकअप के रूप में किया जाता है यदि अन्य भ्रष्ट हो जाए।

इसके अलावा, बंडल **`/var/db/gke.bundle`** और **`/var/db/gkopaque.bundle`** में नियमों के साथ फ़ाइलें होती हैं जो डेटाबेस में डाली जाती हैं। आप रूट के रूप में इस डेटाबेस की जांच कर सकते हैं:
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
**`syspolicyd`** एक XPC सर्वर को विभिन्न ऑपरेशनों के साथ उजागर करता है जैसे कि `assess`, `update`, `record` और `cancel`, जो **`Security.framework` के `SecAssessment*`** APIs का उपयोग करके भी पहुंचा जा सकता है और **`xpctl`** वास्तव में **`syspolicyd`** से XPC के माध्यम से बात करता है।

ध्यान दें कि पहला नियम "**App Store**" में समाप्त होता है और दूसरा "**Developer ID**" में, और पिछले चित्र में यह **App Store और पहचाने गए डेवलपर्स से ऐप्स को निष्पादित करने के लिए सक्षम था**।\
यदि आप उस सेटिंग को App Store में **संशोधित** करते हैं, तो "**Notarized Developer ID" नियम गायब हो जाएंगे**।

यहां **प्रकार GKE** के हजारों नियम भी हैं:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
ये हैश हैं जो निम्नलिखित से हैं:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

या आप पिछले जानकारी को इस तरह सूचीबद्ध कर सकते हैं:
```bash
sudo spctl --list
```
विकल्प **`--master-disable`** और **`--global-disable`** के **`spctl`** पूरी तरह से इन हस्ताक्षर जांचों को **अक्षम** कर देंगे:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
जब पूरी तरह से सक्षम किया जाता है, तो एक नया विकल्प दिखाई देगा:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

यह संभव है कि **जांचें कि क्या एक ऐप को GateKeeper द्वारा अनुमति दी जाएगी**:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper में कुछ ऐप्स के निष्पादन की अनुमति देने के लिए नए नियम जोड़ना संभव है:
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
**कर्नेल एक्सटेंशन** के संबंध में, फ़ोल्डर `/var/db/SystemPolicyConfiguration` में उन kexts की सूचियों के साथ फ़ाइलें होती हैं जिन्हें लोड करने की अनुमति है। इसके अलावा, `spctl` के पास `com.apple.private.iokit.nvram-csr` का अधिकार है क्योंकि यह नए पूर्व-स्वीकृत कर्नेल एक्सटेंशन जोड़ने में सक्षम है जिन्हें `kext-allowed-teams` कुंजी में NVRAM में भी सहेजने की आवश्यकता होती है।

### क्वारंटाइन फ़ाइलें

जब कोई **ऐप्लिकेशन** या फ़ाइल **डाउनलोड** की जाती है, तो विशिष्ट macOS **ऐप्लिकेशन** जैसे वेब ब्राउज़र या ईमेल क्लाइंट **एक विस्तारित फ़ाइल विशेषता** जोड़ते हैं, जिसे सामान्यतः "**क्वारंटाइन फ्लैग**" के रूप में जाना जाता है, डाउनलोड की गई फ़ाइल पर। यह विशेषता सुरक्षा उपाय के रूप में कार्य करती है ताकि फ़ाइल को एक अविश्वसनीय स्रोत (इंटरनेट) से आने के रूप में **चिन्हित** किया जा सके, और संभावित रूप से जोखिम उठाने वाली हो। हालाँकि, सभी ऐप्लिकेशन इस विशेषता को नहीं जोड़ते हैं, उदाहरण के लिए, सामान्य BitTorrent क्लाइंट सॉफ़्टवेयर आमतौर पर इस प्रक्रिया को बायपास करता है।

**क्वारंटाइन फ्लैग की उपस्थिति macOS के गेटकीपर सुरक्षा फ़ीचर को संकेत देती है जब कोई उपयोगकर्ता फ़ाइल को निष्पादित करने का प्रयास करता है**।

यदि **क्वारंटाइन फ्लैग मौजूद नहीं है** (जैसे कुछ BitTorrent क्लाइंट के माध्यम से डाउनलोड की गई फ़ाइलों के साथ), तो गेटकीपर के **चेक किए जा सकते हैं**। इसलिए, उपयोगकर्ताओं को कम सुरक्षित या अज्ञात स्रोतों से डाउनलोड की गई फ़ाइलों को खोलते समय सावधानी बरतनी चाहिए।

> [!NOTE] > **कोड हस्ताक्षरों की** **वैधता** की **जांच** एक **संसाधन-गहन** प्रक्रिया है जिसमें कोड और इसके सभी बंडल किए गए संसाधनों के क्रिप्टोग्राफ़िक **हैश** उत्पन्न करना शामिल है। इसके अलावा, प्रमाणपत्र की वैधता की जांच करने के लिए Apple के सर्वरों पर **ऑनलाइन जांच** करना आवश्यक है यह देखने के लिए कि क्या इसे जारी किए जाने के बाद रद्द कर दिया गया है। इन कारणों से, एक पूर्ण कोड हस्ताक्षर और नोटरीकरण जांच **हर बार ऐप लॉन्च होने पर चलाना व्यावहारिक नहीं है**।
>
> इसलिए, ये चेक **केवल क्वारंटाइन विशेषता वाले ऐप्स को निष्पादित करते समय चलाए जाते हैं।**

> [!WARNING]
> यह विशेषता **फ़ाइल बनाने/डाउनलोड करने वाले ऐप्लिकेशन द्वारा सेट की जानी चाहिए**।
>
> हालाँकि, जो फ़ाइलें सैंडबॉक्स की गई हैं, वे हर फ़ाइल पर यह विशेषता सेट करेंगी जो वे बनाती हैं। और गैर-सैंडबॉक्स ऐप्स इसे स्वयं सेट कर सकते हैं, या **Info.plist** में [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) कुंजी निर्दिष्ट कर सकते हैं, जो सिस्टम को बनाई गई फ़ाइलों पर `com.apple.quarantine` विस्तारित विशेषता सेट करने के लिए मजबूर करेगा,

इसके अलावा, **`qtn_proc_apply_to_self`** को कॉल करने वाली प्रक्रिया द्वारा बनाई गई सभी फ़ाइलें क्वारंटाइन की जाती हैं। या API **`qtn_file_apply_to_path`** एक निर्दिष्ट फ़ाइल पथ पर क्वारंटाइन विशेषता जोड़ता है।

इसकी स्थिति **जांचना और सक्षम/अक्षम करना** (रूट आवश्यक) संभव है:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
आप यह भी **जान सकते हैं कि क्या किसी फ़ाइल में संगरोध विस्तारित विशेषता है**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**विस्तारित** **गुणों** के **मूल्य** की जांच करें और उस ऐप का पता लगाएं जिसने संगरोध गुण को लिखा:
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
वास्तव में एक प्रक्रिया "जो फ़ाइलें वह बनाती है, उन पर संगरोध ध्वज सेट कर सकती है" (मैंने पहले ही एक बनाई गई फ़ाइल में USER_APPROVED ध्वज लागू करने की कोशिश की है लेकिन यह लागू नहीं होगा):

<details>

<summary>स्रोत कोड संगरोध ध्वज लागू करें</summary>
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

और **हटाएं** वह विशेषता:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
और सभी संगरोधित फ़ाइलों को खोजें:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine जानकारी भी एक केंद्रीय डेटाबेस में संग्रहीत होती है जिसे LaunchServices द्वारा प्रबंधित किया जाता है **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** जो GUI को फ़ाइल के मूल के बारे में डेटा प्राप्त करने की अनुमति देता है। इसके अलावा, इसे उन अनुप्रयोगों द्वारा अधिलेखित किया जा सकता है जो इसके मूल को छिपाने में रुचि रखते हैं। इसके अलावा, यह LaunchServices APIS से किया जा सकता है।

#### **libquarantine.dylb**

यह पुस्तकालय कई कार्यों को निर्यात करता है जो विस्तारित विशेषता क्षेत्रों को संशोधित करने की अनुमति देते हैं।

`qtn_file_*` APIs फ़ाइल क्वारंटाइन नीतियों से संबंधित हैं, `qtn_proc_*` APIs प्रक्रियाओं (प्रक्रिया द्वारा बनाई गई फ़ाइलें) पर लागू होते हैं। निर्यातित नहीं किए गए `__qtn_syscall_quarantine*` कार्य वे हैं जो नीतियों को लागू करते हैं जो `mac_syscall` को "Quarantine" के पहले तर्क के रूप में कॉल करते हैं जो अनुरोधों को `Quarantine.kext` पर भेजता है।

#### **Quarantine.kext**

कर्नेल एक्सटेंशन केवल **सिस्टम पर कर्नेल कैश** के माध्यम से उपलब्ध है; हालाँकि, आप **Kernel Debug Kit को** [**https://developer.apple.com/**](https://developer.apple.com/) से डाउनलोड कर सकते हैं, जिसमें एक्सटेंशन का एक प्रतीकित संस्करण होगा।

यह Kext MACF के माध्यम से कई कॉल को हुक करेगा ताकि सभी फ़ाइल जीवनचक्र घटनाओं को ट्रैप किया जा सके: निर्माण, खोलना, नाम बदलना, हार्ड-लिंकिंग... यहां तक कि `setxattr` को `com.apple.quarantine` विस्तारित विशेषता सेट करने से रोकने के लिए।

यह कुछ MIBs का भी उपयोग करता है:

- `security.mac.qtn.sandbox_enforce`: सैंडबॉक्स के साथ क्वारंटाइन को लागू करें
- `security.mac.qtn.user_approved_exec`: क्वारंटाइन की गई प्रक्रियाएँ केवल अनुमोदित फ़ाइलें चला सकती हैं

### XProtect

XProtect macOS में एक अंतर्निहित **एंटी-मैलवेयर** सुविधा है। XProtect **किसी भी अनुप्रयोग की जांच करता है जब इसे पहली बार लॉन्च या संशोधित किया जाता है** इसके ज्ञात मैलवेयर और असुरक्षित फ़ाइल प्रकारों के डेटाबेस के खिलाफ। जब आप कुछ ऐप्स, जैसे Safari, Mail, या Messages के माध्यम से फ़ाइल डाउनलोड करते हैं, तो XProtect स्वचालित रूप से फ़ाइल को स्कैन करता है। यदि यह अपने डेटाबेस में किसी ज्ञात मैलवेयर से मेल खाता है, तो XProtect **फ़ाइल को चलने से रोक देगा** और आपको खतरे के बारे में सूचित करेगा।

XProtect डेटाबेस को **नियमित रूप से** Apple द्वारा नए मैलवेयर परिभाषाओं के साथ अपडेट किया जाता है, और ये अपडेट स्वचालित रूप से आपके Mac पर डाउनलोड और स्थापित होते हैं। यह सुनिश्चित करता है कि XProtect हमेशा नवीनतम ज्ञात खतरों के साथ अद्यतित है।

हालांकि, यह ध्यान देने योग्य है कि **XProtect एक पूर्ण विशेषताओं वाला एंटीवायरस समाधान नहीं है**। यह केवल ज्ञात खतरों की एक विशिष्ट सूची की जांच करता है और अधिकांश एंटीवायरस सॉफ़्टवेयर की तरह ऑन-एक्सेस स्कैनिंग नहीं करता है।

आप नवीनतम XProtect अपडेट के बारे में जानकारी प्राप्त कर सकते हैं:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect **/Library/Apple/System/Library/CoreServices/XProtect.bundle** पर स्थित है और बंडल के अंदर आप जानकारी पा सकते हैं जो XProtect उपयोग करता है:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: उन cdhashes के साथ कोड को विरासत के अधिकारों का उपयोग करने की अनुमति देता है।
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: प्लगइन्स और एक्सटेंशनों की सूची जो BundleID और TeamID के माध्यम से लोड करने की अनुमति नहीं है या न्यूनतम संस्करण को इंगित करती है।
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: मैलवेयर का पता लगाने के लिए यारा नियम।
- **`XProtect.bundle/Contents/Resources/gk.db`**: अवरुद्ध अनुप्रयोगों और TeamIDs के हैश के साथ SQLite3 डेटाबेस।

ध्यान दें कि **`/Library/Apple/System/Library/CoreServices/XProtect.app`** में XProtect से संबंधित एक और ऐप है जो Gatekeeper प्रक्रिया में शामिल नहीं है।

### Not Gatekeeper

> [!CAUTION]
> ध्यान दें कि Gatekeeper **हर बार निष्पादित नहीं होता** जब आप एक अनुप्रयोग निष्पादित करते हैं, केवल _**AppleMobileFileIntegrity**_ (AMFI) केवल **निष्पादनीय कोड हस्ताक्षर** की पुष्टि करेगा जब आप एक ऐप निष्पादित करते हैं जिसे पहले से Gatekeeper द्वारा निष्पादित और सत्यापित किया गया है।

इसलिए, पहले यह संभव था कि एक ऐप को Gatekeeper के साथ कैश करने के लिए निष्पादित किया जाए, फिर **अनुप्रयोग के निष्पादनीय नहीं फाइलों को संशोधित करें** (जैसे Electron asar या NIB फाइलें) और यदि कोई अन्य सुरक्षा उपाय नहीं थे, तो अनुप्रयोग **निष्पादित** होता था **दुष्ट** परिवर्धनों के साथ।

हालांकि, अब यह संभव नहीं है क्योंकि macOS **अनुप्रयोग बंडलों के अंदर फाइलों को संशोधित करने से रोकता है**। इसलिए, यदि आप [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) हमले का प्रयास करते हैं, तो आप पाएंगे कि इसे दुरुपयोग करना अब संभव नहीं है क्योंकि Gatekeeper के साथ इसे कैश करने के लिए ऐप को निष्पादित करने के बाद, आप बंडल को संशोधित नहीं कर पाएंगे। और यदि आप उदाहरण के लिए Contents निर्देशिका का नाम NotCon में बदलते हैं (जैसा कि शोषण में इंगित किया गया है), और फिर ऐप के मुख्य बाइनरी को Gatekeeper के साथ कैश करने के लिए निष्पादित करते हैं, तो यह एक त्रुटि को ट्रिगर करेगा और निष्पादित नहीं होगा।

## Gatekeeper Bypasses

Gatekeeper को बायपास करने का कोई भी तरीका (उपयोगकर्ता को कुछ डाउनलोड करने और निष्पादित करने के लिए प्रबंधित करना जब Gatekeeper इसे अस्वीकार करना चाहिए) macOS में एक भेद्यता माना जाता है। ये कुछ CVEs हैं जो तकनीकों को असाइन किए गए हैं जिन्होंने अतीत में Gatekeeper को बायपास करने की अनुमति दी:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

यह देखा गया कि यदि **Archive Utility** का उपयोग निष्कर्षण के लिए किया जाता है, तो **886 वर्णों से अधिक पथ** वाली फाइलें com.apple.quarantine विस्तारित विशेषता प्राप्त नहीं करती हैं। यह स्थिति अनजाने में उन फाइलों को **Gatekeeper की** सुरक्षा जांचों को **बायपास** करने की अनुमति देती है।

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) की जांच करें।

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

जब एक अनुप्रयोग **Automator** के साथ बनाया जाता है, तो इसे निष्पादित करने के लिए आवश्यक जानकारी `application.app/Contents/document.wflow` के अंदर होती है न कि निष्पादनीय में। निष्पादनीय केवल एक सामान्य Automator बाइनरी है जिसे **Automator Application Stub** कहा जाता है।

इसलिए, आप `application.app/Contents/MacOS/Automator\ Application\ Stub` को **सिस्टम के अंदर एक अन्य Automator Application Stub की ओर एक प्रतीकात्मक लिंक के साथ इंगित कर सकते हैं** और यह `document.wflow` (आपका स्क्रिप्ट) के अंदर जो है उसे **Gatekeeper को ट्रिगर किए बिना निष्पादित करेगा** क्योंकि वास्तविक निष्पादनीय में क्वारंटाइन xattr नहीं है।

उदाहरण के लिए अपेक्षित स्थान: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://ronmasas.com/posts/bypass-macos-gatekeeper) की जांच करें।

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

इस बायपास में एक ज़िप फ़ाइल बनाई गई थी जिसमें एक अनुप्रयोग `application.app/Contents` से संकुचन शुरू कर रहा था न कि `application.app` से। इसलिए, **क्वारंटाइन विशेषता** सभी **फाइलों पर लागू की गई थी `application.app/Contents`** लेकिन **`application.app` पर नहीं**, जिसे Gatekeeper जांच रहा था, इसलिए Gatekeeper को बायपास किया गया क्योंकि जब `application.app` को ट्रिगर किया गया तो **इसमें क्वारंटाइन विशेषता नहीं थी।**
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

यहां तक कि यदि घटक भिन्न हैं, तो इस सुरक्षा कमजोरी का शोषण पिछले वाले के समान है। इस मामले में, हम **`application.app/Contents`** से एक Apple Archive बनाएंगे ताकि **`application.app`** को **Archive Utility** द्वारा अनजिप करते समय क्वारंटाइन विशेषता न मिले।
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) for more information.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** का उपयोग किसी को भी फ़ाइल में एक विशेषता लिखने से रोकने के लिए किया जा सकता है:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
इसके अलावा, **AppleDouble** फ़ाइल प्रारूप एक फ़ाइल को उसके ACEs सहित कॉपी करता है।

[**स्रोत कोड**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में यह देखना संभव है कि xattr के अंदर संग्रहीत ACL पाठ प्रतिनिधित्व जिसे **`com.apple.acl.text`** कहा जाता है, को डिकंप्रेस की गई फ़ाइल में ACL के रूप में सेट किया जाएगा। इसलिए, यदि आपने एक एप्लिकेशन को **AppleDouble** फ़ाइल प्रारूप में एक ज़िप फ़ाइल में संकुचित किया है जिसमें एक ACL है जो अन्य xattrs को इसमें लिखने से रोकती है... तो क्वारंटाइन xattr एप्लिकेशन में सेट नहीं किया गया था:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
[**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) के लिए अधिक जानकारी देखें।

ध्यान दें कि इसे AppleArchives के साथ भी शोषित किया जा सकता है:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

यह पता चला कि **Google Chrome डाउनलोड की गई फ़ाइलों के लिए क्वारंटाइन विशेषता सेट नहीं कर रहा था** कुछ macOS आंतरिक समस्याओं के कारण।

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble फ़ाइल प्रारूप एक फ़ाइल के गुणों को एक अलग फ़ाइल में `._` से शुरू करके संग्रहीत करते हैं, यह **macOS मशीनों के बीच फ़ाइल गुणों को कॉपी करने में मदद करता है**। हालाँकि, यह देखा गया कि एक AppleDouble फ़ाइल को डिकंप्रेस करने के बाद, `._` से शुरू होने वाली फ़ाइल को **क्वारंटाइन विशेषता नहीं दी गई**।
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
एक फ़ाइल बनाने में सक्षम होना जिसमें क्वारंटाइन विशेषता सेट नहीं होगी, यह **गेटकीपर को बायपास करना संभव था।** चाल यह थी कि **एप्पलडबल नाम सम्मेलन** का उपयोग करके एक **DMG फ़ाइल एप्लिकेशन** बनाना (इसे `._` से शुरू करना) और इस छिपी हुई फ़ाइल के लिए एक **दृश्यमान फ़ाइल के रूप में एक सिम लिंक बनाना** जिसमें क्वारंटाइन विशेषता नहीं हो।\
जब **dmg फ़ाइल को निष्पादित किया जाता है**, क्योंकि इसमें क्वारंटाइन विशेषता नहीं है, यह **गेटकीपर को बायपास कर देगी।**
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
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- एक ऐप वाला डायरेक्टरी बनाएं।
- ऐप में uchg जोड़ें।
- ऐप को tar.gz फ़ाइल में संकुचित करें।
- tar.gz फ़ाइल को एक पीड़ित को भेजें।
- पीड़ित tar.gz फ़ाइल खोलता है और ऐप चलाता है।
- Gatekeeper ऐप की जांच नहीं करता है।

### Prevent Quarantine xattr

एक ".app" बंडल में यदि क्वारंटाइन xattr जोड़ा नहीं गया है, तो इसे निष्पादित करते समय **Gatekeeper सक्रिय नहीं होगा**।


{{#include ../../../banners/hacktricks-training.md}}
