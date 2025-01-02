# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

macOS में लॉन्च प्रतिबंध सुरक्षा को बढ़ाने के लिए पेश किए गए थे **यह विनियमित करके कि एक प्रक्रिया कैसे, कौन और कहाँ से शुरू की जा सकती है**। macOS Ventura में शुरू किए गए, ये एक ढांचा प्रदान करते हैं जो **प्रत्येक सिस्टम बाइनरी को विशिष्ट प्रतिबंध श्रेणियों में वर्गीकृत करता है**, जो **ट्रस्ट कैश** के भीतर परिभाषित हैं, जो सिस्टम बाइनरी और उनके संबंधित हैश का एक सूची है। ये प्रतिबंध सिस्टम के भीतर हर निष्पादन योग्य बाइनरी पर लागू होते हैं, जिसमें **विशिष्ट बाइनरी को लॉन्च करने के लिए आवश्यकताओं** को परिभाषित करने वाले **नियमों** का एक सेट शामिल होता है। नियमों में स्वयं प्रतिबंध शामिल होते हैं जिन्हें एक बाइनरी को संतुष्ट करना होता है, माता-पिता के प्रतिबंध जो इसके माता-पिता की प्रक्रिया द्वारा पूरा किए जाने की आवश्यकता होती है, और जिम्मेदार प्रतिबंध जो अन्य संबंधित संस्थाओं द्वारा पालन किए जाने चाहिए।

यह तंत्र तीसरे पक्ष के ऐप्स तक **पर्यावरण प्रतिबंधों** के माध्यम से विस्तारित होता है, जो macOS Sonoma से शुरू होता है, जिससे डेवलपर्स को अपने ऐप्स की सुरक्षा करने की अनुमति मिलती है, जो **पर्यावरण प्रतिबंधों के लिए कुंजी और मानों का एक सेट निर्दिष्ट करते हैं।**

आप **लॉन्च वातावरण और पुस्तकालय प्रतिबंधों** को प्रतिबंध शब्दकोशों में परिभाषित करते हैं जिन्हें आप या तो **`launchd` प्रॉपर्टी लिस्ट फ़ाइलों** में सहेजते हैं, या **अलग प्रॉपर्टी लिस्ट** फ़ाइलों में जो आप कोड साइनिंग में उपयोग करते हैं।

प्रतिबंधों के 4 प्रकार हैं:

- **स्वयं प्रतिबंध**: **चल रही** बाइनरी पर लागू प्रतिबंध।
- **माता-पिता प्रक्रिया**: **प्रक्रिया के माता-पिता** पर लागू प्रतिबंध (उदाहरण के लिए **`launchd`** एक XP सेवा चला रहा है)
- **जिम्मेदार प्रतिबंध**: **सेवा को कॉल करने वाली प्रक्रिया** पर लागू प्रतिबंध एक XPC संचार में
- **पुस्तकालय लोड प्रतिबंध**: चयनात्मक रूप से कोड का वर्णन करने के लिए पुस्तकालय लोड प्रतिबंधों का उपयोग करें जिसे लोड किया जा सकता है

तो जब एक प्रक्रिया दूसरी प्रक्रिया को लॉन्च करने की कोशिश करती है — `execve(_:_:_:)` या `posix_spawn(_:_:_:_:_:_:)` को कॉल करके — ऑपरेटिंग सिस्टम यह जांचता है कि **निष्पादन योग्य** फ़ाइल **अपनी स्वयं की प्रतिबंध** को **संतुष्ट करती है**। यह यह भी जांचता है कि **माता-पिता** **प्रक्रिया** का निष्पादन योग्य **निष्पादन योग्य के माता-पिता के प्रतिबंध** को **संतुष्ट करता है**, और कि **जिम्मेदार** **प्रक्रिया** का निष्पादन योग्य **निष्पादन योग्य के जिम्मेदार प्रक्रिया के प्रतिबंध** को **संतुष्ट करता है**। यदि इनमें से कोई भी लॉन्च प्रतिबंध संतुष्ट नहीं होते हैं, तो ऑपरेटिंग सिस्टम प्रोग्राम को नहीं चलाता।

यदि किसी पुस्तकालय को लोड करते समय **पुस्तकालय प्रतिबंध का कोई भाग सत्य नहीं है**, तो आपकी प्रक्रिया **पुस्तकालय को लोड नहीं करती**।

## LC Categories

एक LC **तथ्यों** और **तार्किक संचालन** (और, या..) से बना होता है जो तथ्यों को जोड़ता है।

[ **एक LC द्वारा उपयोग किए जा सकने वाले तथ्यों का दस्तावेजीकरण किया गया है**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)। उदाहरण के लिए:

- is-init-proc: एक बूलियन मान जो यह संकेत करता है कि क्या निष्पादन योग्य ऑपरेटिंग सिस्टम की प्रारंभिक प्रक्रिया (`launchd`) होनी चाहिए।
- is-sip-protected: एक बूलियन मान जो यह संकेत करता है कि क्या निष्पादन योग्य एक फ़ाइल होनी चाहिए जो सिस्टम इंटीग्रिटी प्रोटेक्शन (SIP) द्वारा सुरक्षित है।
- `on-authorized-authapfs-volume:` एक बूलियन मान जो यह संकेत करता है कि क्या ऑपरेटिंग सिस्टम ने निष्पादन योग्य को एक अधिकृत, प्रमाणित APFS वॉल्यूम से लोड किया।
- `on-authorized-authapfs-volume`: एक बूलियन मान जो यह संकेत करता है कि क्या ऑपरेटिंग सिस्टम ने निष्पादन योग्य को एक अधिकृत, प्रमाणित APFS वॉल्यूम से लोड किया।
- Cryptexes वॉल्यूम
- `on-system-volume:` एक बूलियन मान जो यह संकेत करता है कि क्या ऑपरेटिंग सिस्टम ने निष्पादन योग्य को वर्तमान में बूट किए गए सिस्टम वॉल्यूम से लोड किया।
- /System के अंदर...
- ...

जब एक Apple बाइनरी पर हस्ताक्षर किया जाता है, तो यह **इसे एक LC श्रेणी** में **ट्रस्ट कैश** के भीतर असाइन करता है।

- **iOS 16 LC श्रेणियाँ** [**यहाँ उलट दी गई हैं और दस्तावेजीकृत की गई हैं**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)।
- वर्तमान **LC श्रेणियाँ (macOS 14** - सोनोमा) उलट दी गई हैं और उनके [**विवरण यहाँ पाए जा सकते हैं**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)।

उदाहरण के लिए श्रेणी 1 है:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: सिस्टम या क्रिप्टेक्स वॉल्यूम में होना चाहिए।
- `launch-type == 1`: एक सिस्टम सेवा होनी चाहिए (LaunchDaemons में plist)।
- `validation-category == 1`: एक ऑपरेटिंग सिस्टम निष्पादन योग्य।
- `is-init-proc`: Launchd

### LC श्रेणियों को उलटना

आपके पास इसके बारे में अधिक जानकारी [**यहां**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints) है, लेकिन मूल रूप से, इन्हें **AMFI (AppleMobileFileIntegrity)** में परिभाषित किया गया है, इसलिए आपको **KEXT** प्राप्त करने के लिए कर्नेल डेवलपमेंट किट डाउनलोड करने की आवश्यकता है। **`kConstraintCategory`** से शुरू होने वाले प्रतीक **दिलचस्प** होते हैं। इन्हें निकालने पर आपको एक DER (ASN.1) एन्कोडेड स्ट्रीम मिलेगी जिसे आपको [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) या python-asn1 लाइब्रेरी और इसके `dump.py` स्क्रिप्ट, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) के साथ डिकोड करने की आवश्यकता होगी, जो आपको एक अधिक समझने योग्य स्ट्रिंग देगा।

## पर्यावरण प्रतिबंध

ये **तीसरे पक्ष के अनुप्रयोगों** में सेट किए गए लॉन्च प्रतिबंध हैं। डेवलपर अपने अनुप्रयोग में **तथ्यों** और **तार्किक ऑपरेटरों का चयन** कर सकता है ताकि स्वयं तक पहुंच को प्रतिबंधित किया जा सके।

एक अनुप्रयोग के पर्यावरण प्रतिबंधों को सूचीबद्ध करना संभव है:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

In **macOS** में कुछ ट्रस्ट कैश हैं:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

और iOS में यह **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** में है।

> [!WARNING]
> Apple Silicon डिवाइस पर चलने वाले macOS में, यदि कोई Apple द्वारा साइन किया गया बाइनरी ट्रस्ट कैश में नहीं है, तो AMFI इसे लोड करने से मना कर देगा।

### Enumerating Trust Caches

पिछले ट्रस्ट कैश फ़ाइलें **IMG4** और **IM4P** प्रारूप में हैं, IM4P IMG4 प्रारूप का पेलोड सेक्शन है।

आप डेटाबेस के पेलोड को निकालने के लिए [**pyimg4**](https://github.com/m1stadev/PyIMG4) का उपयोग कर सकते हैं:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(एक और विकल्प यह हो सकता है कि आप उपकरण [**img4tool**](https://github.com/tihmstar/img4tool) का उपयोग करें, जो M1 पर भी चलेगा भले ही रिलीज़ पुरानी हो और x86_64 के लिए यदि आप इसे सही स्थानों पर स्थापित करते हैं)।

अब आप उपकरण [**trustcache**](https://github.com/CRKatri/trustcache) का उपयोग करके जानकारी को पढ़ने योग्य प्रारूप में प्राप्त कर सकते हैं:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
विश्वास कैश निम्नलिखित संरचना का पालन करता है, इसलिए **LC श्रेणी चौथा कॉलम है**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
फिर, आप डेटा निकालने के लिए [**इस स्क्रिप्ट**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) का उपयोग कर सकते हैं।

उस डेटा से आप उन ऐप्स की जांच कर सकते हैं जिनका **launch constraints मान `0`** है, जो वे हैं जो सीमित नहीं हैं ([**यहाँ जांचें**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) कि प्रत्येक मान क्या है)।

## हमले की रोकथाम

Launch Constraints कई पुराने हमलों को **यह सुनिश्चित करके रोकते हैं कि प्रक्रिया अप्रत्याशित परिस्थितियों में निष्पादित नहीं होगी:** उदाहरण के लिए अप्रत्याशित स्थानों से या अप्रत्याशित माता-पिता प्रक्रिया द्वारा बुलाए जाने पर (यदि केवल launchd इसे लॉन्च करना चाहिए)

इसके अलावा, Launch Constraints **डाउनग्रेड हमलों को भी रोकते हैं।**

हालांकि, वे **सामान्य XPC** दुरुपयोग, **Electron** कोड इंजेक्शन या **dylib इंजेक्शन** को बिना लाइब्रेरी सत्यापन के रोकते नहीं हैं (जब तक कि उन टीम आईडी को नहीं जाना जाता जो लाइब्रेरी लोड कर सकते हैं)।

### XPC डेमन सुरक्षा

Sonoma रिलीज़ में, एक महत्वपूर्ण बिंदु डेमन XPC सेवा की **जिम्मेदारी कॉन्फ़िगरेशन** है। XPC सेवा अपनी जिम्मेदारी के लिए उत्तरदायी है, जबकि कनेक्टिंग क्लाइंट जिम्मेदार नहीं है। यह फीडबैक रिपोर्ट FB13206884 में दस्तावेजित है। यह सेटअप दोषपूर्ण लग सकता है, क्योंकि यह XPC सेवा के साथ कुछ इंटरैक्शन की अनुमति देता है:

- **XPC सेवा लॉन्च करना**: यदि इसे एक बग माना जाए, तो यह सेटअप हमलावर कोड के माध्यम से XPC सेवा को प्रारंभ करने की अनुमति नहीं देता है।
- **सक्रिय सेवा से कनेक्ट करना**: यदि XPC सेवा पहले से चल रही है (संभवतः इसके मूल एप्लिकेशन द्वारा सक्रिय), तो इससे कनेक्ट करने में कोई बाधा नहीं है।

XPC सेवा पर प्रतिबंध लागू करना **संभावित हमलों के लिए खिड़की को संकीर्ण करके** फायदेमंद हो सकता है, लेकिन यह प्राथमिक चिंता को संबोधित नहीं करता है। XPC सेवा की सुरक्षा सुनिश्चित करने के लिए **कनेक्टिंग क्लाइंट को प्रभावी ढंग से मान्य करना** आवश्यक है। यह सेवा की सुरक्षा को मजबूत करने का एकमात्र तरीका है। इसके अलावा, यह ध्यान देने योग्य है कि उल्लेखित जिम्मेदारी कॉन्फ़िगरेशन वर्तमान में कार्यात्मक है, जो कि इच्छित डिज़ाइन के साथ मेल नहीं खा सकता है।

### Electron सुरक्षा

यहां तक कि यह आवश्यक है कि एप्लिकेशन को **LaunchService द्वारा खोला जाना चाहिए** (माता-पिता की सीमाओं में)। इसे **`open`** का उपयोग करके (जो env वेरिएबल सेट कर सकता है) या **Launch Services API** का उपयोग करके (जहां env वेरिएबल को इंगित किया जा सकता है) प्राप्त किया जा सकता है।

## संदर्भ

- [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [https://theevilbit.github.io/posts/launch_constraints_deep_dive/](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{{#include ../../../banners/hacktricks-training.md}}
