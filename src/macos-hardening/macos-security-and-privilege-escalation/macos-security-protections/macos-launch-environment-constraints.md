# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

macOS में Launch constraints को सुरक्षा बढ़ाने के लिए पेश किया गया था। ये **नियमित करते हैं कि कोई process कैसे, किसके द्वारा और कहाँ से शुरू किया जा सकता है**। macOS Ventura में शुरू किए गए ये constraints एक ऐसा framework प्रदान करते हैं जो **हर system binary को अलग-अलग constraint categories में वर्गीकृत करता है**। ये categories **trust cache** में परिभाषित होती हैं, जो system binaries और उनके संबंधित hashes की सूची है। ये constraints system की हर executable binary पर लागू होते हैं और **किसी खास binary को launch करने की आवश्यकताएँ बताने वाले rules** का एक सेट बनाते हैं। इन rules में self constraints शामिल हैं, जिन्हें binary को पूरा करना होता है; parent constraints, जिन्हें उसकी parent process को पूरा करना होता है; और responsible constraints, जिनका पालन अन्य संबंधित entities को करना होता है।<sup>[[1]](#references)[[4]](#references)</sup>

macOS Sonoma से यह mechanism **Environment Constraints** के ज़रिए third-party apps तक भी विस्तारित हुआ है। इससे developers environment constraints के लिए **keys और values का एक सेट तय करके अपने apps को सुरक्षित रख सकते हैं।**<sup>[[5]](#references)</sup>

आप **launch environment और library constraints** को constraint dictionaries में परिभाषित करते हैं। इन्हें आप **`launchd` property list files** में सेव कर सकते हैं, या code signing में इस्तेमाल की जाने वाली **अलग property list** files में रख सकते हैं।<sup>[[5]](#references)</sup>

Constraints के 4 प्रकार हैं:

- **Self Constraints**: चल रही binary पर लागू constraints।
- **Parent Process**: process के **parent पर लागू constraints** (उदाहरण के लिए, XP service चलाने वाला **`launchd`**)
- **Responsible Constraints**: XPC communication में **service को call करने वाली process पर लागू constraints**
- **Library load constraints**: लोड किए जा सकने वाले code का चुनिंदा रूप से वर्णन करने के लिए library load constraints का उपयोग करें।

इसलिए, जब कोई process `execve(_:_:_:)` या `posix_spawn(_:_:_:_:_:)` को call करके कोई दूसरी process launch करने की कोशिश करती है, तो operating system जाँचता है कि **executable** file अपने **self constraint** को **पूरा करती है**। यह यह भी जाँचता है कि **parent** **process** की executable, executable के **parent constraint** को **पूरा करती है**, और **responsible** **process** की executable, executable के **responsible process constraint** को **पूरा करती है**। अगर इनमें से कोई भी launch constraint पूरा नहीं होता, तो operating system program नहीं चलाता।

अगर library लोड करते समय **library constraint** का कोई भी हिस्सा पूरा नहीं होता, तो आपकी process उस library को **लोड नहीं करती**।

## LC Categories

एक LC, **facts** और उन्हें मिलाने वाले **logical operations** (and, or...) से बना होता है।

किसी LC में इस्तेमाल किए जा सकने वाले [**facts यहाँ दस्तावेज़ित हैं**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)। उदाहरण के लिए:

- is-init-proc: एक Boolean value, जो बताती है कि executable को operating system की initialization process (`launchd`) होना ज़रूरी है या नहीं।
- is-sip-protected: एक Boolean value, जो बताती है कि executable का System Integrity Protection (SIP) द्वारा सुरक्षित file होना ज़रूरी है या नहीं।
- `on-authorized-authapfs-volume:` एक Boolean value, जो बताती है कि operating system ने executable को किसी authorized, authenticated APFS volume से लोड किया है या नहीं।
- `on-authorized-authapfs-volume`: एक Boolean value, जो बताती है कि operating system ने executable को किसी authorized, authenticated APFS volume से लोड किया है या नहीं।
  - Cryptexes volume
- `on-system-volume:`एक Boolean value, जो बताती है कि operating system ने executable को वर्तमान में boot किए गए system volume से लोड किया है या नहीं।
  - /System के अंदर...
- ...

जब किसी Apple binary पर हस्ताक्षर किए जाते हैं, तो उसे **trust cache** के अंदर एक LC category में **रखा जाता है**।

- **iOS 16 LC categories** को [**reverse-engineer करके यहाँ दस्तावेज़ित किया गया था**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)।<sup>[[6]](#references)</sup>
- मौजूदा **LC categories (macOS 14** - Somona) को reverse-engineer किया गया है और उनके [**विवरण यहाँ देखे जा सकते हैं**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)।<sup>[[7]](#references)</sup>

उदाहरण के लिए, Category 1 है:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: System या Cryptexes volume में होना चाहिए।
- `launch-type == 1`: एक system service होना चाहिए (LaunchDaemons में plist)।
- `validation-category == 1`: एक operating system executable।
- `is-init-proc`: Launchd

### LC Categories को Reverse करना

इसके बारे में अधिक जानकारी [**यहाँ**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints) उपलब्ध है, लेकिन मूल रूप से, ये **AMFI (AppleMobileFileIntegrity)** में परिभाषित हैं, इसलिए **KEXT** पाने के लिए आपको Kernel Development Kit डाउनलोड करना होगा। **`kConstraintCategory`** से शुरू होने वाले symbols **महत्वपूर्ण** हैं। इन्हें extract करने पर आपको DER (ASN.1) encoded stream मिलेगा, जिसे आपको [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) या python-asn1 library की `dump.py` script, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) से decode करना होगा। इससे आपको अधिक समझने योग्य string मिलेगी।<sup>[[3]](#references)[[8]](#references)</sup>

## Environment Constraints

ये **third party applications** में कॉन्फ़िगर किए गए Launch Constraints हैं। Developer अपने application में access को प्रतिबंधित करने के लिए **facts** और **logical operands** चुन सकता है।

किसी application के Environment Constraints को इस तरह enumerate किया जा सकता है:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

**macOS** में कुछ trust caches हैं:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

और iOS में यह **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** में होता दिखता है।

> [!WARNING]
> Apple Silicon डिवाइस पर चल रहे macOS में, अगर कोई Apple-signed binary trust cache में नहीं है, तो AMFI उसे लोड करने से मना कर देगा।

### Trust Caches की सूची बनाना

ऊपर दी गई trust cache फ़ाइलें **IMG4** फ़ॉर्मैट में हैं। **IM4P**, IMG4 फ़ॉर्मैट का payload section होता है।

डेटाबेस का payload निकालने के लिए [**pyimg4**](https://github.com/m1stadev/PyIMG4) का उपयोग कर सकते हैं:

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

(एक अन्य विकल्प [**img4tool**](https://github.com/tihmstar/img4tool) tool का उपयोग करना हो सकता है। यह पुराना release होने के बावजूद M1 पर भी चलेगा, और यदि आप इसे सही locations पर install करते हैं, तो x86_64 पर भी चलेगा।)

अब आप जानकारी को पढ़ने योग्य format में पाने के लिए [**trustcache**](https://github.com/CRKatri/trustcache) tool का उपयोग कर सकते हैं:

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

Trust cache की संरचना निम्नलिखित है, इसलिए **LC category चौथा column है**

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

फिर, डेटा निकालने के लिए आप [**इस स्क्रिप्ट**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) का उपयोग कर सकते हैं।

उस डेटा से आप उन Apps की जाँच कर सकते हैं जिनकी **launch constraints वैल्यू `0`** है। ये वे Apps हैं जिन पर कोई constraint नहीं है (हर वैल्यू का अर्थ जानने के लिए [**यहाँ देखें**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)।)<sup>[[6]](#references)</sup>

## हमलों के शमन

Launch Constraints कई पुराने हमलों को **यह सुनिश्चित करके रोक सकते थे कि process अप्रत्याशित परिस्थितियों में execute न हो:** उदाहरण के लिए, अप्रत्याशित locations से या किसी अप्रत्याशित parent process द्वारा (यदि इसे केवल launchd ही launch करना चाहिए)।

इसके अलावा, Launch Constraints **downgrade attacks को भी रोकते हैं।**

हालाँकि, ये सामान्य XPC दुरुपयोग, **Electron** code injections या library validation के बिना **dylib injections** को नहीं रोकते (जब तक कि libraries load कर सकने वाली team IDs ज्ञात न हों)।<sup>[[3]](#references)</sup>

### XPC Daemon सुरक्षा

Sonoma release में daemon XPC service का **responsibility configuration** एक उल्लेखनीय पहलू है। XPC service स्वयं अपने लिए जवाबदेह है, न कि उससे connect करने वाला client। इसे feedback report FB13206884 में दर्ज किया गया है। यह व्यवस्था त्रुटिपूर्ण लग सकती है, क्योंकि इससे XPC service के साथ कुछ प्रकार के interactions संभव हो जाते हैं:

- **XPC Service को launch करना**: यदि इसे bug माना जाए, तो यह व्यवस्था attacker code के ज़रिए XPC service शुरू करने की अनुमति नहीं देती।
- **चालू Service से connect करना**: यदि XPC service पहले से चल रही हो (संभवतः उसके मूल application द्वारा शुरू की गई हो), तो उससे connect करने पर कोई रोक नहीं है।

XPC service पर constraints लागू करना **संभावित हमलों के लिए उपलब्ध समय-सीमा कम करके** मददगार हो सकता है, लेकिन इससे मुख्य चिंता दूर नहीं होती। XPC service को सुरक्षित रखने के लिए, उससे connect करने वाले client को प्रभावी ढंग से **validate करना अनिवार्य है**। Service की सुरक्षा मज़बूत करने का यही एकमात्र तरीका है। यह भी ध्यान देने योग्य है कि बताया गया responsibility configuration अभी काम कर रहा है, जो शायद अपेक्षित design से मेल न खाता हो।<sup>[[3]](#references)</sup>

### Electron सुरक्षा

भले ही यह ज़रूरी हो कि application को **LaunchService द्वारा खोला जाए** (parents constraints में), यह **`open`** का उपयोग करके किया जा सकता है (जो env variables set कर सकता है), या **Launch Services API** का उपयोग करके (जिसमें env variables दिए जा सकते हैं)।<sup>[[3]](#references)</sup>

Policy-specific spawn attributes के पीछे मौजूद सामान्य MACF mechanism के लिए, [MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input) देखें।

### CVE-2025-43253 - spawn के समय अंतर्निहित constraints को override करना

Launch constraints (आधिकारिक तौर पर **lightweight code requirements**, *LWCR*) को **AMFI MAC policy** लागू करती है। `posix_spawn` caller को **`posix_spawnattr_setmacpolicyinfo_np()`** के ज़रिए MAC policy को मनमाना blob देने देता है, और AMFI इस रास्ते से caller द्वारा दिया गया LWCR dictionary स्वीकार करता था। Bug यह था कि **attacker द्वारा दिए गए constraints, binary के अंतर्निहित constraints की जगह ले लेते थे**, बजाय इसके कि उन्हें अतिरिक्त रूप से जाँचा जाता:

- एक न्यूनतम (यहाँ तक कि खाली) launch-constraints dictionary बनाएँ।
- **constraint category को `127` पर set करें**। यह ऐसी वैल्यू है जिसे AMFI spawn attributes में स्वीकार करता है, लेकिन **लागू नहीं करता** — execution को रोकने के बजाय यह केवल `Launch Constraint Violation (not enforcing)` log करता है।
- इसे spawn attributes के ज़रिए pass करें, और process ऐसे context में launch हो जाता है जिसे उसके वास्तविक self/parent constraints ने निषिद्ध किया होता।

Fix के बाद, अंतर्निहित और दिए गए **दोनों** constraints validate किए जाते हैं, इसलिए दिया गया dictionary अब अंतर्निहित constraints को कमज़ोर नहीं कर सकता।<sup>[[2]](#references)</sup>

> [!TIP]
> Constraint enforcement का audit करते समय इस सामान्य pattern पर ध्यान दें: untrusted input को policy *देने* की अनुमति देने वाला API अक्सर दिलचस्प होता है, खासकर जब policy engine दी गई वैल्यू को अतिरिक्त requirement के बजाय replacement मानता हो।



## References

- [1] [Objective by the Sea #OBTS v6.0 दिन 2 (लाइव-स्ट्रीम)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: macOS पर Launch Constraints को bypass करना (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch और Environment Constraints का गहन विश्लेषण - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [System app या command tool क्यों नहीं चलता? Launch constraints और trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Environment constraints से अपने Mac app को सुरक्षित रखें - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16 में पेश किए गए Launch Constraints का विवरण (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [पुराने अच्छे LaunchAgents से आगे - इसके बारे में यहाँ पढ़ें](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
