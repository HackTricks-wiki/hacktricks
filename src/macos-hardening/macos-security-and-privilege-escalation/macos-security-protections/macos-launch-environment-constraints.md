# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

macOS में Launch constraints को इस सुरक्षा को बढ़ाने के लिए प्रस्तुत किया गया था कि **किस प्रकार, कौन और किस स्थान से किसी process को initiate किया जा सकता है**। macOS Ventura में शुरू की गई ये constraints एक ऐसा framework प्रदान करती हैं जो **प्रत्येक system binary को अलग-अलग constraint categories में वर्गीकृत करता है**। ये categories **trust cache** में परिभाषित होती हैं, जो system binaries और उनके संबंधित hashes की सूची है। ये constraints system के प्रत्येक executable binary तक विस्तारित होती हैं और इनमें **किसी विशेष binary को launch करने के लिए आवश्यकताओं** को परिभाषित करने वाले **rules** शामिल होते हैं। इन rules में self constraints शामिल होती हैं, जिन्हें binary को पूरा करना आवश्यक होता है; parent constraints, जिन्हें उसके parent process को पूरा करना आवश्यक होता है; और responsible constraints, जिनका पालन अन्य संबंधित entities द्वारा किया जाना आवश्यक होता है।

macOS Sonoma से शुरू होकर यह mechanism third-party apps तक भी विस्तारित होता है। इसे **Environment Constraints** के माध्यम से किया जाता है, जिससे developers environment constraints के लिए **keys और values का एक set निर्दिष्ट करके** अपनी apps को सुरक्षित कर सकते हैं।

आप **launch environment और library constraints** को constraint dictionaries में define करते हैं, जिन्हें आप **`launchd` property list files** में save करते हैं, या **separate property list** files में रखते हैं, जिनका उपयोग आप code signing में करते हैं।

4 प्रकार की constraints होती हैं:

- **Self Constraints**: **running** binary पर लागू की जाने वाली constraints।
- **Parent Process**: process के **parent** पर लागू की जाने वाली constraints (उदाहरण के लिए, **`launchd`** द्वारा चलाया जा रहा XP service)
- **Responsible Constraints**: XPC communication में **service को call करने वाले process** पर लागू की जाने वाली constraints
- **Library load constraints**: load किए जा सकने वाले code का चयनात्मक वर्णन करने के लिए library load constraints का उपयोग करें

इसलिए जब कोई process — `execve(_:_:_:)` या `posix_spawn(_:_:_:_:_:_:)` को call करके — किसी अन्य process को launch करने का प्रयास करता है, तो operating system यह जाँचता है कि **executable** file अपनी **self constraint** को **satisfy** करती है। यह यह भी जाँचता है कि **parent** **process** का executable, executable की **parent constraint** को **satisfy** करता है, और **responsible** **process** का executable, executable की responsible process **constraint** को **satisfy** करता है। यदि इनमें से कोई launch constraint satisfy नहीं होती, तो operating system program को run नहीं करता।

यदि किसी library को load करते समय **library constraint** का कोई भी भाग true नहीं है, तो आपका process उस library को **load नहीं करता**।

## LC Categories

एक LC **facts** और **logical operations** (and, or..) से बना होता है, जो facts को combine करता है।

[ **वे facts जिनका उपयोग एक LC कर सकता है, documented हैं**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)। उदाहरण के लिए:

- is-init-proc: एक Boolean value, जो बताती है कि executable operating system का initialization process (`launchd`) होना आवश्यक है या नहीं।
- is-sip-protected: एक Boolean value, जो बताती है कि executable का System Integrity Protection (SIP) द्वारा protected file होना आवश्यक है या नहीं।
- `on-authorized-authapfs-volume:` एक Boolean value, जो बताती है कि operating system ने executable को किसी authorized, authenticated APFS volume से load किया है या नहीं।
- `on-authorized-authapfs-volume`: एक Boolean value, जो बताती है कि operating system ने executable को किसी authorized, authenticated APFS volume से load किया है या नहीं।
- Cryptexes volume
- `on-system-volume:`एक Boolean value, जो बताती है कि operating system ने executable को वर्तमान में boot किए गए system volume से load किया है या नहीं।
- Inside /System...
- ...

जब किसी Apple binary पर हस्ताक्षर किए जाते हैं, तो उसे **trust cache** के अंदर एक LC category में **assign** किया जाता है।

- **iOS 16 LC categories** को [**यहाँ reverse और documented किया गया है**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)।<sup>[6]</sup>
- Current **LC categories (macOS 14** - Somona) को reverse किया गया है और उनके [**descriptions यहाँ पाए जा सकते हैं**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)।<sup>[7]</sup>

उदाहरण के लिए Category 1 है:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: System या Cryptexes volume में होना आवश्यक है।
- `launch-type == 1`: यह एक system service होना चाहिए (LaunchDaemons में plist)।
- `validation-category == 1`: एक operating system executable।
- `is-init-proc`: Launchd

### LC Categories को Reverse करना

आपको इसके बारे में [**यहाँ अधिक जानकारी**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints) मिल सकती है, लेकिन मूल रूप से, ये **AMFI (AppleMobileFileIntegrity)** में परिभाषित होते हैं, इसलिए आपको Kernel Development Kit डाउनलोड करके **KEXT** प्राप्त करना होगा। **`kConstraintCategory`** से शुरू होने वाले symbols **महत्वपूर्ण** हैं। इन्हें extract करने पर आपको एक DER (ASN.1) encoded stream मिलेगी, जिसे आपको [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) या python-asn1 library और उसकी `dump.py` script, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) से decode करना होगा। इससे आपको अधिक समझने योग्य string मिलेगी।<sup>[3]</sup>

## Environment Constraints

ये **third party applications** में configured Launch Constraints हैं। Developer अपने application में access को प्रतिबंधित करने के लिए **facts** और **logical operands** चुन सकता है।

किसी application के Environment Constraints को इस प्रकार enumerate करना संभव है:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

**macOS** में कुछ trust caches हैं:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

और iOS में यह **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** में दिखाई देता है।

> [!WARNING]
> Apple Silicon devices पर चल रहे macOS में, यदि कोई Apple signed binary trust cache में नहीं है, तो AMFI उसे load करने से इनकार कर देगा।

### Trust Caches की गणना

पिछली trust cache files **IMG4** और **IM4P** format में हैं, जिसमें IM4P, IMG4 format का payload section होता है।

आप databases का payload extract करने के लिए [**pyimg4**](https://github.com/m1stadev/PyIMG4) का उपयोग कर सकते हैं:
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
(एक अन्य विकल्प [**img4tool**](https://github.com/tihmstar/img4tool) tool का उपयोग करना हो सकता है, जो release पुराना होने पर भी M1 पर और यदि इसे उचित locations में install किया जाए तो x86_64 के लिए भी चलेगा)।

अब आप जानकारी को readable format में प्राप्त करने के लिए [**trustcache**](https://github.com/CRKatri/trustcache) tool का उपयोग कर सकते हैं:
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
फिर, आप data extract करने के लिए [**इस script**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) का उपयोग कर सकते हैं।

उस data से आप उन Apps को check कर सकते हैं जिनकी **launch constraints value `0`** है; ये वे Apps हैं जो constrained नहीं हैं (हर value का अर्थ जानने के लिए [**यहाँ check करें**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056))।<sup>[6]</sup>

## Attack Mitigations

Launch Constraints ने कई पुराने attacks को **यह सुनिश्चित करके mitigate किया होता कि process unexpected conditions में execute न हो:** उदाहरण के लिए, unexpected locations से या किसी unexpected parent process द्वारा invoke होकर (यदि इसे केवल launchd ही launch करना चाहिए)।

इसके अलावा, Launch Constraints **downgrade attacks को भी mitigate करते हैं।**

हालाँकि, वे बिना library validation के होने वाले आम **XPC** abuses, **Electron** code injections या **dylib injections** को **mitigate नहीं करते** (जब तक कि libraries load कर सकने वाली team IDs ज्ञात न हों)।<sup>[3]</sup>

### XPC Daemon Protection

Sonoma release में एक महत्वपूर्ण बिंदु daemon XPC service का **responsibility configuration** है। Connecting client के responsible होने के बजाय XPC service स्वयं के लिए accountable होती है। इसे feedback report FB13206884 में document किया गया है। यह setup flawed लग सकता है, क्योंकि यह XPC service के साथ कुछ interactions की अनुमति देता है:

- **XPC Service को Launch करना**: यदि इसे bug माना जाए, तो यह setup attacker code के माध्यम से XPC service को initiate करने की अनुमति नहीं देता।
- **Active Service से Connect करना**: यदि XPC service पहले से चल रही हो (संभवतः उसके original application द्वारा activate की गई हो), तो उससे connect करने में कोई बाधा नहीं होती।

हालाँकि XPC service पर constraints लागू करना **potential attacks की window को narrow करके** लाभदायक हो सकता है, लेकिन इससे primary concern का समाधान नहीं होता। XPC service की security सुनिश्चित करने के लिए मूल रूप से **connecting client को effectively validate करना** आवश्यक है। Service की security को मजबूत करने का यही एकमात्र तरीका है। यह भी ध्यान देने योग्य है कि बताई गई responsibility configuration वर्तमान में operational है, जो intended design के अनुरूप नहीं हो सकती है।<sup>[3]</sup>

### Electron Protection

भले ही यह आवश्यक हो कि application को **LaunchService द्वारा opened किया जाए** (parents constraints में)। इसे **`open`** का उपयोग करके प्राप्त किया जा सकता है (जो env variables set कर सकता है) या **Launch Services API** का उपयोग करके (जहाँ env variables indicate किए जा सकते हैं)।<sup>[3]</sup>

### CVE-2025-43253 - Spawn time पर built-in constraints को Override करना

Launch constraints (officially **lightweight code requirements**, *LWCR*) को **AMFI MAC policy** द्वारा enforce किया जाता है। `posix_spawn` caller को **`posix_spawnattr_setmacpolicyinfo_np()`** के माध्यम से MAC policy को एक arbitrary blob देने की अनुमति देता है, और AMFI उस path के माध्यम से caller-supplied LWCR dictionary स्वीकार करता था। Bug यह था कि **attacker-supplied constraints binary की built-in constraints को replace कर देती थीं**, बजाय इसके कि उन्हें built-in constraints के अतिरिक्त check किया जाता:

- एक minimal (यहाँ तक कि empty) launch-constraints dictionary बनाएँ।
- **constraint category को `127` पर set करें**, यह ऐसी value है जिसे AMFI spawn attributes में allow करता है लेकिन **enforce नहीं करता** — execution को block करने के बजाय यह केवल `Launch Constraint Violation (not enforcing)` log करता है।
- इसे spawn attributes के माध्यम से pass करें, और process ऐसे context में launch हो जाता है जिसे उसकी वास्तविक self/parent constraints ने forbidden किया होता।

Fix के बाद, **built-in और supplied दोनों constraints validate की जाती हैं**, इसलिए supplied dictionary अब built-in constraint को weaken नहीं कर सकती।<sup>[2]</sup>

> [!TIP]
> Constraint enforcement audit करते समय यह general shape तलाशें: ऐसा API जो untrusted input को policy *supply* करने देता है, तब interesting होता है जब policy engine supplied value को additional requirement के बजाय replacement की तरह treat करता है।

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
