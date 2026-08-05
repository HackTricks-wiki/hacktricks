# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## मूल जानकारी

macOS में Launch constraints को security बढ़ाने के लिए पेश किया गया था, ताकि **किस प्रकार, कौन और किस स्थान से कोई process शुरू किया जा सकता है, इसे नियंत्रित किया जा सके**। macOS Ventura में शुरू की गई ये constraints एक ऐसा framework प्रदान करती हैं, जो **हर system binary को अलग-अलग constraint categories में वर्गीकृत करता है**। ये categories **trust cache** में परिभाषित होती हैं, जिसमें system binaries और उनके संबंधित hashes की सूची होती है। ये constraints system के प्रत्येक executable binary तक विस्तारित होती हैं और **किसी विशेष binary को launch करने के लिए आवश्यकताओं** को निर्धारित करने वाले **rules** का एक set शामिल करती हैं। इन rules में self constraints शामिल होती हैं, जिन्हें binary को स्वयं पूरा करना आवश्यक है; parent constraints, जिन्हें उसके parent process को पूरा करना आवश्यक है; और responsible constraints, जिनका पालन अन्य संबंधित entities को करना होता है।

यह mechanism macOS Sonoma से third-party apps तक भी विस्तारित है। इसे **Environment Constraints** कहा जाता है और developers को **environment constraints के लिए keys और values का एक set निर्दिष्ट करके** अपने apps को सुरक्षित रखने की अनुमति देता है।

आप **launch environment और library constraints** को constraint dictionaries में define करते हैं, जिन्हें आप या तो **`launchd` property list files** में save करते हैं, या अलग **property list** files में, जिनका उपयोग आप code signing में करते हैं।

Constraints के 4 types हैं:

- **Self Constraints**: **running** binary पर लागू की जाने वाली constraints।
- **Parent Process**: process के **parent** पर लागू की जाने वाली constraints (उदाहरण के लिए, **`launchd`** द्वारा चलाया जा रहा XP service)
- **Responsible Constraints**: XPC communication में **service को call करने वाले process** पर लागू की जाने वाली constraints
- **Library load constraints**: ऐसे code का selective description देने के लिए library load constraints का उपयोग करें जिसे load किया जा सकता है।

इसलिए, जब कोई process — `execve(_:_:_:)` या `posix_spawn(_:_:_:_:_:_:)` को call करके — किसी अन्य process को launch करने का प्रयास करता है, तो operating system जाँचता है कि **executable** file अपनी **self constraint** को **पूरा करती है**। यह भी जाँचा जाता है कि **parent** **process** का executable, executable की **parent constraint** को **पूरा करता है**, और **responsible** **process** का executable, executable की responsible process **constraint** को **पूरा करता है**। यदि इनमें से कोई भी launch constraint पूरी नहीं होती, तो operating system program को run नहीं करता।

यदि किसी library को load करते समय **library constraint का कोई भी भाग true नहीं होता**, तो आपका process उस library को **load नहीं करता**।

## LC Categories

एक LC, **facts** और **logical operations** (and, or आदि) से बना होता है, जो facts को combine करते हैं।

[**वे facts जिन्हें एक LC उपयोग कर सकता है, documented हैं**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)। उदाहरण के लिए:

- is-init-proc: एक Boolean value, जो बताती है कि executable operating system का initialization process (`launchd`) होना आवश्यक है या नहीं।
- is-sip-protected: एक Boolean value, जो बताती है कि executable का System Integrity Protection (SIP) द्वारा protected file होना आवश्यक है या नहीं।
- `on-authorized-authapfs-volume:` एक Boolean value, जो बताती है कि operating system ने executable को किसी authorized, authenticated APFS volume से load किया है या नहीं।
- `on-authorized-authapfs-volume`: एक Boolean value, जो बताती है कि operating system ने executable को किसी authorized, authenticated APFS volume से load किया है या नहीं।
- Cryptexes volume
- `on-system-volume:`एक Boolean value, जो बताती है कि operating system ने executable को वर्तमान में boot किए गए system volume से load किया है या नहीं।
- /System के अंदर...
- ...

जब किसी Apple binary को sign किया जाता है, तो उसे **trust cache** के अंदर एक LC category में **assign** किया जाता है।

- **iOS 16 LC categories** को [**यहाँ reverse और documented किया गया है**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)।<sup>[[6]](#references)</sup>
- वर्तमान **LC categories (macOS 14** - Somona) को reverse किया गया है और उनके [**descriptions यहाँ पाए जा सकते हैं**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)।<sup>[[7]](#references)</sup>

उदाहरण के लिए Category 1 है:<sup>[[7]](#references)</sup>
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

आपको इसके बारे में [**यहाँ अधिक जानकारी मिल सकती है**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), लेकिन मूल रूप से, ये **AMFI (AppleMobileFileIntegrity)** में defined होते हैं, इसलिए आपको Kernel Development Kit download करके **KEXT** प्राप्त करना होगा। **`kConstraintCategory`** से शुरू होने वाले symbols **महत्वपूर्ण** हैं। इन्हें extract करने पर आपको DER (ASN.1) encoded stream मिलेगी, जिसे आपको [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) या python-asn1 library और उसकी `dump.py` script, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) से decode करना होगा। इससे आपको अधिक समझने योग्य string मिलेगी।<sup>[[3]](#references)</sup>

## Environment Constraints

ये Launch Constraints हैं, जिन्हें **third party applications** में configure किया जाता है। Developer अपने application में access को प्रतिबंधित करने के लिए **facts** और **logical operands to use** चुन सकता है।

किसी application के Environment Constraints को इस प्रकार enumerate किया जा सकता है:
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
> Apple Silicon devices पर चलने वाले macOS में, यदि कोई Apple signed binary trust cache में मौजूद नहीं है, तो AMFI उसे load करने से मना कर देगा।

### Trust Caches को Enumerate करना

पिछली trust cache files **IMG4** और **IM4P** format में होती हैं, जिसमें IM4P, IMG4 format का payload section होता है।

आप databases के payload को extract करने के लिए [**pyimg4**](https://github.com/m1stadev/PyIMG4) का उपयोग कर सकते हैं:
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
(एक अन्य विकल्प [**img4tool**](https://github.com/tihmstar/img4tool) tool का उपयोग करना हो सकता है, जो release पुराना होने पर भी M1 पर और x86_64 के लिए उचित locations में install करने पर चलेगा)।

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
trust cache की संरचना निम्नलिखित है, इसलिए **LC category चौथा column है**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
फिर, आप data extract करने के लिए [**this one**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) जैसी script का उपयोग कर सकते हैं।

उस data से आप उन Apps को check कर सकते हैं जिनका **launch constraints value `0`** है। ये वे Apps हैं जिन पर कोई constraint नहीं है (हर value का अर्थ जानने के लिए [**check here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056))।<sup>[[6]](#references)</sup>

## Attack Mitigations

Launch Constraints ने कई पुराने attacks को mitigate किया होता, क्योंकि वे **यह सुनिश्चित करते हैं कि process unexpected conditions में execute न हो:** उदाहरण के लिए, unexpected locations से या unexpected parent process द्वारा invoke न हो (यदि इसे केवल launchd को launch करना चाहिए)।

इसके अलावा, Launch Constraints **downgrade attacks को भी mitigate करते हैं।**

हालाँकि, वे common XPC abuses, **Electron** code injections या library validation के बिना **dylib injections** को mitigate **नहीं** करते (जब तक कि libraries load करने वाले team IDs ज्ञात न हों)।<sup>[[3]](#references)</sup>

### XPC Daemon Protection

Sonoma release में एक महत्वपूर्ण बिंदु daemon XPC service का **responsibility configuration** है। XPC service स्वयं के लिए accountable होती है, connecting client के responsible होने के बजाय। इसे feedback report FB13206884 में document किया गया है। यह setup flawed लग सकता है, क्योंकि यह XPC service के साथ कुछ interactions की अनुमति देता है:

- **XPC Service को Launch करना**: यदि इसे bug माना जाए, तो यह setup attacker code के माध्यम से XPC service को initiate करने की अनुमति नहीं देता।
- **Active Service से Connect करना**: यदि XPC service पहले से running है (संभवतः उसकी original application द्वारा activated), तो उससे connect करने में कोई बाधा नहीं है।

हालाँकि XPC service पर constraints लागू करना **potential attacks के लिए window को narrow करके** beneficial हो सकता है, लेकिन यह primary concern को address नहीं करता। XPC service की security सुनिश्चित करने के लिए मूल रूप से **connecting client को effectively validate करना** आवश्यक है। Service की security को मजबूत करने का यही एकमात्र तरीका है। यह भी ध्यान देने योग्य है कि उल्लिखित responsibility configuration वर्तमान में operational है, जो intended design के अनुरूप नहीं हो सकता।<sup>[[3]](#references)</sup>

### Electron Protection

भले ही यह required हो कि application को **LaunchService द्वारा opened किया जाना चाहिए** (parents constraints में)। इसे **`open`** का उपयोग करके (जो env variables set कर सकता है) या **Launch Services API** का उपयोग करके (जहाँ env variables indicate किए जा सकते हैं) achieve किया जा सकता है।<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Overriding the built-in constraints at spawn time

Launch constraints (officially **lightweight code requirements**, *LWCR*) को **AMFI MAC policy** द्वारा enforce किया जाता है। `posix_spawn` caller को **`posix_spawnattr_setmacpolicyinfo_np()`** के माध्यम से किसी MAC policy को arbitrary blob देने देता है, और AMFI इस path के माध्यम से caller-supplied LWCR dictionary accept करता था। Bug यह था कि **attacker-supplied constraints binary की built-in constraints को replace कर देती थीं**, बजाय इसके कि उन्हें built-in constraints के अतिरिक्त check किया जाता:

- एक minimal (यहाँ तक कि empty) launch-constraints dictionary बनाएँ।
- **constraint category को `127` पर set करें**, यह ऐसी value है जिसे AMFI spawn attributes में allow करता है, लेकिन **enforce नहीं करता** — execution को block करने के बजाय केवल `Launch Constraint Violation (not enforcing)` log करता है।
- इसे spawn attributes के माध्यम से pass करें, और process ऐसे context में launch हो जाता है जिसे उसकी वास्तविक self/parent constraints ने forbid किया होता।

Fix के बाद, **built-in और supplied दोनों constraints validate की जाती हैं**, इसलिए supplied dictionary अब built-in constraint को weaken नहीं कर सकती।<sup>[[2]](#references)</sup>

> [!TIP]
> Constraint enforcement को audit करते समय यह general shape देखें: ऐसा API जो untrusted input को policy *supply* करने देता है, तब interesting होता है जब policy engine supplied value को additional requirement के बजाय replacement के रूप में treat करता है।

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
