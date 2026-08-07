# macOS Kernel Extensions और Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) **`.kext`** extension वाले **packages** होते हैं, जिन्हें **सीधे macOS kernel space में load** किया जाता है और जो main operating system को अतिरिक्त functionality प्रदान करते हैं।

### Deprecation status और DriverKit / System Extensions
**macOS Catalina (10.15)** से Apple ने अधिकांश legacy KPIs को *deprecated* कर दिया और **System Extensions और DriverKit** frameworks पेश किए, जो **user-space** में run होते हैं। **macOS Big Sur (11)** से operating system उन third-party kexts को *load करने से मना कर देगा* जो deprecated KPIs पर निर्भर हैं, जब तक कि machine को **Reduced Security** mode में boot न किया गया हो। Apple Silicon पर kexts enable करने के लिए user को अतिरिक्त रूप से:

1. **Recovery** में reboot करके → *Startup Security Utility* खोलना होगा।
2. **Reduced Security** select करके **“Allow user management of kernel extensions from identified developers”** को tick करना होगा।
3. Reboot करके **System Settings → Privacy & Security** से kext को approve करना होगा।

DriverKit/System Extensions से लिखे गए User-land drivers attack surface को काफी **कम करते हैं**, क्योंकि crashes या memory corruption kernel space के बजाय sandboxed process तक सीमित रहते हैं।<sup>[[1]](#references)</sup>

> 📝 macOS Sequoia (15) से Apple ने कई legacy networking और USB KPIs को पूरी तरह हटा दिया है – vendors के लिए एकमात्र forward-compatible solution System Extensions पर migrate करना है।

### Requirements

जाहिर है, यह इतना powerful है कि **kernel extension को load करना complicated** है। Kernel extension को load करने के लिए उसे इन **requirements** को पूरा करना होगा:

- **Recovery mode में प्रवेश करते समय**, kernel **extensions को load होने की अनुमति** होनी चाहिए:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension को **kernel code signing certificate से signed** होना चाहिए, जिसे केवल **Apple grant** कर सकता है। Apple company और इसकी आवश्यकता के कारणों की detail में review करेगा।
- Kernel extension का **notarized** होना भी आवश्यक है; Apple इसे malware के लिए check कर सकेगा।
- इसके बाद, केवल **root** user ही **kernel extension को load** कर सकता है और package के अंदर की files का **root के स्वामित्व में होना** आवश्यक है।
- Upload process के दौरान package को एक **protected non-root location** में तैयार किया जाना चाहिए: `/Library/StagedExtensions` (इसके लिए `com.apple.rootless.storage.KernelExtensionManagement` grant आवश्यक है)।
- अंत में, इसे load करने का प्रयास करते समय user को [**confirmation request प्राप्त होगी**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) और, यदि इसे accept किया जाता है, तो इसे load करने के लिए computer को **restart** करना होगा।

### Loading process

Catalina में यह इस तरह होता था: यह ध्यान देना interesting है कि **verification** process **userland** में होता है। हालांकि, केवल वे applications जिनके पास **`com.apple.private.security.kext-management`** grant है, **kernel से extension load करने का request** कर सकती हैं: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli extension load करने के लिए **verification** process **start** करता है।
- यह **Mach service** का उपयोग करके message भेजते हुए **`kextd`** से communicate करेगा।
2. **`kextd`** कई चीजों को check करेगा, जैसे कि **signature**।
- यह **`syspolicyd`** से यह **check** करने के लिए communicate करेगा कि extension को **load** किया जा सकता है या नहीं।
3. यदि extension पहले load नहीं किया गया है, तो **`syspolicyd`** **user को prompt** करेगा।
- **`syspolicyd`**, result को **`kextd`** को report करेगा।
4. अंत में **`kextd`**, extension को **load करने के लिए kernel को बताने** में सक्षम होगा।

यदि **`kextd`** उपलब्ध नहीं है, तो **`kextutil`** समान checks perform कर सकता है।

### Enumeration और management (loaded kexts)

`kextstat` historical tool था, लेकिन recent macOS releases में यह **deprecated** है। Modern interface **`kmutil`** है:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
पुराना syntax अभी भी संदर्भ के लिए उपलब्ध है:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` का उपयोग **Kernel Collection (KC) की सामग्री dump करने** या यह सत्यापित करने के लिए भी किया जा सकता है कि कोई kext सभी symbol dependencies को resolve करता है:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> हालांकि kernel extensions के `/System/Library/Extensions/` में होने की अपेक्षा की जाती है, यदि आप इस folder में जाएंगे तो आपको **कोई binary नहीं मिलेगी**। ऐसा **kernelcache** के कारण है और किसी `.kext` को reverse करने के लिए आपको इसे प्राप्त करने का तरीका ढूंढना होगा।

**kernelcache**, **XNU kernel** का एक **pre-compiled और pre-linked version** है, जिसमें आवश्यक device **drivers** और **kernel extensions** शामिल होते हैं। इसे **compressed** format में store किया जाता है और boot-up process के दौरान memory में decompress किया जाता है। kernelcache, kernel और महत्वपूर्ण drivers का ready-to-run version उपलब्ध कराकर **तेज boot time** संभव बनाता है। इससे वह time और resources बचते हैं जो boot time पर इन components को dynamically load और link करने में लगते।

kernelcache के मुख्य लाभ **loading speed** हैं और यह कि सभी modules prelinked होते हैं (इसलिए load time impediment नहीं होता)। इसके अलावा, जब सभी modules prelinked हो जाते हैं, तो KXLD को memory से हटाया जा सकता है, इसलिए **XNU नए KEXTs load नहीं कर सकता।**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool Apple के AEA (Apple Encrypted Archive / AEA asset) containers को decrypt करता है — यह encrypted container format है जिसका उपयोग Apple OTA assets और कुछ IPSW pieces के लिए करता है — और underlying .dmg/asset archive तैयार कर सकता है, जिसे आप दिए गए aastuff tools से extract कर सकते हैं।


### Local Kernelcache

iOS में यह **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** में स्थित होता है। macOS में आप इसे इस command से ढूंढ सकते हैं: **`find / -name "kernelcache" 2>/dev/null`** \
मेरे मामले में macOS में यह यहां मिला:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

यहां [**version 14 का symbols वाला kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en) भी खोजें।

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format, Apple द्वारा अपने iOS और macOS devices में **firmware** components (जैसे **kernelcache**) को securely **store और verify** करने के लिए उपयोग किया जाने वाला container format है। IMG4 format में एक header और कई tags शामिल होते हैं, जो data के विभिन्न हिस्सों को encapsulate करते हैं। इनमें actual payload (जैसे kernel या bootloader), एक signature और manifest properties का एक set शामिल होता है। यह format cryptographic verification को support करता है, जिससे device firmware component को execute करने से पहले उसकी authenticity और integrity की पुष्टि कर सकता है।

यह आमतौर पर निम्नलिखित components से बना होता है:

- **Payload (IM4P)**:
- अक्सर compressed (LZFSE4, LZSS, …)
- Optional रूप से encrypted
- **Manifest (IM4M)**:
- Signature शामिल होती है
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- इसे APNonce के नाम से भी जाना जाता है
- कुछ updates को replay करने से रोकता है
- OPTIONAL: आमतौर पर यह नहीं मिलता

Kernelcache को Decompress करें:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### kernel के लिए Disarm symbols

**`Disarm`** matchers का उपयोग करके kernelcache से functions को symbolicate करने की अनुमति देता है। ये matchers केवल सरल pattern rules (text lines) हैं, जो disarm को binary के अंदर functions, arguments और panic/log strings को पहचानने और auto-symbolicate करने का तरीका बताते हैं।

इसलिए, आप मूल रूप से उस string को निर्दिष्ट करते हैं जिसका उपयोग कोई function कर रहा है और disarm उसे ढूंढकर **symbolicate** कर देगा।

आप कुछ `xnu.matchers` [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) के **`Matchers`** section में पा सकते हैं। आप अपने स्वयं के matchers भी बना सकते हैं।
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Download

एक **IPSW (iPhone/iPad Software)** Apple का firmware package format है, जिसका उपयोग device restores, updates और full firmware bundles के लिए किया जाता है। अन्य चीज़ों के अलावा, इसमें **kernelcache** शामिल होता है।

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) में सभी kernel debug kits मिल सकते हैं। आप इसे download करके mount कर सकते हैं, [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool से open कर सकते हैं, **`.kext`** folder तक पहुंच सकते हैं और इसे **extract** कर सकते हैं।

इसे symbols के लिए जांचें:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

कभी-कभी Apple **symbols** के साथ **kernelcache** जारी करता है। आप उन पेजों पर दिए गए links का अनुसरण करके **symbols** वाले कुछ firmwares download कर सकते हैं। इन firmwares में अन्य files के साथ **kernelcache** भी शामिल होगा।

**kernel cache** को **extract** करने के लिए आप यह कर सकते हैं:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
**files extract** करने का एक और विकल्प `.ipsw` extension को `.zip` में बदलकर उसे **unzip** करना है।

Firmware को extract करने के बाद आपको इस तरह की file मिलेगी: **`kernelcache.release.iphone14`**। यह **IMG4** format में है, आप इससे interesting info निकालने के लिए उपयोग कर सकते हैं:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### kernelcache का निरीक्षण

जांचें कि kernelcache में symbols हैं या नहीं, इसके साथ
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
इसके साथ अब हम **सभी extensions** या **जिसमें आपकी रुचि है उसे** **extract** कर सकते हैं:
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## हाल की vulnerabilities और exploitation techniques

| वर्ष | CVE | सारांश |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`** में मौजूद logic flaw ने *root* attacker को एक malicious file-system bundle register करने की अनुमति दी, जिसने अंततः एक **unsigned kext** लोड किया, **System Integrity Protection (SIP)** को **bypass** किया और persistent rootkits सक्षम किए। macOS 14.2 / 15.2 में patch किया गया। <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` entitlement वाले installation daemon का दुरुपयोग arbitrary post-install scripts execute करने, SIP disable करने और arbitrary kexts लोड करने के लिए किया जा सकता था। <sup>[[3]](#references)</sup> |

**red-teamers के लिए मुख्य निष्कर्ष**

1. **ऐसे entitled daemons (`codesign -dvv /path/bin | grep entitlements`) खोजें जो Disk Arbitration, Installer या Kext Management के साथ interact करते हों।**
2. **SIP bypasses का दुरुपयोग लगभग हमेशा kext लोड करने की क्षमता देता है → kernel code execution**।

**रक्षात्मक सुझाव**

*SIP enabled रखें*, non-Apple binaries से आने वाले `kmutil load`/`kmutil create -n aux` invocations को monitor करें और `/Library/Extensions` में होने वाले किसी भी write पर alert करें। Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` लगभग real-time visibility प्रदान करते हैं।

## macOS kernel और kexts की debugging

Apple का recommended workflow एक **Kernel Debug Kit (KDK)** बनाना है जो running build से match करता हो और फिर **KDP (Kernel Debugging Protocol)** network session के माध्यम से **LLDB** attach करना है।

### panic की one-shot local debugging
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### दूसरे Mac से Live remote debugging

1. Target machine के लिए exact **KDK** version download + install करें।
2. Target Mac और host Mac को **USB-C या Thunderbolt cable** से connect करें।
3. **Target** पर:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. **host** पर:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### किसी विशिष्ट loaded kext से LLDB attach करना
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP केवल **read-only** interface उपलब्ध कराता है। Dynamic instrumentation के लिए आपको binary को on-disk patch करना होगा, **kernel function hooking** (जैसे `mach_override`) का उपयोग करना होगा या पूर्ण read/write के लिए driver को **hypervisor** में migrate करना होगा।

## संदर्भ

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
