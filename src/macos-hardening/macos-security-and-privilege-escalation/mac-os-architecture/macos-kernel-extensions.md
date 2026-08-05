# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) **`.kext`** extension वाले **packages** होते हैं, जिन्हें **सीधे macOS kernel space में load** किया जाता है और ये मुख्य operating system को अतिरिक्त functionality प्रदान करते हैं।

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)** से Apple ने अधिकांश legacy KPIs को *deprecated* चिह्नित किया और **System Extensions & DriverKit** frameworks पेश किए, जो **user-space** में run होते हैं। **macOS Big Sur (11)** से operating system उन third-party kexts को *load करने से मना कर देगा* जो deprecated KPIs पर निर्भर हैं, जब तक कि machine को **Reduced Security** mode में boot न किया गया हो। Apple Silicon पर kexts enable करने के लिए user को अतिरिक्त रूप से:

1. **Recovery** में reboot करें → *Startup Security Utility*।
2. **Reduced Security** चुनें और **“Allow user management of kernel extensions from identified developers”** को tick करें।
3. Reboot करें और **System Settings → Privacy & Security** से kext को approve करें।

DriverKit/System Extensions के साथ लिखे गए User-land drivers attack surface को काफी **कम करते हैं**, क्योंकि crashes या memory corruption kernel space के बजाय sandboxed process तक सीमित रहते हैं।<sup>[[1]](#references)</sup>

> 📝 macOS Sequoia (15) से Apple ने कई legacy networking और USB KPIs को पूरी तरह हटा दिया है – vendors के लिए एकमात्र forward-compatible solution System Extensions पर migrate करना है।

### Requirements

जाहिर है, यह इतना powerful है कि **kernel extension को load करना complicated** है। Kernel extension को load किए जाने के लिए इन **requirements** को पूरा करना आवश्यक है:

- **Recovery mode में प्रवेश करते समय**, kernel **extensions को load करने की अनुमति** होनी चाहिए:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension को **kernel code signing certificate से signed** होना चाहिए, जिसे केवल **Apple grant** कर सकता है। Apple company और इसकी आवश्यकता के कारणों की विस्तृत समीक्षा करेगा।
- Kernel extension का **notarized** होना भी आवश्यक है; Apple इसे malware के लिए check कर सकेगा।
- इसके बाद, केवल **root** user ही **kernel extension को load** कर सकता है और package के अंदर की files का **root के ownership में होना** आवश्यक है।
- Upload process के दौरान package को एक **protected non-root location** में तैयार किया जाना चाहिए: `/Library/StagedExtensions` (इसके लिए `com.apple.rootless.storage.KernelExtensionManagement` grant आवश्यक है)।
- अंत में, इसे load करने का प्रयास करते समय user को [**confirmation request प्राप्त होगी**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) और, यदि इसे accept किया जाता है, तो इसे load करने के लिए computer को **restart** करना होगा।

### Loading process

Catalina में प्रक्रिया इस तरह थी: यह ध्यान देने योग्य है कि **verification** process **userland** में होता है। हालांकि, केवल वे applications जिनके पास **`com.apple.private.security.kext-management`** grant है, **kernel से extension load करने का अनुरोध** कर सकते हैं: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli extension को load करने के लिए **verification** process **start** करता है।
- यह **Mach service** का उपयोग करके message भेजकर **`kextd`** से communicate करेगा।
2. **`kextd`** कई चीजों को check करेगा, जैसे **signature**।
- यह यह **check** करने के लिए **`syspolicyd`** से communicate करेगा कि extension को **load** किया जा सकता है या नहीं।
3. यदि extension को पहले load नहीं किया गया है, तो **`syspolicyd`** **user को prompt** करेगा।
- **`syspolicyd`** result को **`kextd`** को report करेगा।
4. अंततः **`kextd`**, extension को **load करने के लिए kernel को बताने** में सक्षम होगा।

यदि **`kextd`** उपलब्ध नहीं है, तो **`kextutil`** वही checks perform कर सकता है।

### Enumeration & management (loaded kexts)

`kextstat` historical tool था, लेकिन हाल के macOS releases में यह **deprecated** है। Modern interface **`kmutil`** है:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
पुराना syntax अभी भी reference के लिए उपलब्ध है:
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
> भले ही kernel extensions के `/System/Library/Extensions/` में होने की उम्मीद की जाती है, लेकिन यदि आप इस folder में जाएंगे तो आपको **कोई binary नहीं मिलेगी**। ऐसा **kernelcache** के कारण है और किसी `.kext` को reverse करने के लिए आपको इसे प्राप्त करने का तरीका ढूंढना होगा।

**kernelcache**, **XNU kernel** का एक **pre-compiled और pre-linked version** है, जिसमें आवश्यक device **drivers** और **kernel extensions** शामिल होते हैं। इसे **compressed** format में store किया जाता है और boot-up process के दौरान memory में decompress किया जाता है। kernelcache, kernel और महत्वपूर्ण drivers का ready-to-run version उपलब्ध कराकर **तेज boot time** संभव बनाता है। इससे boot के समय इन components को dynamically load और link करने में लगने वाला समय और resources कम हो जाते हैं।

kernelcache के मुख्य लाभ **loading speed** हैं और यह कि सभी modules prelinked होते हैं (load time में कोई बाधा नहीं होती)। इसके अलावा, जब सभी modules prelinked हो जाते हैं, तो KXLD को memory से remove किया जा सकता है, इसलिए **XNU नए KEXTs load नहीं कर सकता।**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool Apple के AEA (Apple Encrypted Archive / AEA asset) containers को decrypt करता है — यह encrypted container format है, जिसका उपयोग Apple OTA assets और कुछ IPSW pieces के लिए करता है — और underlying .dmg/asset archive बना सकता है, जिसे आप दिए गए aastuff tools से extract कर सकते हैं।

### Local Kerlnelcache

iOS में यह **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** में स्थित होता है। macOS में आप इसे इस command से खोज सकते हैं: **`find / -name "kernelcache" 2>/dev/null`** \
मेरे मामले में macOS में यह यहां मिला:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

यहां [**symbols वाले version 14 का kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en) भी खोजें।

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format एक container format है, जिसका उपयोग Apple अपने iOS और macOS devices में **firmware** components (जैसे **kernelcache**) को सुरक्षित रूप से **store और verify करने** के लिए करता है। IMG4 format में एक header और कई tags शामिल होते हैं, जो data के अलग-अलग हिस्सों को encapsulate करते हैं। इनमें actual payload (जैसे kernel या bootloader), एक signature और manifest properties का एक set शामिल होता है। यह format cryptographic verification को support करता है, जिससे device firmware component को execute करने से पहले उसकी authenticity और integrity की पुष्टि कर सकता है।

यह आमतौर पर निम्नलिखित components से बना होता है:

- **Payload (IM4P)**:
- अक्सर compressed (LZFSE4, LZSS, …)
- वैकल्पिक रूप से encrypted
- **Manifest (IM4M)**:
- Signature शामिल होती है
- अतिरिक्त Key/Value dictionary
- **Restore Info (IM4R)**:
- APNonce के नाम से भी जाना जाता है
- कुछ updates को replay करने से रोकता है
- OPTIONAL: आमतौर पर यह नहीं मिलता

Kernelcache को decompress करें:
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

**`Disarm`** matchers का उपयोग करके kernelcache से functions को symbolicate करने की अनुमति देता है। ये matchers केवल simple pattern rules (text lines) हैं, जो disarm को binary के अंदर functions, arguments और panic/log strings को पहचानने और auto-symbolicate करने का तरीका बताते हैं।

इसलिए मूल रूप से आप वह string बताते हैं जिसका उपयोग कोई function कर रहा है, और disarm उसे ढूँढकर **symbolicate** कर देगा।
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# /tmp/extracted पर जाएँ जहाँ disarm ने filesets को extract किया है
disarm -e filesets kernelcache.release.d23 # हमेशा /tmp/extracted में extract करें
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # ध्यान दें कि xnu.matchers वास्तव में matchers वाली एक file है
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# ipsw tool install करें
brew install blacktop/tap/ipsw

# IPSW से केवल kernelcache extract करें
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# आपको कुछ ऐसा मिलना चाहिए:
#   out/Firmware/kernelcache.release.iPhoneXX
#   या एक IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# यदि आपको IMG4 payload मिलता है:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

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

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# सभी extensions की सूची बनाएं
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox extract करें
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# सभी extract करें
kextex_all kernelcache.release.iphone14.e

# symbols के लिए extension जांचें
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# नवीनतम panic के लिए symbolication bundle बनाएं
```bash
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # kernel context में backtrace प्राप्त करें
```

### Attaching LLDB to a specific loaded kext

```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
