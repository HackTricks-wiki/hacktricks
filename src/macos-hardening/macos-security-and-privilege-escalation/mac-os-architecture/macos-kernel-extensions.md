# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## मूल जानकारी

Kernel extensions (Kexts) **packages** होते हैं जिनकी एक्सटेंशन **`.kext`** होती है और ये **macOS kernel space में सीधे लोड** की जाती हैं, जिससे main operating system को अतिरिक्त फ़ंक्शनैलिटी मिलती है।

### डिप्रेकेशन स्थिति & DriverKit / System Extensions
macOS Catalina (10.15) से शुरू होकर Apple ने अधिकांश legacy KPIs को *deprecated* के रूप में चिह्नित किया और ऐसे **System Extensions & DriverKit** फ्रेमवर्क पेश किए जो **user-space** में चलते हैं। macOS Big Sur (11) से ऑपरेटिंग सिस्टम उन third-party kexts को *लोड़ करने से इनकार* कर देगा जो deprecated KPIs पर निर्भर करते हैं, जब तक कि मशीन **Reduced Security** मोड में बूट न हो। Apple Silicon पर, kexts को सक्षम करने के लिए उपयोगकर्ता को अतिरिक्त रूप से निम्न करना होगा:

1. **Recovery** में रीबूट करें → *Startup Security Utility*।
2. **Reduced Security** चुनें और **“Allow user management of kernel extensions from identified developers”** को टिक करें।
3. रीबूट करें और kext को **System Settings → Privacy & Security** से मंजूरी दें।

DriverKit/System Extensions के साथ लिखे गए user‑land drivers हमला सतह को नाटकीय रूप से **reduce attack surface** करते हैं क्योंकि crashes या memory corruption एक sandboxed process तक सीमित रहते हैं न कि kernel space तक।

> 📝 macOS Sequoia (15) से Apple ने कई legacy networking और USB KPIs को पूरी तरह हटा दिया है – vendors के लिए आगे‑संगत समाधान सिर्फ System Extensions में माइग्रेट करना ही है।

### आवश्यकताएँ

स्पष्ट रूप से, यह इतनी शक्तिशाली चीज़ है कि kernel extension को लोड करना **जटिल** है। एक kernel extension को लोड करने के लिए निम्न **शर्तें** पूरी करनी होती हैं:

- जब **recovery mode में प्रवेश** किया जाता है, तो kernel **extensions को लोड करने की अनुमति** होनी चाहिए:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension को **kernel code signing certificate** से साइन किया होना चाहिए, जो केवल **Apple** द्वारा ही जारी किया जा सकता है। Apple कंपनी और आवश्यकता के कारणों की विस्तृत समीक्षा करेगा।
- kernel extension को **notarized** भी होना चाहिए, ताकि Apple उसमें मैलवेयर के लिए जाँच कर सके।
- फिर, केवल **root** उपयोगकर्ता kernel extension को **लोड** कर सकता है और package के अंदर की फाइलें **root** की ही होनी चाहिए।
- अपलोड प्रोसेस के दौरान, package को एक **protected non-root location** में तैयार किया जाना चाहिए: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant)।
- अंत में, जब इसे लोड करने का प्रयास किया जाता है, तो उपयोगकर्ता [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) करेगा और, यदि स्वीकार किया गया, तो इसे लोड करने के लिए कंप्यूटर को **restarted** करना होगा।

### लोडिंग प्रक्रिया

Catalina में यह इस तरह था: यह दिलचस्प है कि **verification** प्रक्रिया **userland** में होती है। हालांकि, केवल उन applications के पास जो **`com.apple.private.security.kext-management`** grant रखते हैं, kernel को extension लोड करने का अनुरोध करने का अधिकार होता है: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli एक्स्टेंशन लोड करने के लिए **verification** प्रक्रिया **शुरू** करता है
- यह **`kextd`** से एक **Mach service** का उपयोग करके बात करेगा।
2. **`kextd`** कई चीज़ों की जाँच करेगा, जैसे कि **signature**
- यह यह जाँचने के लिए **`syspolicyd`** से बात करेगा कि extension को **लोड** किया जा सकता है या नहीं।
3. यदि extension पहले से लोड नहीं किया गया है तो **`syspolicyd`** उपयोगकर्ता को **prompt** करेगा।
- **`syspolicyd`** परिणाम को **`kextd`** को रिपोर्ट करेगा
4. अंततः **`kextd`** kernel को extension **लोड करने के लिए कह** पाएगा

यदि **`kextd`** उपलब्ध नहीं है, तो **`kextutil`** वही जाँचें कर सकता है।

### Enumeration & management (loaded kexts)

`kextstat` ऐतिहासिक टूल था लेकिन हाल के macOS रिलीज़ में यह **deprecated** है। आधुनिक इंटरफ़ेस **`kmutil`** है:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
पुराना सिंटैक्स संदर्भ के लिए अभी भी उपलब्ध है:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` का उपयोग **dump the contents of a Kernel Collection (KC)** करने के लिए भी किया जा सकता है या यह सत्यापित करने के लिए कि एक kext सभी symbol dependencies को resolve करता है:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> भले ही kernel extensions अपेक्षित हैं `/System/Library/Extensions/` में, अगर आप इस फ़ोल्डर में जाएँ तो आप **कोई binary नहीं पाएँगे**। इसका कारण **kernelcache** है और किसी `.kext` को reverse करने के लिए आपको इसे प्राप्त करने का तरीका ढूंढना होगा।

The **kernelcache** एक **pre-compiled और pre-linked version of the XNU kernel** है, साथ ही ज़रूरी device **drivers** और **kernel extensions** के साथ। यह एक **compressed** फ़ॉर्मेट में स्टोर होता है और boot-up प्रक्रिया के दौरान memory में decompress हो जाता है। kernelcache एक **तेज़ boot time** सुनिश्चित करता है क्योंकि kernel और आवश्यक drivers का एक ready-to-run संस्करण उपलब्ध रहता है, जिससे उन components को boot के समय dynamically लोड और लिंक करने में लगने वाला समय और संसाधन कम हो जाते हैं।

kernelcache के मुख्य फायदे हैं **लोडिंग की गति** और यह कि सभी modules prelinked होते हैं (कोई load time बाधा नहीं)। और जब सभी modules prelinked हो जाते हैं तो KXLD को memory से हटाया जा सकता है ताकि **XNU नए KEXTs लोड न कर सके।**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool Apple की AEA (Apple Encrypted Archive / AEA asset) containers को decrypt करता है — वह encrypted container format जो Apple OTA assets और कुछ IPSW हिस्सों के लिए उपयोग करता है — और यह underlying .dmg/asset archive बना सकता है जिसे आप फिर provided aastuff tools से extract कर सकते हैं।


### स्थानीय Kerlnelcache

iOS में यह स्थित है **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** macOS में आप इसे पा सकते हैं: **`find / -name "kernelcache" 2>/dev/null`** \
मेरे मामले में macOS में मुझे यह मिला:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

यहाँ भी देखें [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 फ़ाइल फॉर्मेट एक container format है जो Apple अपने iOS और macOS devices में सुरक्षित रूप से **firmware components को स्टोर और verify करने** के लिए उपयोग करता है (जैसे **kernelcache**)। IMG4 format में एक header और कई tags होते हैं जो अलग-अलग डेटा के हिस्सों को encapsulate करते हैं, जिनमें वास्तविक payload (जैसे kernel या bootloader), एक signature, और manifest properties का एक सेट शामिल होता है। यह फॉर्मेट cryptographic verification का समर्थन करता है, जिससे device यह पुष्टि कर सकता है कि firmware component वास्तविक और अखंड है इससे पहले कि उसे execute किया जाए।

यह आम तौर पर निम्नलिखित components से बना होता है:

- **Payload (IM4P)**:
- अक्सर compressed (LZFSE4, LZSS, …)
- वैकल्पिक रूप से encrypted
- **Manifest (IM4M)**:
- Signature शामिल करता है
- अतिरिक्त Key/Value dictionary
- **Restore Info (IM4R)**:
- जिसे APNonce भी कहा जाता है
- कुछ updates के replay को रोकता है
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

**`Disarm`** matchers का उपयोग करके kernelcache से functions को symbolicate करने की अनुमति देता है।

ये matchers केवल सरल pattern rules (text lines) हैं जो disarm को बताते हैं कि binary के अंदर functions, arguments और panic/log strings को कैसे recognise और auto-symbolicate किया जाए।
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# /tmp/extracted पर जाएं जहाँ disarm ने filesets निकाले थे
disarm -e filesets kernelcache.release.d23 # हमेशा /tmp/extracted में निकालें
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # ध्यान दें कि xnu.matchers वास्तव में matchers वाली फ़ाइल है
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
# ipsw tool इंस्टॉल करें
brew install blacktop/tap/ipsw

# केवल IPSW से kernelcache निकालें
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# आपको कुछ ऐसा मिलेगा:
#   out/Firmware/kernelcache.release.iPhoneXX
#   या एक IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# अगर आपको IMG4 payload मिलता है:
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
# सभी एक्सटेंशन सूचीबद्ध करें
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox निकालें
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# सभी निकालें
kextex_all kernelcache.release.iphone14.e

# एक्सटेंशन में प्रतीकों के लिए जाँच करें
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
# नवीनतम पैनिक के लिए symbolication बंडल बनाएं
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
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
(lldb) bt  # get backtrace in kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# kext का लोड पता पहचानें
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# जुड़ें
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
