# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

Kernel extensions (Kexts) वे पैकेज हैं जिनका एक्सटेंशन **`.kext`** होता है और जिन्हें **macOS kernel space** में सीधे लोड किया जाता है, जो मुख्य ऑपरेटिंग सिस्टम को अतिरिक्त कार्यक्षमता प्रदान करते हैं।

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)** से Apple ने अधिकांश legacy KPIs को *deprecated* घोषित किया और ऐसे **System Extensions & DriverKit** फ्रेमवर्क पेश किए जो **user-space** में चलते हैं। **macOS Big Sur (11)** से ऑपरेटिंग सिस्टम उन थर्ड-पार्टी kexts को *लोड करने से इनकार* करेगा जो deprecated KPIs पर निर्भर करते हैं, जब तक मशीन **Reduced Security** मोड में बूट न हो। Apple Silicon पर kexts सक्षम करने के लिए उपयोगकर्ता को अतिरिक्त रूप से यह करना होगा:

1. Reboot into **Recovery** → *Startup Security Utility*।
2. Select **Reduced Security** और **“Allow user management of kernel extensions from identified developers”** को टिक करें।
3. Reboot करें और kext को **System Settings → Privacy & Security** से अनुमोदित करें।

DriverKit/System Extensions से लिखे गए user-land drivers हमला सतह को नाटकीय रूप से **reduce attack surface** करते हैं क्योंकि crashes या memory corruption kernel space के बजाय एक sandboxed process तक सीमित रहते हैं।

> 📝 macOS Sequoia (15) से Apple ने कई legacy networking और USB KPIs को पूरी तरह से हटा दिया है – vendors के लिए एकमात्र forward-compatible समाधान है कि वे System Extensions पर माइग्रेट करें।

### आवश्यकताएँ

स्पष्ट है कि यह इतना शक्तिशाली है कि किसी kernel extension को **लोड करना जटिल** होता है। किसी kernel extension को लोड करने के लिए जो **requirements** होने चाहिए वे निम्न हैं:

- जब **Recovery mode** में प्रवेश किया जाता है, तो kernel **extensions को लोड करने की अनुमति** होनी चाहिए:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension को **kernel code signing certificate** के साथ साइन किया जाना चाहिए, जिसे केवल **Apple** द्वारा प्रदान किया जा सकता है। Apple कंपनी और इसके उपयोग के कारणों की विस्तार से समीक्षा करेगा।
- kernel extension को **notarized** भी होना चाहिए, ताकि Apple इसे मैलवेयर के लिए जांच सके।
- इसके बाद, **root** उपयोगकर्ता ही वह होता है जो **kernel extension को लोड** कर सकता है और पैकेज के अंदर की फाइलें **root की ملکियत** होनी चाहिए।
- अपलोड प्रक्रिया के दौरान, पैकेज को एक **protected non-root location** में तैयार किया जाना चाहिए: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant)।
- अंत में, जब इसे लोड करने का प्रयास किया जाता है, तो उपयोगकर्ता [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) करेगा और यदि स्वीकार कर लिया गया, तो कंप्यूटर को इसे लोड करने के लिए **restarted** करना होगा।

### लोडिंग प्रक्रिया

Catalina में यह इस तरह था: यह ध्यान देने योग्य है कि **verification** प्रक्रिया **userland** में होती है। हालांकि, केवल उन अनुप्रयोगों के पास जो **`com.apple.private.security.kext-management`** grant रखते हैं, वे ही **request the kernel to load an extension** कर सकते हैं: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI किसी extension को लोड करने के लिए **verification** प्रक्रिया **शुरू** करता है
- यह एक **Mach service** का उपयोग करके **`kextd`** से बात करेगा।
2. **`kextd`** कई चीज़ों की जाँच करेगा, जैसे कि **signature**
- यह यह जाँचने के लिए **`syspolicyd`** से बात करेगा कि extension **लोड** की जा सकती है या नहीं।
3. अगर extension पहले लोड नहीं हुई है तो **`syspolicyd`** उपयोगकर्ता को **prompt** करेगा।
- **`syspolicyd`** परिणाम की रिपोर्ट **`kextd`** को करेगा
4. अंत में **`kextd`** kernel को extension को **लोड करने के लिए कह** सकेगा

यदि **`kextd`** उपलब्ध नहीं है, तो **`kextutil`** वही चेक्स कर सकता है।

### अनुक्रमण और प्रबंधन (लोड किए गए kexts)

`kextstat` ऐतिहासिक उपकरण था लेकिन हालिया macOS रिलीज़ में यह **deprecated** है। आधुनिक इंटरफ़ेस **`kmutil`** है:
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
`kmutil inspect` का उपयोग भी **dump the contents of a Kernel Collection (KC)** करने या यह सत्यापित करने के लिए किया जा सकता है कि एक kext सभी symbol dependencies को resolve करता है:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Even though the kernel extensions are expected to be in `/System/Library/Extensions/`, if you go to this folder you **won't find any binary**. This is because of the **kernelcache** and in order to reverse one `.kext` you need to find a way to obtain it.

The **kernelcache** is a **pre-compiled and pre-linked version of the XNU kernel**, along with essential device **drivers** and **kernel extensions**. It's stored in a **compressed** format and gets decompressed into memory during the boot-up process. The kernelcache facilitates a **faster boot time** by having a ready-to-run version of the kernel and crucial drivers available, reducing the time and resources that would otherwise be spent on dynamically loading and linking these components at boot time.

The main benefits of the kernelcache is **speed of loading** and that all modules are prelinked (no load time impediment). And that once all modules have been prelinked- KXLD can be removed from memory so **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.


### Local Kerlnelcache

In iOS it's located in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS you can find it with: **`find / -name "kernelcache" 2>/dev/null`** \
In my case in macOS I found it in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

The IMG4 file format is a container format used by Apple in its iOS and macOS devices for securely **storing and verifying firmware** components (like **kernelcache**). The IMG4 format includes a header and several tags which encapsulate different pieces of data including the actual payload (like a kernel or bootloader), a signature, and a set of manifest properties. The format supports cryptographic verification, allowing the device to confirm the authenticity and integrity of the firmware component before executing it.

It's usually composed of the following components:

- **Payload (IM4P)**:
- Often compressed (LZFSE4, LZSS, …)
- Optionally encrypted
- **Manifest (IM4M)**:
- Contains Signature
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- Also known as APNonce
- Prevents replaying of some updates
- OPTIONAL: Usually this isn't found

Decompress the Kernelcache:
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
#### Disarm symbols for the kernel

**`Disarm`** matchers का उपयोग करके kernelcache से functions को symbolicate करने की अनुमति देता है. ये matchers सिर्फ सरल pattern नियम (text lines) हैं जो disarm को बताते हैं कि वह किसी binary के अंदर functions, arguments और panic/log strings को कैसे पहचान कर auto-symbolicate करे.

तो मूलतः आप उस string को दर्शाते हैं जो किसी function द्वारा उपयोग किया जा रहा है और disarm उसे ढूंढकर और **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# /tmp/extracted पर जाएँ जहाँ disarm ने filesets निकाले
disarm -e filesets kernelcache.release.d23 # हमेशा /tmp/extracted में निकालें
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # ध्यान दें कि xnu.matchers वास्तव में matchers वाली एक फ़ाइल है
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
# ipsw tool स्थापित करें
brew install blacktop/tap/ipsw

# केवल IPSW से kernelcache निकालें
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# आपको कुछ ऐसा मिलेगा:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

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
# सभी एक्सटेंशन सूचीबद्ध करें
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox निकालें
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# सभी निकालें
kextex_all kernelcache.release.iphone14.e

# एक्सटेंशन में symbols की जांच करें
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

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
