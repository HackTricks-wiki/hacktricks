# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Kernel extensions (Kexts) ni **packages** zenye extension ya **`.kext`** ambazo **hupakiwa moja kwa moja kwenye nafasi ya kernel ya macOS**, zikitoa utendaji wa ziada kwa mfumo mkuu wa uendeshaji.

### Hali ya kuondolewa & DriverKit / System Extensions
Kuanzia **macOS Catalina (10.15)** Apple iliweka alama kwa KPIs nyingi za zamani kuwa *deprecated* na kuanzisha frameworks za **System Extensions & DriverKit** zinazotumika katika **user-space**. Kuanzia **macOS Big Sur (11)**, mfumo wa uendeshaji *utakataa kupakia* kexts za third-party zinazotegemea KPIs zilizowekwa kuwa deprecated isipokuwa mashine iwashwe katika hali ya **Reduced Security**. Kwenye Apple Silicon, kuwezesha kexts pia kunahitaji mtumiaji:

1. Kuwasha upya kwenye **Recovery** → *Startup Security Utility*.
2. Kuchagua **Reduced Security** na kuweka tiki kwenye **“Allow user management of kernel extensions from identified developers”**.
3. Kuwasha upya na kuidhinisha kext kupitia **System Settings → Privacy & Security**.

User-land drivers zilizoandikwa kwa DriverKit/System Extensions **hupunguza kwa kiasi kikubwa attack surface** kwa sababu crashes au memory corruption hubaki ndani ya process iliyo kwenye sandbox badala ya kernel space.<sup>[1]</sup>

> 📝 Kuanzia macOS Sequoia (15), Apple imeondoa kabisa legacy networking na USB KPIs kadhaa – suluhisho pekee linaloendana na matoleo yajayo kwa vendors ni kuhamia kwenye System Extensions.

### Mahitaji

Kwa kawaida, hii ina nguvu kubwa kiasi kwamba **kupakia kernel extension ni jambo gumu**. Haya ndiyo **mahitaji** ambayo kernel extension lazima itimize ili ipakiwe:

- Wakati wa **kuingia recovery mode**, kernel **extensions lazima ziruhusiwe** kupakiwa:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension lazima iwe **imesainiwa kwa kernel code signing certificate**, ambayo inaweza **kutolewa na Apple pekee**. Apple itakagua kwa kina kampuni hiyo na sababu za kuhitajika kwake.
- Kernel extension lazima pia iwe **notarized**; Apple itaweza kuikagua kwa malware.
- Kisha, mtumiaji wa **root** ndiye anayeweza **kupakia kernel extension**, na files zilizo ndani ya package lazima **ziwe za root**.
- Wakati wa upload process, package lazima iandaliwe katika **protected non-root location**: `/Library/StagedExtensions` (inahitaji `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Mwishowe, wakati wa kujaribu kuipakia, mtumiaji [**atapokea ombi la uthibitisho**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) na, akikubali, computer lazima **iwashwe upya** ili kuipakia.

### Mchakato wa kupakia

Katika Catalina ilikuwa hivi: Inafurahisha kutambua kwamba mchakato wa **verification** hutokea katika **userland**. Hata hivyo, applications zilizo na grant ya **`com.apple.private.security.kext-management`** pekee ndizo zinaweza **kuomba kernel ipakie extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **huanzisha** mchakato wa **verification** wa kupakia extension
- Itawasiliana na **`kextd`** kwa kutuma ujumbe kupitia **Mach service**.
2. **`kextd`** itakagua mambo kadhaa, kama vile **signature**
- Itawasiliana na **`syspolicyd`** ili **kuangalia** kama extension inaweza **kupakiwa**.
3. **`syspolicyd`** **itamuuliza** **mtumiaji** ikiwa extension haijawahi kupakiwa awali.
- **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. **`kextd`** hatimaye itaweza **kuambia kernel ipakie** extension

Ikiwa **`kextd`** haipatikani, **`kextutil`** inaweza kufanya ukaguzi huohuo.

### Enumeration & management (loaded kexts)

`kextstat` ilikuwa tool ya kihistoria, lakini **imepitwa na wakati** katika matoleo ya hivi karibuni ya macOS. Interface ya kisasa ni **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Sintaksia ya zamani bado inapatikana kwa marejeleo:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` pia inaweza kutumika **kutupa yaliyomo kwenye Kernel Collection (KC)** au kuthibitisha kwamba kext inatatua dependencies zote za symbols:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Ingawa kernel extensions zinatarajiwa kuwa katika `/System/Library/Extensions/`, ukienda kwenye folder hii **hutapata binary yoyote**. Hii ni kwa sababu ya **kernelcache**, na ili kureverse `.kext` moja unahitaji kutafuta njia ya kuipata.

**kernelcache** ni **toleo lililokusanywa na kuunganishwa mapema la XNU kernel**, pamoja na **drivers** muhimu za vifaa na **kernel extensions**. Huhifadhiwa katika muundo **uliobanwa** na kufunguliwa kwenye memory wakati wa mchakato wa boot-up. kernelcache huwezesha **boot time ya haraka** kwa kuwa na toleo la kernel na drivers muhimu lililo tayari kuendeshwa, hivyo kupunguza muda na rasilimali ambazo zingetumika vinginevyo kupakia na kuunganisha components hizi dynamically wakati wa boot.

Faida kuu za kernelcache ni **speed ya loading** na kwamba modules zote zimeunganishwa mapema (hakuna kizuizi cha load time). Na baada ya modules zote kuunganishwa mapema, KXLD inaweza kuondolewa kwenye memory, hivyo **XNU haiwezi kupakia KEXTs mpya.**

> [!TIP]
> Tool ya [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) hudecrypt Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — muundo wa encrypted container unaotumiwa na Apple kwa OTA assets na baadhi ya IPSW pieces — na inaweza kutoa .dmg/asset archive ya msingi ambayo unaweza kisha kuiextract kwa kutumia aastuff tools zilizotolewa.


### Kernelcache ya Kwenye Mfumo

Katika iOS iko kwenye **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; katika macOS unaweza kuipata kwa: **`find / -name "kernelcache" 2>/dev/null`** \
Katika hali yangu, katika macOS niliipata kwenye:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Pia ipate hapa [**kernelcache ya version 14 yenye symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) iliyobanwa

IMG4 file format ni container format inayotumiwa na Apple katika vifaa vyake vya iOS na macOS kwa **kuhifadhi na kuthibitisha firmware** components kwa usalama (kama **kernelcache**). IMG4 format inajumuisha header na tags kadhaa zinazofungasha vipande mbalimbali vya data, ikiwemo payload halisi (kama kernel au bootloader), signature, na seti ya manifest properties. Format hii inasaidia cryptographic verification, hivyo kifaa kinaweza kuthibitisha authenticity na integrity ya firmware component kabla ya kuiendesha.

Kwa kawaida huwa na components zifuatazo:

- **Payload (IM4P)**:
- Mara nyingi hubanwa (LZFSE4, LZSS, …)
- Inaweza kuwa encrypted
- **Manifest (IM4M)**:
- Huwa na Signature
- Key/Value dictionary ya ziada
- **Restore Info (IM4R)**:
- Pia inajulikana kama APNonce
- Huzuia replaying ya baadhi ya updates
- OPTIONAL: Kwa kawaida hii haipatikani

Decompress Kernelcache:
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
#### Disarm symbols za kernel

**`Disarm`** inaruhusu kusymbolicate functions kutoka kwenye kernelcache kwa kutumia matchers. Matchers hizi ni rules rahisi za pattern (mistari ya maandishi) zinazoieleza disarm jinsi ya kutambua na ku-auto-symbolicate functions, arguments na panic/log strings ndani ya binary.

Kwa ufupi, unaonyesha string ambayo function inatumia, na disarm itaipata na **kuisymbolicate**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Nenda kwenye /tmp/extracted ambako disarm ilitoa filesets
disarm -e filesets kernelcache.release.d23 # Daima toa kwenye /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Kumbuka kwamba xnu.matchers kwa hakika ni file yenye matchers
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
# Sakinisha zana ya ipsw
brew install blacktop/tap/ipsw

# Toa kernelcache pekee kutoka kwenye IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Unapaswa kupata kitu kama:
#   out/Firmware/kernelcache.release.iPhoneXX
#   au payload ya IMG4: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Ukipata payload ya IMG4:
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
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
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
# Unda kifurushi cha symbolication cha panic ya hivi karibuni
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
# Tambua anwani ya upakiaji ya kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Unganisha
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
