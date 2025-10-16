# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Kernel extensions (Kexts) ni **packages** zenye nyongeza ya **`.kext`** ambazo **zinapakiwa moja kwa moja ndani ya kernel space ya macOS**, zikitoa uwezo zaidi kwa mfumo mkuu wa uendeshaji.

### Hali ya kuachwa matumizi & DriverKit / System Extensions
Kuanzia na **macOS Catalina (10.15)** Apple ilitaja KPIs nyingi za kale kama *deprecated* na kuanzisha mifumo ya **System Extensions & DriverKit** inayotumia **user-space**. Kuanzia **macOS Big Sur (11)** mfumo wa uendeshaji uta *kataza kupakia* kexts za wataalamu wa tatu zinazotegemea KPIs zilizopitwa isipokuwa mashine itakapoanzishwa katika hali ya **Reduced Security**. Kwenye Apple Silicon, kuwezesha kexts pia kunahitaji mtumiaji:

1. Reboot kwenda **Recovery** → *Startup Security Utility*.
2. Chagua **Reduced Security** na weke **“Allow user management of kernel extensions from identified developers”**.
3. Reboot na idhinishe kext kutoka **System Settings → Privacy & Security**.

User-land drivers zilizoandikwa kwa DriverKit/System Extensions zinapunguza kwa kiasi kikubwa attack surface kwa sababu crashes au uharibifu wa kumbukumbu huwekewa mipaka ndani ya process iliyosandbox badala ya kernel space.

> 📝 Kuanzia macOS Sequoia (15) Apple imeondoa KPIs kadhaa za mitandao na USB za zamani kabisa – suluhisho pekee linaloendelea kwa wasambazaji ni kuhama kwenda System Extensions.

### Mahitaji

Bayana, hii ni nguvu kiasi cha kwamba ni **magumu kupakia kernel extension**. Haya ndiyo **mahitaji** ambayo kernel extension lazima yasite ili yapakwe:

- Wakati **kuingia recovery mode**, kernel **extensions lazima ziruhusiwe** kupakiwa:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension lazima iwe **imewekwa sahihi kwa kitambulisho cha kernel code signing**, ambacho kinaweza tu **kutolewa na Apple**. Apple itapitia kwa undani kampuni na sababu za hitaji.
- Kernel extension lazima pia iwe **notarized**, Apple itakuwa na uwezo wa kuikagua kwa ajili ya malware.
- Kisha, mtumiaji **root** ndiye anayeweza **kupakia kernel extension** na faili ndani ya package lazima ziwe **mmiliki root**.
- Wakati wa mchakato wa upload, package lazima itayarishwe katika eneo **lililolindwa non-root**: `/Library/StagedExtensions` (inahitaji ruhusa ya `com.apple.rootless.storage.KernelExtensionManagement`).
- Mwishowe, wakati wa kujaribu kuipakia, mtumiaji [**atapata ombi la uthibitisho**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) na, ikiwa itakubaliwa, kompyuta lazima **irejeshwe** kwa ajili ya kupakia.

### Mchakato wa kupakia

Katika Catalina ilikuwa hivi: Inavutia kutambua kwamba mchakato wa **uthibitisho** hufanyika katika **userland**. Hata hivyo, programu pekee zenye ruhusa ya **`com.apple.private.security.kext-management`** zinaweza **kuomba kernel upakie extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **huanza** mchakato wa **uthibitisho** wa kupakia extension
- Itaanziana na **`kextd`** kwa kutuma kwa kutumia **Mach service**.
2. **`kextd`** itakagua mambo kadhaa, kama vile **signature**
- Itaanziana na **`syspolicyd`** ili **kuangalia** kama extension inaweza **kupakuliwa**.
3. **`syspolicyd`** itamwuliza **mtumiaji** endapo extension haikuwa imepakiwa hapo awali.
- **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. **`kextd`** hatimaye ataweza **kuambia kernel apakie** extension

Ikiwa **`kextd`** haipatikani, **`kextutil`** inaweza kufanya ukaguzi huo huo.

### Uorodheshaji & usimamizi (kexts zilizopakiwa)

`kextstat` ilikuwa zana ya kihistoria lakini imekuwa **deprecated** katika matoleo ya hivi karibuni ya macOS. Kiolesura cha kisasa ni **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Sintaksia ya zamani bado inapatikana kwa marejeo:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` pia inaweza kutumika **dump the contents of a Kernel Collection (KC)** au kuthibitisha kwamba kext inatatua symbol dependencies zote:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Ingawa kernel extensions zinatarajiwa kuwa katika `/System/Library/Extensions/`, ikiwa utaenda kwenye folda hii **hautapata binary yoyote**. Hii ni kwa sababu ya **kernelcache** na ili ku-reverse `.kext` moja unahitaji kupata njia ya kuipata.

The **kernelcache** ni toleo **lililotengenezwa mapema na ku-link-ishwa mapema la kernel ya XNU**, pamoja na **drivers** muhimu za kifaa na **kernel extensions**. Imehifadhiwa kwa muundo uliyo **compress** na inatolewa kwa kumbukumbu wakati wa mchakato wa boot-up. Kernelcache inasaidia kupata **muda mfupi wa kuanza (faster boot time)** kwa kuwa na toleo linaloweza kuanzishwa la kernel na drivers muhimu tayari, ikipunguza muda na rasilimali ambazo vingetumika kwa kupakia na ku-link kwa nguvu vipengele hivi wakati wa boot.

Manufaa makuu ya kernelcache ni **mwendo wa ku-loading** na kwamba moduli zote zimetolewa mapema (hakuna ucheleweshaji wa muda wa kupakia). Na mara moduli zote zikitolewa mapema - KXLD inaweza kuondolewa kwenye kumbukumbu hivyo **XNU haiwezi kupakia KEXTs mpya.**

> [!TIP]
> Zana ya [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) ina-decrypt Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — muundo uliosimbwa Apple unayotumika kwa OTA assets na baadhi ya vipande vya IPSW — na inaweza kutoa .dmg/asset archive ya msingi ambayo unaweza kisha kuichakata kwa kutumia aastuff tools zilizotolewa.

### Local Kernelcache

Katika iOS iko katika **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** katika macOS unaweza kuipata kwa: **`find / -name "kernelcache" 2>/dev/null`** \
Katika kesi yangu kwenye macOS nilipata katika:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Pata pia hapa [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Muundo wa faili wa IMG4 ni muundo wa kontena unaotumika na Apple katika vifaa vyake vya iOS na macOS kwa ajili ya **kuhifadhi na kuthibitisha firmware** sehemu (kama **kernelcache**). Muundo wa IMG4 una header na tags kadhaa ambazo zinajumuisha vipande tofauti vya data ikiwa ni pamoja na payload halisi (kama kernel au bootloader), saini, na seti ya mali za manifest. Muundo huu unaunga mkono uthibitishaji wa kriptografia, ukiruhusu kifaa kuthibitisha uhalali na uadilifu wa sehemu ya firmware kabla ya kuitekeleza.

Kwa kawaida umeundwa kwa vipengele vifuatavyo:

- **Payload (IM4P)**:
  - Mara nyingi iliyokompress (LZFSE4, LZSS, …)
  - Hiari ku-encrypt
- **Manifest (IM4M)**:
  - Inajumuisha Signature
  - Kamusi ya ziada ya Key/Value
- **Restore Info (IM4R)**:
  - Pia inajulikana kama APNonce
  - Inazuia kureplays baadhi ya masasisho
  - OPTIONAL: Kwa kawaida hii haipatikani

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
#### Alama za Disarm kwa kernel

**`Disarm`** inaruhusu symbolicate functions kutoka kernelcache kwa kutumia matchers. Matchers hizi ni tu sheria za muundo rahisi (mistari ya maandishi) zinazomwambia disarm jinsi ya kutambua & auto-symbolicate functions, arguments na panic/log strings ndani ya binary.

Kwa kifupi, unaonyesha string ambayo function inaitumia na disarm itaitafuta na **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Nenda kwenye /tmp/extracted ambako disarm ilivunja filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
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
# Sakinisha ipsw tool
brew install blacktop/tap/ipsw

# Toa tu kernelcache kutoka IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Unapaswa kupata kitu kama:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Ikiwa unapata IMG4 payload:
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
# Orodhesha viendelezo vyote
kextex -l kernelcache.release.iphone14.e
## Toa com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Toa zote
kextex_all kernelcache.release.iphone14.e

# Kagua kiendelezo kwa alama
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
# Unda bundle ya symbolication kwa panic ya hivi karibuni
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
# Tambua anwani ya kupakia ya kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Ambatisha
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
