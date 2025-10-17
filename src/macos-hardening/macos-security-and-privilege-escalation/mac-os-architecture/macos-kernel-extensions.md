# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Kernel extensions (Kexts) ni **vifurushi** zenye nyongeza ya **`.kext`** ambazo zinapakiwa **mojawapo ndani ya nafasi ya kernel ya macOS**, zikitoa utendakazi wa ziada kwa mfumo mkuu wa uendeshaji.

### Hali ya kuachwa matumizi & DriverKit / System Extensions
Kuanzia **macOS Catalina (10.15)** Apple ilitangaza KPIs nyingi za urithi kama *deprecated* na kuanzisha mfumo wa **System Extensions & DriverKit** unaofanya kazi katika **user-space**. Kuanzia **macOS Big Sur (11)** mfumo wa uendeshaji utakataa *kupakia* kexts za wahusika wa tatu zinazotegemea KPIs zilizotangazwa kuwa deprecated isipokuwa mashine ianzishwe katika mode ya **Reduced Security**. Kwa Apple Silicon, kuwezesha kexts pia kunamhitaji mtumiaji kufanya:

1. Reboot katika **Recovery** → *Startup Security Utility*.
2. Chagua **Reduced Security** na weka tiki **“Allow user management of kernel extensions from identified developers”**.
3. Reboot na idhini kext kutoka **System Settings → Privacy & Security**.

Madereva wa user-land yaliyoandikwa kwa DriverKit/System Extensions yanapunguza kwa kiasi kikubwa uso wa mashambulizi kwa sababu crashes au uharibifu wa kumbukumbu unazuilika kwa mchakato uliopotoka ndani ya sandbox badala ya nafasi ya kernel.

> 📝 Kuanzia macOS Sequoia (15) Apple imeondoa KPIs kadhaa za zamani kwa mitandao na USB kabisa – suluhisho pekee linaloendana na mustakabali kwa wauzaji ni kuhama kwenda System Extensions.

### Mahitaji

Bila shaka, hii ni nguvu sana kiasi kwamba ni **ngumu kupakia kernel extension**. Hivi ni **mahitaji** ambayo kernel extension lazima yatimize ili ipakwe:

- Wakati **kuingia recovery mode**, extensions za kernel lazima ziruhusiwe kupakiwa:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension lazima isainiwa kwa **cheti cha kusaini msimbo wa kernel**, ambacho kinaweza kutolewa tu na Apple. Apple itapitia kwa undani kampuni na sababu zinazoeleza kwanini inahitajika.
- Kernel extension pia lazima iwe **notarized**, Apple itakuwa na uwezo wa kuikagua kwa malware.
- Kisha, mtumiaji **root** ndiye anaweza **kupakia kernel extension** na faili ndani ya kifurushi lazima ziwe **zimilikiwa na root**.
- Wakati wa mchakato wa upakiaji, kifurushi lazima kiandaliwe katika eneo lililolindwa lisilo la root: `/Library/StagedExtensions` (inahitaji grant ya `com.apple.rootless.storage.KernelExtensionManagement`).
- Mwisho, unapojaribu kuipakia, mtumiaji [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) na, ikiwa itakubaliwa, kompyuta lazima ianzishwe upya ili kuiweka.

### Loading process

Katika Catalina ilikuwa hivi: Inavutia kutambua kwamba mchakato wa **ukaguzi** hufanyika katika **userland**. Hata hivyo, ni programu tu zenye grant ya `com.apple.private.security.kext-management` zinazoweza **kuomba kernel ipe kigezo cha kupakia extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **huanza** mchakato wa **ukaguzi** kwa ajili ya kupakia extension
- Itawasiliana na **`kextd`** kwa kutumia **Mach service**.
2. **`kextd`** itakagua mambo kadhaa, kama vile **saini**
- Itawasiliana na **`syspolicyd`** ili **kuangalia** kama extension inaweza **kuingizwa**.
3. **`syspolicyd`** itamwomba **mtumiaji** ruhusa ikiwa extension haikuwekwa awali.
- **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. **`kextd`** hatimaye itakuwa na uwezo wa **kumuambia kernel aingize** extension

Ikiwa **`kextd`** haipatikani, **`kextutil`** inaweza kufanya ukaguzi ule ule.

### Orodha & usimamizi (kexts zilizopakiwa)

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
`kmutil inspect` pia inaweza kutumika **dump the contents of a Kernel Collection (KC)** au kuthibitisha kwamba kext inatatua all symbol dependencies:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Even though the kernel extensions are expected to be in `/System/Library/Extensions/`, if you go to this folder you **won't find any binary**. This is because of the **kernelcache** and in order to reverse one `.kext` you need to find a way to obtain it.

The **kernelcache** ni toleo **iliyo tayari kukusanywa na kuunganishwa kabla (pre-compiled and pre-linked) la kernel ya XNU**, pamoja na **drivers** muhimu za kifaa na **kernel extensions**. Hifadhi yake iko katika muundo ulioshinikwa (**compressed**) na inafunguliwa (decompressed) katika memory wakati wa mchakato wa boot. kernelcache inasaidia kupata **muda wa kuanza (boot) kwa haraka** kwa kuwa na toleo la kernel na drivers muhimu tayari kufanya kazi, hivyo kupunguza muda na rasilimali ambazo zingetumika kwenye upakiaji na uunganishaji wa nyongeza hizo kwa wakati wa boot.

Manufaa makuu ya kernelcache ni **kwa kasi ya upakiaji** na kwamba moduli zote zimeunganishwa mapema (hakuna ucheleweshaji wa wakati wa kupakia). Na mara moduli zote zikitangazwa awali- KXLD inaweza kuondolewa kutoka kwenye memory hivyo **XNU haiwezi kupakia KEXTs mpya.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.

### Kernelcache ya Mahali

In iOS iko katika **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** kwenye macOS unaweza kuipata kwa: **`find / -name "kernelcache" 2>/dev/null`** \
Katika kesi yangu kwenye macOS nilipata katika:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Pata pia hapa the [**kernelcache ya toleo la 14 yenye symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Muundo wa faili wa IMG4 ni muundo wa container unaotumika na Apple kwenye vifaa vyake vya iOS na macOS kwa **kuhifadhi na kuthibitisha firmware** kwa usalama (kama kernelcache). Muundo wa IMG4 una header na tags kadhaa zinazoingiza vipande tofauti vya data ikiwemo payload yenyewe (kama kernel au bootloader), sahihi (signature), na seti ya mali za manifest. Muundo huo unaweza kusaidia uthibitisho wa kriptografia, kuruhusu kifaa kuthibitisha uhalali na uadilifu wa sehemu ya firmware kabla ya kuiendesha.

Mara nyingi unaundwa na vipengele vifuatavyo:

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
#### Disarm alama kwa kernel

**`Disarm`** inaruhusu symbolicate functions kutoka kernelcache kwa kutumia matchers. Matchers hizi ni kanuni za muundo rahisi (mistari ya maandishi) zinazomuambia disarm jinsi ya kutambua na auto-symbolicate functions, arguments na panic/log strings ndani ya binary.

Kwa kifupi unaonyesha kamba ya maandishi ambayo function inatumia, na disarm itaiipata na **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Nenda kwenye /tmp/extracted ambapo disarm ilitoa filesets
disarm -e filesets kernelcache.release.d23 # Daima toa kwenye /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Kumbuka kwamba xnu.matchers ni faili yenye matchers
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
#   au IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

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
# Orodhesha nyongeza zote
kextex -l kernelcache.release.iphone14.e
## Toa com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Toa zote
kextex_all kernelcache.release.iphone14.e

# Angalia nyongeza kwa alama
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
# Tengeneza symbolication bundle kwa panic ya hivi karibuni
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
(lldb) bt  # pata backtrace katika muktadha wa kernel
```

### Attaching LLDB to a specific loaded kext

```bash
# Tambua anwani ya kupakia ya kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Unganisha
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
