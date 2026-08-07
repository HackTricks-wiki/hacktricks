# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Kernel extensions (Kexts) ni **packages** zenye extension ya **`.kext`** ambazo **hupakiwa moja kwa moja kwenye macOS kernel space**, zikitoa utendaji wa ziada kwa operating system kuu.

### Hali ya kuondolewa & DriverKit / System Extensions
Kuanzia **macOS Catalina (10.15)** Apple iliweka KPIs nyingi za zamani kama *deprecated* na kuanzisha frameworks za **System Extensions & DriverKit** zinazofanya kazi katika **user-space**. Kuanzia **macOS Big Sur (11)** operating system *itakataa kupakia* kexts za third-party zinazotegemea KPIs zilizowekwa deprecated isipokuwa mashine iwashwe katika hali ya **Reduced Security**. Kwenye Apple Silicon, kuwezesha kexts pia kunamhitaji mtumiaji:

1. Kuwasha upya katika **Recovery** → *Startup Security Utility*.
2. Kuchagua **Reduced Security** na kuweka alama kwenye **“Allow user management of kernel extensions from identified developers”**.
3. Kuwasha upya na kuidhinisha kext kupitia **System Settings → Privacy & Security**.

User-land drivers zilizoandikwa kwa DriverKit/System Extensions **hupunguza kwa kiasi kikubwa attack surface** kwa sababu crashes au memory corruption hubaki ndani ya process iliyowekwa kwenye sandbox badala ya kernel space.<sup>[[1]](#references)</sup>

> 📝 Kuanzia macOS Sequoia (15) Apple imeondoa kabisa legacy networking na USB KPIs kadhaa – suluhisho pekee linaloendana na matoleo yajayo kwa vendors ni kuhamia System Extensions.

### Mahitaji

Kwa wazi, hili lina nguvu kubwa kiasi kwamba **kupakia kernel extension ni jambo gumu**. Haya ndiyo **mahitaji** ambayo kernel extension lazima itimize ili ipakiwe:

- Wakati wa **kuingia recovery mode**, kernel **extensions lazima ziruhusiwe** kupakiwa:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension lazima iwe **signed with a kernel code signing certificate**, ambayo inaweza **kutolewa na Apple pekee**. Apple itakagua kwa undani kampuni na sababu za kuhitajika kwake.
- Kernel extension lazima pia iwe **notarized**; Apple itaweza kuikagua dhidi ya malware.
- Kisha, mtumiaji wa **root** ndiye anayeweza **kupakia kernel extension**, na files zilizo ndani ya package lazima **ziwe za root**.
- Wakati wa upload process, package lazima iandaliwe katika **protected non-root location**: `/Library/StagedExtensions` (inahitajika `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Mwishowe, wakati wa kujaribu kuipakia, mtumiaji [**atapokea ombi la uthibitisho**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) na, ikiwa atalikubali, computer lazima **iwashwe upya** ili kuipakia.

### Loading process

Katika Catalina ilikuwa hivi: Inafurahisha kutambua kwamba mchakato wa **verification** hufanyika katika **userland**. Hata hivyo, ni applications zilizo na **`com.apple.private.security.kext-management`** grant pekee zinazoweza **kuomba kernel ipakie extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **huanzisha** mchakato wa **verification** wa kupakia extension
- Itawasiliana na **`kextd`** kwa kutuma ombi kupitia **Mach service**.
2. **`kextd`** itaangalia mambo kadhaa, kama vile **signature**
- Itawasiliana na **`syspolicyd`** ili **kuangalia** ikiwa extension inaweza **kupakiwa**.
3. **`syspolicyd`** itamwomba **mtumiaji** uthibitisho ikiwa extension haikuwahi kupakiwa awali.
- **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. **`kextd`** hatimaye itaweza **kuambia kernel ipakie** extension

Ikiwa **`kextd`** haipatikani, **`kextutil`** inaweza kufanya checks hizo hizo.

### Enumeration & management (loaded kexts)

`kextstat` ilikuwa tool ya kihistoria lakini **imewekwa deprecated** katika matoleo ya hivi karibuni ya macOS. Interface ya kisasa ni **`kmutil`**:
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
`kmutil inspect` pia inaweza kutumika **kudump contents za Kernel Collection (KC)** au kuthibitisha kwamba kext inatatua symbol dependencies zote:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Ingawa kernel extensions zinatarajiwa kuwa katika `/System/Library/Extensions/`, ukienda kwenye folda hii **hutapata binary yoyote**. Hii ni kwa sababu ya **kernelcache**, na ili kureverse `.kext` moja unahitaji kutafuta njia ya kuipata.

**Kernelcache** ni toleo la **XNU kernel lililokusanywa na kuunganishwa mapema**, pamoja na **drivers** muhimu za vifaa na **kernel extensions**. Huhifadhiwa katika muundo **uliobanwa** na hufunguliwa kwenye memory wakati wa mchakato wa boot-up. Kernelcache huwezesha **boot time ya haraka zaidi** kwa kuwa na toleo la kernel na drivers muhimu lililo tayari kuendeshwa, hivyo kupunguza muda na rasilimali ambazo zingetumika kupakia na kuunganisha vipengele hivi dynamically wakati wa boot.

Faida kuu za kernelcache ni **kasi ya kupakia**, na kwamba modules zote huunganishwa mapema (hakuna kizuizi cha load time). Pia, modules zote zikishaunganishwa mapema, KXLD inaweza kuondolewa kwenye memory, hivyo **XNU haiwezi kupakia KEXT mpya.**

> [!TIP]
> Tool ya [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) hudecrypt Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — muundo wa encrypted container unaotumiwa na Apple kwa OTA assets na baadhi ya vipande vya IPSW — na inaweza kutengeneza .dmg/asset archive ya msingi ambayo unaweza ku-extract kwa kutumia aastuff tools zilizotolewa.

### Kernelcache ya Ndani

Katika iOS hupatikana kwenye **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; katika macOS unaweza kuipata kwa: **`find / -name "kernelcache" 2>/dev/null`** \
Katika hali yangu, kwenye macOS niliipata hapa:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Pia pata hapa [**kernelcache ya version 14 yenye symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) iliyobanwa

Muundo wa file wa IMG4 ni container format inayotumiwa na Apple katika vifaa vyake vya iOS na macOS kwa ajili ya **kuhifadhi na kuthibitisha firmware** components (kama **kernelcache**) kwa usalama. Muundo wa IMG4 una header na tags kadhaa zinazofunga pamoja sehemu tofauti za data, zikiwemo payload halisi (kama kernel au bootloader), signature, na seti ya manifest properties. Muundo huu unaunga mkono cryptographic verification, hivyo kifaa kinaweza kuthibitisha authenticity na integrity ya firmware component kabla ya kui-execute.

Kwa kawaida huundwa na components zifuatazo:

- **Payload (IM4P)**:
- Mara nyingi huwa compressed (LZFSE4, LZSS, …)
- Huenda ikawa encrypted
- **Manifest (IM4M)**:
- Ina Signature
- Key/Value dictionary ya ziada
- **Restore Info (IM4R)**:
- Pia inajulikana kama APNonce
- Huzuia kureplay baadhi ya updates
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

**`Disarm`** huruhusu kuhusisha functions na symbols kutoka kwenye kernelcache kwa kutumia matchers. Matchers hawa ni sheria rahisi za pattern (mistari ya maandishi) zinazoeleza disarm jinsi ya kutambua na ku-**symbolicate** functions, arguments na panic/log strings ndani ya binary.

Kwa kifupi, unaonyesha string ambayo function inatumia, na disarm itaipata na kui-**symbolicate**.

Unaweza kupata baadhi ya `xnu.matchers` kwenye [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) katika sehemu ya **`Matchers`**. Unaweza pia kuunda matchers zako mwenyewe.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Pakua

**IPSW (iPhone/iPad Software)** ni muundo wa package ya firmware ya Apple unaotumika kurejesha vifaa, kufanya updates, na vifurushi kamili vya firmware. Miongoni mwa vitu vingine, ina **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Katika [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) inawezekana kupata kernel debug kits zote. Unaweza kuipakua, kuimount, kuifungua kwa kutumia tool ya [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), kufikia folder ya **`.kext`** na **kuiextract**.

Iikague kwa symbols ukitumia:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Wakati mwingine Apple hutoa **kernelcache** yenye **symbols**. Unaweza kupakua baadhi ya firmwares zilizo na symbols kwa kufuata links kwenye kurasa hizo. Firmwares hizo zitakuwa na **kernelcache** pamoja na mafaili mengine.

Ili **extract** kernel cache unaweza kufanya:
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
Chaguo jingine la **extract** files linaanza kwa kubadilisha extension kutoka `.ipsw` kuwa `.zip` na kisha kuifanyia **unzip**.

Baada ya ku-extract firmware utapata file kama: **`kernelcache.release.iphone14`**. Iko katika format ya **IMG4**, unaweza ku-extract taarifa muhimu kwa kutumia:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Kukagua kernelcache

Angalia kama kernelcache ina symbols kwa kutumia
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Kwa kutumia hii sasa tunaweza **kutoa extensions zote** au **ile unayoihitaji:**
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
## Vulnerabilities za hivi karibuni na mbinu za exploitation

| Year | CVE | Muhtasari |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Kasoro ya kimantiki katika **`storagekitd`** ilimruhusu mshambuliaji wa *root* kusajili bundle hasidi ya mfumo wa faili, ambayo hatimaye ilipakia **kext isiyotiwa saini**, **ikipita System Integrity Protection (SIP)** na kuwezesha rootkits zinazoendelea. Ilirekebishwa katika macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon yenye entitlement `com.apple.rootless.install` inaweza kutumiwa vibaya kutekeleza scripts kiholela za post-install, kuzima SIP na kupakia kext kiholela. <sup>[[3]](#references)</sup> |

**Mambo muhimu kwa red-teamers**

1. **Tafuta daemons zenye entitlements (`codesign -dvv /path/bin | grep entitlements`) zinazoingiliana na Disk Arbitration, Installer au Kext Management.**
2. **Kutumia vibaya SIP bypasses karibu kila mara hutoa uwezo wa kupakia kext → kernel code execution**.

**Vidokezo vya ulinzi**

*Washa SIP*, fuatilia matumizi ya `kmutil load`/`kmutil create -n aux` yanayotoka kwenye binaries zisizo za Apple na toa alert kwa write yoyote kwenye `/Library/Extensions`. Events za Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` hutoa mwonekano wa karibu real-time.

## Debugging ya macOS kernel na kexts

Workflow inayopendekezwa na Apple ni kuunda **Kernel Debug Kit (KDK)** inayolingana na build inayoendesha, kisha kuunganisha **LLDB** kupitia session ya mtandao ya **KDP (Kernel Debugging Protocol)**.

### One-shot local debug ya panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live remote debugging kutoka kwenye Mac nyingine

1. Pakua + sakinisha toleo kamili la **KDK** kwa mashine ya **target**.
2. Unganisha Mac ya **target** na Mac ya **host** kwa **USB-C au Thunderbolt cable**.
3. Kwenye **target**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Kwenye **host**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Kuambatisha LLDB kwenye kext maalum iliyopakiwa
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️ KDP hutoa interface ya **read-only** pekee. Kwa dynamic instrumentation utahitaji ku-patch binary iliyo kwenye diski, kutumia **kernel function hooking** (kwa mfano, `mach_override`) au kuhamisha driver kwenye **hypervisor** kwa read/write kamili.

## Marejeo

- [1] [Usalama wa DriverKit kwa macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Kuchanganua CVE-2024-44243, bypass ya macOS System Integrity Protection kupitia kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft yagundua vulnerability mpya ya macOS, Shrootless, inayoweza kubypass System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
