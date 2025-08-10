# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) ni **packages** zenye **`.kext`** extension ambazo zinapakiwa moja kwa moja kwenye **macOS kernel space**, zikitoa kazi za ziada kwa mfumo mkuu wa uendeshaji.

### Deprecation status & DriverKit / System Extensions
Kuanza na **macOS Catalina (10.15)** Apple ilitambua KPIs nyingi za zamani kama *deprecated* na kuanzisha **System Extensions & DriverKit** frameworks ambazo zinafanya kazi katika **user-space**. Kuanzia **macOS Big Sur (11)** mfumo wa uendeshaji uta *kataa kupakia* kexts za wahusika wengine zinazotegemea KPIs za zamani isipokuwa mashine imeanzishwa katika **Reduced Security** mode. Kwenye Apple Silicon, kuwezesha kexts kunahitaji mtumiaji:

1. Kuanzisha upya kwenye **Recovery** → *Startup Security Utility*.
2. Kuchagua **Reduced Security** na kuangalia **“Allow user management of kernel extensions from identified developers”**.
3. Kuanzisha upya na kuidhinisha kext kutoka **System Settings → Privacy & Security**.

Madereva wa user-land waliandikwa kwa DriverKit/System Extensions hupunguza kwa kiasi kikubwa **attack surface** kwa sababu ajali au uharibifu wa kumbukumbu unak confined kwenye mchakato wa sandboxed badala ya kernel space.

> 📝 Kuanzia macOS Sequoia (15) Apple imeondoa kabisa KPIs kadhaa za zamani za networking na USB – suluhisho pekee linaloweza kuendana na siku zijazo kwa wauzaji ni kuhamia kwenye System Extensions.

### Requirements

Kwa wazi, hii ni nguvu sana kwamba ni **ngumu kupakia kernel extension**. Hizi ndizo **mahitaji** ambayo kernel extension lazima ikidhi ili ipakie:

- Wakati wa **kuingia kwenye recovery mode**, kernel **extensions lazima ziaruhusiwe** kupakiwa:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension lazima iwe **signed with a kernel code signing certificate**, ambayo inaweza tu **kupewa na Apple**. Nani atakayeangalia kwa undani kampuni na sababu zinazohitajika.
- Kernel extension lazima pia iwe **notarized**, Apple itakuwa na uwezo wa kuangalia kwa malware.
- Kisha, mtumiaji wa **root** ndiye anayeweza **kupakia kernel extension** na faili ndani ya package lazima **zihusiane na root**.
- Wakati wa mchakato wa kupakia, package lazima iwe tayari katika **mahali salama yasiyo ya root**: `/Library/StagedExtensions` (inahitaji `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Hatimaye, wakati wa kujaribu kuipakia, mtumiaji atapokea [**ombwe la uthibitisho**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) na, ikiwa imekubaliwa, kompyuta lazima **ianzishwe upya** ili kuipakia.

### Loading process

Katika Catalina ilikuwa hivi: Ni ya kuvutia kutambua kwamba mchakato wa **verification** unafanyika katika **userland**. Hata hivyo, ni programu pekee zenye **`com.apple.private.security.kext-management`** grant zinaweza **kuomba kernel kupakia extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inaanza** mchakato wa **verification** wa kupakia extension
- Itazungumza na **`kextd`** kwa kutuma kwa kutumia **Mach service**.
2. **`kextd`** itakagua mambo kadhaa, kama vile **signature**
- Itazungumza na **`syspolicyd`** ili **kuangalia** ikiwa extension inaweza **kupakiwa**.
3. **`syspolicyd`** itamwomba **mtumiaji** ikiwa extension haijawahi kupakiwa hapo awali.
- **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. **`kextd`** hatimaye itakuwa na uwezo wa **kueleza kernel kupakia** extension

Ikiwa **`kextd`** haipatikani, **`kextutil`** inaweza kufanya ukaguzi sawa.

### Enumeration & management (loaded kexts)

`kextstat` ilikuwa chombo cha kihistoria lakini sasa ni **deprecated** katika toleo za hivi karibuni za macOS. Kiolesura cha kisasa ni **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Syntax ya zamani bado inapatikana kwa marejeleo:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` inaweza pia kutumika **kutoa maudhui ya Kernel Collection (KC)** au kuthibitisha kwamba kext inatatua utegemezi wote wa alama:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Ingawa nyongeza za kernel zinatarajiwa kuwa katika `/System/Library/Extensions/`, ukitembelea folda hii hu **wezi kupata binary yoyote**. Hii ni kwa sababu ya **kernelcache** na ili kubadilisha moja `.kext` unahitaji kupata njia ya kuipata.

**Kernelcache** ni **toleo lililotayarishwa na kuunganishwa la kernel ya XNU**, pamoja na madereva muhimu na **nyongeza za kernel**. Inahifadhiwa katika muundo wa **kimecompressed** na inachukuliwa kwenye kumbukumbu wakati wa mchakato wa kuanzisha. Kernelcache inarahisisha **wakati wa kuanzisha haraka** kwa kuwa na toleo lililo tayari la kernel na madereva muhimu yanapatikana, kupunguza muda na rasilimali ambazo zingetumika kwa kupakia na kuunganisha vipengele hivi kwa wakati wa kuanzisha.

### Local Kerlnelcache

Katika iOS inapatikana katika **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** katika macOS unaweza kuipata kwa: **`find / -name "kernelcache" 2>/dev/null`** \
Katika kesi yangu katika macOS niliipata katika:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Muundo wa faili ya IMG4 ni muundo wa kontena unaotumiwa na Apple katika vifaa vyake vya iOS na macOS kwa ajili ya **kuhifadhi na kuthibitisha kwa usalama** vipengele vya firmware (kama **kernelcache**). Muundo wa IMG4 unajumuisha kichwa na lebo kadhaa ambazo zinafunga vipande tofauti vya data ikiwa ni pamoja na mzigo halisi (kama kernel au bootloader), saini, na seti ya mali za manifest. Muundo huu unasaidia uthibitisho wa kificho, ukiruhusu kifaa kuthibitisha uhalali na uadilifu wa kipengele cha firmware kabla ya kukitekeleza.

Kwa kawaida unajumuisha vipengele vifuatavyo:

- **Payload (IM4P)**:
- Mara nyingi imekandamizwa (LZFSE4, LZSS, …)
- Inaweza kuwa na usimbuaji
- **Manifest (IM4M)**:
- Inajumuisha Saini
- Kamusi ya Key/Value ya ziada
- **Restore Info (IM4R)**:
- Pia inajulikana kama APNonce
- Inazuia kurudiwa kwa baadhi ya masasisho
- HIARI: Kwa kawaida hii haipatikani

Fungua Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Katika [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) inawezekana kupata vifaa vyote vya ufuatiliaji wa kernel. Unaweza kuvipakua, kuvifunga, kuvifungua kwa kutumia chombo cha [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), kufikia folda ya **`.kext`** na **kuvitoa**.

Angalia kwa alama na:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Wakati mwingine Apple inatoa **kernelcache** yenye **symbols**. Unaweza kupakua firmware kadhaa zenye symbols kwa kufuata viungo kwenye kurasa hizo. Firmware zitakuwa na **kernelcache** pamoja na faili nyingine.

Ili **extract** faili, anza kwa kubadilisha kiambishi kutoka `.ipsw` hadi `.zip` na **unzip**.

Baada ya kutoa firmware utapata faili kama: **`kernelcache.release.iphone14`**. Iko katika muundo wa **IMG4**, unaweza kutoa taarifa muhimu kwa kutumia:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Kukagua kernelcache

Angalia ikiwa kernelcache ina alama za
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Na hii sasa tunaweza **kuchota nyongeza zote** au **ile unayovutiwa nayo:**
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
## Uthibitisho wa hivi karibuni & mbinu za unyakuzi

| Mwaka | CVE | Muhtasari |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Hitilafu ya mantiki katika **`storagekitd`** iliruhusu mshambuliaji *root* kujiandikisha kwenye kifurushi cha mfumo wa faili chenye uharibifu ambacho hatimaye kilipakia **kext isiyo na saini**, **kikiuka Ulinzi wa Uthibitisho wa Mfumo (SIP)** na kuwezesha rootkits za kudumu. Imefanyiwa marekebisho katika macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Daemon ya usakinishaji yenye haki `com.apple.rootless.install` inaweza kutumika vibaya kutekeleza scripts za baada ya usakinishaji, kuzima SIP na kupakia kexts za kiholela.  |

**Mambo ya kujifunza kwa red-teamers**

1. **Tafuta daemons zenye haki (`codesign -dvv /path/bin | grep entitlements`) zinazoshirikiana na Disk Arbitration, Installer au Usimamizi wa Kext.**
2. **Kutumia SIP kikiuka karibu kila wakati kunatoa uwezo wa kupakia kext → utekelezaji wa msimbo wa kernel**.

**Vidokezo vya kujihami**

*Hifadhi SIP ikiwa imewezeshwa*, fuatilia `kmutil load`/`kmutil create -n aux` maombi yanayotoka kwa binaries zisizo za Apple na onyo juu ya maandiko yoyote kwenye `/Library/Extensions`. Matukio ya Usalama wa Kituo `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` yanatoa mwonekano wa karibu wa wakati halisi.

## Kurekebisha kernel ya macOS & kexts

Mchakato unaopendekezwa na Apple ni kujenga **Kernel Debug Kit (KDK)** inayolingana na toleo linalotumika na kisha kuunganisha **LLDB** kupitia kikao cha mtandao cha **KDP (Kernel Debugging Protocol)**.

### Kurekebisha mara moja kwa mahali pa paniki
```bash
# Create a symbolication bundle for the latest panic
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
4. Kwenye **host**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Kuunganisha LLDB na kext maalum iliyopakiwa
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP inatoa tu **interface ya kusoma pekee**. Kwa uhandisi wa dynamic utahitaji kubadilisha binary kwenye diski, kutumia **kernel function hooking** (mfano `mach_override`) au kuhamasisha dereva kwa **hypervisor** kwa ajili ya kusoma/kandika kamili.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
