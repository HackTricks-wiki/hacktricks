# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) ni **packages** zenye **`.kext`** extension ambazo zinapakiwa moja kwa moja kwenye **macOS kernel space**, zikitoa kazi za ziada kwa mfumo mkuu wa uendeshaji.

### Requirements

Kwa wazi, hii ni nguvu sana kiasi kwamba ni **ngumu kupakia kernel extension**. Hizi ndizo **requirements** ambazo kernel extension lazima ikidhi ili ipakie:

- Wakati wa **kuingia kwenye recovery mode**, kernel **extensions lazima ziaruhusiwe** kupakiwa:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension lazima iwe **signed with a kernel code signing certificate**, ambayo inaweza tu **kupewa na Apple**. Nani atakayeangalia kwa undani kampuni na sababu zinazohitajika.
- Kernel extension lazima pia iwe **notarized**, Apple itakuwa na uwezo wa kuangalia kwa malware.
- Kisha, mtumiaji wa **root** ndiye anayeweza **kupakia kernel extension** na faili ndani ya package lazima **zihusiane na root**.
- Wakati wa mchakato wa kupakia, package lazima iwe tayari katika **mahali salama yasiyo ya root**: `/Library/StagedExtensions` (inahitaji `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Hatimaye, wakati wa kujaribu kuipakia, mtumiaji atapokea [**ombile la uthibitisho**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) na, ikiwa itakubaliwa, kompyuta lazima **irejeshwe** ili kuipakia.

### Loading process

Katika Catalina ilikuwa hivi: Ni muhimu kutaja kwamba mchakato wa **verification** unafanyika katika **userland**. Hata hivyo, ni programu pekee zenye **`com.apple.private.security.kext-management`** grant zinaweza **kuomba kernel kupakia extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inaanza** mchakato wa **verification** wa kupakia extension
- Itazungumza na **`kextd`** kwa kutuma kwa kutumia **Mach service**.
2. **`kextd`** itakagua mambo kadhaa, kama vile **signature**
- Itazungumza na **`syspolicyd`** ili **kuangalia** ikiwa extension inaweza **kupakiwa**.
3. **`syspolicyd`** itamwomba **mtumiaji** ikiwa extension haijawahi kupakiwa hapo awali.
- **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. **`kextd`** hatimaye itakuwa na uwezo wa **kueleza kernel kupakia** extension

Ikiwa **`kextd`** haipatikani, **`kextutil`** inaweza kufanya ukaguzi sawa.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> Ingawa nyongeza za kernel zinatarajiwa kuwa katika `/System/Library/Extensions/`, ukitembelea folda hii **hutapata binary yoyote**. Hii ni kwa sababu ya **kernelcache** na ili kubadilisha moja ya `.kext` unahitaji kupata njia ya kuipata.

**Kernelcache** ni **toleo lililotayarishwa na kuunganishwa la kernel ya XNU**, pamoja na **madereva** muhimu na **nyongeza za kernel**. Inahifadhiwa katika muundo wa **kushinikizwa** na inachukuliwa kutoka kwenye kumbukumbu wakati wa mchakato wa kuanzisha. Kernelcache inarahisisha **wakati wa kuanzisha haraka** kwa kuwa na toleo lililo tayari la kernel na madereva muhimu yanapatikana, kupunguza muda na rasilimali ambazo zingetumika kwa kupakia na kuunganisha vipengele hivi kwa wakati wa kuanzisha.

### Local Kerlnelcache

Katika iOS inapatikana katika **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** katika macOS unaweza kuipata kwa: **`find / -name "kernelcache" 2>/dev/null`** \
Katika kesi yangu katika macOS niliipata katika:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Muundo wa faili ya IMG4 ni muundo wa kontena unaotumiwa na Apple katika vifaa vyake vya iOS na macOS kwa ajili ya **kuhifadhi na kuthibitisha** vipengele vya firmware kwa usalama (kama **kernelcache**). Muundo wa IMG4 unajumuisha kichwa na lebo kadhaa ambazo zinafunga vipande tofauti vya data ikiwa ni pamoja na mzigo halisi (kama kernel au bootloader), saini, na seti ya mali za manifest. Muundo huu unasaidia uthibitishaji wa kificho, kuruhusu kifaa kuthibitisha ukweli na uadilifu wa kipengele cha firmware kabla ya kukitekeleza.

Kwa kawaida unajumuisha vipengele vifuatavyo:

- **Payload (IM4P)**:
- Mara nyingi inashinikizwa (LZFSE4, LZSS, …)
- Inaweza kuwa na usimbuaji
- **Manifest (IM4M)**:
- Inajumuisha Saini
- Kamusi ya Kifunguo/Thamani ya ziada
- **Restore Info (IM4R)**:
- Pia inajulikana kama APNonce
- Inazuia kurudiwa kwa baadhi ya masasisho
- HIARI: Kwa kawaida hii haipatikani

Fungua Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Pakua&#x20;

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Katika [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) inawezekana kupata vifaa vyote vya ufuatiliaji wa kernel. Unaweza kuvipakua, kuvifunga, kuvifungua kwa kutumia chombo cha [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), kufikia folda ya **`.kext`** na **kuvitoa**.

Angalia kwa alama na:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Wakati mwingine Apple inatoa **kernelcache** pamoja na **symbols**. Unaweza kupakua firmware kadhaa zenye symbols kwa kufuata viungo kwenye kurasa hizo. Firmware zitakuwa na **kernelcache** pamoja na faili nyingine.

Ili **extract** faili, anza kwa kubadilisha kiendelezi kutoka `.ipsw` hadi `.zip` na **unzip**.

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
## Urekebishaji

## Marejeleo

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
