# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Kernel extensions (Kexts) is **pakkette** met ’n **`.kext`**-uitbreiding wat **direk in die macOS kernel space gelaai word**, en addisionele funksionaliteit aan die hoofbedryfstelsel verskaf.

### Deprecation status & DriverKit / System Extensions
Vanaf **macOS Catalina (10.15)** het Apple die meeste legacy KPIs as *deprecated* gemerk en die **System Extensions & DriverKit**-frameworks bekendgestel, wat in **user-space** loop. Vanaf **macOS Big Sur (11)** sal die bedryfstelsel *weier om* derdeparty-kexts te laai wat op deprecated KPIs staatmaak, tensy die masjien in **Reduced Security**-modus gestart word. Op Apple Silicon vereis die aktivering van kexts addisioneel dat die gebruiker:

1. Herbegin in **Recovery** → *Startup Security Utility*.
2. Kies **Reduced Security** en merk **“Allow user management of kernel extensions from identified developers”**.
3. Herbegin en keur die kext goed vanaf **System Settings → Privacy & Security**.

User-land drivers wat met DriverKit/System Extensions geskryf is, **verminder die aanvaloppervlak** dramaties, omdat crashes of memory corruption beperk word tot ’n sandboxed proses eerder as kernel space.<sup>[[1]](#references)</sup>

> 📝 Vanaf macOS Sequoia (15) het Apple verskeie legacy networking- en USB-KPIs heeltemal verwyder – die enigste vorentoe-versoenbare oplossing vir vendors is om na System Extensions te migreer.

### Vereistes

Dit is vanselfsprekend so kragtig dat dit **ingewikkeld is om ’n kernel extension te laai**. Dit is die **vereistes** waaraan ’n kernel extension moet voldoen om gelaai te word:

- Wanneer **recovery mode binnegegaan word**, moet kernel **extensions toegelaat word om gelaai te word**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die kernel extension moet **met ’n kernel code signing certificate onderteken wees**, wat slegs **deur Apple toegestaan** kan word. Apple sal die maatskappy en die redes waarom dit benodig word, in detail hersien.
- Die kernel extension moet ook **genotarizeer** wees; Apple sal dit vir malware kan nagaan.
- Daarna is die **root**-gebruiker die een wat die **kernel extension kan laai**, en die lêers binne die pakket moet aan **root behoort**.
- Tydens die upload-proses moet die pakket in ’n **beskermde nie-root-ligging** voorberei word: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Wanneer daar uiteindelik gepoog word om dit te laai, sal die gebruiker [**’n bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) en, indien dit aanvaar word, moet die rekenaar **herbegin** word om dit te laai.

### Laaiproses

In Catalina was dit soos volg: Dit is interessant om daarop te let dat die **verifikasie**-proses in **userland** plaasvind. Slegs toepassings met die **`com.apple.private.security.kext-management`** grant kan egter **die kernel versoek om ’n extension te laai**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **begin** die **verifikasie**-proses om ’n extension te laai
- Dit sal met **`kextd`** kommunikeer deur ’n **Mach service** te gebruik.
2. **`kextd`** sal verskeie dinge nagaan, soos die **signature**
- Dit sal met **`syspolicyd`** kommunikeer om te **kontroleer** of die extension **gelaai kan word**.
3. **`syspolicyd`** sal die **gebruiker vra** indien die extension nie voorheen gelaai is nie.
- **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik vir die **kernel kan sê om** die extension te **laai**

Indien **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

### Enumerasie & bestuur (gelaaide kexts)

`kextstat` was die historiese hulpmiddel, maar dit is **deprecated** in onlangse macOS-vrystellings. Die moderne koppelvlak is **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Ouer sintaksis is steeds beskikbaar vir verwysing:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` kan ook ingespan word om die inhoud van ’n Kernel Collection (KC) te **dump** of te verifieer dat ’n kext alle simboolafhanklikhede oplos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Alhoewel daar verwag word dat die kernel extensions in `/System/Library/Extensions/` is, sal jy **geen binary** vind as jy na hierdie vouer gaan nie. Dit is as gevolg van die **kernelcache**, en om een `.kext` te reverse, moet jy ’n manier vind om dit te verkry.

Die **kernelcache** is ’n **vooraf-gecompileerde en vooraf-gelinkte weergawe van die XNU-kernel**, saam met noodsaaklike toestel-**drivers** en **kernel extensions**. Dit word in ’n **saamgeperste** formaat gestoor en tydens die boot-proses in geheue gedekomprimeer. Die kernelcache maak ’n **vinniger boottyd** moontlik deur ’n gereed-vir-uitvoering-weergawe van die kernel en belangrike drivers beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins aan die dinamiese laai en linking van hierdie komponente tydens boottyd bestee sou word.

Die belangrikste voordele van die kernelcache is **laaispoed** en die feit dat alle modules vooraf gelink is (geen laaityd-belemmering nie). En sodra alle modules vooraf gelink is, kan KXLD uit die geheue verwyder word, sodat **XNU nie nuwe KEXTs kan laai nie.**

> [!TIP]
> Die [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota)-tool dekripteer Apple se AEA (Apple Encrypted Archive / AEA asset)-houers — die geënkripteerde houerformaat wat Apple vir OTA-assets en sommige IPSW-dele gebruik — en kan die onderliggende .dmg/asset-argief genereer wat jy dan met die ingeslote aastuff-tools kan uitpak.


### Local Kerlnelcache

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; in macOS kan jy dit vind met: **`find / -name "kernelcache" 2>/dev/null`** \
In my geval het ek dit in macOS hier gevind:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Vind ook hier die [**kernelcache van weergawe 14 met symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Die IMG4-lêerformaat is ’n houerformaat wat Apple in sy iOS- en macOS-toestelle gebruik om firmware-komponente (soos **kernelcache**) veilig te **stoor en te verifieer**. Die IMG4-formaat sluit ’n header en verskeie tags in wat verskillende stukke data inkapsuleer, insluitend die werklike payload (soos ’n kernel of bootloader), ’n signature en ’n stel manifest-eienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel in staat stel om die egtheid en integriteit van die firmware-komponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

- **Payload (IM4P)**:
- Dikwels compressed (LZFSE4, LZSS, …)
- Opsioneel encrypted
- **Manifest (IM4M)**:
- Bevat Signature
- Addisionele Key/Value-dictionary
- **Restore Info (IM4R)**:
- Ook bekend as APNonce
- Voorkom die replay van sommige updates
- OPTIONAL: Dit word gewoonlik nie gevind nie

Decomprimeer die Kernelcache:
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
#### Disarm-simbole vir die kernel

**`Disarm`** laat jou toe om funksies vanaf die kernelcache met behulp van matchers te symboliseer. Hierdie matchers is bloot eenvoudige patroonreëls (teksreëls) wat disarm vertel hoe om funksies, argumente en panic/log-stringe binne ’n binary te herken en outomaties te simboliseer.

Basies dui jy die string aan wat ’n funksie gebruik, en disarm sal dit vind en **dit simboliseer**.

Jy kan sommige `xnu.matchers` by [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in die **`Matchers`**-afdeling vind. Jy kan ook jou eie matchers skep.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Aflaai

'n **IPSW (iPhone/iPad Software)** is Apple se firmware-pakketformaat wat vir toestelherstel, opdaterings en volledige firmware-bundels gebruik word. Dit bevat onder andere die **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) is dit moontlik om al die kernel debug kits te vind. Jy kan dit aflaai, mount, dit met die [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html)-tool oopmaak, toegang tot die **`.kext`**-lêergids verkry en dit **extract**.

Kontroleer dit vir symbols met:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Soms stel Apple **kernelcache** met **symbols** vry. Jy kan sommige firmwares met symbols aflaai deur die skakels op daardie bladsye te volg. Die firmwares sal onder andere die **kernelcache** bevat.

Om die kernel cache te **extract**, kan jy die volgende doen:
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
Nog ’n opsie om die lêers te **extract**, is om eers die uitbreiding van `.ipsw` na `.zip` te verander en dit te **unzip**.

Nadat die firmware geëxtract is, sal jy ’n lêer soos: **`kernelcache.release.iphone14`** kry. Dit is in **IMG4**-formaat; jy kan die interessante inligting met die volgende extract:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**: begaan?
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
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspeksie van kernelcache

Kontroleer of die kernelcache simbole bevat met
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Hiermee kan ons nou **al die uitbreidings onttrek** of die **een waarin jy belangstel:**
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
## Onlangse kwesbaarhede & exploitation techniques

| Jaar | CVE | Opsomming |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logikafout in **`storagekitd`** het ’n *root*-aanvaller toegelaat om ’n kwaadwillige lêerstelsel-bundel te registreer wat uiteindelik ’n **unsigned kext** gelaai het, **System Integrity Protection (SIP)** omseil het en volgehoue rootkits moontlik gemaak het. Gelap in macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon met die entitlement `com.apple.rootless.install` kon misbruik word om arbitrêre post-install scripts uit te voer, SIP te deaktiveer en arbitrêre kexts te laai. <sup>[[3]](#references)</sup> |

**Belangrike punte vir red-teamers**

1. **Soek na entitled daemons (`codesign -dvv /path/bin | grep entitlements`) wat met Disk Arbitration, Installer of Kext Management in wisselwerking tree.**
2. **Die misbruik van SIP bypasses verleen byna altyd die vermoë om ’n kext te laai → kernel code execution**.

**Defensiewe wenke**

*Hou SIP geaktiveer*, monitor vir `kmutil load`/`kmutil create -n aux`-invocations wat van nie-Apple-binaries afkomstig is en skep alerts vir enige skrywe na `/Library/Extensions`. Endpoint Security-events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` bied byna real-time sigbaarheid.

## Debugging van die macOS-kernel & kexts

Apple se aanbevole workflow is om ’n **Kernel Debug Kit (KDK)** te bou wat met die lopende build ooreenstem en dan **LLDB** oor ’n **KDP (Kernel Debugging Protocol)**-netwerksessie te koppel.

### Eenmalige plaaslike debug van ’n panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live remote debugging vanaf ’n ander Mac

1. Laai die presiese **KDK**-weergawe vir die teikenmasjien af en installeer dit.
2. Koppel die target Mac en die host Mac met ’n **USB-C- of Thunderbolt-kabel**.
3. Op die **target**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Op die **host**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Heg LLDB aan ’n spesifieke gelaaide kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP stel slegs ’n **read-only**-koppelvlak bloot. Vir dynamic instrumentation sal jy die binary op skyf moet patch, **kernel function hooking** moet gebruik (bv. `mach_override`), of die driver na ’n **hypervisor** moet migreer vir volledige read/write.

## Verwysings

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Ontleding van CVE-2024-44243, ’n macOS System Integrity Protection-bypass deur kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft ontdek nuwe macOS-kwesbaarheid, Shrootless, wat System Integrity Protection kan omseil - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
