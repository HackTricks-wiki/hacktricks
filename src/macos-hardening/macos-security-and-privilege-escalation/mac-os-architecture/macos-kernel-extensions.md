# macOS Kernuitbreidings & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Kernel extensions (Kexts) is **pakkette** met 'n **`.kext`** uitbreiding wat **direk in die macOS kernruimte gelaai** word en addisionele funksionaliteit aan die hoof bedryfstelsel verskaf.

### Depresiasie-status & DriverKit / System Extensions
Begin met **macOS Catalina (10.15)** het Apple die meeste ou KPI's as *verouderd* aangeteken en die **System Extensions & DriverKit** raamwerke bekendgestel wat in die **gebruikersruimte** loop. Vanaf **macOS Big Sur (11)** sal die bedryfstelsel *weier om te laai* derdeparty kexts wat op verouderde KPI's staatmaak, tensy die masjien in **Verminderde Sekuriteit** modus opstart. Op Apple Silicon vereis die inskakeling van kexts verder dat die gebruiker:

1. Herbegin na **Recovery** → *Startup Security Utility*.
2. Kies **Verminderde Sekuriteit** en merk **“Laat gebruikerbeheer van kernel-uitbreidings van geïdentifiseerde ontwikkelaars toe”**.
3. Herbegin en keur die kext goed vanaf **System Settings → Privacy & Security**.

Gebruiker-ruimte bestuurders wat met DriverKit/System Extensions geskryf is, verminder die aanvaloppervlak dramaties omdat ineenstortings of geheuekorrupsie tot 'n sandboxed proses beperk word eerder as die kernruimte.

> 📝 Vanaf macOS Sequoia (15) het Apple verskeie ou netwerk- en USB-KPIs heeltemal verwyder – die enigste vorentoe-kompatibele oplossing vir verskaffers is om na System Extensions te migreer.

### Vereistes

Natuurlik is dit so kragtig dat dit **komplekse is om 'n kerneluitbreiding te laai**. Dit is die **vereistes** wat 'n kerneluitbreiding moet voldoen om gelaai te word:

- Wanneer daar in **recovery mode** ingegaan word, moet kernel **uitbreidings toegelaat** word om gelaai te word:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die kerneluitbreiding moet **onderteken wees met 'n kernel code signing sertifikaat**, wat slegs deur Apple **toegekend** kan word. Apple sal die maatskappy en die redes waarom dit nodig is in detail hersien.
- Die kerneluitbreiding moet ook **notarized** wees; Apple sal dit vir malware kan nagaan.
- Dan is die **root** gebruiker die een wat die **kerneluitbreiding kan laai** en die lêers binne die pakket moet **aan root behoort**.
- Tydens die oplaai-proses moet die pakket in 'n **beskermde non-root ligging** voorberei word: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` toekenning).
- Laastens, wanneer daar probeer word om dit te laai, sal die gebruiker [**'n bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) en, indien aanvaar, moet die rekenaar **herbegin** om dit te laai.

### Laaiprogram

In Catalina het dit so gegaan: Dit is interessant om op te let dat die **verifikasie** proses in die **gebruikersruimte** plaasvind. Slegs toepassings met die **`com.apple.private.security.kext-management`** grant kan egter die **kern versoek om 'n uitbreiding te laai**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **begin** die **verifikasie** proses om 'n uitbreiding te laai
- Dit sal met **`kextd`** kommunikeer deur 'n **Mach service** te gebruik.
2. **`kextd`** sal verskeie dinge nagaan, soos die **handtekening**
- Dit sal met **`syspolicyd`** praat om te **kontroleer** of die uitbreiding gelaai kan word.
3. **`syspolicyd`** sal die **gebruiker** aanroep indien die uitbreiding nie voorheen gelaai is nie.
- **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik die kern kan vertel om die uitbreiding te **laai**

Indien **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

### Opsomming & bestuur (gelaaide kexts)

`kextstat` was die historiese hulpmiddel maar dit is in onlangse macOS vrystellings **verouderd**. Die moderne koppelvlak is **`kmutil`**:
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
`kmutil inspect` kan ook gebruik word om **dump the contents of a Kernel Collection (KC)** of om te verifieer dat 'n kext resolve all symbol dependencies:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Alhoewel die kernel extensions verwag word om in `/System/Library/Extensions/` te wees, as jy na hierdie vouer gaan sal jy **nie 'n binaire vind nie**. Dit is te wyte aan die **kernelcache** en om een `.kext` te reverseer moet jy 'n manier vind om dit te bekom.

Die **kernelcache** is 'n **pre-compiled and pre-linked version of the XNU kernel**, tesame met noodsaaklike toestel **drivers** en **kernel extensions**. Dit word in 'n **gekomprimeerde** formaat gestoor en word tydens die opstartproses in geheue gedekomprimeer. Die kernelcache bevorder 'n **vinniger opstarttyd** deur 'n gereed-om-te-hardloop weergawe van die kern en belangrike drivers beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins bestee sou word aan dinamiese laai en linking van hierdie komponente tydens opstart.

Die hoofvoordele van die kernelcache is 'n **sneller laai** en dat alle modules voorafgekoppel is (geen laaityd-belemmering). En sodra alle modules voorafgekoppel is, kan KXLD uit die geheue verwyder word sodat **XNU nie nuwe KEXTs kan laai nie.**

> [!TIP]
> Die [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool ontsleutel Apple se AEA (Apple Encrypted Archive / AEA asset) houers — die geënkripteerde houerformaat wat Apple vir OTA-assets en sommige IPSW-delen gebruik — en kan die onderliggende .dmg/asset-argief produseer wat jy dan met die verskafde aastuff tools kan uittrek.


### Lokale Kernelcache

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; in macOS kan jy dit vind met: **`find / -name "kernelcache" 2>/dev/null`** \
In my geval op macOS het ek dit gevind in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Vind ook hier die [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Die IMG4-lêerformaat is 'n houerformaat wat deur Apple in sy iOS- en macOS-toestelle gebruik word om firmware-komponente (soos **kernelcache**) veilig te stoor en te verifieer. Die IMG4-formaat sluit 'n header en verskeie tags in wat verskillende datastukke omsluit, insluitend die werklike payload (soos 'n kernel of bootloader), 'n handtekening, en 'n stel manifest-eienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel in staat stel om die egtheid en integriteit van die firmware-komponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

- **Payload (IM4P)**:
- Dikwels gecomprimeer (LZFSE4, LZSS, …)
- Opsioneel versleuteld
- **Manifest (IM4M)**:
- Bevat handtekening
- Bykomende sleutel/waarde-woordeboek
- **Restore Info (IM4R)**:
- Ook bekend as APNonce
- Verhoed die herhaling van sekere opdaterings
- OPSIONEEL: Gewoonlik nie teenwoordig nie

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
#### Disarm-simbole vir die kernel

**`Disarm`** laat toe om funksies uit die kernelcache te symbolicate deur matchers te gebruik. Hierdie matchers is net eenvoudige patroonreëls (teksreëls) wat disarm vertel hoe om funksies, argumente en panic/log-stringe binne 'n binêre te herken en outomaties te symbolicate.

So basies dui jy die string aan wat 'n funksie gebruik en disarm sal dit vind en **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Gaan na /tmp/extracted waar disarm die filesets uitgepak het
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
# Installeer die ipsw-gereedskap
brew install blacktop/tap/ipsw

# Haal slegs die kernelcache uit die IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Jy behoort iets soos die volgende te kry:
#   out/Firmware/kernelcache.release.iPhoneXX
#   of 'n IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# As jy 'n IMG4 payload kry:
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
# Lys alle uitbreidings
kextex -l kernelcache.release.iphone14.e
## Uittrek com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Uittrek alles
kextex_all kernelcache.release.iphone14.e

# Kontroleer die uitbreiding vir simbole
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
# Skep 'n simbolikasiebundel vir die nuutste panic
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
(lldb) bt  # kry backtrace in kernel konteks
```

### Attaching LLDB to a specific loaded kext

```bash
# Identifiseer die laaiadres van die kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Koppel
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
