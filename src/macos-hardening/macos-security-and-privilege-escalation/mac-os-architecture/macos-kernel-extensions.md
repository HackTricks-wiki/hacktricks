# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting

Kernel extensions (Kexts) is **pakkette** met ’n **`.kext`**-uitbreiding wat **direk in die macOS-kernelruimte gelaai word**, en wat addisionele funksionaliteit aan die hoofbedryfstelsel verskaf.

### Deprecation status & DriverKit / System Extensions
Vanaf **macOS Catalina (10.15)** het Apple die meeste legacy KPI's as *deprecated* gemerk en die **System Extensions & DriverKit**-frameworks bekendgestel, wat in **user-space** loop. Vanaf **macOS Big Sur (11)** sal die bedryfstelsel *weier om* third-party kexts te laai wat op deprecated KPI's staatmaak, tensy die masjien in **Reduced Security**-modus geboot word. Op Apple Silicon vereis die aktivering van kexts ook dat die gebruiker:

1. Herlaai na **Recovery** → *Startup Security Utility*.
2. Kies **Reduced Security** en merk **“Allow user management of kernel extensions from identified developers”**.
3. Herlaai en keur die kext goed vanaf **System Settings → Privacy & Security**.

User-land drivers wat met DriverKit/System Extensions geskryf is, **verminder die attack surface dramaties**, omdat crashes of geheuekorrupsie tot ’n sandboxed proses beperk word eerder as die kernelruimte.<sup>[1]</sup>

> 📝 Vanaf macOS Sequoia (15) het Apple verskeie legacy-netwerk- en USB-KPI's heeltemal verwyder – die enigste forward-compatible oplossing vir vendors is om na System Extensions te migreer.

### Vereistes

Dit is vanselfsprekend so kragtig dat dit **ingewikkeld is om ’n kernel extension te laai**. Dit is die **vereistes** waaraan ’n kernel extension moet voldoen om gelaai te word:

- Wanneer **recovery mode binnegegaan word**, moet kernel **extensions toegelaat word** om gelaai te word:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die kernel extension moet **onderteken wees met ’n kernel code signing certificate**, wat slegs **deur Apple toegestaan** kan word. Apple sal die maatskappy en die redes waarom dit benodig word, in detail hersien.
- Die kernel extension moet ook **notarized** wees; Apple sal dit vir malware kan nagaan.
- Dan is die **root**-gebruiker die een wat die **kernel extension kan laai**, en die lêers binne die pakket moet aan **root behoort**.
- Tydens die upload-proses moet die pakket in ’n **beskermde non-root-ligging** voorberei word: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement`-grant).
- Wanneer daar uiteindelik probeer word om dit te laai, sal die gebruiker [**’n bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) en, indien dit aanvaar word, moet die rekenaar **herbegin** word om dit te laai.

### Laaiproses

In Catalina was dit soos volg: Dit is interessant om daarop te let dat die **verifikasie**-proses in **userland** plaasvind. Slegs toepassings met die **`com.apple.private.security.kext-management`**-grant kan egter **die kernel versoek om ’n extension te laai**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **begin** die **verifikasie**-proses vir die laai van ’n extension
- Dit sal met **`kextd`** kommunikeer deur boodskappe via ’n **Mach service** te stuur.
2. **`kextd`** sal verskeie dinge nagaan, soos die **signature**
- Dit sal met **`syspolicyd`** kommunikeer om te **kontroleer** of die extension **gelaai kan word**.
3. **`syspolicyd`** sal die **gebruiker vra** indien die extension nie voorheen gelaai is nie.
- **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik vir die kernel kan **sê om** die extension te **laai**

Indien **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

### Enumerasie & bestuur (gelaaide kexts)

`kextstat` was die historiese tool, maar dit is in onlangse macOS-vrystellings **deprecated**. Die moderne interface is **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Ou sintaksis van vroeër is steeds beskikbaar vir verwysing:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` kan ook benut word om **die inhoud van ’n Kernel Collection (KC) te dump** of te verifieer dat ’n kext alle simboolafhanklikhede oplos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Alhoewel daar verwag word dat die kernel extensions in `/System/Library/Extensions/` sal wees, sal jy **geen binary** vind as jy na hierdie vouer gaan nie. Dit is as gevolg van die **kernelcache**, en om een `.kext` te reverse, moet jy ’n manier vind om dit te bekom.

Die **kernelcache** is ’n **voorafgekompileerde en voorafgekoppelde weergawe van die XNU-kernel**, saam met noodsaaklike toestel-**drivers** en **kernel extensions**. Dit word in ’n **gekomprimeerde** formaat gestoor en tydens die boot-up-proses in die geheue gedekomprimeer. Die kernelcache maak ’n **vinniger boot time** moontlik deur ’n gereed-om-te-loop-weergawe van die kernel en belangrike drivers beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins tydens boot-up aan die dinamiese laai en koppeling van hierdie komponente bestee sou word.

Die belangrikste voordele van die kernelcache is **laaispoed** en die feit dat alle modules voorafgekoppel is (geen load time impediment nie). En sodra alle modules voorafgekoppel is, kan KXLD uit die geheue verwyder word, sodat **XNU nie nuwe KEXTs kan laai nie.**

> [!TIP]
> Die [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota)-tool dekripteer Apple se AEA (Apple Encrypted Archive / AEA asset)-houers — die encrypted container format wat Apple vir OTA assets en sommige IPSW-onderdele gebruik — en kan die onderliggende .dmg/asset archive produseer wat jy dan met die verskafde aastuff tools kan ekstrakteer.


### Plaaslike Kernelcache

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. In macOS kan jy dit vind met: **`find / -name "kernelcache" 2>/dev/null`** \
In my geval het ek dit in macOS gevind by:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Vind ook hier die [**kernelcache van weergawe 14 met symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Die IMG4-lêerformaat is ’n container format wat Apple in sy iOS- en macOS-toestelle gebruik om firmware-komponente (soos **kernelcache**) veilig te **stoor en te verifieer**. Die IMG4-formaat bevat ’n header en verskeie tags wat verskillende stukke data inkapsel, insluitend die werklike payload (soos ’n kernel of bootloader), ’n signature en ’n stel manifest-eienskappe. Die formaat ondersteun cryptographic verification, wat die toestel in staat stel om die egtheid en integriteit van die firmware-komponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

- **Payload (IM4P)**:
- Dikwels gecomprimeer (LZFSE4, LZSS, …)
- Opsioneel encrypted
- **Manifest (IM4M)**:
- Bevat Signature
- Addisionele Key/Value dictionary
- **Restore Info (IM4R)**:
- Ook bekend as APNonce
- Verhoed replaying van sommige updates
- OPTIONAL: Gewoonlik word dit nie gevind nie

Dekompresseer die Kernelcache:
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

**`Disarm`** laat jou toe om funksies vanuit die kernelcache met behulp van matchers te symbolicate. Hierdie matchers is eenvoudig patroonreëls (tekslyne) wat vir disarm sê hoe om funksies, argumente en panic/log-stringe binne ’n binary te herken en outomaties te symbolicate.

Basies dui jy die string aan wat ’n funksie gebruik, en disarm sal dit vind en **symbolicate**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Gaan na /tmp/extracted waar disarm die filesets onttrek het
disarm -e filesets kernelcache.release.d23 # Onttrek altyd na /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Let daarop dat xnu.matchers eintlik 'n lêer met die matchers is
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
# Installeer ipsw-tool
brew install blacktop/tap/ipsw

# Onttrek slegs die kernelcache uit die IPSW
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
# Lys alle extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Kontroleer die extension vir symbols
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
# Skep 'n symbolication-bundel vir die jongste panic
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
# Identifiseer die laaiadres van die kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Heg aan
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
