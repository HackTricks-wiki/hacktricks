# macOS Kernel-uitbreidings & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Kernel extensions (Kexts) is **pakkette** met 'n **`.kext`** uitbreiding wat **direk in die macOS kernel-ruimte gelaai word**, en bykomende funksionaliteit aan die hoof-bedryfstelsel voorsien.

### Verouderingsstatus & DriverKit / System Extensions
Begin met **macOS Catalina (10.15)** het Apple die meeste erfenis-KPIs as *deprecated* gemerk en die **System Extensions & DriverKit** raamwerke bekendgestel wat in **user-space** loop. Vanaf **macOS Big Sur (11)** sal die bedryfstelsel *weier om te laai* derdeparty kexts wat op verouderde KPIs staatmaak, tensy die masjien in **Reduced Security** modus begin is. Op Apple Silicon vereis die aktivering van kexts bykomend dat die gebruiker:

1. Herbegin in **Recovery** → *Startup Security Utility*.
2. Kies **Reduced Security** en merk **“Allow user management of kernel extensions from identified developers”**.
3. Herbegin en keur die kext goed vanaf **System Settings → Privacy & Security**.

User-land drivers geskryf met DriverKit/System Extensions verminder dramaties die attack surface omdat crashes of geheuekorpsie tot 'n sandboxed proses beperk word in plaas van in kernel-ruimte.

> 📝 Vanaf macOS Sequoia (15) het Apple verskeie erfenis-netwerk- en USB-KPIs heeltemal verwyder – die enigste vorentoe-verenigbare oplossing vir verskaffers is om na System Extensions te migreer.

### Vereistes

Dit is natuurlik so kragtig dat dit **kompleks is om 'n kernel-uitbreiding te laai**. Dit is die **vereistes** wat 'n kernel-uitbreiding moet voldoen om gelaai te word:

- Wanneer **herstelmodus** betree word, moet kernel **uitbreidings toegelaat** word om gelaai te word:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die kernel-uitbreiding moet **onderteken wees met 'n kernel code signing certificate**, wat slegs deur Apple **toegewys** kan word. Apple sal die maatskappy en die redes in detail hersien.
- Die kernel-uitbreiding moet ook **notarized** wees; Apple sal dit vir malware kan nagaan.
- Dan is die **root** gebruiker die een wat die **kernel-uitbreiding kan laai** en die lêers binne die pakket moet **aan root behoort**.
- Tydens die oplaai-proses moet die pakket voorberei word in 'n **beskermde nie-root ligging**: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Laastens, wanneer daar gepoog word om dit te laai, sal die gebruiker [**'n bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) en, indien aanvaar, moet die rekenaar **herbegin** om dit te laai.

### Laaiproses

In Catalina was dit soos volg: Dit is interessant om op te let dat die **verifikasie** proses in **userland** plaasvind. Alleen toepassings met die **`com.apple.private.security.kext-management`** grant kan die **kernel versoek om 'n extensie te laai**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **begin** die **verifikasie** proses om 'n extensie te laai
- Dit sal met **`kextd`** kommunikeer deur 'n **Mach service** te gebruik.
2. **`kextd`** sal verskeie dinge nagaan, soos die **handtekening**
- Dit sal met **`syspolicyd`** kommunikeer om te **kontroleer** of die extensie gelaai kan word.
3. **`syspolicyd`** sal die **gebruiker** vra as die extensie nog nie voorheen gelaai is nie.
- **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik die kernel kan sê om die extensie te laai

As **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

### Enumerasie & bestuur (gelaaide kexts)

`kextstat` was die historiese instrument maar dit is **deprecated** in onlangse macOS-uitgawes. Die moderne koppelvlak is **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Ou sintaksis is steeds beskikbaar vir verwysing:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` kan ook gebruik word om **die inhoud van 'n Kernel Collection (KC) te dump** of te verifieer dat 'n kext alle simboolafhanklikhede oplos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Alhoewel die kernel extensions verwag word in `/System/Library/Extensions/`, as jy na hierdie gids gaan sal jy **geen binêre lêer vind nie**. Dit is as gevolg van die **kernelcache** en om een `.kext` te reverseer moet jy 'n manier vind om dit te bekom.

Die **kernelcache** is 'n **vooraf-gekompileerde en vooraf-gekoppelde weergawe van die XNU kernel**, saam met noodsaaklike toestel **drivers** en **kernel extensions**. Dit word in 'n **gekomprimeerde** formaat gestoor en word tydens die opstartproses na geheue gedekomprimeer. Die kernelcache fasiliteer 'n **sneller opstarttyd** deur 'n gereed-om-te-loop weergawe van die kernel en kritieke drivers beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins bestee sou word aan dinamiese laai en koppeling van hierdie komponente tydens opstart.

Die hoofvoordele van die kernelcache is die **laaispoed** en dat alle modules voorafgekoppel is (geen laaityd-vertraging nie). En omdat alle modules voorafgekoppel is, kan KXLD uit geheue verwyder word sodat **XNU nie nuwe KEXTs kan laai nie.**

> [!TIP]
> Die [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool ontsleutel Apple se AEA (Apple Encrypted Archive / AEA asset) houers — die geënkripteerde containerformaat wat Apple gebruik vir OTA-assets en sommige IPSW-stukke — en kan die onderliggende .dmg/asset-argief produseer wat jy dan met die verskafde aastuff tools kan uittrek.


### Lokale kernelcache

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS kan jy dit vind met: **`find / -name "kernelcache" 2>/dev/null`** \
In my geval in macOS het ek dit gevind in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Vind ook hier die [**kernelcache van weergawe 14 met simbole**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) gecomprimeer

Die IMG4-lêerformaat is 'n containerformaat wat Apple in sy iOS- en macOS-toestelle gebruik om firmwarekomponente (soos die **kernelcache**) veilig te **berg en te verifieer**. Die IMG4-formaat sluit 'n header en verskeie tags in wat verskillende datastukke inkapsuleer, insluitend die werklike payload (soos 'n kernel of bootloader), 'n handtekening, en 'n stel manifest-eienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel toelaat om die egtheid en integriteit van die firmwarekomponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

- **Payload (IM4P)**:
  - Dikwels gecomprimeer (LZFSE4, LZSS, …)
  - Opsioneel enkripteer
- **Manifest (IM4M)**:
  - Bevat handtekening
  - Bykomende sleutel/waarde-woordelys
- **Restore Info (IM4R)**:
  - Ook bekend as APNonce
  - Voorkom die herhaling van sekere opdaterings
  - OPSIONEEL: Gewoonlik nie gevind nie

Dekomprimeer die Kernelcache:
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
#### Disarm simbole vir die kernel

**`Disarm`** laat toe om functions uit die kernelcache te symbolicate met behulp van matchers.

Hierdie matchers is net eenvoudige pattern rules (text lines) wat disarm vertel hoe om functions, arguments en panic/log strings binne 'n binary te herken en outomaties te auto-symbolicate.

Basies dui jy die string aan wat 'n function gebruik en disarm sal dit vind en **symbolicate dit**.
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
# Installeer die ipsw-hulpmiddel
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
# Lys alle uitbreidings
kextex -l kernelcache.release.iphone14.e
## Onttrek com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Onttrek alles
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
# Skep 'n symbolikasiebundel vir die nuutste kernpaniek
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
# Identifiseer laaiadres van die kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Koppel
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
