# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Kernel uitbreidings (Kexts) is **pakkette** met 'n **`.kext`** uitbreiding wat **direk in die macOS kernel ruimte gelaai word**, wat bykomende funksionaliteit aan die hoofbedryfstelsel bied.

### Deprecasie status & DriverKit / Stelsel Uitbreidings
Begin met **macOS Catalina (10.15)** het Apple die meeste ou KPIs as *verouderd* gemerk en die **Stelsel Uitbreidings & DriverKit** raamwerke bekendgestel wat in **gebruikersruimte** loop. Vanaf **macOS Big Sur (11)** sal die bedryfstelsel *weier om* derdeparty kexts te laai wat op verouderde KPIs staatmaak, tensy die masjien in **Verminderde Sekuriteit** modus geboot word. Op Apple Silicon vereis die inskakeling van kexts ook dat die gebruiker:

1. Herbegin in **Herstel** → *Opstart Sekuriteit Nutsgoed*.
2. Kies **Verminderde Sekuriteit** en merk **“Laat gebruikersbestuur van kernel uitbreidings van geïdentifiseerde ontwikkelaars toe”**.
3. Herbegin en keur die kext goed van **Stelselinstellings → Privaatheid & Sekuriteit**.

Gebruikersland bestuurders wat met DriverKit/Stelsel Uitbreidings geskryf is, **verlaag aansienlik die aanvaloppervlak** omdat crashes of geheuebesoedeling beperk is tot 'n sandboxed proses eerder as kernel ruimte.

> 📝 Vanaf macOS Sequoia (15) het Apple verskeie ou netwerk- en USB KPIs heeltemal verwyder – die enigste vooruit-compatibele oplossing vir verskaffers is om na Stelsel Uitbreidings te migreer.

### Vereistes

Dit is duidelik dat dit so kragtig is dat dit **komplikasies het om 'n kernel uitbreiding te laai**. Dit is die **vereistes** waaraan 'n kernel uitbreiding moet voldoen om gelaai te word:

- Wanneer **herstelmodus betree word**, moet kernel **uitbreidings toegelaat word** om gelaai te word:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die kernel uitbreiding moet **onderteken wees met 'n kernel kode ondertekeningssertifikaat**, wat slegs **deur Apple** toegestaan kan word. Wie die maatskappy en die redes waarom dit nodig is, in detail sal hersien.
- Die kernel uitbreiding moet ook **genotarieer** wees, Apple sal dit vir malware kan nagaan.
- Dan is die **root** gebruiker die een wat die **kernel uitbreiding kan laai** en die lêers binne die pakkie moet **aan root behoort**.
- Tydens die oplaadproses moet die pakkie in 'n **beskermde nie-root ligging** voorberei word: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Laastens, wanneer daar probeer word om dit te laai, sal die gebruiker [**'n bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) en, indien aanvaar, moet die rekenaar **herbegin** om dit te laai.

### Laai proses

In Catalina was dit soos volg: Dit is interessant om op te let dat die **verifikasie** proses in **gebruikersland** plaasvind. egter, slegs toepassings met die **`com.apple.private.security.kext-management`** grant kan **die kernel vra om 'n uitbreiding te laai**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **begin** die **verifikasie** proses om 'n uitbreiding te laai
- Dit sal met **`kextd`** praat deur 'n **Mach diens** te gebruik.
2. **`kextd`** sal verskeie dinge nagaan, soos die **handtekening**
- Dit sal met **`syspolicyd`** praat om te **kontroleer** of die uitbreiding **gelaai kan word**.
3. **`syspolicyd`** sal die **gebruiker** **vra** as die uitbreiding nie voorheen gelaai is nie.
- **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik in staat wees om die kernel te **vertel om** die uitbreiding te laai

As **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

### Enumerasie & bestuur (gelaaide kexts)

`kextstat` was die historiese hulpmiddel, maar dit is **verouderd** in onlangse macOS vrystellings. Die moderne koppelvlak is **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Oudere sintaksis is steeds beskikbaar vir verwysing:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` kan ook gebruik word om **die inhoud van 'n Kernel Collection (KC)' te dump of te verifieer dat 'n kext al die simbool afhanklikhede oplos:**
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Alhoewel die kernel uitbreidings verwag word om in `/System/Library/Extensions/` te wees, as jy na hierdie gids gaan, **sal jy geen binêre vind**. Dit is as gevolg van die **kernelcache** en om een `.kext` te reverse, moet jy 'n manier vind om dit te verkry.

Die **kernelcache** is 'n **vooraf-gecompileerde en vooraf-gekoppelde weergawe van die XNU-kern**, saam met noodsaaklike toestel **drywers** en **kernel uitbreidings**. Dit word in 'n **gecomprimeerde** formaat gestoor en word tydens die opstartproses in geheue gedecomprimeer. Die kernelcache fasiliteer 'n **sneller opstarttyd** deur 'n gereed-om-te-loop weergawe van die kern en belangrike drywers beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins aan die dinamiese laai en koppeling van hierdie komponente tydens opstart bestee sou word.

### Plaaslike Kernelcache

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS kan jy dit vind met: **`find / -name "kernelcache" 2>/dev/null`** \
In my geval in macOS het ek dit gevind in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Die IMG4 lêerformaat is 'n houerformaat wat deur Apple in sy iOS en macOS toestelle gebruik word om firmware komponente (soos **kernelcache**) veilig te **stoor en te verifieer**. Die IMG4 formaat sluit 'n kop en verskeie etikette in wat verskillende stukke data kapsuleer, insluitend die werklike payload (soos 'n kern of opstartlader), 'n handtekening, en 'n stel manifest eienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel toelaat om die egtheid en integriteit van die firmware komponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

- **Payload (IM4P)**:
- Gereeld gecomprimeer (LZFSE4, LZSS, …)
- Opsioneel versleuteld
- **Manifest (IM4M)**:
- Bevat Handtekening
- Bykomende Sleutel/Waarde woordeboek
- **Herstel Inligting (IM4R)**:
- Ook bekend as APNonce
- Voorkom die herhaling van sommige opdaterings
- OPSIONEEL: Gewoonlik word dit nie gevind nie

Decompress die Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Laai Af

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) is dit moontlik om al die kernel debug kits te vind. Jy kan dit aflaai, monteer, dit oopmaak met die [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) hulpmiddel, toegang verkry tot die **`.kext`** gids en **uitpak**.

Kontroleer dit vir simbole met:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Soms stel Apple **kernelcache** met **symbols** vry. Jy kan sommige firmware met symbols aflaai deur die skakels op daardie bladsye te volg. Die firmware sal die **kernelcache** saam met ander lêers bevat.

Om die lêers te **onttrek**, begin deur die uitbreiding van `.ipsw` na `.zip` te verander en dit te **ontzip**.

Na die onttrekking van die firmware sal jy 'n lêer soos: **`kernelcache.release.iphone14`** kry. Dit is in **IMG4** formaat, jy kan die interessante inligting onttrek met:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

Kontroleer of die kernelcache simbole het met
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Met hierdie kan ons nou **alle die uitbreidings** of die **een waarin jy belangstel:**
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
## Onlangs kwesbaarhede & uitbuitingstegnieke

| Jaar | CVE | Samevatting |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logika fout in **`storagekitd`** het 'n *root* aanvaller toegelaat om 'n kwaadwillige lêerstelsel bundel te registreer wat uiteindelik 'n **ongetekende kext** gelaai het, **wat die Stelselintegriteitbeskerming (SIP)** omseil en volgehoue rootkits moontlik maak. Gepatch in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installasie daemon met die regte `com.apple.rootless.install` kon misbruik word om arbitrêre post-installasie skripte uit te voer, SIP te deaktiveer en arbitrêre kexts te laai.  |

**Neem-aways vir rooi-spanne**

1. **Soek na bevoegde daemons (`codesign -dvv /path/bin | grep entitlements`) wat met Disk Arbitration, Installer of Kext Bestuur interaksie het.**
2. **Die misbruik van SIP omseilings bied byna altyd die vermoë om 'n kext te laai → kernkode-uitvoering**.

**Verdedigende wenke**

*Hou SIP ingeskakel*, monitor vir `kmutil load`/`kmutil create -n aux` aanroepings wat van nie-Apple binaries kom en waarsku oor enige skrywe na `/Library/Extensions`. Eindpunt Sekuriteit gebeurtenisse `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` bied byna regte tydsigbaarheid.

## Foutopsporing van macOS kern & kexts

Apple se aanbevole werksvloei is om 'n **Kernel Debug Kit (KDK)** te bou wat ooreenstem met die lopende weergawe en dan **LLDB** oor 'n **KDP (Kernel Debugging Protocol)** netwerk sessie aan te sluit.

### Eenmalige plaaslike foutopsporing van 'n paniek
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Leef afstandsdebugin van 'n ander Mac

1. Laai af + installeer die presiese **KDK** weergawe vir die teiken masjien.
2. Koppel die teiken Mac en die gasheer Mac met 'n **USB-C of Thunderbolt-kabel**.
3. Op die **teiken**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Op die **gasheer**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Om LLDB aan 'n spesifieke gelaaide kext te heg
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP stel slegs 'n **lees-slegs** koppelvlak beskikbaar. Vir dinamiese instrumentering sal jy die binêre op-disk moet patch, **kernel funksie hooking** benut (bv. `mach_override`) of die bestuurder na 'n **hypervisor** migreer vir volle lees/skryf.

## References

- DriverKit Sekuriteit – Apple Platform Sekuriteitsgids
- Microsoft Sekuriteitsblog – *Analiseer CVE-2024-44243 SIP omseiling*

{{#include ../../../banners/hacktricks-training.md}}
