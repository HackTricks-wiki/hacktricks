# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die I/O Kit is 'n oopbron, objekgeoriënteerde **toestelbestuurderraamwerk** in die XNU-kern, wat **dinamies gelaaide toestelbestuurders** hanteer. Dit laat modulêre kode toe om op die vlug by die kern gevoeg te word, met ondersteuning vir uiteenlopende hardeware.

IOKit-bestuurders sal basies **funksies vanuit die kern uitvoer**. Hierdie funksieparameter-**tipes** is **vooraf gedefinieer** en word geverifieer. Soortgelyk aan XPC is IOKit boonop net nog 'n laag **bo-op Mach-boodskappe**.

**IOKit XNU-kernkode** word deur Apple as oopbron beskikbaar gestel by [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Die IOKit-komponente in gebruikerspasie is ook as oopbron beskikbaar by [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Geen **IOKit-bestuurders** is egter as oopbron beskikbaar nie. Van tyd tot tyd kan 'n vrystelling van 'n bestuurder nietemin simbole bevat wat dit makliker maak om dit te debug. Kyk hier hoe om [**die bestuurderuitbreidings uit die firmware te kry**](#ipsw)**.**

Dit is in **C++** geskryf. Jy kan ontmangelde C++-simbole kry met:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **blootgestelde funksies** kan **bykomende sekuriteitskontroles** uitvoer wanneer 'n kliënt probeer om 'n funksie aan te roep, maar let daarop dat die toepassings gewoonlik deur die **sandbox** beperk word tot die IOKit-funksies waarmee hulle kan interaksie hê.

## Drivers

In macOS is hulle geleë in:

- **`/System/Library/Extensions`**
- KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
- **`/Library/Extensions`**
- KEXT-lêers wat deur derdeparty-sagteware geïnstalleer is.

In iOS is hulle geleë in:

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Tot en met nommer 9 word die gelyste drivers **in adres 0 gelaai**. Dit beteken dat dit nie werklike drivers is nie, maar **deel van die kernel en hulle kan nie afgelaai word nie**.

Om spesifieke extensions te vind, kan jy gebruik:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Om kernel extensions te laai en te ontlaai, doen:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** is ’n belangrike deel van die IOKit-raamwerk in macOS en iOS wat as ’n databasis dien om die stelsel se hardewarekonfigurasie en -toestand voor te stel. Dit is ’n **hiërargiese versameling objekte wat al die hardeware en drywers verteenwoordig** wat op die stelsel gelaai is, sowel as hul verhoudings tot mekaar.

Jy kan die IORegistry met die CLI **`ioreg`** verkry om dit vanaf die konsole te inspekteer (veral nuttig vir iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Jy kan **`IORegistryExplorer`** van **Xcode Additional Tools** by [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) aflaai en die **macOS IORegistry** deur ’n **grafiese** koppelvlak inspekteer.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer word "planes" gebruik om die verhoudings tussen verskillende objekte in die IORegistry te organiseer en te vertoon. Elke plane verteenwoordig ’n spesifieke tipe verhouding of ’n bepaalde aansig van die stelsel se hardeware- en bestuurderkonfigurasie. Hier is sommige van die algemene planes wat jy in IORegistryExplorer kan teëkom:

1. **IOService Plane**: Dit is die mees algemene plane en vertoon die diensobjekte wat bestuurders en nubs (kommunikasiekanale tussen bestuurders) verteenwoordig. Dit wys die provider-client-verhoudings tussen hierdie objekte.
2. **IODeviceTree Plane**: Hierdie plane verteenwoordig die fisiese verbindings tussen toestelle soos hulle aan die stelsel gekoppel is. Dit word dikwels gebruik om die hiërargie van toestelle wat via busse soos USB of PCI gekoppel is, te visualiseer.
3. **IOPower Plane**: Vertoon objekte en hul verhoudings met betrekking tot kragbestuur. Dit kan wys watter objekte die kragtoestand van ander beïnvloed, wat nuttig is vir die debugging van kragverwante probleme.
4. **IOUSB Plane**: Spesifiek gefokus op USB-toestelle en hul verhoudings, en wys die hiërargie van USB-hubs en gekoppelde toestelle.
5. **IOAudio Plane**: Hierdie plane word gebruik om oudiotoestelle en hul verhoudings binne die stelsel voor te stel.
6. ...

## Driver Comm Code Example

Die volgende kode koppel aan die IOKit-diens `YourServiceNameHere` en roep selector 0:

- Dit roep eers **`IOServiceMatching`** en **`IOServiceGetMatchingServices`** om die diens te verkry.
- Dit stel dan ’n verbinding op deur **`IOServiceOpen`** te roep.
- Laastens roep dit ’n funksie met **`IOConnectCallScalarMethod`**, wat selector 0 aandui (die selector is die nommer wat aan die funksie wat jy wil roep, toegeken is).

<details>
<summary>Example user-space call to a driver selector</summary>
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
</details>

Daar is **ander** funksies wat gebruik kan word om IOKit-funksies aan te roep, buiten **`IOConnectCallScalarMethod`**, soos **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reverse engineering van driver entrypoint

Jy kan hierdie byvoorbeeld uit ’n [**firmware image (ipsw)**](#ipsw) verkry. Laai dit dan in jou gunsteling decompiler.

Jy kan begin deur die **`externalMethod`**-funksie te decompile, aangesien dit die driver-funksie is wat die call sal ontvang en die korrekte funksie sal aanroep:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Daardie aaklige gedemanglede call beteken:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Let daarop dat die **`self`**-parameter in die vorige definisie ontbreek; die korrekte definisie sou wees:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Eintlik kan jy die werklike definisie vind by [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Met hierdie inligting kan jy Ctrl+Right -> `Edit function signature` herskryf en die bekende tipes stel:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Die nuwe gedecompileerde kode sal soos volg lyk:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Vir die volgende stap moet die **`IOExternalMethodDispatch2022`**-struct gedefinieer wees. Dit is opensource by [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176); jy kan dit definieer:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Nou, wanneer jy die `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` volg, kan jy baie data sien:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Verander die Data Type na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

na die verandering:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

En aangesien ons nou weet dat daar ’n **array van 7 elemente** is (kyk na die finale gedecompileerde kode), klik om ’n array van 7 elemente te skep:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nadat die array geskep is, kan jy al die uitgevoerde funksies sien:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy onthou, hoef ons nie die naam van die funksie te gebruik om ’n **exported** funksie vanuit user space te **call** nie, maar eerder die **selector number**. Hier kan jy sien dat selector **0** die funksie **`initializeDecoder`** is, selector **1** **`startDecoder`** is, selector **2** **`initializeEncoder`** is...

## Onlangse IOKit-aanvaloppervlak (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) het gewys dat ’n permissive `IOHIDSystem`-client HID-events kon gryp, selfs met secure input; maak seker dat `externalMethod`-handlers entitlements afdwing in plaas daarvan om slegs die user-client-tipe te gebruik.<sup>[[2]](#references)</sup>
- **IOGPUFamily memory corruption** – CVE-2024-44197 en CVE-2025-24257 het OOB-writes reggemaak wat bereikbaar was vanaf sandboxed apps wat malformed variable-length data na GPU-user clients stuur; die gewone bug is swak bounds rondom `IOConnectCallStructMethod`-arguments.<sup>[[1]](#references)</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) het bevestig dat HID-user clients steeds ’n sandbox-escape-vektor is; fuzz enige driver wat keyboard/event queues blootstel.<sup>[[3]](#references)</sup>

### Vinnige triage- en fuzzing-wenke

- Enumerate all external methods for a user client from userland to seed a fuzzer:
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- Let tydens reversing op `IOExternalMethodDispatch2022`-tellings. ’n Algemene bug-patroon in onlangse CVE's is inkonsekwente `structureInputSize`/`structureOutputSize` teenoor die werklike `copyin`-lengte, wat tot heap OOB in `IOConnectCallStructMethod` lei.
- Sandbox-bereikbaarheid hang steeds van entitlements af. Voordat jy tyd aan ’n target bestee, kontroleer of die kliënt vanaf ’n derdeparty-app toegelaat word:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Vir GPU/iomfb-bugs is dit dikwels voldoende om oorgroot skikkings deur `IOConnectCallMethod` te stuur om foutiewe grense te aktiveer. Minimale harness (selector X) om grootteverwarring te aktiveer:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Gebruikersruimte-bestuurders

### Basiese inligting

**DriverKit** is Apple se gebruikersruimte-vervanging vir kernel extensions (kexts), wat in macOS 10.15 bekendgestel is. DriverKit-binaries (`.dext`-bundels) loop as gebruikersruimteprosesse, maar kommunikeer direk met die kernel deur ’n bevoorregte IOKit-koppelvlak.

DriverKit-uitbreidings bestuur hardeware:
- **USB**-beheerders en -toestelle
- **Thunderbolt** / PCIe-toestelle
- **HID** (sleutelborde, muise, game controllers)
- **Audio**-hardeware
- **Networking**-koppelvlakke
- **Serial**- en **Block Storage**-toestelle

Anders as kexts (wat ’n selflaai met SIP gedeaktiveer of notarization vereis het), word DriverKit-uitbreidings deur `SystemExtensions.framework` geïnstalleer en vereis dit slegs **eenmalige gebruikergoedkeuring**.

### Ontdekking & enumerasie
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### Sekuriteitsimplikasies

> [!WARNING]
> DriverKit-binaries het ’n **direkte kommunikasiekanaal na die kernel**. Die stuur van misvormde boodskappe deur hierdie kanaal kan kernel-kwesbaarhede aktiveer. Elke driver registreer spesifieke user-client-klasse, en misvormde `IOConnectCallMethod`-aanroepe kan kernel-geheuekorrupsie veroorsaak.

**Aanvaloppervlak:**
1. **Kernel IOKit-boodskap-Fuzzing** — Elke DriverKit user-client stel selectors bloot wat vanuit user space aangeroep kan word. Misvormde argumente aktiveer kernel-foute.
2. **USB-toestel-spoofing** — ’n Gekompromitteerde USB DriverKit-binêre kan ’n kwaadwillige USB-toestelprofiel aanbied (byvoorbeeld om ’n sleutelbord vir HID-inspuiting na te boots).
3. **DMA-aanvalle** — PCIe/Thunderbolt DriverKit-uitbreidings het moontlik DMA-toegang tot fisiese geheue.
4. **Persistence** — Sodra dit as ’n stelseluitbreiding geïnstalleer is, bly DriverKit-binaries oor herlaaiings en programopdaterings heen voortbestaan.

### DriverKit IOKit User-Client Fuzzing
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### DriverKit CVEs

| CVE | Beskrywing |
|---|---|
| CVE-2022-26766 | DriverKit USB stack-kwesbaarheid — kernel code execution |
| CVE-2021-30838 | IOKit user-client type confusion in grafiese drivers |
| CVE-2024-44197 | IOGPUFamily OOB write via malformed DriverKit arguments |

## Verwysings

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799-opsomming](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
