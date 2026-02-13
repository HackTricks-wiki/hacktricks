# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die I/O Kit is 'n open-source, objektgeoriënteerde **toestelbestuurderraamwerk** in die XNU-kern en hanteer **dynamies gelaaide toestelbestuurders**. Dit laat modulêre kode toe om op die vlieg by die kern gevoeg te word en ondersteun uiteenlopende hardeware.

IOKit-drivers sal basies **funksies vanaf die kern eksporteer**. Hierdie funksieparameter **tipes** is **vooraf gedefinieer** en word geverifieer. Boonop, soortgelyk aan XPC, is IOKit net nog 'n laag op **Mach-boodskappe**.

**IOKit XNU kernel code** is deur Apple as open source beskikbaar gestel in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Verder is die user space IOKit-komponente ook open source by [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Daar is egter **geen IOKit drivers** wat open source is nie. Van tyd tot tyd kan 'n vrystelling van 'n bestuurder egter simbole bevat wat dit makliker maak om dit te debug. Check how to [**get the driver extensions from the firmware here**](#ipsw)**.**

Dit is geskryf in **C++**. Jy kan gedemanglede C++-simbolle kry met:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** kan **addisionele sekuriteitskontroles** uitvoer wanneer 'n client probeer om 'n funksie aan te roep, maar let daarop dat die apps gewoonlik deur die **sandbox** beperk is tot watter IOKit-funksies hulle kan gebruik.

## Drivers

Op macOS is hulle geleë in:

- **`/System/Library/Extensions`**
- KEXT files ingebou in die OS X-bedryfstelsel.
- **`/Library/Extensions`**
- KEXT files geïnstalleer deur 3rd party software

Op iOS is hulle geleë in:

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
Tot en met nommer 9 is die gelysde bestuurders **gelaai by adres 0**. Dit beteken dat dit nie werklike bestuurders is nie, maar deel van die kernel is en nie ontlaai kan word nie.

Om spesifieke uitbreidings te vind, kan jy gebruik:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Om kernuitbreidings te laai en te ontlaai, doen:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** is 'n kritieke deel van die IOKit-framework in macOS en iOS wat dien as 'n databasis om die stelsel se hardewarekonfigurasie en -status voor te stel. Dit is 'n **hiërargiese versameling van objekte wat al die hardeware en drywers voorstel** wat op die stelsel gelaai is, en hul verhoudings tot mekaar.

Jy kan die IORegistry kry met die cli **`ioreg`** om dit vanaf die konsole te inspekteer (veral nuttig vir iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Jy kan **`IORegistryExplorer`** aflaai vanaf **Xcode Additional Tools** by [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) en die **macOS IORegistry** deur 'n **grafiese** koppelvlak inspekteer.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer word "planes" gebruik om die verhoudings tussen verskillende objekte in die IORegistry te organiseer en te vertoon. Elke plane verteenwoordig 'n spesifieke tipe verhouding of 'n bepaalde aansig van die stelsel se hardeware- en bestuurderkonfigurasie. Hier is 'n paar van die algemene planes wat jy in IORegistryExplorer kan teëkom:

1. **IOService Plane**: Dit is die mees algemene plane; dit vertoon die service-objekte wat drivers en nubs (kommunikasiekanale tussen drivers) verteenwoordig. Dit wys die verskaffer-klient-verhoudings tussen hierdie objekte.
2. **IODeviceTree Plane**: Hierdie plane verteenwoordig die fisiese verbindings tussen toestelle soos hulle aan die stelsel geheg is. Dit word dikwels gebruik om die hiërargie van toestelle wat deur busse soos USB of PCI verbind is, te visualiseer.
3. **IOPower Plane**: Toont objekte en hul verhoudings rakende kragbestuur. Dit kan wys watter objekte die kragstatus van ander beïnvloed, nuttig vir foutopsporing van kragverwante probleme.
4. **IOUSB Plane**: Spesifiek gefokus op USB-toestelle en hul verhoudings, wat die hiërargie van USB-hubs en gekoppelde toestelle wys.
5. **IOAudio Plane**: Hierdie plane verteenwoordig audio-toestelle en hul verhoudings binne die stelsel.
6. ...

## Driver Comm-kodevoorbeeld

Die volgende kode koppel aan die IOKit-diens `YourServiceNameHere` en roep selector 0 aan:

- Eerstens roep dit **`IOServiceMatching`** en **`IOServiceGetMatchingServices`** aan om die diens te kry.
- Dit stel dan 'n verbinding op deur **`IOServiceOpen`** aan te roep.
- En uiteindelik roep dit 'n funksie aan met **`IOConnectCallScalarMethod`** wat die selector 0 aandui (die selector is die nommer wat aan die funksie wat jy wil aanroep toegewys is).

<details>
<summary>Voorbeeld van 'n gebruikersruimte-oproep na 'n driver-selector</summary>
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

Daar is **ander** funksies wat gebruik kan word om IOKit funksies aan te roep behalwe **`IOConnectCallScalarMethod`** soos **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Omkeer-analise van die bestuurder se ingangspunt

Jy kan hierdie byvoorbeeld verkry uit 'n [**firmware image (ipsw)**](#ipsw). Laai dit dan in jou gunsteling decompiler.

Begin met die dekompilering van die **`externalMethod`** funksie, aangesien dit die bestuurderfunksie is wat die oproep sal ontvang en die korrekte funksie sal aanroep:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Daardie afskuwelike gedemanglede oproep beteken:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Let op hoe in die vorige definisie die **`self`**-parameter ontbreek; die korrekte definisie sou wees:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
In werklikheid kan jy die werklike definisie by [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Met hierdie inligting kan jy Ctrl+Right -> `Edit function signature` herskryf en die bekende tipes stel:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Die nuwe gedecompileerde kode sal soos volg lyk:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Vir die volgende stap moet ons die **`IOExternalMethodDispatch2022`** struct gedefinieer hê. Dit is opensource in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), jy kan dit definieer:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Nou, as jy die `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` volg, sien jy baie data:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Verander die Data Type na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

na die verandering:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

En soos ons nou daar is het ons 'n **array of 7 elements** (kyk die finale gedecompileerde kode), klik om 'n array of 7 elements te skep:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nadat die array geskep is, kan jy al die exported functions sien:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Indien jy onthou: om 'n **exported** function vanaf user space te call, hoef ons nie die funksienaam te gebruik nie, maar die **selector number**. Hier sien jy dat selector **0** die function **`initializeDecoder`** is, selector **1** is **`startDecoder`**, selector **2** is **`initializeEncoder`**...

## Onlangse IOKit attack surface (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) het getoon dat 'n permissive `IOHIDSystem` client HID events kon gryp selfs met secure input; verseker dat `externalMethod` handlers entitlements afdwing in plaas van slegs die user-client type.
- **IOGPUFamily memory corruption** – CVE-2024-44197 en CVE-2025-24257 het OOB writes reggestel wat bereikbaar was vanaf sandboxed apps wat malformed variable-length data aan GPU user clients deurgee; die gewone fout is swak bounds rondom `IOConnectCallStructMethod` arguments.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) het bevestig dat HID user clients steeds 'n sandbox-escape vector is; fuzz enige driver wat keyboard/event queues blootstel.

### Vinnige triage & fuzzing wenke

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
- Wanneer jy reversing doen, let op die `IOExternalMethodDispatch2022` aantalle.
- ’n Algemene foutpatroon in onlangse CVEs is onsamehangende `structureInputSize`/`structureOutputSize` teenoor die werklike `copyin` lengte, wat lei tot heap OOB in `IOConnectCallStructMethod`.
- Sandbox reachability hang steeds af van entitlements. Voordat jy tyd aan ’n teiken bestee, kontroleer of die client vanaf ’n third‑party app toegelaat is:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Vir GPU/iomfb bugs is dit dikwels genoeg om oorgrootte arrays deur `IOConnectCallMethod` te stuur om bad bounds te trigger. Minimal harness (selector X) om size confusion te trigger:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Verwysings

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
