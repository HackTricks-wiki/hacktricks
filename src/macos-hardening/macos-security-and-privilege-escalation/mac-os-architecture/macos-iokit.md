# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die I/O Kit is 'n oopbron, objek-georiënteerde **toestuurder-raamwerk** in die XNU-kern, wat **dynamies gelaaide toestel bestuurders** hanteer. Dit laat modulaire kode toe om aan die kern bygevoeg te word terwyl dit loop, wat verskillende hardeware ondersteun.

IOKit bestuurders sal basies **funksies uit die kern** **eksporteer**. Hierdie funksieparameter **tipes** is **vooraf gedefinieer** en word geverifieer. Boonop, soortgelyk aan XPC, is IOKit net 'n ander laag op **bo van Mach-boodskappe**.

**IOKit XNU-kernkode** is oopbron gemaak deur Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Boonop is die gebruikersruimte IOKit-komponente ook oopbron [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Egter, **geen IOKit bestuurders** is oopbron. In elk geval, van tyd tot tyd kan 'n vrystelling van 'n bestuurder kom met simbole wat dit makliker maak om dit te debug. Kyk hoe om [**die bestuurder uitbreidings uit die firmware hier te kry**](./#ipsw)**.**

Dit is geskryf in **C++**. Jy kan demangled C++ simbole kry met:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **blootgestelde funksies** kan **addisionele sekuriteitskontroles** uitvoer wanneer 'n kliënt probeer om 'n funksie aan te roep, maar let daarop dat die toepassings gewoonlik **beperk** is deur die **sandbox** waartoe IOKit-funksies hulle kan interaksie.

## Bestuurders

In macOS is hulle geleë in:

- **`/System/Library/Extensions`**
- KEXT-lêers ingebou in die OS X-bedryfstelsel.
- **`/Library/Extensions`**
- KEXT-lêers geïnstalleer deur 3de party sagteware

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
Tot en met nommer 9 is die gelysde bestuurders **gelaai in die adres 0**. Dit beteken dat dit nie werklike bestuurders is nie, maar **deel van die kern is en hulle kan nie ontlaai word nie**.

Om spesifieke uitbreidings te vind, kan jy gebruik maak van:
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

Die **IORegistry** is 'n belangrike deel van die IOKit-raamwerk in macOS en iOS wat dien as 'n databasis om die stelsels se hardewarekonfigurasie en toestand voor te stel. Dit is 'n **hiërargiese versameling van objekke wat al die hardeware en bestuurders** wat op die stelsel gelaai is, verteenwoordig, en hul verhoudings tot mekaar.

Jy kan die IORegistry verkry met die cli **`ioreg`** om dit vanaf die konsole te inspekteer (spesifiek nuttig vir iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
U kan **`IORegistryExplorer`** aflaai van **Xcode Additional Tools** vanaf [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) en die **macOS IORegistry** deur 'n **grafiese** koppelvlak inspekteer.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer word "vliegtuie" gebruik om die verhoudings tussen verskillende objekte in die IORegistry te organiseer en weer te gee. Elke vliegtuig verteenwoordig 'n spesifieke tipe verhouding of 'n bepaalde uitsig van die stelsel se hardeware en stuurprogramkonfigurasie. Hier is 'n paar van die algemene vliegtuie wat u in IORegistryExplorer mag teëkom:

1. **IOService Plane**: Dit is die mees algemene vliegtuig, wat die diensobjekte vertoon wat stuurprogramme en nubs (kommunikasiekanale tussen stuurprogramme) verteenwoordig. Dit toon die verskaffer-klant verhoudings tussen hierdie objek.
2. **IODeviceTree Plane**: Hierdie vliegtuig verteenwoordig die fisiese verbande tussen toestelle soos hulle aan die stelsel gekoppel is. Dit word dikwels gebruik om die hiërargie van toestelle wat via busse soos USB of PCI gekoppel is, te visualiseer.
3. **IOPower Plane**: Vertoon objek en hul verhoudings in terme van kragbestuur. Dit kan wys watter objek die kragtoestand van ander beïnvloed, nuttig vir die ontfouting van kragverwante probleme.
4. **IOUSB Plane**: Spesifiek gefokus op USB-toestelle en hul verhoudings, wat die hiërargie van USB-hubs en gekonnekteerde toestelle toon.
5. **IOAudio Plane**: Hierdie vliegtuig is vir die verteenwoordiging van klanktoestelle en hul verhoudings binne die stelsel.
6. ...

## Driver Comm Code Example

Die volgende kode verbind met die IOKit diens `"YourServiceNameHere"` en roep die funksie binne die selektor 0 aan. Vir dit:

- dit roep eers **`IOServiceMatching`** en **`IOServiceGetMatchingServices`** aan om die diens te verkry.
- Dit vestig dan 'n verbinding deur **`IOServiceOpen`** aan te roep.
- En dit roep uiteindelik 'n funksie aan met **`IOConnectCallScalarMethod`** wat die selektor 0 aandui (die selektor is die nommer wat die funksie wat u wil aanroep, toegeken is).
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
Daar is **ander** funksies wat gebruik kan word om IOKit funksies aan te roep behalwe **`IOConnectCallScalarMethod`** soos **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Terugkeer van bestuurder se ingangspunt

Jy kan hierdie verkry byvoorbeeld van 'n [**firmware beeld (ipsw)**](./#ipsw). Laai dit dan in jou gunsteling decompiler.

Jy kan begin om die **`externalMethod`** funksie te dekompileer, aangesien dit die bestuurder funksie is wat die oproep sal ontvang en die korrekte funksie sal aanroep:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Daardie vreselike oproep demagled beteken:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Let op hoe die **`self`** parameter in die vorige definisie gemis is, die goeie definisie sou wees:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Werklik, jy kan die werklike definisie vind in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Met hierdie inligting kan jy Ctrl+Regter -> `Wysig funksie handtekening` en die bekende tipes stel:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Die nuwe dekompileringskode sal soos volg lyk:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Vir die volgende stap moet ons die **`IOExternalMethodDispatch2022`** struktuur gedefinieer hê. Dit is oopbron in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), jy kan dit definieer:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Nou, volg die `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` kan jy 'n baie data sien:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Verander die Data Tipe na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

na die verandering:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

En soos ons nou daar is, het ons 'n **array van 7 elemente** (kyk die finale dekompileringskode), klik om 'n array van 7 elemente te skep:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nadat die array geskep is, kan jy al die geexporteerde funksies sien:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy onthou, om 'n **geexporteerde** funksie vanuit gebruikersruimte te **roep**, hoef ons nie die naam van die funksie te roep nie, maar die **selector nommer**. Hier kan jy sien dat die selector **0** die funksie **`initializeDecoder`** is, die selector **1** is **`startDecoder`**, die selector **2** **`initializeEncoder`**...

{{#include ../../../banners/hacktricks-training.md}}
