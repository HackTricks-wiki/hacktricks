# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

I/O Kit je otvorenog koda, objektno-orijentisan **okvir za upravljačke programe uređaja** u XNU kernelu, koji rukuje **dinamički učitavanim drajverima uređaja**. Omogućava modularnom kodu da se dodaje u kernel u hodu (on-the-fly), podržavajući raznovrstan hardver.

IOKit drajveri će u suštini **izvoziti funkcije iz kernela**. Tipovi parametara tih funkcija su **predefinisani** i verifikovani. Štaviše, slično XPC-u, IOKit je samo još jedan sloj na **vrhu Mach messages**.

**IOKit XNU kernel code** je otvorenog koda i Apple ga objavljuje na [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Takođe, komponente IOKit-a u korisničkom prostoru su otvorenog koda na [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Međutim, **nijedni IOKit drajveri** nisu otvorenog koda. Ipak, povremeno izdanje drajvera može sadržati simbole koji olakšavaju njegovo debugovanje. Pogledajte kako [**preuzeti driver ekstenzije iz firmvera ovde**](#ipsw)**.**

Napisano je u **C++**. Možete dobiti demanglovane C++ simbole sa:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **izložene funkcije** mogu izvoditi **dodatne sigurnosne provere** kada klijent pokuša da pozove funkciju, ali imajte na umu da su aplikacije obično **ograničene** od strane **sandbox**-a u pogledu toga sa kojim IOKit funkcijama mogu da interaguju.

## Drajveri

Na macOS-u se nalaze:

- **`/System/Library/Extensions`**
- KEXT fajlovi ugrađeni u operativni sistem OS X.
- **`/Library/Extensions`**
- KEXT fajlovi koje instalira softver treće strane

Na iOS-u se nalaze:

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
Do broja 9, navedeni drivers su **loaded in the address 0**. To znači da oni nisu pravi drivers, već **part of the kernel i ne mogu da budu unloaded**.

Da biste pronašli specific extensions možete koristiti:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Da biste učitali i uklonili kernel ekstenzije, uradite:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** je ključni deo IOKit framework-a u macOS i iOS koji služi kao baza podataka za predstavljanje konfiguracije hardvera sistema i njegovog stanja. To je **hijerarhijska kolekcija objekata koja predstavlja sav hardver i drajvere** učitane u sistem, i njihove međusobne odnose.

You can get the IORegistry using the cli **`ioreg`** to inspect it from the console (specially useful for iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Možete preuzeti **`IORegistryExplorer`** iz **Xcode Additional Tools** sa [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i pregledati **macOS IORegistry** kroz **grafički** interfejs.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

U IORegistryExplorer-u, "planes" se koriste za organizovanje i prikaz odnosa između različitih objekata u IORegistry-ju. Svaka plane predstavlja određeni tip odnosa ili poseban pogled na hardver sistema i konfiguraciju drajvera. Evo nekih od uobičajenih "planes" koje možete sresti u IORegistryExplorer-u:

1. **IOService Plane**: Ovo je najopštija ravan, prikazuje servisne objekte koji predstavljaju drajvere i nubs (kanale za komunikaciju između drajvera). Prikazuje provider-client odnose između ovih objekata.
2. **IODeviceTree Plane**: Ova ravan predstavlja fizičke veze između uređaja kako su povezani na sistem. Često se koristi za vizuelizaciju hijerarhije uređaja povezanih preko sabirnica kao što su USB ili PCI.
3. **IOPower Plane**: Prikazuje objekte i njihove odnose u kontekstu upravljanja napajanjem. Može pokazati koji objekti utiču na stanje napajanja drugih, što je korisno za otklanjanje problema vezanih za napajanje.
4. **IOUSB Plane**: Fokusirana posebno na USB uređaje i njihove odnose, prikazuje hijerarhiju USB hub-ova i povezanih uređaja.
5. **IOAudio Plane**: Ova ravan služi za predstavljanje audio uređaja i njihovih odnosa unutar sistema.
6. ...

## Primer koda za komunikaciju sa drajverom

Sledeći kod se povezuje na IOKit servis `YourServiceNameHere` i poziva selector 0:

- Prvo poziva **`IOServiceMatching`** i **`IOServiceGetMatchingServices`** da dobije servis.
- Zatim uspostavlja konekciju pozivom **`IOServiceOpen`**.
- Na kraju poziva funkciju sa **`IOConnectCallScalarMethod`** koja koristi selector 0 (selector je broj dodeljen funkciji koju želite da pozovete).

<details>
<summary>Primer user-space poziva na selector drajvera</summary>
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

Postoje **druge** funkcije koje se mogu koristiti za pozivanje IOKit funkcija pored **`IOConnectCallScalarMethod`**, kao što su **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reverzovanje ulazne tačke drajvera

Te funkcije, na primer, možete dobiti iz [**firmware image (ipsw)**](#ipsw). Zatim image učitajte u vaš omiljeni dekompajler.

Možete početi dekompajlirati funkciju **`externalMethod`**, jer je to drajverska funkcija koja će primati poziv i pozivati odgovarajuću funkciju:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Ta užasna demanglovana poziv znači:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Primetite da u prethodnoj definiciji parametar **`self`** nedostaje; ispravna definicija bi bila:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Zapravo, pravu definiciju možete pronaći u [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Sa ovim informacijama možete prepraviti Ctrl+Right -> `Edit function signature` i postaviti poznate tipove:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Novi dekompilovani kod će izgledati ovako:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Za sledeći korak potrebno je da bude definisan struct **`IOExternalMethodDispatch2022`**. On je opensource u [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), možete ga definisati:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Sada, prateći `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, možete videti mnogo podataka:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Promenite tip podatka u **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

posle promene:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

I kao što sada vidite, tamo imamo **niz od 7 elemenata** (pogledajte finalni dekompilovani kod), kliknite da kreirate niz od 7 elemenata:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nakon što je niz kreiran, možete videti sve eksportovane funkcije:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako se sećate, da biste **pozvali** an **exported** funkciju iz user space-a ne treba da pozivate ime funkcije, već **selector number**. Ovde možete videti da je selector **0** funkcija **`initializeDecoder`**, selector **1** je **`startDecoder`**, selector **2** **`initializeEncoder`**...

## Nedavno IOKit attack surface (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) je pokazao da permisivan `IOHIDSystem` client može da uhvati HID događaje čak i uz secure input; osigurajte da `externalMethod` handleri primenjuju entitlements umesto da se oslanjaju samo na tip user-client-a.
- **IOGPUFamily memory corruption** – CVE-2024-44197 i CVE-2025-24257 su ispravili OOB writes dostupne iz sandboxed aplikacija koje šalju malformirane variable-length podatke GPU user clientima; uobičajeni bug su loše granice oko argumenata `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) je potvrdio da HID user clients ostaju vektor za bekstvo iz sandboksa; fuzz any driver exposing keyboard/event queues.

### Brza trijaža & fuzzing saveti

- Enumerišite sve external methods za user client iz userlanda kako biste seed-ovali fuzzer:
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
- Prilikom reverziranja, obrati pažnju na `IOExternalMethodDispatch2022` counts. Čest obrazac buga u nedavnim CVE-ovima je neusaglašenost `structureInputSize`/`structureOutputSize` u odnosu na stvarnu dužinu `copyin`, što dovodi do heap OOB u `IOConnectCallStructMethod`.
- Dostupnost Sandboxa i dalje zavisi od entitlements. Pre nego što potrošiš vreme na cilj, proveri da li je klijent dozvoljen iz aplikacije treće strane:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Za GPU/iomfb ranjivosti, prosleđivanje prevelikih nizova kroz `IOConnectCallMethod` često je dovoljno da izazove pogrešno rukovanje granicama. Minimalni harness (selector X) za izazivanje size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Reference

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
