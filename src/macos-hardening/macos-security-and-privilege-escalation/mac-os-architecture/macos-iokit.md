# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

I/O Kit je open-source, objektno-orijentisan **framework za device drivere** u XNU kernelu i upravlja **dinamički učitanim device driverima**. Omogućava modularnom kodu da se dodaje u kernel u hodu, uz podršku za raznovrstan hardver.

IOKit driveri u osnovi **izvoze funkcije iz kernela**. **Tipovi** parametara ovih funkcija su **unapred definisani** i proveravaju se. Pored toga, slično kao XPC, IOKit je samo još jedan sloj **iznad Mach poruka**.

**IOKit XNU kernel kod** Apple objavljuje kao open-source na [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Takođe, user space IOKit komponente su dostupne kao open-source na [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Međutim, **nijedan IOKit driver** nije open-source. Ipak, s vremena na vreme izdanje drivera može sadržati simbole koji olakšavaju njegovo debugovanje. Pogledajte kako da [**preuzmete driver ekstenzije iz firmware-a ovde**](#ipsw)**.**

Napisan je u jeziku **C++**. Demanglovane C++ simbole možete dobiti pomoću:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **izložene funkcije** mogu izvršavati **dodatne bezbednosne provere** kada klijent pokuša da pozove funkciju, ali imajte na umu da su aplikacije obično **ograničene** pomoću **sandbox-a** u pogledu IOKit funkcija sa kojima mogu da komuniciraju.

## Drajveri

U macOS-u se nalaze u:

- **`/System/Library/Extensions`**
- KEXT datoteke ugrađene u operativni sistem OS X.
- **`/Library/Extensions`**
- KEXT datoteke koje instalira softver trećih strana

U iOS-u se nalaze u:

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
Do broja 9, navedeni drajveri su **učitani na adresi 0**. To znači da to nisu pravi drajveri, već su **deo kernela i ne mogu se učitati**.

Da biste pronašli određene ekstenzije, možete koristiti:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Za učitavanje i uklanjanje kernel extensions koristite:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** je ključni deo IOKit framework-a u macOS-u i iOS-u koji služi kao baza podataka za predstavljanje hardverske konfiguracije i stanja sistema. To je **hijerarhijska kolekcija objekata koji predstavljaju sav hardver i drajvere** učitane na sistemu, kao i njihove međusobne odnose.

IORegistry možete dobiti pomoću CLI alata **`ioreg`** kako biste ga pregledali iz konzole (posebno korisno za iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Možete preuzeti **`IORegistryExplorer`** iz odeljka **Xcode Additional Tools** na adresi [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i pregledati **macOS IORegistry** kroz **grafički** interfejs.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

U aplikaciji IORegistryExplorer, „planes“ se koriste za organizovanje i prikaz odnosa između različitih objekata u IORegistry-ju. Svaki plane predstavlja određenu vrstu odnosa ili poseban prikaz hardverske i driver konfiguracije sistema. Ovo su neki od uobičajenih planes koje možete videti u aplikaciji IORegistryExplorer:

1. **IOService Plane**: Ovo je najopštiji plane, koji prikazuje service objekte koji predstavljaju drivere i nubs (komunikacione kanale između drivera). Prikazuje odnose provider-client između ovih objekata.
2. **IODeviceTree Plane**: Ovaj plane predstavlja fizičke veze između uređaja koji su povezani sa sistemom. Često se koristi za vizuelizaciju hijerarhije uređaja povezanih preko magistrala kao što su USB ili PCI.
3. **IOPower Plane**: Prikazuje objekte i njihove odnose u kontekstu upravljanja napajanjem. Može prikazati koji objekti utiču na stanje napajanja drugih objekata, što je korisno za otklanjanje problema povezanih sa napajanjem.
4. **IOUSB Plane**: Posebno je usmeren na USB uređaje i njihove odnose, prikazujući hijerarhiju USB hubova i povezanih uređaja.
5. **IOAudio Plane**: Ovaj plane služi za predstavljanje audio uređaja i njihovih odnosa unutar sistema.
6. ...

## Primer koda za komunikaciju sa driverom

Sledeći kod se povezuje sa IOKit servisom `YourServiceNameHere` i poziva selector 0:

- Najpre poziva **`IOServiceMatching`** i **`IOServiceGetMatchingServices`** kako bi dobio servis.
- Zatim uspostavlja konekciju pozivanjem **`IOServiceOpen`**.
- Na kraju poziva funkciju pomoću **`IOConnectCallScalarMethod`**, uz navođenje selectora 0 (selector je broj dodeljen funkciji koju želite da pozovete).

<details>
<summary>Primer user-space poziva driver selectora</summary>
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

Postoje **druge** funkcije koje se mogu koristiti za pozivanje IOKit funkcija, pored **`IOConnectCallScalarMethod`**, kao što su **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reverse engineering ulazne tačke driver-a

Do njih možete doći, na primer, iz [**firmware image-a (ipsw)**](#ipsw). Zatim ga učitajte u svoj omiljeni decompiler.

Možete početi sa decompilacijom funkcije **`externalMethod`**, pošto je to funkcija driver-a koja će primiti poziv i pozvati odgovarajuću funkciju:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Taj užasan demangled poziv znači:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Imajte na umu da je u prethodnoj definiciji izostavljen parametar **`self`**, a ispravna definicija bi bila:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Zapravo, stvarnu definiciju možete pronaći na [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Sa ovim informacijama možete prepisati Ctrl+Right -> `Edit function signature` i postaviti poznate tipove:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Novi decompiled code će izgledati ovako:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Za sledeći korak potrebno je da imamo definisanu strukturu **`IOExternalMethodDispatch2022`**. Ona je opensource na adresi [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), pa je možete definisati:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Sada, prateći `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, možete videti mnogo podataka:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Promenite Data Type u **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

nakon izmene:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Pošto sada znamo da se ovde nalazi **array od 7 elemenata** (pogledajte konačni decompiled code), kliknite da biste kreirali array od 7 elemenata:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nakon kreiranja array-a možete videti sve exported functions:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ako se sećate, da bismo **pozvali** **exported** funkciju iz user space-a, ne moramo da pozovemo ime funkcije, već **selector number**. Ovde možete videti da je selector **0** funkcija **`initializeDecoder`**, selector **1** je **`startDecoder`**, a selector **2** je **`initializeEncoder`**...

## Skorašnja IOKit attack surface (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) je pokazao da permisivni `IOHIDSystem` client može da preuzme HID events čak i kada je secure input omogućen; uverite se da `externalMethod` handlers primenjuju entitlements umesto da proveravaju samo user-client type.<sup>[[2]](#references)</sup>
- **IOGPUFamily memory corruption** – CVE-2024-44197 i CVE-2025-24257 ispravili su OOB writes dostupne sandboxed apps koje prosleđuju neispravne variable-length data GPU user clients; uobičajeni bug je nedovoljna provera bounds oko argumenata funkcije `IOConnectCallStructMethod`.<sup>[[1]](#references)</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) je potvrdio da HID user clients i dalje predstavljaju sandbox-escape vector; fuzzujte svaki driver koji izlaže keyboard/event queues.<sup>[[3]](#references)</sup>

### Brzi triage i fuzzing saveti

- Enumerišite sve external methods za user client iz userland-a da biste pripremili fuzzer:
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
- Prilikom reverse engineering-a, obratite pažnju na broj `IOExternalMethodDispatch2022` stavki. Čest obrazac greške u novijim CVE-ovima je neusaglašenost vrednosti `structureInputSize`/`structureOutputSize` u odnosu na stvarnu dužinu `copyin` operacije, što dovodi do heap OOB u `IOConnectCallStructMethod`.
- Reachability iz Sandbox-a i dalje zavisi od entitlements-a. Pre nego što utrošite vreme na target, proverite da li je client-u dozvoljen pristup iz third-party aplikacije:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Kod GPU/iomfb bugs, prosleđivanje oversized arrays kroz `IOConnectCallMethod` često je dovoljno za aktiviranje pogrešnih granica. Minimalni harness (selector X) za aktiviranje zabune u veličini:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Driveri u korisničkom prostoru

### Osnovne informacije

**DriverKit** je Apple-ova zamena u korisničkom prostoru za ekstenzije kernela (kexts), uvedena u macOS 10.15. DriverKit binarni fajlovi (`.dext` bundles) rade kao procesi u korisničkom prostoru, ali direktno komuniciraju sa kernelom putem privilegovanog IOKit interfejsa.

DriverKit ekstenzije upravljaju hardverom:
- **USB** kontrolerima i uređajima
- **Thunderbolt** / PCIe uređajima
- **HID** uređajima (tastature, miševi, kontroleri za igre)
- **Audio** hardverom
- **Networking** interfejsima
- **Serial** i **Block Storage** uređajima

Za razliku od kexts (koji su zahtevali pokretanje sistema sa onemogućenim SIP-om ili notarizaciju), DriverKit ekstenzije se instaliraju putem `SystemExtensions.framework` i zahtevaju samo **jednokratno odobrenje korisnika**.

### Otkrivanje i enumeracija
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
### Bezbednosne implikacije

> [!WARNING]
> DriverKit binarni fajlovi imaju **direktan komunikacioni kanal ka kernelu**. Slanje neispravnih poruka kroz ovaj kanal može aktivirati ranjivosti kernela. Svaki driver registruje specifične user-client klase, a neispravni `IOConnectCallMethod` pozivi mogu izazvati oštećenje memorije kernela.

**Attack surface:**
1. **Kernel IOKit message fuzzing** — Svaki DriverKit user-client izlaže selektore koji se mogu pozivati iz user space-a. Neispravni argumenti aktiviraju kernel bugove.
2. **USB device spoofing** — Kompromitovani USB DriverKit binarni fajl može predstaviti zlonamerni profil USB uređaja (npr. emulirati tastaturu za HID injection).
3. **DMA attacks** — PCIe/Thunderbolt DriverKit ekstenzije imaju potencijalni DMA pristup fizičkoj memoriji.
4. **Persistence** — Kada se instaliraju kao system extension, DriverKit binarni fajlovi opstaju nakon ponovnog pokretanja sistema i ažuriranja aplikacija.

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
### DriverKit CVE-ovi

| CVE | Opis |
|---|---|
| CVE-2022-26766 | Ranjivost u DriverKit USB stack-u — izvršavanje koda u kernelu |
| CVE-2021-30838 | Type confusion u IOKit user-client-u u grafičkim drajverima |
| CVE-2024-44197 | OOB upis kroz neispravne DriverKit argumente u IOGPUFamily |

## Reference

- [1] [Apple bezbednosna ažuriranja – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – sažetak za IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple bezbednosna ažuriranja – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
