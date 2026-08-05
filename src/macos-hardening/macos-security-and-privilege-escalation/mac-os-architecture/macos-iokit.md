# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

I/O Kit ni **device-driver framework** yenye open-source ndani ya XNU kernel, inayoshughulikia **dynamically loaded device drivers**. Inaruhusu code ya modular kuongezwa kwenye kernel wakati wa utekelezaji, na kusaidia hardware mbalimbali.

IOKit drivers kimsingi **hu-export functions kutoka kwenye kernel**. **Aina** za parameter za functions hizi **zimefafanuliwa mapema** na huthibitishwa. Zaidi ya hayo, kama ilivyo kwa XPC, IOKit ni layer nyingine tu iliyo **juu ya Mach messages**.

**IOKit XNU kernel code** imewekwa opensource na Apple kwenye [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Zaidi ya hayo, components za IOKit za user space pia zimewekwa opensource kwenye [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Hata hivyo, **hakuna IOKit drivers** zilizowekwa opensource. Hata hivyo, mara kwa mara release ya driver inaweza kuja na symbols zinazorahisisha ku-debug. Angalia jinsi ya [**kupata driver extensions kutoka kwenye firmware hapa**](#ipsw)**.**

Imeandikwa kwa **C++**. Unaweza kupata symbols za C++ zilizofanyiwa demangle kwa:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> **functions zilizo exposed** za IOKit zinaweza kufanya **ukaguzi wa ziada wa usalama** mteja anapojaribu kuita function, lakini kumbuka kuwa apps kwa kawaida **zimewekewa mipaka** na **sandbox** kuhusu functions za IOKit ambazo zinaweza kuingiliana nazo.

## Drivers

Katika macOS zinapatikana katika:

- **`/System/Library/Extensions`**
- Faili za KEXT zilizojengwa ndani ya mfumo wa uendeshaji wa OS X.
- **`/Library/Extensions`**
- Faili za KEXT zilizosakinishwa na software ya wahusika wengine

Katika iOS zinapatikana katika:

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
Hadi nambari 9, drivers zilizoorodheshwa **zimepakiwa kwenye address 0**. Hii inamaanisha kuwa hizo si drivers halisi bali ni **sehemu ya kernel na haziwezi ku-unload**.

Ili kupata extensions mahususi unaweza kutumia:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Ili kupakia na kupakua kernel extensions, fanya:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** ni sehemu muhimu ya framework ya IOKit katika macOS na iOS inayotumika kama database ya kuwakilisha usanidi na hali ya hardware ya mfumo. Ni **mkusanyiko wa kihierarkia wa objects unaowakilisha hardware na drivers zote** zilizopakiwa kwenye mfumo, pamoja na uhusiano wao.

Unaweza kupata IORegistry ukitumia cli **`ioreg`** ili kuikagua kutoka kwenye console (hasa muhimu kwa iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Unaweza kupakua **`IORegistryExplorer`** kutoka **Xcode Additional Tools** kupitia [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) na kukagua **macOS IORegistry** kupitia kiolesura cha **graphical**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Katika IORegistryExplorer, "planes" hutumiwa kupanga na kuonyesha mahusiano kati ya objects tofauti katika IORegistry. Kila plane inawakilisha aina mahususi ya uhusiano au mwonekano fulani wa usanidi wa hardware na driver wa mfumo. Hizi ni baadhi ya planes za kawaida unazoweza kukutana nazo katika IORegistryExplorer:

1. **IOService Plane**: Hii ndiyo plane ya jumla zaidi, inayoonyesha service objects zinazowakilisha drivers na nubs (channels za mawasiliano kati ya drivers). Inaonyesha mahusiano ya provider-client kati ya objects hizi.
2. **IODeviceTree Plane**: Plane hii inawakilisha miunganisho ya kimwili kati ya devices zinapounganishwa kwenye mfumo. Mara nyingi hutumiwa kuonyesha hierarchy ya devices zilizounganishwa kupitia buses kama USB au PCI.
3. **IOPower Plane**: Huonyesha objects na mahusiano yao kuhusiana na power management. Inaweza kuonyesha ni objects zipi zinazoathiri power state ya objects nyingine, jambo linalofaa kwa debugging ya matatizo yanayohusiana na power.
4. **IOUSB Plane**: Inalenga hasa USB devices na mahusiano yao, ikionyesha hierarchy ya USB hubs na devices zilizounganishwa.
5. **IOAudio Plane**: Plane hii hutumika kuwakilisha audio devices na mahusiano yao ndani ya mfumo.
6. ...

## Mfano wa Code ya Mawasiliano na Driver

Code ifuatayo huunganisha service ya IOKit `YourServiceNameHere` na kuita selector 0:

- Kwanza huita **`IOServiceMatching`** na **`IOServiceGetMatchingServices`** ili kupata service.
- Kisha huanzisha connection kwa kuita **`IOServiceOpen`**.
- Hatimaye huita function kwa kutumia **`IOConnectCallScalarMethod`**, ikionyesha selector 0 (selector ni nambari iliyopewa function unayotaka kuita).

<details>
<summary>Mfano wa user-space call kwa driver selector</summary>
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

Kuna **functions** nyingine zinazoweza kutumika kuita functions za IOKit, mbali na **`IOConnectCallScalarMethod`**, kama vile **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Kureverse driver entrypoint

Unaweza kuzipata, kwa mfano, kutoka kwenye [**firmware image (ipsw)**](#ipsw). Kisha, ipakie kwenye decompiler unayopendelea.

Unaweza kuanza kufanya decompile ya function ya **`externalMethod`**, kwa kuwa hii ndiyo function ya driver itakayopokea call na kuita function sahihi:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Hiyo call ya kutisha iliyofanyiwa demangle inamaanisha:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Kumbuka kwamba katika ufafanuzi uliotangulia, parameta **`self`** imeachwa; ufafanuzi sahihi ungekuwa:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Kwa kweli, unaweza kupata ufafanuzi halisi katika [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Kwa maelezo haya unaweza kuandika upya Ctrl+Right -> `Edit function signature` na kuweka types zinazojulikana:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Code mpya ya decompiled itaonekana hivi:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Kwa hatua inayofuata tunahitaji kuwa tumefafanua struct ya **`IOExternalMethodDispatch2022`**. Iko opensource kwenye [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), unaweza kuifafanua:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Sasa, ukifuata `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` unaweza kuona data nyingi:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Badilisha Data Type kuwa **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

baada ya mabadiliko:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Na kwa kuwa tunajua kuwa kuna **array ya vipengele 7** (angalia code ya mwisho ya decompiled), bofya ili kuunda array yenye vipengele 7:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Baada ya array kuundwa unaweza kuona functions zote zilizotolewa:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unakumbuka, ili **kuita** function **iliyotolewa** kutoka user space hatuhitaji kuita jina la function, bali **nambari ya selector**. Hapa unaweza kuona kuwa selector **0** ni function **`initializeDecoder`**, selector **1** ni **`startDecoder`**, selector **2** ni **`initializeEncoder`**...

## Attack surface ya IOKit ya hivi karibuni (2023–2025)

- **Keystroke capture kupitia IOHIDFamily** – CVE-2024-27799 (14.5) ilionyesha kuwa client ya `IOHIDSystem` yenye ruhusa pana inaweza kunasa matukio ya HID hata secure input ikiwa imewashwa; hakikisha handlers za `externalMethod` zinatekeleza entitlements badala ya kutegemea tu aina ya user-client.<sup>[[2]](#references)</sup>
- **Uharibifu wa memory wa IOGPUFamily** – CVE-2024-44197 na CVE-2025-24257 zilirekebisha writes za OOB zinazoweza kufikiwa na apps zilizo kwenye sandbox zinazopitisha data yenye urefu unaobadilika na iliyoundwa vibaya kwa GPU user clients; bug ya kawaida ni bounds duni kuzunguka arguments za `IOConnectCallStructMethod`.<sup>[[1]](#references)</sup>
- **Ufuatiliaji wa keystroke wa zamani** – CVE-2023-42891 (14.2) ilithibitisha kuwa HID user clients bado ni vector ya sandbox-escape; fuzz driver yoyote inayowasilisha keyboard/event queues.<sup>[[3]](#references)</sup>

### Vidokezo vya haraka vya triage na fuzzing

- Orodhesha external methods zote za user client kutoka userland ili kuanzisha fuzzer:
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
- Wakati wa reversing, zingatia idadi za `IOExternalMethodDispatch2022`. Muundo wa kawaida wa bug katika CVE za hivi karibuni ni kutolingana kwa `structureInputSize`/`structureOutputSize` dhidi ya urefu halisi wa `copyin`, hali inayosababisha heap OOB katika `IOConnectCallStructMethod`.
- Ufikikaji wa Sandbox bado unategemea entitlements. Kabla ya kutumia muda kuchunguza target, hakikisha kama client inaruhusiwa kutoka kwa third-party app:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Kwa bugs za GPU/iomfb, kupitisha arrays zenye ukubwa uliopitiliza kupitia `IOConnectCallMethod` mara nyingi hutosha kusababisha ukaguzi mbaya wa bounds. Harness ndogo (selector X) ya kusababisha mkanganyiko wa ukubwa:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — User-Space Drivers

### Maelezo ya Msingi

**DriverKit** ni mbadala wa Apple wa user-space kwa kernel extensions (kexts), ulioanzishwa katika macOS 10.15. Binaries za DriverKit (bundles za `.dext`) huendeshwa kama michakato ya user-space lakini huwasiliana moja kwa moja na kernel kupitia interface ya IOKit yenye privileges.

DriverKit extensions hudhibiti hardware:
- Vidhibiti na vifaa vya **USB**
- Vifaa vya **Thunderbolt** / PCIe
- **HID** (keyboards, mice, game controllers)
- Hardware ya **Audio**
- Interfaces za **Networking**
- Vifaa vya **Serial** na **Block Storage**

Tofauti na kexts (ambazo zilihitaji SIP-disabled boot au notarization), DriverKit extensions husakinishwa kupitia `SystemExtensions.framework` na huhitaji tu **idhini ya mtumiaji ya mara moja**.

### Ugunduzi na Uorodheshaji
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
### Athari za Usalama

> [!WARNING]
> DriverKit binaries zina **direct communication channel to the kernel**. Kutuma messages zilizoundwa vibaya kupitia channel hii kunaweza ku-trigger kernel vulnerabilities. Kila driver husajili user-client classes maalum, na calls za IOConnectCallMethod zilizoundwa vibaya zinaweza kusababisha kernel memory corruption.

**Attack surface:**
1. **Kernel IOKit message fuzzing** — Kila DriverKit user-client hufichua selectors zinazoweza kuitwa kutoka user space. Arguments zilizoundwa vibaya hu-trigger kernel bugs.
2. **USB device spoofing** — DriverKit binary ya USB iliyo-compromise inaweza kuwasilisha malicious USB device profile (kwa mfano, kuiga keyboard kwa HID injection).
3. **DMA attacks** — PCIe/Thunderbolt DriverKit extensions zinaweza kuwa na DMA access kwa physical memory.
4. **Persistence** — Mara inapowekwa kama system extension, DriverKit binaries huendelea kuwepo baada ya reboots na app updates.

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

| CVE | Maelezo |
|---|---|
| CVE-2022-26766 | Vulnerability katika DriverKit USB stack — kernel code execution |
| CVE-2021-30838 | IOKit user-client type confusion katika graphic drivers |
| CVE-2024-44197 | IOGPUFamily OOB write kupitia DriverKit arguments zilizoundwa vibaya |

## Marejeo

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – Muhtasari wa IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
