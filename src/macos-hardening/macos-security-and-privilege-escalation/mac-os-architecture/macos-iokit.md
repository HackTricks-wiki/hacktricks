# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

I/O Kit ni mfumo wa chanzo wazi, unaotegemea vitu (object-oriented) wa mfumo wa dereva wa kifaa (device-driver framework) katika kernel ya XNU, unaoshughulikia madereva ya kifaa yanayopakuliwa wakati wa utekelezaji (dynamically loaded device drivers). Unaruhusu kuongezwa kwa msimbo wa modular kwenye kernel kwa wakati wa utekelezaji, ukisaidia vifaa mbalimbali.

Madereva ya IOKit kwa msingi hutoa (export) functions kutoka kernel. Aina za vigezo vya functions hizi (function parameter **types**) zimewekwa mapema (**predefined**) na zinathibitishwa. Zaidi ya hayo, kama XPC, IOKit ni tabaka jingine juu ya **Mach messages**.

**IOKit XNU kernel code** imetolewa kama chanzo wazi na Apple katika [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Vilevile, vipengele vya IOKit vinavyofanya kazi katika user space vimewekwa kama chanzo wazi [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Hata hivyo, **hakuna madereva ya IOKit** yaliyochanzo wazi. Kwa kawaida, mara kwa mara toleo la dereva linaweza kuja na symbols ambazo zinafanya iwe rahisi kuibug (debug). Angalia jinsi ya [**pata nyongeza za dereva kutoka firmware hapa**](#ipsw).

Imeandikwa kwa **C++**. Unaweza kupata alama za C++ zilizo-demangle kwa:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **funsi zilizo wazi** zinaweza kufanya **ukaguzi wa usalama wa ziada** wakati mteja anapojaribu kuita funsi, lakini kumbuka kwamba programu kwa kawaida ziko **zilizo na mipaka** kupitia **sandbox** kwa funsi za IOKit ambazo zinaweza kuingiliana nazo.

## Madereva

Katika macOS zinapatikana katika:

- **`/System/Library/Extensions`**
- KEXT files zilijengwa ndani ya mfumo wa uendeshaji wa OS X.
- **`/Library/Extensions`**
- KEXT files zilizowekwa na software ya wahusika wa tatu

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
Mpaka nambari 9, drivers walioorodheshwa wamepakiwa katika **address 0**. Hii ina maana kwamba hao si drivers halisi bali **sehemu ya kernel na hawawezi kuondolewa**.

Ili kutafuta extensions maalum unaweza kutumia:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Ili kupakia na kuondoa kernel extensions fanya:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** ni sehemu muhimu ya mfumo wa IOKit katika macOS na iOS ambayo hufanya kazi kama hifadhidata ya kuwakilisha muundo wa vifaa vya mfumo na hali yake. Ni **mkusanyo wa kihierarkia wa vitu vinavyowakilisha vifaa vyote na madereva ya kifaa** yaliyopakiwa kwenye mfumo, pamoja na uhusiano wao kwa kila mmoja.

Unaweza kupata IORegistry kwa kutumia cli **`ioreg`** kuikagua kutoka kwenye konsoli (hasa muhimu kwa iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Kwenye IORegistryExplorer, "planes" hutumika kupanga na kuonyesha uhusiano kati ya vitu tofauti katika IORegistry. Kila plane inawakilisha aina maalum ya uhusiano au mtazamo fulani wa usanidi wa vifaa (hardware) na driver za mfumo. Hapa chini kuna baadhi ya planes za kawaida utakazokutana nazo katika IORegistryExplorer:

1. **IOService Plane**: Hii ndiyo plane ya jumla zaidi, ikionyesha service objects ambazo zinawakilisha drivers na nubs (mihana/kanali za mawasiliano kati ya drivers). Inaonyesha mahusiano ya provider-client kati ya vitu hivi.
2. **IODeviceTree Plane**: Plane hii inawakilisha miunganisho ya kimwili kati ya vifaa vinavyounganishwa kwenye mfumo. Mara nyingi hutumika kuona muundo wa hierarkia ya vifaa vinavyounganishwa kupitia bus kama USB au PCI.
3. **IOPower Plane**: Inaonyesha vitu na mahusiano yao kwa mtazamo wa usimamizi wa nguvu (power management). Inaweza kuonyesha ni vitu gani vinavyoathiri hali ya nguvu ya vingine, muhimu kwa kubaini matatizo yanayohusiana na nguvu.
4. **IOUSB Plane**: Inalenga hasa vifaa vya USB na mahusiano yao, ikionyesha hierarkia ya USB hubs na vifaa vilivyounganishwa.
5. **IOAudio Plane**: Plane hii ni kwa kuwakilisha vifaa vya sauti na mahusiano yao ndani ya mfumo.
6. ...

## Mfano wa Msimbo wa Mawasiliano ya Driver

Msimbo ufuatao unaunganisha na huduma ya IOKit `YourServiceNameHere` na kuita selector 0:

- Kwanza inaita **`IOServiceMatching`** na **`IOServiceGetMatchingServices`** kupata huduma.
- Kisha inaunda muunganisho kwa kuita **`IOServiceOpen`**.
- Mwisho inaita kazi kwa **`IOConnectCallScalarMethod`** ikielezea selector 0 (selector ni nambari iliyopangwa kwa kazi unayotaka kuita).

<details>
<summary>Mfano wa wito wa user-space kwa selector ya driver</summary>
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

Kuna **kazi nyingine** ambazo zinaweza kutumika kuita kazi za IOKit mbali na **`IOConnectCallScalarMethod`** kama **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

Unaweza kupata hizi kwa mfano kutoka kwa [**firmware image (ipsw)**](#ipsw). Kisha, ziiweke kwenye decompiler unayopendelea.

Unaweza kuanza decompiling ya **`externalMethod`** kwani hii ndiyo driver function itakayopokea wito na kuita function sahihi:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Wito huo mbaya uliodemangled unamaanisha:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Angalia jinsi kiparamu **`self`** kilivyokosekana katika ufafanuzi uliopita; ufafanuzi sahihi utakuwa:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Kwa kweli, unaweza kupata ufafanuzi halisi katika [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
With this info you can rewrite Ctrl+Right -> `Edit function signature` and set the known types:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

The new decompiled code will look like:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

For the next step we need to have defined the **`IOExternalMethodDispatch2022`** struct. It's opensource in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), you could define it:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Now, following the `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` you can see a lot of data:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Change the Data Type to **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

after the change:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

And as we now in there we have an **array of 7 elements** (check the final decompiled code), click to create an array of 7 elements:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

After the array is created you can see all the exported functions:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Kama unavyokumbuka, ili **call** **exported** function kutoka user space hatuhitaji kutumia jina la function, bali nambari ya **selector**. Hapa unaweza kuona kuwa selector **0** ni function **`initializeDecoder`**, selector **1** ni **`startDecoder`**, selector **2** **`initializeEncoder`**...

## Recent IOKit attack surface (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) ilionyesha kwamba mteja wa `IOHIDSystem` mwenye ruhusa anaweza kunyakua HID events hata akiwa na secure input; hakikisha `externalMethod` handlers zinahitaji entitlements badala ya kutegemea aina ya user-client pekee.
- **IOGPUFamily memory corruption** – CVE-2024-44197 na CVE-2025-24257 zilirekebisha OOB writes zinazoweza kufikiwa kutoka kwa sandboxed apps zinazotuma malformed variable-length data kwa GPU user clients; mende ya kawaida ni mipaka duni kuzunguka vigezo vya `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) ilithibitisha kuwa HID user clients bado ni vector ya kutoroka kutoka sandbox; fuzz driver yoyote inayofichua keyboard/event queues.

### Quick triage & fuzzing tips

- Orodhesha external methods zote za user client kutoka userland ili kuzipatia fuzzer seed:
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
- When reversing, zingatia idadi za `IOExternalMethodDispatch2022`. Mfano wa mdudu unaotokea mara kwa mara katika CVE za hivi karibuni ni kutokubaliana kwa `structureInputSize`/`structureOutputSize` ikilinganishwa na urefu halisi wa `copyin`, kusababisha heap OOB katika `IOConnectCallStructMethod`.
- Ufikikaji wa Sandbox bado unategemea entitlements. Kabla ya kutumia muda kwenye lengo, angalia kama client anaruhusiwa kutoka kwa app ya third‑party:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Kwa GPU/iomfb bugs, kupitisha oversized arrays kupitia `IOConnectCallMethod` mara nyingi inatosha kusababisha bad bounds. Minimal harness (selector X) to trigger size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Marejeo

- [Sasisho za Usalama za Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 muhtasari](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Sasisho za Usalama za Apple – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
