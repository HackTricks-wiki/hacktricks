# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## मूलभूत जानकारी

I/O Kit XNU kernel में एक open-source, object-oriented **device-driver framework** है, जो **dynamically loaded device drivers** को संभालता है। यह kernel में तुरंत modular code जोड़ने की सुविधा देता है और विभिन्न hardware को support करता है।

IOKit drivers मूल रूप से **kernel से functions export** करेंगे। इन functions के parameter **types** **predefined** होते हैं और उनका verification किया जाता है। इसके अलावा, XPC की तरह ही, IOKit भी **Mach messages** के **ऊपर** मौजूद एक अन्य layer है।

**IOKit XNU kernel code** को Apple ने [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) पर open-source किया है। इसके अलावा, user space IOKit components भी open-source हैं: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)।

हालाँकि, **कोई भी IOKit drivers** open-source नहीं हैं। फिर भी, समय-समय पर किसी driver की release symbols के साथ आ सकती है, जिससे उसे debug करना आसान हो जाता है। [**यहाँ firmware से driver extensions प्राप्त करने का तरीका देखें**](#ipsw)**।**

यह **C++** में लिखा गया है। आप निम्नलिखित command से demangled C++ symbols प्राप्त कर सकते हैं:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit की **exposed functions** तब **additional security checks** कर सकती हैं जब कोई client किसी function को call करने का प्रयास करता है, लेकिन ध्यान दें कि apps आमतौर पर **sandbox** द्वारा उन IOKit functions तक सीमित होते हैं जिनके साथ वे interact कर सकते हैं।

## Drivers

macOS में ये यहां स्थित होते हैं:

- **`/System/Library/Extensions`**
- OS X operating system में built-in KEXT files।
- **`/Library/Extensions`**
- 3rd party software द्वारा installed KEXT files

iOS में ये यहां स्थित होते हैं:

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
Number 9 तक listed drivers **address 0 पर loaded होते हैं**। इसका अर्थ है कि वे वास्तविक drivers नहीं हैं, बल्कि **kernel का हिस्सा हैं और उन्हें unloaded नहीं किया जा सकता**।

Specific extensions खोजने के लिए आप इसका उपयोग कर सकते हैं:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
kernel extensions को load और unload करने के लिए:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**, macOS और iOS में IOKit framework का एक महत्वपूर्ण हिस्सा है, जो system के hardware configuration और state को दर्शाने के लिए database के रूप में काम करता है। यह **system पर loaded सभी hardware और drivers को दर्शाने वाले objects तथा उनके आपसी संबंधों का एक hierarchical collection** है।

आप console से इसका निरीक्षण करने के लिए CLI **`ioreg`** का उपयोग करके IORegistry प्राप्त कर सकते हैं (यह विशेष रूप से iOS के लिए उपयोगी है)।
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
आप **Xcode Additional Tools** से **`IORegistryExplorer`** को [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) से download कर सकते हैं और **graphical** interface के माध्यम से **macOS IORegistry** का निरीक्षण कर सकते हैं।

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer में, **planes** का उपयोग IORegistry में अलग-अलग objects के बीच संबंधों को व्यवस्थित करने और प्रदर्शित करने के लिए किया जाता है। प्रत्येक plane एक विशिष्ट प्रकार के संबंध या system के hardware और driver configuration के किसी विशेष view को दर्शाता है। IORegistryExplorer में आपको मिलने वाले कुछ सामान्य planes यहां दिए गए हैं:

1. **IOService Plane**: यह सबसे सामान्य plane है, जो drivers और nubs (drivers के बीच communication channels) का प्रतिनिधित्व करने वाले service objects को प्रदर्शित करता है। यह इन objects के बीच provider-client संबंध दिखाता है।
2. **IODeviceTree Plane**: यह plane devices के बीच physical connections को दर्शाता है, जैसे कि वे system से जुड़े होते हैं। इसका उपयोग अक्सर USB या PCI जैसे buses के माध्यम से जुड़े devices की hierarchy को visualize करने के लिए किया जाता है।
3. **IOPower Plane**: power management के संदर्भ में objects और उनके संबंधों को प्रदर्शित करता है। यह दिखा सकता है कि कौन-से objects अन्य objects की power state को प्रभावित कर रहे हैं, जो power-related issues को debug करने में उपयोगी है।
4. **IOUSB Plane**: विशेष रूप से USB devices और उनके संबंधों पर केंद्रित है और USB hubs तथा connected devices की hierarchy दिखाता है।
5. **IOAudio Plane**: यह plane system के भीतर audio devices और उनके संबंधों को दर्शाने के लिए है।
6. ...

## Driver Comm Code Example

निम्नलिखित code IOKit service `YourServiceNameHere` से connect होता है और selector 0 को call करता है:

- सबसे पहले यह service प्राप्त करने के लिए **`IOServiceMatching`** और **`IOServiceGetMatchingServices`** को call करता है।
- इसके बाद यह **`IOServiceOpen`** को call करके connection स्थापित करता है।
- और अंत में यह **`IOConnectCallScalarMethod`** के साथ एक function को call करता है, जिसमें selector 0 निर्दिष्ट होता है (selector वह number है जो call किए जाने वाले function को assign किया गया है)।

<details>
<summary>Driver selector को call करने का user-space example</summary>
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

**`IOConnectScalarMethod`** के अलावा **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** जैसे **IOKit functions** को call करने के लिए **अन्य** functions का भी उपयोग किया जा सकता है...

## Driver entrypoint को reverse करना

आप इन्हें उदाहरण के लिए किसी [**firmware image (ipsw)**](#ipsw) से प्राप्त कर सकते हैं। फिर इसे अपने पसंदीदा decompiler में load करें।

आप **`externalMethod`** function को decompile करना शुरू कर सकते हैं, क्योंकि यही driver function call प्राप्त करेगा और सही function को call करेगा:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

उस भयानक call का demangled रूप है:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
ध्यान दें कि पिछली definition में **`self`** param छूट गया है, सही definition यह होगी:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
वास्तविक परिभाषा आप [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) में पा सकते हैं:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
इस जानकारी के साथ आप Ctrl+Right दबाकर `Edit function signature` को फिर से लिख सकते हैं और ज्ञात types सेट कर सकते हैं:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

नया decompiled code इस तरह दिखाई देगा:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

अगले चरण के लिए हमारे पास **`IOExternalMethodDispatch2022`** struct परिभाषित होना चाहिए। यह [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) में opensource है, आप इसे define कर सकते हैं:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

अब, `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` को follow करने पर आपको बहुत-सा data दिखाई देगा:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Data Type को **`IOExternalMethodDispatch2022:`** में बदलें:

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

बदलाव के बाद:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

और जैसा कि अब हम जानते हैं, इसमें **7 elements की array** है (अंतिम decompiled code देखें), इसलिए 7 elements की array बनाने के लिए click करें:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Array बनने के बाद आप सभी exported functions देख सकते हैं:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आपको याद हो, user space से किसी **exported** function को **call** करने के लिए हमें function के नाम को call करने की आवश्यकता नहीं होती, बल्कि **selector number** का उपयोग करना होता है। यहां आप देख सकते हैं कि selector **0**, **`initializeDecoder`** function है; selector **1**, **`startDecoder`** है; और selector **2**, **`initializeEncoder`** है...

## हाल की IOKit attack surface (2023–2025)

- **IOHIDFamily के माध्यम से Keystroke capture** – CVE-2024-27799 (14.5) ने दिखाया कि एक permissive `IOHIDSystem` client secure input के बावजूद HID events प्राप्त कर सकता है; सुनिश्चित करें कि `externalMethod` handlers केवल user-client type पर निर्भर रहने के बजाय entitlements लागू करें।<sup>[[2]](#references)</sup>
- **IOGPUFamily memory corruption** – CVE-2024-44197 और CVE-2025-24257 ने sandboxed apps से reachable OOB writes को ठीक किया, जो GPU user clients को malformed variable-length data भेजने पर संभव थे; सामान्य bug `IOConnectCallStructMethod` arguments के आसपास खराब bounds checking होता है।<sup>[[1]](#references)</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) ने पुष्टि की कि HID user clients अब भी sandbox-escape vector बने हुए हैं; keyboard/event queues expose करने वाले किसी भी driver को fuzz करें।<sup>[[3]](#references)</sup>

### Quick triage और fuzzing tips

- fuzzer को seed करने के लिए userland से user client के सभी external methods enumerate करें:
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
- Reversing करते समय `IOExternalMethodDispatch2022` counts पर ध्यान दें। हाल के CVEs में एक सामान्य bug pattern `structureInputSize`/`structureOutputSize` और वास्तविक `copyin` length के बीच असंगति है, जिससे `IOConnectCallStructMethod` में heap OOB हो सकता है।
- Sandbox reachability अभी भी entitlements पर निर्भर करती है। किसी target पर समय लगाने से पहले जाँच लें कि client को third-party app से अनुमति है:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfb bugs के लिए, `IOConnectCallMethod` के माध्यम से oversized arrays पास करना अक्सर bad bounds को trigger करने के लिए पर्याप्त होता है। size confusion को trigger करने वाला Minimal harness (selector X):
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — User-Space Drivers

### मूल जानकारी

**DriverKit** kernel extensions (kexts) का Apple का user-space replacement है, जिसे macOS 10.15 में पेश किया गया था। DriverKit binaries (`.dext` bundles) user-space processes के रूप में चलते हैं, लेकिन privileged IOKit interface के माध्यम से kernel से सीधे communicate करते हैं।

DriverKit extensions hardware को manage करते हैं:
- **USB** controllers और devices
- **Thunderbolt** / PCIe devices
- **HID** (keyboards, mice, game controllers)
- **Audio** hardware
- **Networking** interfaces
- **Serial** और **Block Storage** devices

kexts के विपरीत (जिनके लिए SIP-disabled boot या notarization आवश्यक था), DriverKit extensions को `SystemExtensions.framework` के माध्यम से install किया जाता है और इनके लिए केवल **one-time user approval** आवश्यक होता है।

### Discovery & Enumeration
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
### Security Implications

> [!WARNING]
> DriverKit binaries में **kernel के साथ direct communication channel** होता है। इस channel के माध्यम से malformed messages भेजने पर kernel vulnerabilities trigger हो सकती हैं। प्रत्येक driver specific user-client classes register करता है, और malformed `IOConnectCallMethod` calls kernel memory corruption का कारण बन सकती हैं।

**Attack surface:**
1. **Kernel IOKit message fuzzing** — प्रत्येक DriverKit user-client user space से call किए जा सकने वाले selectors expose करता है। Malformed arguments kernel bugs trigger कर सकते हैं।
2. **USB device spoofing** — एक compromised USB DriverKit binary malicious USB device profile प्रस्तुत कर सकता है (जैसे, HID injection के लिए keyboard emulate करना)।
3. **DMA attacks** — PCIe/Thunderbolt DriverKit extensions को physical memory तक potential DMA access प्राप्त हो सकता है।
4. **Persistence** — system extension के रूप में install होने के बाद DriverKit binaries reboots और app updates के दौरान persist रहती हैं।

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

| CVE | विवरण |
|---|---|
| CVE-2022-26766 | DriverKit USB stack vulnerability — kernel code execution |
| CVE-2021-30838 | graphic drivers में IOKit user-client type confusion |
| CVE-2024-44197 | malformed DriverKit arguments के माध्यम से IOGPUFamily OOB write |

## संदर्भ

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 का सारांश](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
