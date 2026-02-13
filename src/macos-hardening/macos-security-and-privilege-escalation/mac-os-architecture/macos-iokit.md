# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

The I/O Kit XNU kernel में एक open-source, object-oriented **device-driver framework** है, जो **dynamically loaded device drivers** को हैंडल करता है। यह मॉड्यूलर कोड को ऑन-द-फ्लाई kernel में जोड़ने की अनुमति देता है और विविध हार्डवेयर का समर्थन करता है।

IOKit drivers मूलतः kernel से **export functions from the kernel** करते हैं। इन फ़ंक्शन पैरामीटर की **types** पहले से **predefined** होती हैं और सत्यापित की जाती हैं। इसके अलावा, XPC की तरह, IOKit केवल Mach messages के **top** पर एक और लेयर है।

**IOKit XNU kernel code** Apple द्वारा opensourced है [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)। इसके अलावा, user space IOKit components भी opensourced हैं [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

हालाँकि, **no IOKit drivers** opensource नहीं हैं। फिर भी, कभी-कभी किसी driver के रिलीज़ में symbols शामिल होते हैं जो उसे debug करना आसान बना देते हैं। देखें कि [**get the driver extensions from the firmware here**](#ipsw)**।**

यह **C++** में लिखा गया है। आप demangled C++ symbols प्राप्त कर सकते हैं:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** जब कोई client किसी function को कॉल करने की कोशिश करता है तो अतिरिक्त सुरक्षा जाँच कर सकते हैं, लेकिन ध्यान दें कि apps आमतौर पर उस **sandbox** द्वारा **limited** होते हैं जिनके साथ वे IOKit functions interact कर सकते हैं।

## Drivers

macOS में वे निम्न स्थानों पर स्थित होते हैं:

- **`/System/Library/Extensions`**
- OS X ऑपरेटिंग सिस्टम में शामिल KEXT फ़ाइलें।
- **`/Library/Extensions`**
- KEXT फ़ाइलें जो 3rd-party सॉफ़्टवेयर द्वारा इंस्टॉल की जाती हैं

iOS में वे स्थित हैं:

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
नंबर 9 तक सूचीबद्ध drivers **address 0 पर लोड होते हैं**। इसका मतलब है कि वे असली drivers नहीं हैं बल्कि **kernel का हिस्सा हैं और इन्हें अनलोड नहीं किया जा सकता**।

विशिष्ट extensions खोजने के लिए आप उपयोग कर सकते हैं:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
कर्नेल एक्सटेंशन्स को लोड और अनलोड करने के लिए:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** macOS और iOS में IOKit framework का एक महत्वपूर्ण हिस्सा है, जो सिस्टम के हार्डवेयर कॉन्फ़िगरेशन और स्थिति को प्रतिनिधित्व करने वाले डेटाबेस के रूप में कार्य करता है। यह एक **पदानुक्रमिक ऑब्जेक्ट्स का संग्रह है जो सिस्टम पर लोड सभी हार्डवेयर और ड्राइवरों का प्रतिनिधित्व करते हैं**, और उनके आपसी संबंधों को दर्शाता है।

आप console से इसे निरीक्षण करने के लिए cli में **`ioreg`** का उपयोग करके IORegistry प्राप्त कर सकते हैं (विशेष रूप से iOS के लिए उपयोगी)।
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
आप **`IORegistryExplorer`** को **Xcode Additional Tools** से [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) से डाउनलोड कर सकते हैं और **macOS IORegistry** को एक **ग्राफिकल** इंटरफ़ेस के माध्यम से निरीक्षण कर सकते हैं।

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer में, "planes" का उपयोग IORegistry में विभिन्न ऑब्जेक्ट्स के बीच संबंधों को व्यवस्थित और प्रदर्शित करने के लिए किया जाता है। प्रत्येक plane एक विशिष्ट प्रकार के संबंध या सिस्टम के हार्डवेयर और ड्राइवर कॉन्फ़िगरेशन का एक विशेष दृश्य प्रस्तुत करता है। नीचे IORegistryExplorer में मिलने वाले कुछ सामान्य planes दिए गए हैं:

1. **IOService Plane**: यह सबसे सामान्य plane है, जो उन service ऑब्जेक्ट्स को दिखाता है जो drivers और nubs (drivers के बीच संचार चैनल) का प्रतिनिधित्व करते हैं। यह इन ऑब्जेक्ट्स के बीच provider-client संबंध दिखाता है।
2. **IODeviceTree Plane**: यह plane सिस्टम से जुड़े होने पर devices के बीच भौतिक कनेक्शनों का प्रतिनिधित्व करता है। इसे अक्सर उन डिवाइसों की hierarchy को विज़ुअलाइज़ करने के लिए उपयोग किया जाता है जो USB या PCI जैसे बसों के माध्यम से जुड़ी होती हैं।
3. **IOPower Plane**: पावर मैनेजमेंट के संदर्भ में ऑब्जेक्ट्स और उनके संबंध दिखाता है। यह दिखा सकता है कि कौन से ऑब्जेक्ट्स दूसरों की पावर स्थिति को प्रभावित कर रहे हैं, जो पावर-संबंधी समस्याओं को डिबग करने में उपयोगी है।
4. **IOUSB Plane**: विशेष रूप से USB डिवाइसों और उनके संबंधों पर केंद्रित, USB हब्स और जुड़े हुए डिवाइसों की hierarchy दिखाता है।
5. **IOAudio Plane**: यह plane सिस्टम के भीतर ऑडियो डिवाइसों और उनके संबंधों का प्रतिनिधित्व करने के लिए है।
6. ...

## ड्राइवर कम्युनिकेशन कोड उदाहरण

निम्नलिखित कोड IOKit सेवा `YourServiceNameHere` से कनेक्ट करता है और selector 0 को कॉल करता है:

- यह पहले सेवा प्राप्त करने के लिए **`IOServiceMatching`** और **`IOServiceGetMatchingServices`** को कॉल करता है।
- फिर यह कनेक्शन स्थापित करने के लिए **`IOServiceOpen`** को कॉल करता है।
- और अंत में यह **`IOConnectCallScalarMethod`** के साथ एक फ़ंक्शन को कॉल करता है, जो selector 0 को निर्दिष्ट करता है (selector वह संख्या है जो कॉल करने वाले फ़ंक्शन को असाइन की गई है)।

<details>
<summary>ड्राइवर सेलेक्टर के लिए user-space कॉल का उदाहरण</summary>
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

IOKit functions को कॉल करने के लिए **`IOConnectCallScalarMethod`** के अलावा और भी **फ़ंक्शन** मौजूद हैं, जैसे **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## ड्राइवर entrypoint को रिवर्स करना

आप इन्हें उदाहरण के लिए [**firmware image (ipsw)**](#ipsw) से प्राप्त कर सकते हैं। फिर इन्हें अपने पसंदीदा decompiler में लोड करें।

आप **`externalMethod`** फ़ंक्शन का decompile करना शुरू कर सकते हैं क्योंकि यह वह driver फ़ंक्शन है जो कॉल प्राप्त करेगा और सही फ़ंक्शन को कॉल करेगा:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

उस demagled कॉल का मतलब है:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
ध्यान दें कि पिछली परिभाषा में **`self`** पैरामीटर छूटा हुआ है, सही परिभाषा इस प्रकार होगी:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
दरअसल, आप वास्तविक परिभाषा [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
इन जानकारी के साथ आप Ctrl+Right -> `Edit function signature` को बदलकर ज्ञात प्रकार सेट कर सकते हैं:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

नया decompiled कोड इस तरह दिखेगा:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

अगले चरण के लिए हमें **`IOExternalMethodDispatch2022`** struct परिभाषित होना चाहिए। यह opensource है [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), आप इसे परिभाषित कर सकते हैं:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

अब `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` का अनुसरण करते हुए आप बहुत सारे डेटा देख सकते हैं:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Data Type को **`IOExternalMethodDispatch2022:`** में बदलें:

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

बदलाव के बाद:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

और जैसा कि आप देख सकते हैं, वहाँ एक **array of 7 elements** है (final decompiled code देखें) — 7 elements का array बनाने के लिए क्लिक करें:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Array बन जाने के बाद आप सभी exported functions देख सकते हैं:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आपको याद हो, user space से किसी **exported** function को **call** करने के लिए हमें function के नाम को call करने की ज़रूरत नहीं होती, बल्कि **selector number** का उपयोग करते हैं। यहाँ आप देख सकते हैं कि selector **0** function **`initializeDecoder`** है, selector **1** **`startDecoder`** है, selector **2** **`initializeEncoder`** है...

## हालिया IOKit attack surface (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) ने दिखाया कि एक permissive `IOHIDSystem` client secure input होने पर भी HID events पकड़ सकता है; सुनिश्चित करें कि `externalMethod` handlers user-client type की बजाय entitlements लागू करें।
- **IOGPUFamily memory corruption** – CVE-2024-44197 और CVE-2025-24257 ने उन OOB writes को ठीक किया जो कि sandboxed apps द्वारा malformed variable-length data को GPU user clients को पास करते समय पहुँच योग्य थे; आम बग `IOConnectCallStructMethod` arguments के चारों ओर poor bounds के कारण होते हैं।
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) ने पुष्टि की कि HID user clients अभी भी sandbox-escape के लिए एक vector बने हुए हैं; keyboard/event queues expose करने वाले किसी भी driver को fuzz करें।

### त्वरित triage और fuzzing टिप्स

- userland से किसी user client के लिए सभी external methods की सूची बनाएं ताकि आप fuzzer को seed कर सकें:
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
- रिवर्स करते समय, `IOExternalMethodDispatch2022` की गिनतियों पर ध्यान दें। हालिया CVEs में एक सामान्य बग पैटर्न असंगत `structureInputSize`/`structureOutputSize` और वास्तविक `copyin` लंबाई के बीच है, जिससे `IOConnectCallStructMethod` में heap OOB होता है।
- Sandbox तक पहुँच अभी भी entitlements पर निर्भर करती है। किसी लक्ष्य पर समय खर्च करने से पहले जाँच करें कि client को third‑party app से अनुमति दी गई है या नहीं:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfb बग्स के लिए, `IOConnectCallMethod` के माध्यम से oversized arrays पास करना अक्सर bad bounds ट्रिगर करने के लिए पर्याप्त होता है। Minimal harness (selector X) size confusion ट्रिगर करने के लिए:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## संदर्भ

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
