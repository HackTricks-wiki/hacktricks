# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

I/O Kit एक ओपन-सोर्स, ऑब्जेक्ट-ओरिएंटेड **डिवाइस-ड्राइवर फ्रेमवर्क** है जो XNU कर्नेल में है, जो **डायनामिकली लोडेड डिवाइस ड्राइवर** को संभालता है। यह कर्नेल में ऑन-द-फ्लाई मॉड्यूलर कोड जोड़ने की अनुमति देता है, जो विविध हार्डवेयर का समर्थन करता है।

IOKit ड्राइवर मूल रूप से **कर्नेल से फ़ंक्शन निर्यात** करेंगे। इन फ़ंक्शन पैरामीटर **प्रकार** **पूर्व-परिभाषित** होते हैं और सत्यापित किए जाते हैं। इसके अलावा, XPC की तरह, IOKit **Mach संदेशों** के **ऊपर** एक और परत है।

**IOKit XNU कर्नेल कोड** को Apple द्वारा [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) पर ओपनसोर्स किया गया है। इसके अलावा, उपयोगकर्ता स्थान IOKit घटक भी ओपनसोर्स हैं [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)।

हालांकि, **कोई IOKit ड्राइवर** ओपनसोर्स नहीं हैं। फिर भी, समय-समय पर एक ड्राइवर का रिलीज़ ऐसे प्रतीकों के साथ आ सकता है जो इसे डिबग करना आसान बनाते हैं। यहाँ देखें कि [**फर्मवेयर से ड्राइवर एक्सटेंशन कैसे प्राप्त करें**](#ipsw)**।**

यह **C++** में लिखा गया है। आप demangled C++ प्रतीकों को प्राप्त कर सकते हैं:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** अतिरिक्त **सुरक्षा जांच** कर सकते हैं जब एक क्लाइंट किसी फ़ंक्शन को कॉल करने की कोशिश करता है लेकिन ध्यान दें कि ऐप्स आमतौर पर **sandbox** द्वारा **सीमित** होते हैं कि वे IOKit फ़ंक्शंस के साथ किस प्रकार इंटरैक्ट कर सकते हैं।

## ड्राइवर

macOS में ये निम्नलिखित स्थानों पर स्थित हैं:

- **`/System/Library/Extensions`**
- KEXT फ़ाइलें जो OS X ऑपरेटिंग सिस्टम में निर्मित हैं।
- **`/Library/Extensions`**
- KEXT फ़ाइलें जो 3rd पार्टी सॉफ़्टवेयर द्वारा स्थापित की गई हैं।

iOS में ये निम्नलिखित स्थानों पर स्थित हैं:

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
9 तक सूचीबद्ध ड्राइवर **पता 0 में लोड होते हैं**। इसका मतलब है कि वे असली ड्राइवर नहीं हैं बल्कि **कर्नेल का हिस्सा हैं और इन्हें अनलोड नहीं किया जा सकता**।

विशिष्ट एक्सटेंशन खोजने के लिए आप उपयोग कर सकते हैं:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
कर्नेल एक्सटेंशन को लोड और अनलोड करने के लिए करें:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** macOS और iOS में IOKit ढांचे का एक महत्वपूर्ण हिस्सा है जो सिस्टम की हार्डवेयर कॉन्फ़िगरेशन और स्थिति का प्रतिनिधित्व करने के लिए एक डेटाबेस के रूप में कार्य करता है। यह **वस्तुओं का एक पदानुक्रमित संग्रह है जो सिस्टम पर लोड किए गए सभी हार्डवेयर और ड्राइवरों का प्रतिनिधित्व करता है, और उनके बीच के संबंधों को** दर्शाता है।

आप CLI **`ioreg`** का उपयोग करके IORegistry प्राप्त कर सकते हैं ताकि इसे कंसोल से निरीक्षण किया जा सके (विशेष रूप से iOS के लिए उपयोगी)।
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
आप **`IORegistryExplorer`** को **Xcode Additional Tools** से [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) से डाउनलोड कर सकते हैं और **macOS IORegistry** का निरीक्षण **ग्राफिकल** इंटरफेस के माध्यम से कर सकते हैं।

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer में, "planes" का उपयोग IORegistry में विभिन्न वस्तुओं के बीच संबंधों को व्यवस्थित और प्रदर्शित करने के लिए किया जाता है। प्रत्येक plane एक विशिष्ट प्रकार के संबंध या सिस्टम के हार्डवेयर और ड्राइवर कॉन्फ़िगरेशन का एक विशेष दृश्य दर्शाता है। यहाँ कुछ सामान्य planes हैं जिनका आप IORegistryExplorer में सामना कर सकते हैं:

1. **IOService Plane**: यह सबसे सामान्य plane है, जो सेवा वस्तुओं को प्रदर्शित करता है जो ड्राइवरों और नब्स (ड्राइवरों के बीच संचार चैनल) का प्रतिनिधित्व करते हैं। यह इन वस्तुओं के बीच प्रदाता-ग्राहक संबंधों को दिखाता है।
2. **IODeviceTree Plane**: यह plane उन उपकरणों के बीच भौतिक कनेक्शनों का प्रतिनिधित्व करता है जब वे सिस्टम से जुड़े होते हैं। इसका उपयोग अक्सर USB या PCI जैसे बसों के माध्यम से जुड़े उपकरणों की पदानुक्रम को दृश्य बनाने के लिए किया जाता है।
3. **IOPower Plane**: यह पावर प्रबंधन के संदर्भ में वस्तुओं और उनके संबंधों को प्रदर्शित करता है। यह दिखा सकता है कि कौन सी वस्तुएं अन्य की पावर स्थिति को प्रभावित कर रही हैं, जो पावर से संबंधित समस्याओं को डिबग करने के लिए उपयोगी है।
4. **IOUSB Plane**: विशेष रूप से USB उपकरणों और उनके संबंधों पर केंद्रित, USB हब और जुड़े उपकरणों की पदानुक्रम को दिखाता है।
5. **IOAudio Plane**: यह plane ऑडियो उपकरणों और उनके संबंधों का प्रतिनिधित्व करने के लिए है।
6. ...

## Driver Comm Code Example

निम्नलिखित कोड IOKit सेवा `"YourServiceNameHere"` से कनेक्ट करता है और चयनकर्ता 0 के अंदर फ़ंक्शन को कॉल करता है। इसके लिए:

- यह पहले **`IOServiceMatching`** और **`IOServiceGetMatchingServices`** को कॉल करता है ताकि सेवा प्राप्त की जा सके।
- फिर यह **`IOServiceOpen`** को कॉल करके एक कनेक्शन स्थापित करता है।
- और अंत में **`IOConnectCallScalarMethod`** के साथ एक फ़ंक्शन को कॉल करता है जो चयनकर्ता 0 को इंगित करता है (चयनकर्ता वह संख्या है जो फ़ंक्शन को कॉल करने के लिए असाइन की गई है)।
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
अन्य कार्य हैं जिन्हें **`IOConnectCallScalarMethod`** के अलावा IOKit कार्यों को कॉल करने के लिए उपयोग किया जा सकता है जैसे **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## ड्राइवर एंट्रीपॉइंट को रिवर्स करना

आप इन्हें उदाहरण के लिए [**फर्मवेयर इमेज (ipsw)**](#ipsw) से प्राप्त कर सकते हैं। फिर, इसे अपने पसंदीदा डिकंपाइलर में लोड करें।

आप **`externalMethod`** कार्य को डिकंपाइल करना शुरू कर सकते हैं क्योंकि यह वह ड्राइवर कार्य है जो कॉल प्राप्त करेगा और सही कार्य को कॉल करेगा:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

उस भयानक कॉल का डेमैग्लेड अर्थ है:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
ध्यान दें कि पिछले परिभाषा में **`self`** पैरामीटर गायब है, सही परिभाषा होगी:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
वास्तव में, आप असली परिभाषा [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) में पा सकते हैं:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
इस जानकारी के साथ आप Ctrl+Right -> `Edit function signature` को फिर से लिख सकते हैं और ज्ञात प्रकार सेट कर सकते हैं:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

नया डिकंपाइल किया गया कोड इस तरह दिखेगा:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

अगले चरण के लिए हमें **`IOExternalMethodDispatch2022`** संरचना को परिभाषित करना होगा। यह ओपनसोर्स है [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), आप इसे परिभाषित कर सकते हैं:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

अब, `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` के बाद आप बहुत सारे डेटा देख सकते हैं:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

डेटा प्रकार को **`IOExternalMethodDispatch2022:`** में बदलें:

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

बदलाव के बाद:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

और जैसा कि हम अब वहां हैं, हमारे पास **7 तत्वों का एक एरे** है (अंतिम डिकंपाइल किए गए कोड की जांच करें), 7 तत्वों का एक एरे बनाने के लिए क्लिक करें:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

एरे बनाने के बाद आप सभी निर्यातित कार्यों को देख सकते हैं:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप याद रखें, तो **यूजर स्पेस** से एक **निर्यातित** कार्य को **कॉल** करने के लिए हमें कार्य का नाम कॉल करने की आवश्यकता नहीं है, बल्कि **सेलेक्टर नंबर** की आवश्यकता है। यहां आप देख सकते हैं कि सेलेक्टर **0** कार्य **`initializeDecoder`** है, सेलेक्टर **1** **`startDecoder`** है, सेलेक्टर **2** **`initializeEncoder`** है...

{{#include ../../../banners/hacktricks-training.md}}
