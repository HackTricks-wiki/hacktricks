# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

**Grand Central Dispatch (GCD),** जिसे **libdispatch** (`libdispatch.dyld`) के नाम से भी जाना जाता है, macOS और iOS दोनों में उपलब्ध है। यह एक तकनीक है जिसे Apple ने मल्टीकोर हार्डवेयर पर समवर्ती (मल्टीथ्रेडेड) निष्पादन के लिए एप्लिकेशन समर्थन को अनुकूलित करने के लिए विकसित किया है।

**GCD** **FIFO queues** प्रदान करता है और प्रबंधित करता है, जिनमें आपका एप्लिकेशन **block objects** के रूप में **tasks** सबमिट कर सकता है। डिस्पैच कतारों में सबमिट किए गए ब्लॉक्स को **सिस्टम द्वारा पूरी तरह से प्रबंधित थ्रेड्स के पूल पर निष्पादित किया जाता है।** GCD स्वचालित रूप से डिस्पैच कतारों में कार्यों को निष्पादित करने के लिए थ्रेड्स बनाता है और उन कार्यों को उपलब्ध कोर पर चलाने के लिए शेड्यूल करता है।

> [!TIP]
> संक्षेप में, **समानांतर** में कोड निष्पादित करने के लिए, प्रक्रियाएँ **GCD** को **कोड के ब्लॉक्स** भेज सकती हैं, जो उनके निष्पादन का ध्यान रखेगा। इसलिए, प्रक्रियाएँ नए थ्रेड्स नहीं बनातीं; **GCD दिए गए कोड को अपने स्वयं के थ्रेड्स के पूल के साथ निष्पादित करता है** (जो आवश्यकतानुसार बढ़ या घट सकता है)।

यह समानांतर निष्पादन को सफलतापूर्वक प्रबंधित करने में बहुत सहायक है, प्रक्रियाओं द्वारा बनाए गए थ्रेड्स की संख्या को काफी कम करता है और समानांतर निष्पादन का अनुकूलन करता है। यह उन कार्यों के लिए आदर्श है जिन्हें **महान समानांतरता** (ब्रूट-फोर्सिंग?) की आवश्यकता होती है या उन कार्यों के लिए जो मुख्य थ्रेड को अवरुद्ध नहीं करना चाहिए: उदाहरण के लिए, iOS पर मुख्य थ्रेड UI इंटरैक्शन को संभालता है, इसलिए कोई भी अन्य कार्यक्षमता जो ऐप को लटका सकती है (खोज, वेब तक पहुंचना, फ़ाइल पढ़ना...) इस तरह से प्रबंधित की जाती है।

### Blocks

एक ब्लॉक एक **स्वयं निहित कोड का खंड** है (जैसे एक फ़ंक्शन जिसमें तर्क होते हैं जो एक मान लौटाता है) और यह बाउंड वेरिएबल भी निर्दिष्ट कर सकता है।\
हालांकि, कंपाइलर स्तर पर ब्लॉक्स मौजूद नहीं होते, वे `os_object`s होते हैं। इन वस्तुओं में से प्रत्येक दो संरचनाओं से बना होता है:

- **block literal**:
- यह **`isa`** फ़ील्ड से शुरू होता है, जो ब्लॉक की कक्षा की ओर इशारा करता है:
- `NSConcreteGlobalBlock` (ब्लॉक्स `__DATA.__const` से)
- `NSConcreteMallocBlock` (हीप में ब्लॉक्स)
- `NSConcreateStackBlock` (स्टैक में ब्लॉक्स)
- इसमें **`flags`** होते हैं (जो ब्लॉक विवरण में मौजूद फ़ील्ड को इंगित करते हैं) और कुछ आरक्षित बाइट्स
- कॉल करने के लिए फ़ंक्शन पॉइंटर
- ब्लॉक विवरण के लिए एक पॉइंटर
- आयातित ब्लॉक वेरिएबल (यदि कोई हो)
- **block descriptor**: इसका आकार उस डेटा पर निर्भर करता है जो मौजूद है (जैसा कि पिछले फ़्लैग में संकेतित है)
- इसमें कुछ आरक्षित बाइट्स होते हैं
- इसका आकार
- इसमें आमतौर पर एक Objective-C शैली के हस्ताक्षर के लिए एक पॉइंटर होगा ताकि यह पता चल सके कि पैरामीटर के लिए कितनी जगह की आवश्यकता है (फ्लैग `BLOCK_HAS_SIGNATURE`)
- यदि वेरिएबल संदर्भित हैं, तो इस ब्लॉक में एक कॉपी हेल्पर (शुरुआत में मान की कॉपी करना) और डिस्पोज हेल्पर (इसे मुक्त करना) के लिए पॉइंटर्स भी होंगे।

### Queues

एक डिस्पैच कतार एक नामित वस्तु है जो निष्पादन के लिए ब्लॉक्स का FIFO क्रम प्रदान करती है।

ब्लॉक्स को निष्पादित करने के लिए कतारों में सेट किया जाता है, और ये 2 मोड का समर्थन करते हैं: `DISPATCH_QUEUE_SERIAL` और `DISPATCH_QUEUE_CONCURRENT`। बेशक, **सीरियल** वाला **रेस कंडीशन** समस्याओं का सामना नहीं करेगा क्योंकि एक ब्लॉक तब तक निष्पादित नहीं होगा जब तक कि पिछले वाला समाप्त नहीं हो गया है। लेकिन **दूसरे प्रकार की कतार में यह हो सकता है**।

डिफ़ॉल्ट कतारें:

- `.main-thread`: `dispatch_get_main_queue()` से
- `.libdispatch-manager`: GCD का कतार प्रबंधक
- `.root.libdispatch-manager`: GCD का कतार प्रबंधक
- `.root.maintenance-qos`: सबसे कम प्राथमिकता वाले कार्य
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND` के रूप में उपलब्ध
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE` के रूप में उपलब्ध
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT` के रूप में उपलब्ध
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH` के रूप में उपलब्ध
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: उच्चतम प्राथमिकता
- `.root.background-qos.overcommit`

ध्यान दें कि यह सिस्टम होगा जो **निर्धारित करेगा कि प्रत्येक समय कौन से थ्रेड्स कौन सी कतारों को संभालते हैं** (एक ही कतार में कई थ्रेड्स काम कर सकते हैं या एक ही थ्रेड विभिन्न कतारों में किसी बिंदु पर काम कर सकता है)

#### Attributtes

जब **`dispatch_queue_create`** के साथ एक कतार बनाई जाती है, तो तीसरा तर्क एक `dispatch_queue_attr_t` होता है, जो आमतौर पर या तो `DISPATCH_QUEUE_SERIAL` (जो वास्तव में NULL है) या `DISPATCH_QUEUE_CONCURRENT` होता है, जो एक `dispatch_queue_attr_t` संरचना के लिए एक पॉइंटर होता है जो कतार के कुछ पैरामीटर को नियंत्रित करने की अनुमति देता है।

### Dispatch objects

libdispatch द्वारा उपयोग की जाने वाली कई वस्तुएं हैं और कतारें और ब्लॉक्स केवल उनमें से 2 हैं। इन वस्तुओं को `dispatch_object_create` के साथ बनाना संभव है:

- `block`
- `data`: डेटा ब्लॉक्स
- `group`: ब्लॉक्स का समूह
- `io`: Async I/O अनुरोध
- `mach`: Mach पोर्ट
- `mach_msg`: Mach संदेश
- `pthread_root_queue`: pthread थ्रेड पूल के साथ एक कतार और कार्य कतारें नहीं
- `queue`
- `semaphore`
- `source`: इवेंट स्रोत

## Objective-C

Objective-C में समानांतर निष्पादन के लिए एक ब्लॉक भेजने के लिए विभिन्न फ़ंक्शन हैं:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): एक डिस्पैच कतार पर असिंक्रोनस निष्पादन के लिए एक ब्लॉक सबमिट करता है और तुरंत लौटता है।
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): निष्पादन के लिए एक ब्लॉक ऑब्जेक्ट सबमिट करता है और उस ब्लॉक के निष्पादित होने के बाद लौटता है।
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): एक एप्लिकेशन के जीवनकाल के लिए केवल एक बार एक ब्लॉक ऑब्जेक्ट को निष्पादित करता है।
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): निष्पादन के लिए एक कार्य आइटम सबमिट करता है और केवल तब लौटता है जब यह निष्पादित हो जाता है। [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) के विपरीत, यह फ़ंक्शन ब्लॉक को निष्पादित करते समय कतार के सभी गुणों का सम्मान करता है।

ये फ़ंक्शन इन पैरामीटर की अपेक्षा करते हैं: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

यह एक **ब्लॉक का संरचना** है:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
और यह **`dispatch_async`** के साथ **parallelism** का उपयोग करने का एक उदाहरण है:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** एक पुस्तकालय है जो **Swift bindings** प्रदान करता है Grand Central Dispatch (GCD) ढांचे के लिए जो मूल रूप से C में लिखा गया है।\
**`libswiftDispatch`** पुस्तकालय C GCD APIs को एक अधिक Swift-फ्रेंडली इंटरफेस में लपेटता है, जिससे Swift डेवलपर्स के लिए GCD के साथ काम करना आसान और अधिक सहज हो जाता है।

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Code example**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

निम्नलिखित Frida स्क्रिप्ट का उपयोग **कई `dispatch`** फ़ंक्शनों में हुक करने और कतार का नाम, बैकट्रेस और ब्लॉक निकालने के लिए किया जा सकता है: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

वर्तमान में Ghidra न तो ObjectiveC **`dispatch_block_t`** संरचना को समझता है, न ही **`swift_dispatch_block`** को।

तो यदि आप इसे समझाना चाहते हैं, तो आप बस **उन्हें घोषित कर सकते हैं**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

फिर, कोड में एक स्थान खोजें जहाँ वे **उपयोग किए गए हैं**:

> [!TIP]
> "block" के सभी संदर्भों को नोट करें ताकि आप समझ सकें कि संरचना का उपयोग किया जा रहा है।

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

वेरिएबल पर राइट-क्लिक करें -> वेरिएबल को फिर से टाइप करें और इस मामले में **`swift_dispatch_block`** का चयन करें:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra स्वचालित रूप से सब कुछ फिर से लिख देगा:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
