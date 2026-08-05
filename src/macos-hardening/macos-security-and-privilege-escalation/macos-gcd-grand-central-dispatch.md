# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

**Grand Central Dispatch (GCD),** जिसे **libdispatch** (`libdispatch.dyld`) के नाम से भी जाना जाता है, macOS और iOS दोनों में उपलब्ध है। यह Apple द्वारा विकसित technology है, जिसे multicore hardware पर concurrent (multithreaded) execution के लिए application support को optimize करने के लिए बनाया गया है।

**GCD** **FIFO queues** प्रदान और manage करता है, जिनमें आपका application **block objects** के रूप में **tasks submit** कर सकता है। Dispatch queues में submit किए गए blocks को system द्वारा पूरी तरह manage किए जाने वाले **threads के pool** पर **execute** किया जाता है। GCD dispatch queues में मौजूद tasks को execute करने के लिए automatically threads create करता है और उन tasks को available cores पर run करने के लिए schedule करता है।

> [!TIP]
> संक्षेप में, code को **parallel** execute करने के लिए processes, **GCD को code के blocks भेज** सकते हैं, जो उनके execution का ध्यान रखेगा। इसलिए processes नए threads create नहीं करते; **GCD दिए गए code को अपने threads के pool से execute करता है** (जो आवश्यकता के अनुसार बढ़ या घट सकता है)।

यह parallel execution को सफलतापूर्वक manage करने में बहुत उपयोगी है, processes द्वारा create किए जाने वाले threads की संख्या को काफी कम करता है और parallel execution को optimize करता है। यह उन tasks के लिए ideal है जिनमें **बहुत अधिक parallelism** (brute-forcing?) की आवश्यकता होती है या जिन्हें main thread को block नहीं करना चाहिए। उदाहरण के लिए, iOS पर main thread UI interactions को handle करता है, इसलिए ऐसी कोई भी अन्य functionality जिससे app hang हो सकता है (searching, web access करना, file पढ़ना...) इस तरीके से manage की जाती है।

### Blocks

एक block **self contained code section** होता है (arguments वाले ऐसे function की तरह जो कोई value return करता है) और यह bound variables को भी specify कर सकता है।\
हालांकि compiler level पर blocks मौजूद नहीं होते, वे `os_object`s होते हैं। इनमें से प्रत्येक object दो structures से बना होता है:

- **block literal**:
- यह **`isa`** field से शुरू होता है, जो block की class की ओर point करता है:
- `NSConcreteGlobalBlock` (`__DATA.__const` से blocks)
- `NSConcreteMallocBlock` (heap में blocks)
- `NSConcreateStackBlock` (stack में blocks)
- इसमें **`flags`** होते हैं (जो block descriptor में मौजूद fields को indicate करते हैं) और कुछ reserved bytes होते हैं
- call किए जाने वाले function का pointer
- block descriptor का pointer
- Block की imported variables (यदि कोई हों)
- **block descriptor**: इसका size मौजूद data पर निर्भर करता है (जैसा कि पिछले flags में indicate किया गया है)
- इसमें कुछ reserved bytes होते हैं
- इसका size
- इसमें आमतौर पर Objective-C style signature का pointer होता है, ताकि यह पता चल सके कि params के लिए कितनी space आवश्यक है (flag `BLOCK_HAS_SIGNATURE`)
- यदि variables reference की गई हों, तो इस block में copy helper (शुरुआत में value को copy करने के लिए) और dispose helper (इसे free करने के लिए) के pointers भी होंगे।

### Queues

एक dispatch queue एक named object है, जो execution के लिए blocks का FIFO ordering प्रदान करता है।

Blocks को execute करने के लिए queues में set किया जाता है, और ये 2 modes support करते हैं: `DISPATCH_QUEUE_SERIAL` और `DISPATCH_QUEUE_CONCURRENT`। स्वाभाविक रूप से **serial** queue में **race condition** की समस्याएं **नहीं होंगी**, क्योंकि पिछला block पूरा होने तक कोई block execute नहीं होगा। लेकिन **दूसरे प्रकार की queue में यह समस्या हो सकती है**।

Default queues:

- `.main-thread`: `dispatch_get_main_queue()` से
- `.libdispatch-manager`: GCD का queue manager
- `.root.libdispatch-manager`: GCD का queue manager
- `.root.maintenance-qos`: सबसे कम priority वाले tasks
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND` के रूप में उपलब्ध
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE` के रूप में उपलब्ध
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT` के रूप में उपलब्ध
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH` के रूप में उपलब्ध
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: सबसे अधिक priority
- `.root.background-qos.overcommit`

ध्यान दें कि **किस समय कौन-से threads कौन-सी queues को handle करेंगे**, इसका निर्णय system करेगा (कई threads एक ही queue पर काम कर सकते हैं या कोई एक thread किसी समय अलग-अलग queues पर काम कर सकता है)

#### Attributes

**`dispatch_queue_create`** से queue create करते समय तीसरा argument एक `dispatch_queue_attr_t` होता है, जो आमतौर पर या तो `DISPATCH_QUEUE_SERIAL` होता है (जो वास्तव में NULL है) या `DISPATCH_QUEUE_CONCURRENT` होता है, जो एक `dispatch_queue_attr_t` struct का pointer है और queue के कुछ parameters को control करने की अनुमति देता है।

### Dispatch objects

libdispatch द्वारा कई objects का उपयोग किया जाता है और queues तथा blocks उनमें से केवल 2 हैं। इन objects को `dispatch_object_create` से create करना संभव है:

- `block`
- `data`: Data blocks
- `group`: Blocks का group
- `io`: Async I/O requests
- `mach`: Mach ports
- `mach_msg`: Mach messages
- `pthread_root_queue`: pthread thread pool वाली queue और workqueues नहीं
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Objetive-C में block को parallel execution के लिए भेजने हेतु अलग-अलग functions उपलब्ध हैं:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): किसी block को dispatch queue पर asynchronous execution के लिए submit करता है और तुरंत return करता है।
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): किसी block object को execution के लिए submit करता है और उस block का execution पूरा होने के बाद return करता है।
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): किसी application के lifetime में block object को केवल एक बार execute करता है।
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): किसी work item को execution के लिए submit करता है और केवल उसके execution पूरा होने के बाद return करता है। [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) के विपरीत, यह function block को execute करते समय queue के सभी attributes का सम्मान करता है।

इन functions को ये parameters अपेक्षित होते हैं: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

यह **Block का struct** है:
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
और यह **parallelism** को **`dispatch_async`** के साथ उपयोग करने का एक उदाहरण है:
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

**`libswiftDispatch`** एक library है जो Grand Central Dispatch (GCD) framework के लिए **Swift bindings** प्रदान करती है, जिसे मूल रूप से C में लिखा गया है।\
**`libswiftDispatch`** library C GCD APIs को अधिक Swift-friendly interface में wrap करती है, जिससे Swift developers के लिए GCD के साथ काम करना आसान और अधिक intuitive हो जाता है।

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**कोड उदाहरण**:
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

निम्नलिखित Frida script का उपयोग कई **`dispatch`** functions में **hook** करने और queue name, backtrace तथा block निकालने के लिए किया जा सकता है: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)।
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

वर्तमान में Ghidra न तो ObjectiveC **`dispatch_block_t`** structure को समझता है, न ही **`swift_dispatch_block`** structure को।

इसलिए यदि आप चाहते हैं कि यह उन्हें समझे, तो आप उन्हें बस **declare** कर सकते हैं:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

फिर, code में ऐसी जगह खोजें जहाँ उनका **use** किया गया हो:

> [!TIP]
> "block" के सभी references पर ध्यान दें, ताकि आप समझ सकें कि struct का use किया जा रहा है, यह कैसे पता लगाया जा सकता है।

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Variable पर right click करें -> Retype Variable और इस मामले में **`swift_dispatch_block`** चुनें:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra अपने-आप सब कुछ rewrite कर देगा:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (queue/thread-pool implementation)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
