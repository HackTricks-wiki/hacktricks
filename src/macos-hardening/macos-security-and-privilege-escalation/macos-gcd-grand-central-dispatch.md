# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

**Grand Central Dispatch (GCD),** inayojulikana pia kama **libdispatch** (`libdispatch.dyld`), inapatikana kwenye macOS na iOS. Ni teknolojia iliyotengenezwa na Apple kwa ajili ya kuboresha usaidizi wa application kwa utekelezaji wa concurrent (multithreaded) kwenye hardware yenye multicore.<sup>[[4]](#references)</sup>

**GCD** hutoa na kusimamia **FIFO queues** ambazo application yako inaweza **kutuma tasks** kwa muundo wa **block objects**. Blocks zinazotumwa kwenye dispatch queues **hutekelezwa kwenye pool ya threads** inayosimamiwa kikamilifu na system. GCD huunda threads kiotomatiki kwa ajili ya kutekeleza tasks zilizo kwenye dispatch queues na kupanga tasks hizo zitekelezwe kwenye cores zinazopatikana.<sup>[[1]](#references)</sup>

> [!TIP]
> Kwa muhtasari, ili kutekeleza code kwa **parallel**, processes zinaweza kutuma **blocks za code kwa GCD**, ambayo itashughulikia utekelezaji wake. Kwa hiyo, processes hazitengenezi threads mpya; **GCD hutekeleza code iliyotolewa kwa kutumia pool yake ya threads** (ambayo inaweza kuongezeka au kupungua inapohitajika).

Hii husaidia sana kusimamia utekelezaji wa parallel kwa ufanisi, huku ikipunguza kwa kiasi kikubwa idadi ya threads zinazoundwa na processes na kuboresha utekelezaji wa parallel. Hii ni bora kwa tasks zinazohitaji **parallelism kubwa** (brute-forcing?) au kwa tasks ambazo hazipaswi kuzuia main thread: Kwa mfano, main thread kwenye iOS hushughulikia mwingiliano wa UI, hivyo functionality nyingine yoyote inayoweza kufanya app igande (kutafuta, kufikia web, kusoma file...) husimamiwa kwa njia hii.

### Blocks

Block ni **sehemu ya code inayojitosheleza** (kama function yenye arguments inayorejesha value) na pia inaweza kubainisha variables zilizofungwa.\
Hata hivyo, katika kiwango cha compiler blocks hazipo; ni `os_object`s. Kila moja ya objects hizi imeundwa na structures mbili:

- **block literal**:
- Huanzia kwenye field ya **`isa`**, inayoelekeza kwenye class ya block:
- `NSConcreteGlobalBlock` (blocks kutoka `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks zilizo kwenye heap)
- `NSConcreateStackBlock` (blocks zilizo kwenye stack)
- Ina **`flags`** (zinazoonyesha fields zilizopo kwenye block descriptor) pamoja na bytes zilizotengwa
- Function pointer ya kuita
- Pointer inayoelekeza kwenye block descriptor
- Variables zilizoingizwa kwenye Block (ikiwa zipo)
- **block descriptor**: Ukubwa wake hutegemea data iliyopo (kama ilivyoonyeshwa na flags zilizotangulia)
- Ina bytes zilizotengwa
- Ukubwa wake
- Kwa kawaida huwa na pointer inayoelekeza kwenye signature ya mtindo wa Objective-C ili kujua kiasi cha nafasi kinachohitajika kwa params (flag `BLOCK_HAS_SIGNATURE`)
- Ikiwa variables zimereferenziwa, block hii pia itakuwa na pointers zinazoelekeza kwenye copy helper (inayocopy value mwanzoni) na dispose helper (inayoifree).

### Queues

Dispatch queue ni object yenye jina inayotoa mpangilio wa FIFO wa blocks kwa ajili ya executions.<sup>[[3]](#references)</sup>

Blocks huwekwa kwenye queues ili zitekelezwe, na queues hizi zinaunga mkono modes 2: `DISPATCH_QUEUE_SERIAL` na `DISPATCH_QUEUE_CONCURRENT`. Bila shaka, **serial** **haitakuwa na** matatizo ya race condition kwa sababu block haitatekelezwa hadi ile iliyotangulia imalize. Lakini **aina nyingine ya queue inaweza kuwa nayo**.

Default queues:

- `.main-thread`: Kutoka `dispatch_get_main_queue()`
- `.libdispatch-manager`: Queue manager ya GCD
- `.root.libdispatch-manager`: Queue manager ya GCD
- `.root.maintenance-qos`: Tasks zenye priority ya chini zaidi
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Priority ya juu zaidi
- `.root.background-qos.overcommit`

Kumbuka kuwa ni system inayoamua **ni threads zipi zitashughulikia queues zipi kwa kila wakati** (threads nyingi zinaweza kufanya kazi kwenye queue moja, au thread hiyo hiyo inaweza kufanya kazi kwenye queues tofauti wakati fulani)

#### Attributtes

Wakati wa kuunda queue kwa kutumia **`dispatch_queue_create`**, argument ya tatu ni `dispatch_queue_attr_t`, ambayo kwa kawaida huwa `DISPATCH_QUEUE_SERIAL` (ambayo kwa kweli ni NULL) au `DISPATCH_QUEUE_CONCURRENT`, ambayo ni pointer ya struct ya `dispatch_queue_attr_t inayoruhusu kudhibiti baadhi ya parameters za queue.

### Dispatch objects

Kuna objects kadhaa ambazo libdispatch hutumia, na queues pamoja na blocks ni 2 tu kati yake. Inawezekana kuunda objects hizi kwa kutumia `dispatch_object_create`:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: Data blocks
- `group`: Group ya blocks
- `io`: Async I/O requests
- `mach`: Mach ports
- `mach_msg`: Mach messages
- `pthread_root_queue`:Queue yenye pthread thread pool na isiyo na workqueues
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Kwenye Objective-C kuna functions tofauti za kutuma block ili itekelezwe kwa parallel:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Hutuma block kwa ajili ya utekelezaji wa asynchronous kwenye dispatch queue na kurejea mara moja.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Hutuma block object kwa ajili ya utekelezaji na kurejea baada ya block hiyo kumaliza kutekelezwa.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Hutekeleza block object mara moja tu katika kipindi chote cha uhai wa application.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Hutuma work item kwa ajili ya utekelezaji na kurejea baada tu ya kumaliza kutekelezwa. Tofauti na [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), function hii huheshimu attributes zote za queue inapotekeleza block.

Functions hizi zinatarajia parameters hizi: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Hii ndiyo **struct ya Block**:
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
Na huu ni mfano wa kutumia **parallelism** pamoja na **`dispatch_async`**:
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

**`libswiftDispatch`** ni library inayotoa **Swift bindings** kwa framework ya Grand Central Dispatch (GCD), ambayo iliandikwa awali kwa C.\
Library ya **`libswiftDispatch`** inafunga C GCD APIs katika interface inayofaa zaidi kwa Swift, na kufanya iwe rahisi na yenye kueleweka zaidi kwa developers wa Swift kufanya kazi na GCD.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Mfano wa msimbo**:
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

Script ifuatayo ya Frida inaweza kutumika **ku-hook kwenye** functions kadhaa za `dispatch` na kutoa jina la queue, backtrace na block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Kwa sasa Ghidra haielewi **`dispatch_block_t`** structure ya ObjectiveC wala **`swift_dispatch_block`** structure.

Kwa hiyo, ikiwa unataka izielewe, unaweza tu **kuzitangaza**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Kisha, tafuta sehemu kwenye code ambapo **zinatumika**:

> [!TIP]
> Zingatia marejeleo yote yaliyofanywa kwa "block" ili kuelewa jinsi unavyoweza kubaini kuwa struct inatumika.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Bofya kulia kwenye variable -> Retype Variable na uchague katika hali hii **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra itaandika upya kila kitu kiotomatiki:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Marejeleo

- [1] [libdispatch — `src/queue.c` (utekelezaji wa queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
