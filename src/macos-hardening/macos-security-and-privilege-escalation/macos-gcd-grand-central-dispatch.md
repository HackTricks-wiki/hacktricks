# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

**Grand Central Dispatch (GCD),** pia inajulikana kama **libdispatch** (`libdispatch.dyld`), inapatikana kwenye macOS na iOS. Ni teknolojia iliyotengenezwa na Apple ili kuboresha usaidizi wa application kwa utekelezaji wa wakati mmoja (multithreaded) kwenye hardware yenye multicore.

**GCD** hutoa na kudhibiti **FIFO queues** ambazo application yako inaweza **kutuma tasks** kwa mfumo wa **block objects**. Blocks zinazotumwa kwenye dispatch queues **hutekelezwa kwenye pool ya threads** inayodhibitiwa kikamilifu na system. GCD huunda threads kiotomatiki kwa ajili ya kutekeleza tasks kwenye dispatch queues na hupanga tasks hizo zitekelezwe kwenye cores zinazopatikana.

> [!TIP]
> Kwa muhtasari, ili kutekeleza code kwa **parallel**, processes zinaweza kutuma **blocks za code kwa GCD**, ambayo itashughulikia utekelezaji wake. Kwa hiyo, processes hazitengenezi threads mpya; **GCD hutekeleza code iliyotolewa kwa kutumia pool yake ya threads** (ambayo inaweza kuongezeka au kupungua inapohitajika).

Hii husaidia sana kudhibiti utekelezaji wa parallel kwa mafanikio, huku ikipunguza kwa kiasi kikubwa idadi ya threads zinazoundwa na processes na kuboresha utekelezaji wa parallel. Hii ni bora kwa tasks zinazohitaji **parallelism kubwa** (brute-forcing?) au kwa tasks ambazo hazipaswi kuzuia main thread: Kwa mfano, main thread kwenye iOS hushughulikia mwingiliano wa UI, kwa hiyo utendaji mwingine wowote unaoweza kufanya app isigande (kutafuta, kufikia web, kusoma file...) hudhibitiwa kwa njia hii.

### Blocks

Block ni **sehemu ya code inayojitosheleza** (kama function yenye arguments inayorudisha value) na pia inaweza kubainisha variables zilizofungwa.\
Hata hivyo, katika kiwango cha compiler blocks hazipo; ni `os_object`s. Kila moja ya objects hizi imeundwa na structures mbili:

- **block literal**:
- Huanzia kwenye field ya **`isa`**, inayoelekeza kwenye class ya block:
- `NSConcreteGlobalBlock` (blocks kutoka `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks zilizo kwenye heap)
- `NSConcreateStackBlock` (blocks zilizo kwenye stack)
- Ina **`flags`** (zinazoonyesha fields zilizopo kwenye block descriptor) na bytes zilizotengwa
- Function pointer ya kuita
- Pointer inayoelekea kwenye block descriptor
- Variables zilizoingizwa kwenye block (ikiwa zipo)
- **block descriptor**: Ukubwa wake hutegemea data iliyopo (kama inavyoonyeshwa na flags zilizotangulia)
- Ina bytes zilizotengwa
- Ukubwa wake
- Kwa kawaida itakuwa na pointer inayoelekea kwenye signature ya mtindo wa Objective-C ili kujua kiasi cha nafasi kinachohitajika kwa params (flag `BLOCK_HAS_SIGNATURE`)
- Ikiwa variables zimereferenziwa, block hii pia itakuwa na pointers zinazoelekea kwenye copy helper (inayonakili value mwanzoni) na dispose helper (inayoifuta).

### Queues

Dispatch queue ni object yenye jina inayotoa mpangilio wa FIFO wa blocks kwa ajili ya utekelezaji.

Blocks huwekwa kwenye queues ili zitekelezwe, na hizi zinaunga mkono modes 2: `DISPATCH_QUEUE_SERIAL` na `DISPATCH_QUEUE_CONCURRENT`. Bila shaka, ile ya **serial** **haitakuwa na** matatizo ya race condition kwa sababu block haitatekelezwa hadi ile iliyotangulia imalize. Lakini **aina nyingine ya queue inaweza kuwa nayo**.

Queues za default:

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

Kumbuka kwamba ni system inayoamua **ni threads zipi zitashughulikia queues zipi kwa kila wakati** (threads nyingi zinaweza kufanya kazi kwenye queue moja, au thread ileile inaweza kufanya kazi kwenye queues tofauti wakati fulani)

#### Attributtes

Wakati wa kuunda queue kwa kutumia **`dispatch_queue_create`**, argument ya tatu ni `dispatch_queue_attr_t`, ambayo kwa kawaida huwa ama `DISPATCH_QUEUE_SERIAL` (ambayo kwa hakika ni NULL) au `DISPATCH_QUEUE_CONCURRENT`, ambayo ni pointer ya struct ya `dispatch_queue_attr_t` inayoruhusu kudhibiti baadhi ya parameters za queue.

### Dispatch objects

Kuna objects kadhaa zinazotumiwa na libdispatch, na queues pamoja na blocks ni 2 tu kati yao. Inawezekana kuunda objects hizi kwa kutumia `dispatch_object_create`:

- `block`
- `data`: Data blocks
- `group`: Group ya blocks
- `io`: Async I/O requests
- `mach`: Mach ports
- `mach_msg`: Mach messages
- `pthread_root_queue`:Queue yenye pool ya pthread thread na isiyotumia workqueues
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Kwenye Objetive-C kuna functions tofauti za kutuma block itekelezwe kwa parallel:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Hutuma block kwa ajili ya utekelezaji wa asynchronous kwenye dispatch queue na kurudi mara moja.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Hutuma block object kwa ajili ya utekelezaji na kurudi baada ya block hiyo kumaliza kutekelezwa.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Hutekeleza block object mara moja tu katika muda wote wa kuwepo kwa application.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Hutuma work item kwa ajili ya utekelezaji na kurudi baada tu ya kumaliza kutekelezwa. Tofauti na [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), function hii huheshimu attributes zote za queue inapotekeleza block.

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
Na huu ni mfano wa kutumia **uendeshaji sambamba** na **`dispatch_async`**:
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

**`libswiftDispatch`** ni library inayotoa **Swift bindings** kwa framework ya Grand Central Dispatch (GCD), ambayo awali iliandikwa kwa C.\
Library ya **`libswiftDispatch`** hufunga C GCD APIs katika interface inayofaa zaidi kwa Swift, hivyo kurahisisha na kufanya iwe angavu zaidi kwa Swift developers kufanya kazi na GCD.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Mfano wa code**:
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

Frida script ifuatayo inaweza kutumika kufanya **hook kwenye** functions kadhaa za `dispatch` na kutoa jina la queue, backtrace na block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Kwa sasa Ghidra haielewi muundo wa **`dispatch_block_t`** wa ObjectiveC, wala muundo wa **`swift_dispatch_block`**.

Kwa hiyo ikiwa unataka iweze kuielewa, unaweza tu **kuitangaza**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Kisha, tafuta sehemu kwenye code ambapo inatumiwa:

> [!TIP]
> Zingatia marejeleo yote ya "block" ili kuelewa jinsi unavyoweza kubaini kuwa struct inatumiwa.

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
