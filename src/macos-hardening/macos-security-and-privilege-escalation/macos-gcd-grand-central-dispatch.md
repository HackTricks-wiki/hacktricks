# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

**Grand Central Dispatch (GCD),** ook bekend as **libdispatch** (`libdispatch.dyld`), is beskikbaar in beide macOS en iOS. Dit is 'n tegnologie wat deur Apple ontwikkel is om toepassingsondersteuning vir gelyktydige (multithreaded) uitvoering op multicore-hardeware te optimaliseer.<sup>[[4]](#references)</sup>

**GCD** verskaf en bestuur **FIFO queues** waaraan jou toepassing **take kan submit** in die vorm van **block objects**. Blocks wat na dispatch queues gesubmit word, word **op 'n poel van threads uitgevoer** wat volledig deur die stelsel bestuur word. GCD skep outomaties threads om die take in die dispatch queues uit te voer en skeduleer daardie take om op die beskikbare cores te loop.<sup>[[1]](#references)</sup>

> [!TIP]
> Kortom, om code in **parallel** uit te voer, kan prosesse **blocks of code na GCD stuur**, wat na hul uitvoering sal omsien. Prosesse skep dus nie nuwe threads nie; **GCD voer die gegewe code met sy eie poel van threads uit** (wat na gelang van die behoefte kan vermeerder of verminder).

Dit is baie nuttig om parallelle uitvoering suksesvol te bestuur, omdat dit die aantal threads wat prosesse skep aansienlik verminder en die parallelle uitvoering optimaliseer. Dit is ideaal vir take wat **groot parallelisme** vereis (brute-forcing?) of vir take wat nie die hoofthread behoort te blokkeer nie: Die hoofthread op iOS hanteer byvoorbeeld UI-interaksies, dus word enige ander funksionaliteit wat die app kan laat hang (soek, toegang tot 'n webwerf, lees van 'n lêer...) op hierdie manier bestuur.

### Blocks

'n Block is 'n **self-contained section of code** (soos 'n funksie met argumente wat 'n waarde terugstuur) en kan ook gebonde veranderlikes spesifiseer.\
Blocks bestaan egter nie op compiler-vlak nie; hulle is `os_object`s. Elk van hierdie objects word deur twee strukture gevorm:

- **block literal**:
- Dit begin met die **`isa`**-veld, wat na die block se class wys:
- `NSConcreteGlobalBlock` (blocks van `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks in die heap)
- `NSConcreateStackBlock` (blocks in die stack)
- Dit het **`flags`** (wat velde aandui wat in die block descriptor teenwoordig is) en sommige gereserveerde bytes
- Die funksiewyser om aan te roep
- 'n Wyser na die block descriptor
- Block se imported variables (indien enige)
- **block descriptor**: Die grootte daarvan hang af van die data wat teenwoordig is (soos deur die vorige flags aangedui)
- Dit het sommige gereserveerde bytes
- Die grootte daarvan
- Dit het gewoonlik 'n wyser na 'n Objective-C-styl signature om te bepaal hoeveel spasie vir die params benodig word (flag `BLOCK_HAS_SIGNATURE`)
- Indien daar na veranderlikes verwys word, sal hierdie block ook pointers na 'n copy helper (wat die waarde aan die begin kopieer) en dispose helper (wat dit vrymaak) hê.

### Queues

'n Dispatch queue is 'n benoemde object wat FIFO-volgorde van blocks vir uitvoering verskaf.<sup>[[3]](#references)</sup>

Blocks word in queues gestel om uitgevoer te word, en hierdie ondersteun 2 modes: `DISPATCH_QUEUE_SERIAL` en `DISPATCH_QUEUE_CONCURRENT`. Die **serial** een sal natuurlik nie **race condition**-probleme hê nie, aangesien 'n block nie uitgevoer sal word totdat die vorige een voltooi is nie. Maar **die ander tipe queue kan dit hê**.

Default queues:

- `.main-thread`: Van `dispatch_get_main_queue()`
- `.libdispatch-manager`: GCD se queue manager
- `.root.libdispatch-manager`: GCD se queue manager
- `.root.maintenance-qos`: Take met die laagste prioriteit
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Hoogste prioriteit
- `.root.background-qos.overcommit`

Let daarop dat die stelsel sal besluit **watter threads op elke tydstip watter queues hanteer** (meerdere threads kan in dieselfde queue werk, of dieselfde thread kan op 'n stadium in verskillende queues werk).

#### Attributtes

Wanneer 'n queue met **`dispatch_queue_create`** geskep word, is die derde argument 'n `dispatch_queue_attr_t`, wat gewoonlik óf `DISPATCH_QUEUE_SERIAL` is (wat eintlik NULL is) óf `DISPATCH_QUEUE_CONCURRENT`, wat 'n wyser na 'n `dispatch_queue_attr_t`-struct is waarmee sommige parameters van die queue beheer kan word.

### Dispatch objects

Daar is verskeie objects wat libdispatch gebruik, en queues en blocks is slegs 2 daarvan. Dit is moontlik om hierdie objects met `dispatch_object_create` te skep:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: Data blocks
- `group`: Groep van blocks
- `io`: Async I/O requests
- `mach`: Mach ports
- `mach_msg`: Mach messages
- `pthread_root_queue`: 'n Queue met 'n pthread thread pool en nie workqueues nie
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

In Objetive-C is daar verskillende funksies om 'n block te stuur om in parallel uitgevoer te word:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Submit 'n block vir asynchronous execution op 'n dispatch queue en return onmiddellik.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Submit 'n block object vir execution en return nadat daardie block klaar uitgevoer is.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Voer 'n block object slegs een keer gedurende die leeftyd van 'n application uit.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Submit 'n work item vir execution en return slegs nadat dit klaar uitgevoer is. Anders as [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), respekteer hierdie funksie al die attributes van die queue wanneer dit die block uitvoer.

Hierdie funksies verwag die volgende parameters: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Dit is die **struct van 'n Block**:
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
En dit is ’n voorbeeld van **parallelisme** met **`dispatch_async`**:
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

**`libswiftDispatch`** is ’n biblioteek wat **Swift bindings** verskaf vir die Grand Central Dispatch (GCD)-framework, wat oorspronklik in C geskryf is.\
Die **`libswiftDispatch`**-biblioteek verpak die C GCD APIs in ’n meer Swift-vriendelike koppelvlak, wat dit vir Swift-ontwikkelaars makliker en meer intuïtief maak om met GCD te werk.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Kodevoorbeeld**:
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

Die volgende Frida-script kan gebruik word om in verskeie **dispatch**-funksies te **hook** en die tou se naam, die backtrace en die blok te onttrek: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Tans verstaan Ghidra nóg die ObjectiveC **`dispatch_block_t`**-struktuur, nóg die **`swift_dispatch_block`**-een.

As jy dus wil hê dat dit hulle moet verstaan, kan jy hulle eenvoudig **declare**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Soek dan ’n plek in die kode waar hulle **gebruik** word:

> [!TIP]
> Let op al die verwysings na "block" om te verstaan hoe jy kan vasstel dat die struktuur gebruik word.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Regsklik op die veranderlike -> Retype Variable en kies in hierdie geval **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra sal alles outomaties herskryf:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Verwysings

- [1] [libdispatch — `src/queue.c` (queue/thread-pool implementation)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
