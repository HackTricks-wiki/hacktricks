# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

**Grand Central Dispatch (GCD),** ook bekend as **libdispatch** (`libdispatch.dyld`), is beskikbaar in beide macOS en iOS. Dit is 'n tegnologie wat deur Apple ontwikkel is om toepassingsondersteuning vir gelyktydige (multithreaded) uitvoering op multicore hardeware te optimaliseer.

**GCD** bied en bestuur **FIFO-rye** waaraan jou toepassing **take kan indien** in die vorm van **blokobjekte**. Blokke wat aan afleweringsrye ingedien word, word **op 'n poel van drade** wat volledig deur die stelsel bestuur word, **uitgevoer**. GCD skep outomaties drade om die take in die afleweringsrye uit te voer en skeduleer daardie take om op die beskikbare kerne te loop.

> [!TIP]
> In samevatting, om kode in **parallel** uit te voer, kan prosesse **kodeblokke na GCD stuur**, wat sorg vir hul uitvoering. Daarom skep prosesse nie nuwe drade nie; **GCD voer die gegewe kode uit met sy eie poel van drade** (wat kan toeneem of afneem soos nodig).

Dit is baie nuttig om parallelle uitvoering suksesvol te bestuur, wat die aantal drade wat prosesse skep, aansienlik verminder en die parallelle uitvoering optimaliseer. Dit is ideaal vir take wat **groot parallelisme** vereis (brute-forcing?) of vir take wat nie die hoofdraad moet blokkeer nie: Byvoorbeeld, die hoofdraad op iOS hanteer UI-interaksies, so enige ander funksionaliteit wat die toepassing kan laat hang (soek, toegang tot 'n web, lees 'n lêer...) word op hierdie manier bestuur.

### Blokke

'n Blok is 'n **self-onderhoudende gedeelte van kode** (soos 'n funksie met argumente wat 'n waarde teruggee) en kan ook gebonde veranderlikes spesifiseer.\
Echter, op kompilervlak bestaan blokke nie, hulle is `os_object`s. Elke van hierdie objekten bestaan uit twee strukture:

- **blok letterlik**:
- Dit begin met die **`isa`** veld, wat na die blok se klas wys:
- `NSConcreteGlobalBlock` (blokke van `__DATA.__const`)
- `NSConcreteMallocBlock` (blokke in die heap)
- `NSConcreateStackBlock` (blokke in die stapel)
- Dit het **`flags`** (wat velde aandui wat in die blok beskrywer teenwoordig is) en 'n paar gereserveerde bytes
- Die funksie-aanwyser om aan te roep
- 'n Aanwyser na die blok beskrywer
- Blok ingevoerde veranderlikes (indien enige)
- **blok beskrywer**: Die grootte hang af van die data wat teenwoordig is (soos aangedui in die vorige vlae)
- Dit het 'n paar gereserveerde bytes
- Die grootte daarvan
- Dit sal gewoonlik 'n aanwyser na 'n Objective-C styl handtekening hê om te weet hoeveel ruimte vir die parameters benodig word (vlag `BLOCK_HAS_SIGNATURE`)
- As veranderlikes verwys word, sal hierdie blok ook aanwysers na 'n kopie-hulpbron (wat die waarde aan die begin kopieer) en 'n ontslag-hulpbron (wat dit vrymaak) hê.

### Rye

'n Afleweringsry is 'n benoemde objek wat FIFO-ordening van blokke vir uitvoerings bied.

Blokke word in rye gestel om uitgevoer te word, en hierdie ondersteun 2 modi: `DISPATCH_QUEUE_SERIAL` en `DISPATCH_QUEUE_CONCURRENT`. Natuurlik sal die **seriale** een **nie race condition** probleme hê nie, aangesien 'n blok nie uitgevoer sal word totdat die vorige een klaar is nie. Maar **die ander tipe ry mag dit hê**.

Standaard rye:

- `.main-thread`: Van `dispatch_get_main_queue()`
- `.libdispatch-manager`: GCD se ry bestuurder
- `.root.libdispatch-manager`: GCD se ry bestuurder
- `.root.maintenance-qos`: Laaste prioriteit take
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

Let op dat dit die stelsel sal wees wat **besluit watter drade watter rye op enige tyd hanteer** (meervoudige drade mag in dieselfde ry werk of dieselfde draad mag op verskillende rye op 'n sekere tyd werk)

#### Attributte

Wanneer 'n ry geskep word met **`dispatch_queue_create`** is die derde argument 'n `dispatch_queue_attr_t`, wat gewoonlik of `DISPATCH_QUEUE_SERIAL` (wat eintlik NULL is) of `DISPATCH_QUEUE_CONCURRENT` is wat 'n aanwyser na 'n `dispatch_queue_attr_t` struktuur is wat toelaat om sommige parameters van die ry te beheer.

### Afleweringsobjekte

Daar is verskeie objekte wat libdispatch gebruik en rye en blokke is net 2 daarvan. Dit is moontlik om hierdie objekten te skep met `dispatch_object_create`:

- `blok`
- `data`: Data blokke
- `group`: Groep van blokke
- `io`: Async I/O versoeke
- `mach`: Mach poorte
- `mach_msg`: Mach boodskappe
- `pthread_root_queue`: 'n ry met 'n pthread draadpoel en nie werkrye nie
- `ry`
- `semaphore`
- `bron`: Gebeurtenisbron

## Objective-C

In Objective-C is daar verskillende funksies om 'n blok te stuur om parallel uitgevoer te word:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Dien 'n blok in vir asynchrone uitvoering op 'n afleweringsry en keer onmiddellik terug.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Dien 'n blokobjek in vir uitvoering en keer terug nadat daardie blok klaar is met uitvoer.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Voer 'n blokobjek slegs een keer uit vir die leeftyd van 'n toepassing.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Dien 'n werksitem in vir uitvoering en keer terug slegs nadat dit klaar is met uitvoer. Anders as [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), respekteer hierdie funksie al die attributen van die ry wanneer dit die blok uitvoer.

Hierdie funksies verwag hierdie parameters: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`ry,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`blok`**

Dit is die **struktuur van 'n Blok**:
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
En dit is 'n voorbeeld om **parallelisme** te gebruik met **`dispatch_async`**:
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

**`libswiftDispatch`** is 'n biblioteek wat **Swift bindings** aan die Grand Central Dispatch (GCD) raamwerk bied wat oorspronklik in C geskryf is.\
Die **`libswiftDispatch`** biblioteek verpak die C GCD APIs in 'n meer Swift-vriendelike koppelvlak, wat dit makliker en meer intuïtief maak vir Swift-ontwikkelaars om met GCD te werk.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Code voorbeeld**:
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

Die volgende Frida-skrip kan gebruik word om **in verskeie `dispatch`** funksies te **hook** en die wachtrynaam, die terugspoor en die blok te onttrek: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Tans verstaan Ghidra nie die ObjectiveC **`dispatch_block_t`** struktuur nie, en ook nie die **`swift_dispatch_block`** een nie.

So as jy wil hê dit moet hulle verstaan, kan jy net **declareer**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Vind dan 'n plek in die kode waar hulle **gebruik** word:

> [!TIP]
> Let op al die verwysings na "block" om te verstaan hoe jy kan agterkom dat die struktuur gebruik word.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Regsklik op die veranderlike -> Her tipe veranderlike en kies in hierdie geval **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra sal outomaties alles herskryf:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
