# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Grand Central Dispatch (GCD),** **libdispatch** (`libdispatch.dyld`) olarak da bilinir ve hem macOS hem de iOS'ta kullanılabilir. Apple tarafından, çok çekirdekli donanımlarda eşzamanlı (multithreaded) yürütme için uygulama desteğini optimize etmek amacıyla geliştirilmiş bir teknolojidir.

**GCD**, uygulamanızın **block object** biçiminde **task'ler gönderebileceği** ve yöneteceği **FIFO kuyrukları** sağlar. Dispatch queue'lara gönderilen block'lar, tamamen sistem tarafından yönetilen bir **thread havuzunda yürütülür**. GCD, dispatch queue'lardaki task'leri yürütmek için otomatik olarak thread'ler oluşturur ve bu task'lerin mevcut core'larda çalışmasını planlar.

> [!TIP]
> Özetle, kodu **parallel** olarak yürütmek için process'ler **GCD'ye kod block'ları gönderebilir** ve GCD bunların yürütülmesini yönetir. Bu nedenle process'ler yeni thread'ler oluşturmaz; **GCD, verilen kodu kendi thread havuzuyla yürütür** (gerektiğinde bu havuz büyüyebilir veya küçülebilir).

Bu yöntem, parallel yürütmeyi başarılı bir şekilde yönetmek için oldukça kullanışlıdır; process'lerin oluşturduğu thread sayısını büyük ölçüde azaltır ve parallel yürütmeyi optimize eder. Bu, **yüksek düzeyde parallelism** gerektiren task'ler (brute-forcing?) veya main thread'i engellememesi gereken task'ler için idealdir: Örneğin, iOS'ta main thread UI etkileşimlerini yönetir; bu nedenle uygulamanın takılmasına neden olabilecek diğer işlevler (arama, web'e erişme, dosya okuma...) bu şekilde yönetilir.

### Block'lar

Bir block, **kendi içinde bağımsız bir kod bölümüdür** (parametreleri olan ve bir değer döndüren bir function gibi) ve bound variable'lar da belirtebilir.\
Ancak compiler seviyesinde block'lar mevcut değildir; bunlar `os_object`'lerdir. Bu object'lerin her biri iki structure'dan oluşur:

- **block literal**:
- Block'ın class'ına işaret eden **`isa`** alanıyla başlar:
- `NSConcreteGlobalBlock` (`__DATA.__const` içindeki block'lar)
- `NSConcreteMallocBlock` (heap'teki block'lar)
- `NSConcreateStackBlock` (stack'teki block'lar)
- Block descriptor'da mevcut olan alanları belirten **`flags`** ve bazı reserved byte'lar
- Çağrılacak function pointer'ı
- Block descriptor'a işaret eden pointer
- Block tarafından import edilen variable'lar (varsa)
- **block descriptor**: Boyutu, mevcut olan data'ya bağlıdır (önceki flag'lerde belirtildiği gibi)
- Bazı reserved byte'lara sahiptir
- Boyutu
- Parametreler için ne kadar alana ihtiyaç olduğunu bilmek amacıyla genellikle Objective-C tarzı bir signature'a işaret eden bir pointer içerir (`BLOCK_HAS_SIGNATURE` flag'i)
- Variable'lara referans veriliyorsa bu block ayrıca bir copy helper'a (başlangıçta değeri kopyalamak için) ve dispose helper'a (değeri serbest bırakmak için) işaret eden pointer'lara sahip olur.

### Kuyruklar

Bir dispatch queue, yürütülecek block'lar için FIFO sıralaması sağlayan adlandırılmış bir object'tir.

Block'lar yürütülmek üzere queue'lara yerleştirilir ve bu queue'lar 2 mode'u destekler: `DISPATCH_QUEUE_SERIAL` ve `DISPATCH_QUEUE_CONCURRENT`. Elbette **serial** olan queue'da **race condition** sorunları **olmaz**, çünkü bir block önceki block tamamlanana kadar yürütülmez. Ancak **diğer queue türünde bu sorun yaşanabilir**.

Default queue'lar:

- `.main-thread`: `dispatch_get_main_queue()` tarafından sağlanır
- `.libdispatch-manager`: GCD'nin queue manager'ı
- `.root.libdispatch-manager`: GCD'nin queue manager'ı
- `.root.maintenance-qos`: En düşük öncelikli task'ler
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND` olarak kullanılabilir
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE` olarak kullanılabilir
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT` olarak kullanılabilir
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH` olarak kullanılabilir
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: En yüksek öncelik
- `.root.background-qos.overcommit`

Her zaman **hangi thread'lerin hangi queue'ları yöneteceğine sistemin karar vereceğini** unutmayın (birden fazla thread aynı queue üzerinde çalışabilir veya aynı thread bir noktada farklı queue'larda çalışabilir).

#### Özellikler

**`dispatch_queue_create`** ile bir queue oluşturulurken üçüncü parametre, genellikle `DISPATCH_QUEUE_SERIAL` (aslında NULL'dur) veya queue'nun bazı parametrelerini kontrol etmeyi sağlayan bir `dispatch_queue_attr_t` struct'ına pointer olan `DISPATCH_QUEUE_CONCURRENT` değeridir.

### Dispatch object'leri

libdispatch'in kullandığı çeşitli object'ler vardır; queue'lar ve block'lar bunlardan yalnızca 2 tanesidir. Bu object'leri `dispatch_object_create` ile oluşturmak mümkündür:

- `block`
- `data`: Data block'ları
- `group`: Block grubu
- `io`: Async I/O request'leri
- `mach`: Mach port'ları
- `mach_msg`: Mach message'ları
- `pthread_root_queue`: pthread thread pool'una sahip, workqueue'su olmayan bir queue
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Objective-C'de bir block'ı parallel olarak yürütülmek üzere göndermek için farklı function'lar vardır:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Bir block'ı bir dispatch queue üzerinde asynchronous olarak yürütülmek üzere gönderir ve hemen döner.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Bir block object'ini yürütülmek üzere gönderir ve block'ın yürütülmesi tamamlandıktan sonra döner.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Bir block object'ini uygulamanın yaşam süresi boyunca yalnızca bir kez yürütür.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Bir work item'ı yürütülmek üzere gönderir ve yalnızca yürütülmesi tamamlandıktan sonra döner. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync)'den farklı olarak bu function, block'ı yürütürken queue'nun tüm attribute'larına uyar.

Bu function'lar şu parametreleri bekler: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Bu, bir Block'ın **struct**'ıdır:
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
Ve bu, **`dispatch_async`** ile **paralellik** kullanmaya yönelik bir örnektir:
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

**`libswiftDispatch`**, başlangıçta C ile yazılmış Grand Central Dispatch (GCD) framework'ü için **Swift bindings** sağlayan bir kütüphanedir.\
**`libswiftDispatch`** kütüphanesi, C GCD API'lerini Swift'e daha uygun bir interface ile sarar ve Swift geliştiricilerinin GCD ile çalışmasını daha kolay ve sezgisel hâle getirir.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Kod örneği**:
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

Aşağıdaki Frida script'i, çeşitli `dispatch` işlevlerine **hook** eklemek ve queue adını, backtrace'i ve block'u çıkarmak için kullanılabilir: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Şu anda Ghidra ne ObjectiveC **`dispatch_block_t`** yapısını ne de **`swift_dispatch_block`** yapısını anlayabiliyor.

Bunları anlamasını istiyorsanız, bunları **tanımlamanız** yeterlidir:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Ardından, bunların **kullanıldığı** kodda bir yer bulun:

> [!TIP]
> Yapının kullanıldığını nasıl tespit edebileceğinizi anlamak için "block" ile ilgili tüm referansları not edin.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Değişkene sağ tıklayın -> Retype Variable seçeneğine tıklayın ve bu durumda **`swift_dispatch_block`** öğesini seçin:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra her şeyi otomatik olarak yeniden yazacaktır:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Referanslar

- [1] [libdispatch — `src/queue.c` (queue/thread-pool implementation)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
