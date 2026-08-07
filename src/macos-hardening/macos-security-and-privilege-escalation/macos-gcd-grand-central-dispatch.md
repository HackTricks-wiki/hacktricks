# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Grand Central Dispatch (GCD),** **libdispatch** (`libdispatch.dyld`) olarak da bilinir ve hem macOS hem de iOS'ta kullanılabilir. Apple tarafından, çok çekirdekli donanımlarda eşzamanlı (çok iş parçacıklı) yürütme için uygulama desteğini optimize etmek amacıyla geliştirilmiş bir teknolojidir.<sup>[[4]](#references)</sup>

**GCD**, uygulamanızın **block nesneleri** biçiminde **görevler gönderebileceği** ve yöneteceği **FIFO kuyrukları** sağlar. Dispatch kuyruklarına gönderilen block'lar, tamamen sistem tarafından yönetilen bir **iş parçacığı havuzunda yürütülür**. GCD, dispatch kuyruklarındaki görevleri yürütmek için otomatik olarak iş parçacıkları oluşturur ve bu görevlerin kullanılabilir çekirdeklerde çalışmasını planlar.<sup>[[1]](#references)</sup>

> [!TIP]
> Özetle, kodu **paralel** olarak yürütmek için süreçler **kod block'larını GCD'ye gönderebilir** ve GCD bunların yürütülmesini yönetir. Bu nedenle süreçler yeni iş parçacıkları oluşturmaz; **GCD, verilen kodu kendi iş parçacığı havuzuyla yürütür** (gerektiğinde bu havuz büyüyebilir veya küçülebilir).

Bu, paralel yürütmeyi başarılı bir şekilde yönetmek için oldukça faydalıdır; süreçlerin oluşturduğu iş parçacığı sayısını büyük ölçüde azaltır ve paralel yürütmeyi optimize eder. Bu, **yüksek düzeyde paralellik** gerektiren görevler (brute-forcing?) veya ana iş parçacığını engellememesi gereken görevler için idealdir: Örneğin iOS'ta ana iş parçacığı kullanıcı arayüzü etkileşimlerini yönetir; bu nedenle uygulamanın donmasına neden olabilecek diğer işlevler (arama yapmak, web'e erişmek, dosya okumak...) bu şekilde yönetilir.

### Block'lar

Bir block, **kendi içinde bütünlük taşıyan bir kod bölümüdür** (değer döndüren ve argüman alan bir function gibi) ve ayrıca bağlı değişkenleri belirtebilir.\
Ancak compiler seviyesinde block'lar mevcut değildir; bunlar `os_object`'lerdir. Bu nesnelerin her biri iki yapıdan oluşur:

- **block literal**:
- Block'ın sınıfını gösteren **`isa`** alanıyla başlar:
- `NSConcreteGlobalBlock` (`__DATA.__const` içindeki block'lar)
- `NSConcreteMallocBlock` (heap'teki block'lar)
- `NSConcreateStackBlock` (stack'teki block'lar)
- Block descriptor'ında mevcut alanları belirten **`flags`** ve bazı ayrılmış byte'lar
- Çağrılacak function pointer
- Block descriptor'ına bir pointer
- Block tarafından içe aktarılan değişkenler (varsa)
- **block descriptor**: Boyutu, mevcut verilere bağlıdır (önceki flags tarafından belirtildiği üzere)
- Bazı ayrılmış byte'lara sahiptir
- Boyutu
- Parametreler için ne kadar alana ihtiyaç olduğunu belirlemek üzere genellikle Objective-C tarzı bir signature'a pointer içerir (`BLOCK_HAS_SIGNATURE` flag'i)
- Değişkenlere başvuruluyorsa bu block ayrıca bir copy helper'a (değeri başlangıçta kopyalayan) ve dispose helper'a (değeri serbest bırakan) pointer'lar içerir.

### Kuyruklar

Bir dispatch kuyruğu, yürütülecek block'ların FIFO sıralamasını sağlayan adlandırılmış bir nesnedir.<sup>[[3]](#references)</sup>

Block'lar yürütülmek üzere kuyruklara yerleştirilir ve bu kuyruklar 2 modu destekler: `DISPATCH_QUEUE_SERIAL` ve `DISPATCH_QUEUE_CONCURRENT`. Elbette **serial** olan türde **race condition** sorunları **olmaz**, çünkü önceki block tamamlanmadan bir block yürütülmez. Ancak **diğer kuyruk türünde bu sorun yaşanabilir**.

Varsayılan kuyruklar:

- `.main-thread`: `dispatch_get_main_queue()` üzerinden
- `.libdispatch-manager`: GCD'nin kuyruk yöneticisi
- `.root.libdispatch-manager`: GCD'nin kuyruk yöneticisi
- `.root.maintenance-qos`: En düşük öncelikli görevler
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

**Her anda hangi iş parçacıklarının hangi kuyrukları yöneteceğine sistemin karar vereceğini** unutmayın (birden fazla iş parçacığı aynı kuyrukta çalışabilir veya aynı iş parçacığı belirli bir zamanda farklı kuyruklarda çalışabilir).

#### Öznitelikler

**`dispatch_queue_create`** ile bir kuyruk oluşturulurken üçüncü argüman, genellikle `DISPATCH_QUEUE_SERIAL` (aslında NULL'dur) veya kuyruğun bazı parametrelerini kontrol etmeyi sağlayan bir `dispatch_queue_attr_t` struct'ına pointer olan `DISPATCH_QUEUE_CONCURRENT` değerlerinden biridir.

### Dispatch nesneleri

libdispatch'in kullandığı çeşitli nesneler vardır ve kuyruklar ile block'lar bunlardan yalnızca 2'sidir. Bu nesneleri `dispatch_object_create` ile oluşturmak mümkündür:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: Veri block'ları
- `group`: Block grubu
- `io`: Async I/O istekleri
- `mach`: Mach port'ları
- `mach_msg`: Mach mesajları
- `pthread_root_queue`: pthread iş parçacığı havuzuna sahip ve workqueue kullanmayan bir kuyruk
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Objective-C'de bir block'ı paralel olarak yürütülmek üzere göndermek için farklı function'lar bulunur:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Bir block'ı dispatch kuyruğunda async olarak yürütülmek üzere gönderir ve hemen geri döner.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Bir block nesnesini yürütülmek üzere gönderir ve bu block'ın yürütülmesi tamamlandıktan sonra geri döner.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Bir block nesnesini uygulamanın yaşam süresi boyunca yalnızca bir kez yürütür.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Bir work item'ı yürütülmek üzere gönderir ve yalnızca yürütme tamamlandıktan sonra geri döner. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync)'den farklı olarak bu function, block'ı yürütürken kuyruğun tüm özniteliklerine uyar.

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
Ve işte **`dispatch_async`** ile **paralellik** kullanmaya bir örnek:
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

**`libswiftDispatch`**, başlangıçta C ile yazılmış Grand Central Dispatch (GCD) framework'ü için **Swift binding'leri** sağlayan bir library'dir.\
**`libswiftDispatch`** library'si, C GCD API'lerini Swift'e daha uygun bir interface ile sarar ve Swift geliştiricilerinin GCD ile çalışmasını daha kolay ve sezgisel hale getirir.

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

Aşağıdaki Frida script'i, birkaç `dispatch` fonksiyonuna **hook** olmak ve queue adını, backtrace'i ve block'u çıkarmak için kullanılabilir: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Şu anda Ghidra ne ObjectiveC **`dispatch_block_t`** yapısını ne de **`swift_dispatch_block`** yapısını anlıyor.

Bu nedenle bunları anlamasını istiyorsanız, bunları **tanımlayabilirsiniz**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Ardından, bunların **kullanıldığı** kodda bir yer bulun:

> [!TIP]
> Yapının kullanıldığını nasıl anlayabileceğinizi görmek için "block" ile ilgili tüm referansları not edin.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Değişkene sağ tıklayın -> Retype Variable öğesini seçin ve bu durumda **`swift_dispatch_block`** seçeneğini belirleyin:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra her şeyi otomatik olarak yeniden yazar:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (queue/thread-pool implementation)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
