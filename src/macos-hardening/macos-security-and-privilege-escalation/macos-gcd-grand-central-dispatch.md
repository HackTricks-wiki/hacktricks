# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Grand Central Dispatch (GCD),** ayrıca **libdispatch** (`libdispatch.dyld`) olarak da bilinir, hem macOS hem de iOS'ta mevcuttur. Bu, Apple tarafından çok çekirdekli donanımda eşzamanlı (çok iş parçacıklı) yürütme için uygulama desteğini optimize etmek amacıyla geliştirilmiş bir teknolojidir.

**GCD**, uygulamanızın **blok nesneleri** şeklinde **görevler** **gönderebileceği** **FIFO kuyrukları** sağlar ve yönetir. Dağıtım kuyruklarına gönderilen bloklar, sistem tarafından tamamen yönetilen bir **iş parçacığı havuzunda** **yürütülür**. GCD, dağıtım kuyruklarındaki görevleri yürütmek için otomatik olarak iş parçacıkları oluşturur ve bu görevlerin mevcut çekirdeklerde çalışmasını planlar.

> [!TIP]
> Özetle, **paralel** kod yürütmek için, süreçler **GCD'ye kod blokları gönderebilir**, bu da yürütmelerini üstlenir. Bu nedenle, süreçler yeni iş parçacıkları oluşturmaz; **GCD verilen kodu kendi iş parçacığı havuzuyla yürütür** (gerekirse artabilir veya azalabilir).

Bu, paralel yürütmeyi başarılı bir şekilde yönetmek için çok yardımcıdır, süreçlerin oluşturduğu iş parçacığı sayısını büyük ölçüde azaltır ve paralel yürütmeyi optimize eder. Bu, **büyük paralellik** gerektiren görevler (brute-forcing?) veya ana iş parçacığını engellemeyen görevler için idealdir: Örneğin, iOS'taki ana iş parçacığı UI etkileşimlerini yönetir, bu nedenle uygulamanın donmasına neden olabilecek herhangi bir diğer işlev (arama, web erişimi, dosya okuma...) bu şekilde yönetilir.

### Bloklar

Bir blok, **kendi kendine yeterli bir kod bölümü** (bir değer döndüren argümanlı bir fonksiyon gibi) olup, bağlı değişkenleri de belirtebilir.\
Ancak, derleyici seviyesinde bloklar mevcut değildir, bunlar `os_object`lerdir. Bu nesnelerin her biri iki yapıdan oluşur:

- **blok literal**:&#x20;
- Blok sınıfına işaret eden **`isa`** alanıyla başlar:
- `NSConcreteGlobalBlock` ( `__DATA.__const`'dan bloklar)
- `NSConcreteMallocBlock` (yığın içindeki bloklar)
- `NSConcreateStackBlock` (yığın içindeki bloklar)
- **`flags`** (blok tanımında mevcut alanları gösterir) ve bazı ayrılmış baytlar
- Çağrılacak fonksiyon işaretçisi
- Blok tanımına işaretçi
- İçe aktarılan blok değişkenleri (varsa)
- **blok tanımı**: Boyutu mevcut veriye bağlıdır (önceki bayraklarda belirtildiği gibi)
- Bazı ayrılmış baytlar içerir
- Boyutu
- Genellikle parametreler için ne kadar alan gerektiğini bilmek için bir Objective-C tarzı imzasına işaretçi içerir (bayrak `BLOCK_HAS_SIGNATURE`)
- Değişkenler referans alındığında, bu blok ayrıca bir kopyalama yardımcı programına (değeri başta kopyalama) ve serbest bırakma yardımcı programına (serbest bırakma) işaretçiler içerir.

### Kuyruklar

Bir dağıtım kuyruğu, yürütme için blokların FIFO sıralamasını sağlayan adlandırılmış bir nesnedir.

Bloklar, yürütülmek üzere kuyruklara yerleştirilir ve bunlar 2 mod destekler: `DISPATCH_QUEUE_SERIAL` ve `DISPATCH_QUEUE_CONCURRENT`. Elbette **seri** olan **yarış durumu** sorunları yaşamayacaktır çünkü bir blok, önceki blok bitene kadar yürütülmeyecektir. Ancak **diğer türdeki kuyrukta bu sorun olabilir**.

Varsayılan kuyruklar:

- `.main-thread`: `dispatch_get_main_queue()`'dan
- `.libdispatch-manager`: GCD'nin kuyruk yöneticisi
- `.root.libdispatch-manager`: GCD'nin kuyruk yöneticisi
- `.root.maintenance-qos`: En düşük öncelikli görevler
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND` olarak mevcut
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE` olarak mevcut
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT` olarak mevcut
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH` olarak mevcut
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: En yüksek öncelik
- `.root.background-qos.overcommit`

Her zaman **hangi iş parçacıklarının hangi kuyrukları yöneteceğine** sistemin karar vereceğini unutmayın (birden fazla iş parçacığı aynı kuyrukta çalışabilir veya aynı iş parçacığı farklı kuyruklarda bir noktada çalışabilir).

#### Özellikler

**`dispatch_queue_create`** ile bir kuyruk oluştururken üçüncü argüman bir `dispatch_queue_attr_t`'dir, bu genellikle ya `DISPATCH_QUEUE_SERIAL` (aslında NULL'dur) ya da bazı kuyruk parametrelerini kontrol etmeye olanak tanıyan bir `dispatch_queue_attr_t` yapısına işaret eden `DISPATCH_QUEUE_CONCURRENT`'dır.

### Dağıtım nesneleri

libdispatch'in kullandığı birkaç nesne vardır ve kuyruklar ile bloklar bunlardan sadece 2'sidir. Bu nesneleri `dispatch_object_create` ile oluşturmak mümkündür:

- `block`
- `data`: Veri blokları
- `group`: Blok grubu
- `io`: Asenkron G/Ç talepleri
- `mach`: Mach portları
- `mach_msg`: Mach mesajları
- `pthread_root_queue`: Bir pthread iş parçacığı havuzuna sahip bir kuyruk ve iş kuyrukları değil
- `queue`
- `semaphore`
- `source`: Olay kaynağı

## Objective-C

Objective-C'de bir bloğu paralel olarak yürütmek için gönderme işlevleri vardır:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Bir bloğu asenkron yürütme için bir dağıtım kuyruğuna gönderir ve hemen döner.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Bir blok nesnesini yürütme için gönderir ve o blok yürütmeyi bitirdikten sonra döner.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Bir blok nesnesini yalnızca bir kez uygulamanın ömrü boyunca yürütür.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Bir iş öğesini yürütme için gönderir ve yalnızca yürütmeyi bitirdikten sonra döner. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) ile karşılaştırıldığında, bu işlev bloğu yürütürken kuyruğun tüm özelliklerine saygı gösterir.

Bu işlevler şu parametreleri bekler: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Bu, bir Blok'un **yapısıdır**:
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
Ve bu, **`dispatch_async`** ile **paralellik** kullanmanın bir örneğidir:
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

**`libswiftDispatch`**, C dilinde yazılmış olan Grand Central Dispatch (GCD) çerçevesine **Swift bağlamaları** sağlayan bir kütüphanedir.\
**`libswiftDispatch`** kütüphanesi, C GCD API'lerini daha Swift dostu bir arayüzle sararak, Swift geliştiricilerinin GCD ile çalışmasını daha kolay ve sezgisel hale getirir.

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

Aşağıdaki Frida script'i **birçok `dispatch`** fonksiyonuna hook yapmak ve kuyruk adını, geri izlemeyi ve bloğu çıkarmak için kullanılabilir: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Şu anda Ghidra, ne ObjectiveC **`dispatch_block_t`** yapısını ne de **`swift_dispatch_block`** yapısını anlamıyor.

Eğer bunları anlamasını istiyorsanız, sadece **tanımlayabilirsiniz**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Sonra, kodda bunların **kullanıldığı** bir yer bulun:

> [!TIP]
> "block" terimine yapılan tüm referansları not edin, böylece yapının nasıl kullanıldığını anlayabilirsiniz.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Değişkene sağ tıklayın -> Değişkeni Yeniden Yazın ve bu durumda **`swift_dispatch_block`**'ı seçin:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra her şeyi otomatik olarak yeniden yazacaktır:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
