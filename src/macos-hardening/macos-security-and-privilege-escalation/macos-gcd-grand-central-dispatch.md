# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

**Grand Central Dispatch (GCD),** znany również jako **libdispatch** (`libdispatch.dyld`), jest dostępny zarówno w macOS, jak i iOS. Jest to technologia opracowana przez Apple w celu optymalizacji obsługi aplikacji pod kątem współbieżnego (wielowątkowego) wykonywania na sprzęcie wielordzeniowym.

**GCD** udostępnia i zarządza **kolejkami FIFO**, do których aplikacja może **przesyłać zadania** w postaci **obiektów block**. Bloki przesłane do kolejek dispatch są **wykonywane w puli wątków** w pełni zarządzanej przez system. GCD automatycznie tworzy wątki do wykonywania zadań w kolejkach dispatch i planuje ich uruchomienie na dostępnych rdzeniach.

> [!TIP]
> Podsumowując, aby wykonywać kod **równolegle**, procesy mogą wysyłać **bloki kodu do GCD**, który zajmie się ich wykonaniem. Procesy nie tworzą więc nowych wątków; **GCD wykonuje dostarczony kod za pomocą własnej puli wątków** (która może zwiększać się lub zmniejszać w razie potrzeby).

Jest to bardzo pomocne w skutecznym zarządzaniu wykonywaniem równoległym, znacznie ograniczając liczbę wątków tworzonych przez procesy i optymalizując wykonywanie równoległe. Rozwiązanie to jest idealne dla zadań wymagających **dużego stopnia równoległości** (brute-forcing?) lub dla zadań, które nie powinny blokować głównego wątku: na przykład główny wątek w iOS obsługuje interakcje z interfejsem użytkownika, więc wszelkie inne funkcje, które mogłyby zawiesić aplikację (wyszukiwanie, dostęp do sieci, odczytywanie pliku...), są zarządzane w ten sposób.

### Bloki

Blok jest **samodzielną sekcją kodu** (jak funkcja z argumentami zwracająca wartość) i może również określać powiązane zmienne.\
Jednak na poziomie kompilatora bloki nie istnieją, są `os_object`s. Każdy z tych obiektów składa się z dwóch struktur:

- **block literal**:
- Zaczyna się od pola **`isa`**, wskazującego klasę bloku:
- `NSConcreteGlobalBlock` (bloki z `__DATA.__const`)
- `NSConcreteMallocBlock` (bloki na stercie)
- `NSConcreateStackBlock` (bloki na stosie)
- Zawiera **`flags`** (wskazujące pola obecne w deskryptorze bloku) oraz kilka zarezerwowanych bajtów
- Wskaźnik funkcji do wywołania
- Wskaźnik do deskryptora bloku
- Zaimportowane zmienne bloku (jeśli występują)
- **block descriptor**: jego rozmiar zależy od obecnych danych (zgodnie z wcześniejszymi flagami)
- Zawiera kilka zarezerwowanych bajtów
- Jego rozmiar
- Zwykle zawiera wskaźnik do sygnatury w stylu Objective-C, aby określić, ile miejsca jest potrzebne na parametry (flaga `BLOCK_HAS_SIGNATURE`)
- Jeśli zmienne są referencjonowane, blok ten będzie również zawierał wskaźniki do funkcji pomocniczej copy (kopiującej wartość na początku) oraz funkcji pomocniczej dispose (zwalniającej ją).

### Kolejki

Kolejka dispatch jest nazwanym obiektem zapewniającym kolejność FIFO wykonywania bloków.

Bloki są umieszczane w kolejkach w celu ich wykonania, a kolejki te obsługują 2 tryby: `DISPATCH_QUEUE_SERIAL` i `DISPATCH_QUEUE_CONCURRENT`. Oczywiście kolejka **serial** **nie będzie mieć problemów z race condition**, ponieważ blok nie zostanie wykonany, dopóki poprzedni się nie zakończy. **Drugi typ kolejki może jednak mieć takie problemy**.

Domyślne kolejki:

- `.main-thread`: Z `dispatch_get_main_queue()`
- `.libdispatch-manager`: Menedżer kolejek GCD
- `.root.libdispatch-manager`: Menedżer kolejek GCD
- `.root.maintenance-qos`: Zadania o najniższym priorytecie
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Dostępna jako `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Dostępna jako `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Dostępna jako `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Dostępna jako `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Najwyższy priorytet
- `.root.background-qos.overcommit`

Należy zauważyć, że to system decyduje, **które wątki w danym momencie obsługują poszczególne kolejki** (wiele wątków może pracować w tej samej kolejce lub ten sam wątek może w pewnym momencie pracować w różnych kolejkach).

#### Atrybuty

Podczas tworzenia kolejki za pomocą **`dispatch_queue_create`** trzecim argumentem jest `dispatch_queue_attr_t`, który zwykle jest albo `DISPATCH_QUEUE_SERIAL` (w rzeczywistości NULL), albo `DISPATCH_QUEUE_CONCURRENT`, będącym wskaźnikiem do struktury `dispatch_queue_attr_t`, która pozwala kontrolować niektóre parametry kolejki.

### Obiekty dispatch

Istnieje kilka obiektów używanych przez libdispatch, a kolejki i bloki są tylko 2 z nich. Obiekty te można tworzyć za pomocą `dispatch_object_create`:

- `block`
- `data`: Bloki danych
- `group`: Grupa bloków
- `io`: Asynchroniczne żądania I/O
- `mach`: Porty Mach
- `mach_msg`: Komunikaty Mach
- `pthread_root_queue`: Kolejka z pulą wątków pthread, a nie workqueues
- `queue`
- `semaphore`
- `source`: Źródło zdarzeń

## Objective-C

W Objective-C istnieją różne funkcje służące do wysyłania bloku do wykonania równoległego:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Przesyła blok do asynchronicznego wykonania w kolejce dispatch i natychmiast zwraca wynik.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Przesyła obiekt block do wykonania i zwraca wynik po zakończeniu wykonywania tego bloku.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Wykonuje obiekt block tylko raz w czasie życia aplikacji.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Przesyła element pracy do wykonania i zwraca wynik dopiero po zakończeniu jego wykonywania. W przeciwieństwie do [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), funkcja ta uwzględnia wszystkie atrybuty kolejki podczas wykonywania bloku.

Funkcje te oczekują następujących parametrów: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

To jest **struct obiektu Block**:
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
A oto przykład użycia **parallelism** z **`dispatch_async`**:
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

**`libswiftDispatch`** to biblioteka zapewniająca **wiązania Swift** dla frameworka Grand Central Dispatch (GCD), który został pierwotnie napisany w języku C.\
Biblioteka **`libswiftDispatch`** opakowuje API GCD języka C w bardziej przyjazny dla Swift interfejs, ułatwiając programistom Swift pracę z GCD i czyniąc ją bardziej intuicyjną.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Przykład kodu**:
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

Poniższy skrypt Frida może służyć do **hookowania kilku funkcji `dispatch`** oraz wyodrębniania nazwy kolejki, backtrace i bloku: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Obecnie Ghidra nie rozumie ani struktury ObjectiveC **`dispatch_block_t`**, ani **`swift_dispatch_block`**.

Jeśli więc chcesz, aby je rozumiał, możesz je po prostu **zadeklarować**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Następnie znajdź w kodzie miejsce, w którym są **używane**:

> [!TIP]
> Zwróć uwagę na wszystkie odwołania do „block”, aby zrozumieć, jak można rozpoznać, że struktura jest używana.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Kliknij zmienną prawym przyciskiem myszy -> Retype Variable i w tym przypadku wybierz **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra automatycznie przepisze wszystko:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (queue/thread-pool implementation)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
