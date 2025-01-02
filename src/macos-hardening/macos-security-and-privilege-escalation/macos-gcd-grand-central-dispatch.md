# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

**Grand Central Dispatch (GCD),** znany również jako **libdispatch** (`libdispatch.dyld`), jest dostępny zarówno w macOS, jak i iOS. To technologia opracowana przez Apple w celu optymalizacji wsparcia aplikacji dla równoległego (wielowątkowego) wykonywania na sprzęcie wielordzeniowym.

**GCD** zapewnia i zarządza **kolejkami FIFO**, do których Twoja aplikacja może **przesyłać zadania** w postaci **obiektów blokowych**. Bloki przesyłane do kolejek dispatch są **wykonywane na puli wątków** w pełni zarządzanej przez system. GCD automatycznie tworzy wątki do wykonywania zadań w kolejkach dispatch i planuje te zadania do uruchomienia na dostępnych rdzeniach.

> [!TIP]
> Podsumowując, aby wykonać kod w **równolegle**, procesy mogą wysyłać **bloki kodu do GCD**, który zajmie się ich wykonaniem. Dlatego procesy nie tworzą nowych wątków; **GCD wykonuje dany kod za pomocą własnej puli wątków** (która może się zwiększać lub zmniejszać w razie potrzeby).

To jest bardzo pomocne w skutecznym zarządzaniu równoległym wykonywaniem, znacznie redukując liczbę wątków tworzonych przez procesy i optymalizując równoległe wykonanie. To jest idealne dla zadań, które wymagają **dużego równoległości** (brute-forcing?) lub dla zadań, które nie powinny blokować głównego wątku: Na przykład, główny wątek w iOS obsługuje interakcje z UI, więc wszelkie inne funkcjonalności, które mogłyby spowodować zawieszenie aplikacji (wyszukiwanie, dostęp do sieci, odczyt pliku...) są zarządzane w ten sposób.

### Bloki

Blok to **samodzielna sekcja kodu** (jak funkcja z argumentami zwracająca wartość) i może również określać zmienne powiązane.\
Jednak na poziomie kompilatora bloki nie istnieją, są `os_object`s. Każdy z tych obiektów składa się z dwóch struktur:

- **literal bloku**:&#x20;
- Zaczyna się od pola **`isa`**, wskazującego na klasę bloku:
- `NSConcreteGlobalBlock` (bloki z `__DATA.__const`)
- `NSConcreteMallocBlock` (bloki w stercie)
- `NSConcreateStackBlock` (bloki na stosie)
- Ma **`flags`** (wskazujące pola obecne w opisie bloku) i kilka zarezerwowanych bajtów
- Wskaźnik do funkcji do wywołania
- Wskaźnik do opisu bloku
- Zmienne importowane przez blok (jeśli są)
- **opis bloku**: Jego rozmiar zależy od danych, które są obecne (jak wskazano w poprzednich flagach)
- Ma kilka zarezerwowanych bajtów
- Jego rozmiar
- Zwykle będzie miał wskaźnik do sygnatury w stylu Objective-C, aby wiedzieć, ile miejsca jest potrzebne na parametry (flaga `BLOCK_HAS_SIGNATURE`)
- Jeśli zmienne są referencjonowane, ten blok będzie również miał wskaźniki do pomocnika kopiującego (kopiującego wartość na początku) i pomocnika zwalniającego (zwalniającego ją).

### Kolejki

Kolejka dispatch to nazwany obiekt zapewniający FIFO porządek bloków do wykonania.

Bloki są ustawiane w kolejkach do wykonania, a te wspierają 2 tryby: `DISPATCH_QUEUE_SERIAL` i `DISPATCH_QUEUE_CONCURRENT`. Oczywiście **kolejka szeregowa** **nie będzie miała problemów z warunkami wyścigu**, ponieważ blok nie zostanie wykonany, dopóki poprzedni nie zakończy się. Ale **drugi typ kolejki może je mieć**.

Domyślne kolejki:

- `.main-thread`: Z `dispatch_get_main_queue()`
- `.libdispatch-manager`: Menedżer kolejek GCD
- `.root.libdispatch-manager`: Menedżer kolejek GCD
- `.root.maintenance-qos`: Zadania o najniższym priorytecie
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Najwyższy priorytet
- `.root.background-qos.overcommit`

Zauważ, że to system zdecyduje **które wątki obsługują które kolejki w danym momencie** (wiele wątków może pracować w tej samej kolejce lub ten sam wątek może pracować w różnych kolejkach w pewnym momencie)

#### Atrybuty

Podczas tworzenia kolejki za pomocą **`dispatch_queue_create`** trzeci argument to `dispatch_queue_attr_t`, który zazwyczaj jest albo `DISPATCH_QUEUE_SERIAL` (co w rzeczywistości jest NULL), albo `DISPATCH_QUEUE_CONCURRENT`, który jest wskaźnikiem do struktury `dispatch_queue_attr_t`, która pozwala kontrolować niektóre parametry kolejki.

### Obiekty dispatch

Istnieje kilka obiektów, które wykorzystuje libdispatch, a kolejki i bloki to tylko 2 z nich. Możliwe jest tworzenie tych obiektów za pomocą `dispatch_object_create`:

- `block`
- `data`: Bloki danych
- `group`: Grupa bloków
- `io`: Asynchroniczne żądania I/O
- `mach`: Porty Mach
- `mach_msg`: Wiadomości Mach
- `pthread_root_queue`: Kolejka z pulą wątków pthread i nie workqueues
- `queue`
- `semaphore`
- `source`: Źródło zdarzeń

## Objective-C

W Objective-C istnieją różne funkcje do wysyłania bloku do wykonania równolegle:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Przesyła blok do asynchronicznego wykonania w kolejce dispatch i natychmiast zwraca.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Przesyła obiekt bloku do wykonania i zwraca po zakończeniu jego wykonania.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Wykonuje obiekt bloku tylko raz w czasie życia aplikacji.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Przesyła element roboczy do wykonania i zwraca tylko po zakończeniu jego wykonania. W przeciwieństwie do [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), ta funkcja respektuje wszystkie atrybuty kolejki podczas wykonywania bloku.

Te funkcje oczekują tych parametrów: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

To jest **struktura bloku**:
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

**`libswiftDispatch`** to biblioteka, która zapewnia **Swift bindings** do frameworka Grand Central Dispatch (GCD), który pierwotnie został napisany w C.\
Biblioteka **`libswiftDispatch`** opakowuje C GCD API w bardziej przyjazny dla Swift interfejs, co ułatwia i czyni bardziej intuicyjnym pracę z GCD dla programistów Swift.

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

Poniższy skrypt Frida może być użyty do **podłączenia się do kilku funkcji `dispatch`** i wyodrębnienia nazwy kolejki, śladu stosu oraz bloku: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Obecnie Ghidra nie rozumie ani struktury ObjectiveC **`dispatch_block_t`**, ani struktury **`swift_dispatch_block`**.

Więc jeśli chcesz, aby je zrozumiała, możesz po prostu **zadeklarować je**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Następnie znajdź miejsce w kodzie, gdzie są **używane**:

> [!TIP]
> Zauważ wszystkie odniesienia do "block", aby zrozumieć, jak możesz ustalić, że struktura jest używana.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Kliknij prawym przyciskiem myszy na zmienną -> Zmień typ zmiennej i wybierz w tym przypadku **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra automatycznie przepisze wszystko:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
