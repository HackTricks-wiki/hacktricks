# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

**Grand Central Dispatch (GCD),** poznat i kao **libdispatch** (`libdispatch.dyld`), dostupan je i u macOS-u i u iOS-u. To je tehnologija koju je razvio Apple radi optimizacije podrške aplikacija za konkurentno (multithreaded) izvršavanje na višejezgrenom hardveru.<sup>[[4]](#references)</sup>

**GCD** obezbeđuje i upravlja **FIFO redovima** u koje vaša aplikacija može da **pošalje zadatke** u obliku **block objekata**. Blocks poslati u dispatch redove **izvršavaju se u skupu thread-ova** kojim u potpunosti upravlja sistem. GCD automatski kreira thread-ove za izvršavanje zadataka u dispatch redovima i raspoređuje te zadatke na dostupna jezgra.<sup>[[1]](#references)</sup>

> [!TIP]
> Ukratko, za izvršavanje koda **paralelno**, procesi mogu da pošalju **blocks koda u GCD**, koji će se pobrinuti za njihovo izvršavanje. Prema tome, procesi ne kreiraju nove thread-ove; **GCD izvršava dati kod pomoću sopstvenog skupa thread-ova** (koji se po potrebi može povećavati ili smanjivati).

Ovo je veoma korisno za uspešno upravljanje paralelnim izvršavanjem, jer značajno smanjuje broj thread-ova koje procesi kreiraju i optimizuje paralelno izvršavanje. Ovo je idealno za zadatke koji zahtevaju **veliki stepen paralelizma** (brute-forcing?) ili za zadatke koji ne bi trebalo da blokiraju glavni thread: Na primer, glavni thread na iOS-u obrađuje interakcije sa korisničkim interfejsom, pa se svim ostalim funkcionalnostima koje bi mogle da zamrznu aplikaciju (pretraga, pristup webu, čitanje fajla...) upravlja na ovaj način.

### Blocks

Block je **samostalna sekcija koda** (poput funkcije sa argumentima koja vraća vrednost), a može da navede i vezane promenljive.\
Međutim, na nivou kompajlera blocks ne postoje; oni su `os_object`s. Svaki od ovih objekata sastoji se od dve strukture:

- **block literal**:
- Počinje poljem **`isa`**, koje pokazuje na klasu block-a:
- `NSConcreteGlobalBlock` (blocks iz `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks na heap-u)
- `NSConcreateStackBlock` (blocks na stack-u)
- Sadrži **`flags`** (koji označava polja prisutna u descriptor-u block-a) i nekoliko rezervisanih bajtova
- Pokazivač na funkciju koju treba pozvati
- Pokazivač na descriptor block-a
- Uvezene promenljive block-a (ako postoje)
- **block descriptor**: Njegova veličina zavisi od prisutnih podataka (kao što je navedeno u prethodnim flags)
- Sadrži nekoliko rezervisanih bajtova
- Njegova veličina
- Obično će sadržati pokazivač na potpis u Objective-C stilu, kako bi se utvrdilo koliko prostora je potrebno za parametre (flag `BLOCK_HAS_SIGNATURE`)
- Ako se promenljive referenciraju, ovaj block će takođe sadržati pokazivače na copy helper (kopiranje vrednosti na početku) i dispose helper (oslobađanje).

### Redovi

Dispatch red je imenovani objekat koji obezbeđuje FIFO redosled izvršavanja blocks.<sup>[[3]](#references)</sup>

Blocks se postavljaju u redove radi izvršavanja, a oni podržavaju 2 režima: `DISPATCH_QUEUE_SERIAL` i `DISPATCH_QUEUE_CONCURRENT`. Naravno, **serial** tip **neće imati** probleme sa race condition-om, jer se block neće izvršiti dok se prethodni ne završi. Međutim, **drugi tip reda može imati takve probleme**.

Podrazumevani redovi:

- `.main-thread`: Iz `dispatch_get_main_queue()`
- `.libdispatch-manager`: GCD queue manager
- `.root.libdispatch-manager`: GCD queue manager
- `.root.maintenance-qos`: Zadaci najnižeg prioriteta
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Dostupan kao `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Dostupan kao `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Dostupan kao `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Dostupan kao `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Najviši prioritet
- `.root.background-qos.overcommit`

Imajte na umu da će sistem odlučiti **koji thread-ovi obrađuju koje redove u kom trenutku** (više thread-ova može raditi u istom redu, ili isti thread u nekom trenutku može raditi u različitim redovima).

#### Atributi

Prilikom kreiranja reda pomoću **`dispatch_queue_create`**, treći argument je `dispatch_queue_attr_t`, koji je obično ili `DISPATCH_QUEUE_SERIAL` (što je zapravo NULL) ili `DISPATCH_QUEUE_CONCURRENT`, koji je pokazivač na strukturu `dispatch_queue_attr_t` i omogućava kontrolu određenih parametara reda.

### Dispatch objekti

Postoji nekoliko objekata koje libdispatch koristi, a redovi i blocks su samo 2 od njih. Ove objekte je moguće kreirati pomoću `dispatch_object_create`:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: Data blocks
- `group`: Grupa blocks
- `io`: Async I/O zahtevi
- `mach`: Mach portovi
- `mach_msg`: Mach poruke
- `pthread_root_queue`: Red sa pthread thread pool-om, a ne workqueues
- `queue`
- `semaphore`
- `source`: Izvor događaja

## Objective-C

U Objective-C-u postoji više funkcija za slanje block-a koji treba da se izvršava paralelno:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Šalje block na asinhrono izvršavanje u dispatch redu i odmah vraća rezultat.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Šalje block objekat na izvršavanje i vraća rezultat nakon što se izvršavanje tog block-a završi.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Izvršava block objekat samo jednom tokom životnog veka aplikacije.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Šalje work item na izvršavanje i vraća rezultat tek nakon što se njegovo izvršavanje završi. Za razliku od [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), ova funkcija poštuje sve atribute reda kada izvršava block.

Ove funkcije očekuju sledeće parametre: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Ovo je **struct Block-a**:
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
A ovo je primer korišćenja **paralelizma** sa **`dispatch_async`**:
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

**`libswiftDispatch`** je biblioteka koja pruža **Swift bindings** za framework Grand Central Dispatch (GCD), koji je prvobitno napisan u jeziku C.\
Biblioteka **`libswiftDispatch`** obavija C GCD API-je interfejsom prilagođenijim jeziku Swift, čime Swift developerima olakšava i čini intuitivnijim rad sa GCD-om.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Primer koda**:
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

Sledeći Frida script može da se koristi za **hookovanje nekoliko `dispatch`** funkcija i izdvajanje imena queue-a, backtrace-a i block-a: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Trenutno Ghidra ne razume ni ObjectiveC **`dispatch_block_t`** strukturu, ni **`swift_dispatch_block`** strukturu.

Dakle, ako želite da ih razume, možete ih jednostavno **deklarisati**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Zatim pronađite mesto u kodu gde se one **koriste**:

> [!TIP]
> Obratite pažnju na sve reference ka "block" da biste razumeli kako možete utvrditi da se struktura koristi.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Kliknite desnim tasterom na promenljivu -> Retype Variable i u ovom slučaju izaberite **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra će automatski ponovo napisati sve:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [1] [libdispatch — `src/queue.c` (implementacija queue/thread-pool-a)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (javni queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
